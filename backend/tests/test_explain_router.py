"""Route-level tests for /scan/explain.

Mongo and OpenRouter are both replaced: get_explanations is swapped for an
in-memory fake collection, and explain_finding for a stub that records how
often it was called. Nothing here touches a network or a database.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pymongo.errors import PyMongoError

from ai_explainer import AIExplainerError
from routers import explain_router as module
from routers.explain_router import FindingExplainRequest, _cache_key

FINDING = {
    "algorithm": "RSA",
    "severity": "critical",
    "attack_vector": "Shor's Algorithm",
    "replacement": "ML-KEM (FIPS 203)",
    "replacement_reason": "Shor's Algorithm factors the modulus.",
    "identifier": "rsa.generate_private_key",
    "match_type": "function_call",
    "language": "python",
    "quantum_vulnerable": True,
    "classical_vulnerable": False,
    "file": "src/auth.py",
    "line": 12,
    "code_snippet": "private_key = rsa.generate_private_key(key_size=2048)",
    "fix_snippet": "kem = oqs.KeyEncapsulation('ML-KEM-768')",
}


def request_model(**overrides) -> FindingExplainRequest:
    return FindingExplainRequest(**{**FINDING, **overrides})


class FakeCollection:
    """The two Motor calls explain_router makes, over a dict."""

    def __init__(self, fail_with: type[Exception] | None = None) -> None:
        self.docs: dict[str, dict] = {}
        self.fail_with = fail_with

    async def find_one(self, query):
        if self.fail_with:
            raise self.fail_with("find_one failed")
        doc = self.docs.get(query["key"])
        # The route filters on expires_at; the fake stores only live docs.
        return dict(doc) if doc else None

    async def update_one(self, filter_, update, upsert=False):
        if self.fail_with:
            raise self.fail_with("update_one failed")
        self.docs[filter_["key"]] = dict(update["$set"])


class StubExplainer:
    def __init__(self, result=("An explanation.", "openai/gpt-4o-mini"), error=None):
        self.result = result
        self.error = error
        self.calls = 0

    async def __call__(self, finding, client):
        self.calls += 1
        if self.error:
            raise self.error
        return self.result


@pytest.fixture
def collection(monkeypatch):
    fake = FakeCollection()
    monkeypatch.setattr(module, "get_explanations", lambda: fake)
    return fake


@pytest.fixture
def explainer(monkeypatch):
    stub = StubExplainer()
    monkeypatch.setattr(module, "explain_finding", stub)
    return stub


@pytest.fixture
def client():
    """A bare app carrying just this router, with the limiter reset.

    The limiter is process-global, so without the reset one test's requests
    would count against the next one's budget.
    """
    module._limiter.reset()
    app = FastAPI()
    app.include_router(module.router)
    app.state.openrouter = None  # explain_finding is stubbed; never used
    with TestClient(app) as test_client:
        yield test_client
    module._limiter.reset()


# --------------------------------------------------------------- cache key


class TestCacheKey:
    def test_key_changes_when_code_snippet_differs(self):
        """The bug the widened key fixes: two files, same algorithm, different
        code. Keyed on the algorithm alone they shared one explanation, so the
        second file got prose naming the first file's variables."""
        first = _cache_key(request_model())
        second = _cache_key(
            request_model(code_snippet="session_key = rsa.generate_private_key(3072)")
        )
        assert first != second

    def test_key_changes_when_fix_snippet_differs(self):
        assert _cache_key(request_model()) != _cache_key(
            request_model(fix_snippet="# a different recommended fix")
        )

    def test_key_is_stable_across_repeated_calls(self):
        keys = {_cache_key(request_model()) for _ in range(5)}
        assert len(keys) == 1

    def test_key_ignores_file_and_line(self):
        """Identical code in two places genuinely deserves one explanation."""
        assert _cache_key(request_model()) == _cache_key(
            request_model(file="other/module.py", line=940)
        )

    def test_key_changes_with_algorithm(self):
        assert _cache_key(request_model()) != _cache_key(request_model(algorithm="DSA"))


# ------------------------------------------------------------------ route


class TestExplainRoute:
    def test_miss_calls_the_model_and_stores_the_result(
        self, client, collection, explainer
    ):
        response = client.post("/scan/explain", json=FINDING)
        assert response.status_code == 200
        assert response.json() == {
            "explanation": "An explanation.",
            "model": "openai/gpt-4o-mini",
            "cached": False,
        }
        assert explainer.calls == 1
        assert len(collection.docs) == 1

    def test_hit_returns_cached_without_calling_the_model(
        self, client, collection, explainer
    ):
        collection.docs[_cache_key(request_model())] = {
            "explanation": "Stored earlier.",
            "model": "openai/gpt-4o-mini",
        }

        response = client.post("/scan/explain", json=FINDING)
        assert response.status_code == 200
        assert response.json()["cached"] is True
        assert response.json()["explanation"] == "Stored earlier."
        assert explainer.calls == 0

    def test_different_code_snippet_is_a_miss_not_a_hit(
        self, client, collection, explainer
    ):
        client.post("/scan/explain", json=FINDING)
        client.post(
            "/scan/explain",
            json={**FINDING, "code_snippet": "key = rsa.generate_private_key(1024)"},
        )
        assert explainer.calls == 2
        assert len(collection.docs) == 2

    def test_code_snippet_reaches_the_explainer(self, client, collection, monkeypatch):
        received = {}

        async def capture(finding, http_client):
            received.update(finding)
            return "text", "model"

        monkeypatch.setattr(module, "explain_finding", capture)
        client.post("/scan/explain", json=FINDING)
        assert received["code_snippet"] == FINDING["code_snippet"]
        assert received["fix_snippet"] == FINDING["fix_snippet"]

    def test_explainer_error_maps_to_502(self, client, collection, monkeypatch):
        monkeypatch.setattr(
            module,
            "explain_finding",
            StubExplainer(error=AIExplainerError("OpenRouter returned 401")),
        )
        response = client.post("/scan/explain", json=FINDING)
        assert response.status_code == 502
        assert "OpenRouter returned 401" in response.json()["detail"]

    def test_nothing_is_cached_when_the_model_fails(
        self, client, collection, monkeypatch
    ):
        monkeypatch.setattr(
            module, "explain_finding", StubExplainer(error=AIExplainerError("truncated"))
        )
        client.post("/scan/explain", json=FINDING)
        assert collection.docs == {}

    def test_missing_algorithm_is_a_422_not_a_502(self, client, collection, explainer):
        response = client.post(
            "/scan/explain", json={k: v for k, v in FINDING.items() if k != "algorithm"}
        )
        assert response.status_code == 422
        assert explainer.calls == 0

    def test_doc_without_an_explanation_is_treated_as_a_miss(
        self, client, collection, explainer
    ):
        collection.docs[_cache_key(request_model())] = {"model": "openai/gpt-4o-mini"}
        response = client.post("/scan/explain", json=FINDING)
        assert response.status_code == 200
        assert response.json()["cached"] is False
        assert explainer.calls == 1


# ------------------------------------------------------- cache degradation


class TestCacheIsNeverAHardDependency:
    def test_lookup_failure_still_serves_the_request(
        self, client, explainer, monkeypatch
    ):
        monkeypatch.setattr(
            module, "get_explanations", lambda: FakeCollection(fail_with=PyMongoError)
        )
        response = client.post("/scan/explain", json=FINDING)
        assert response.status_code == 200
        assert response.json()["explanation"] == "An explanation."
        assert explainer.calls == 1

    def test_store_failure_still_returns_the_explanation(
        self, client, explainer, monkeypatch
    ):
        class WriteOnlyFailure(FakeCollection):
            async def find_one(self, query):
                return None

            async def update_one(self, filter_, update, upsert=False):
                raise PyMongoError("write failed")

        monkeypatch.setattr(module, "get_explanations", lambda: WriteOnlyFailure())
        response = client.post("/scan/explain", json=FINDING)
        assert response.status_code == 200
        assert response.json()["cached"] is False


# ------------------------------------------------------------ rate limiting


class TestRateLimit:
    def test_requests_beyond_the_window_are_rejected_with_429(
        self, client, collection, explainer
    ):
        limit = module._limiter.max_requests
        for _ in range(limit):
            assert client.post("/scan/explain", json=FINDING).status_code == 200

        blocked = client.post("/scan/explain", json=FINDING)
        assert blocked.status_code == 429
        assert "Rate limit exceeded" in blocked.json()["detail"]
        assert blocked.headers["Retry-After"]

    def test_the_limit_caps_calls_to_the_paid_api(self, client, collection, explainer):
        """Every request past the cap must cost nothing, which means it has to
        be refused before explain_finding runs -- varying identifier is exactly
        how an attacker would otherwise force unlimited cache misses."""
        limit = module._limiter.max_requests
        for index in range(limit + 15):
            client.post(
                "/scan/explain", json={**FINDING, "identifier": f"rsa.variant{index}"}
            )
        assert explainer.calls == limit

    def test_reset_clears_the_window(self, client, collection, explainer):
        for _ in range(module._limiter.max_requests):
            client.post("/scan/explain", json=FINDING)
        assert client.post("/scan/explain", json=FINDING).status_code == 429

        module._limiter.reset()
        assert client.post("/scan/explain", json=FINDING).status_code == 200

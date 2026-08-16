"""Route-level tests for /scan/patch.

Mongo and OpenRouter are both replaced: get_patches is swapped for an
in-memory fake collection, and generate_patch for a stub that records how
often it was called. Nothing here touches a network or a database.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pymongo.errors import PyMongoError

from patch_generator import PatchGeneratorError
from routers import patch_router as module
from routers.patch_router import FindingPatchRequest, _cache_key

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

DIFF = (
    "--- a/src/auth.py\n"
    "+++ b/src/auth.py\n"
    "@@ -12,1 +12,1 @@\n"
    "-private_key = rsa.generate_private_key(key_size=2048)\n"
    "+kem = oqs.KeyEncapsulation('ML-KEM-768')\n"
)


def request_model(**overrides) -> FindingPatchRequest:
    return FindingPatchRequest(**{**FINDING, **overrides})


class FakeCollection:
    """The two Motor calls patch_router makes, over a dict."""

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


class StubGenerator:
    def __init__(self, result=(DIFF, "openai/gpt-4o-mini"), error=None):
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
    monkeypatch.setattr(module, "get_patches", lambda: fake)
    return fake


@pytest.fixture
def generator(monkeypatch):
    stub = StubGenerator()
    monkeypatch.setattr(module, "generate_patch", stub)
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
    app.state.openrouter = None  # generate_patch is stubbed; never used
    with TestClient(app) as test_client:
        yield test_client
    module._limiter.reset()


# --------------------------------------------------------------- cache key


class TestCacheKey:
    def test_key_changes_when_code_snippet_differs(self):
        """Wide from the start. Keyed on algorithm and severity alone, two
        files' different RSA lines would share one diff -- and a diff whose
        '-' lines came from another file is worse than no diff at all."""
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

    def test_key_changes_with_algorithm_and_severity(self):
        base = _cache_key(request_model())
        assert base != _cache_key(request_model(algorithm="DSA"))
        assert base != _cache_key(request_model(severity="warning"))

    def test_key_ignores_file_and_line(self):
        """Identical vulnerable code in two places deserves one patch."""
        assert _cache_key(request_model()) == _cache_key(
            request_model(file="other/module.py", line=940)
        )

    def test_patch_and_explanation_caches_are_separate_collections(self):
        """Same key shape, different content: a patch served where an
        explanation was asked for would be a silent product bug."""
        from routers import explain_router

        assert module.get_patches is not explain_router.get_explanations


# ------------------------------------------------------------------ route


class TestPatchRoute:
    def test_miss_calls_the_model_and_stores_the_result(
        self, client, collection, generator
    ):
        response = client.post("/scan/patch", json=FINDING)
        assert response.status_code == 200
        assert response.json() == {
            "patch": DIFF,
            "model": "openai/gpt-4o-mini",
            "cached": False,
        }
        assert generator.calls == 1
        assert len(collection.docs) == 1

    def test_hit_returns_cached_without_calling_the_model(
        self, client, collection, generator
    ):
        collection.docs[_cache_key(request_model())] = {
            "patch": "--- stored earlier\n",
            "model": "openai/gpt-4o-mini",
        }

        response = client.post("/scan/patch", json=FINDING)
        assert response.status_code == 200
        assert response.json()["cached"] is True
        assert response.json()["patch"] == "--- stored earlier\n"
        assert generator.calls == 0

    def test_different_code_snippet_is_a_miss_not_a_hit(
        self, client, collection, generator
    ):
        client.post("/scan/patch", json=FINDING)
        client.post(
            "/scan/patch",
            json={**FINDING, "code_snippet": "key = rsa.generate_private_key(1024)"},
        )
        assert generator.calls == 2
        assert len(collection.docs) == 2

    def test_both_snippets_reach_the_generator(self, client, collection, monkeypatch):
        received = {}

        async def capture(finding, http_client):
            received.update(finding)
            return DIFF, "model"

        monkeypatch.setattr(module, "generate_patch", capture)
        client.post("/scan/patch", json=FINDING)
        assert received["code_snippet"] == FINDING["code_snippet"]
        assert received["fix_snippet"] == FINDING["fix_snippet"]
        assert received["file"] == FINDING["file"]
        assert received["line"] == FINDING["line"]

    def test_generator_error_maps_to_502(self, client, collection, monkeypatch):
        monkeypatch.setattr(
            module,
            "generate_patch",
            StubGenerator(error=PatchGeneratorError("OpenRouter returned 401")),
        )
        response = client.post("/scan/patch", json=FINDING)
        assert response.status_code == 502
        assert "OpenRouter returned 401" in response.json()["detail"]

    def test_nothing_is_cached_when_the_model_fails(
        self, client, collection, monkeypatch
    ):
        monkeypatch.setattr(
            module,
            "generate_patch",
            StubGenerator(error=PatchGeneratorError("truncated")),
        )
        client.post("/scan/patch", json=FINDING)
        assert collection.docs == {}

    def test_doc_without_a_patch_is_treated_as_a_miss(
        self, client, collection, generator
    ):
        collection.docs[_cache_key(request_model())] = {"model": "openai/gpt-4o-mini"}
        response = client.post("/scan/patch", json=FINDING)
        assert response.status_code == 200
        assert response.json()["cached"] is False
        assert generator.calls == 1


# ------------------------------------------------------- required code context


class TestCodeContextIsRequired:
    """Stricter than /scan/explain, deliberately: an explanation with no code
    is merely generic, a patch with no code is a fabricated diff.
    """

    def test_missing_code_snippet_is_a_400_and_costs_nothing(
        self, client, collection, generator
    ):
        response = client.post(
            "/scan/patch",
            json={k: v for k, v in FINDING.items() if k != "code_snippet"},
        )
        assert response.status_code == 400
        assert "code_snippet" in response.json()["detail"]
        assert generator.calls == 0
        assert collection.docs == {}

    def test_missing_fix_snippet_is_a_400_and_costs_nothing(
        self, client, collection, generator
    ):
        response = client.post(
            "/scan/patch",
            json={k: v for k, v in FINDING.items() if k != "fix_snippet"},
        )
        assert response.status_code == 400
        assert "fix_snippet" in response.json()["detail"]
        assert generator.calls == 0

    def test_empty_code_snippet_is_a_400(self, client, collection, generator):
        response = client.post("/scan/patch", json={**FINDING, "code_snippet": "   "})
        assert response.status_code == 400
        assert generator.calls == 0

    def test_both_missing_are_named_in_one_message(
        self, client, collection, generator
    ):
        response = client.post(
            "/scan/patch",
            json={
                k: v
                for k, v in FINDING.items()
                if k not in ("code_snippet", "fix_snippet")
            },
        )
        assert response.status_code == 400
        detail = response.json()["detail"]
        assert "code_snippet" in detail and "fix_snippet" in detail

    def test_missing_algorithm_is_also_a_400(self, client, collection, generator):
        response = client.post(
            "/scan/patch", json={k: v for k, v in FINDING.items() if k != "algorithm"}
        )
        assert response.status_code == 400
        assert generator.calls == 0


# ------------------------------------------------------- cache degradation


class TestCacheIsNeverAHardDependency:
    def test_lookup_failure_still_serves_the_request(
        self, client, generator, monkeypatch
    ):
        monkeypatch.setattr(
            module, "get_patches", lambda: FakeCollection(fail_with=PyMongoError)
        )
        response = client.post("/scan/patch", json=FINDING)
        assert response.status_code == 200
        assert response.json()["patch"] == DIFF
        assert generator.calls == 1

    def test_store_failure_still_returns_the_patch(
        self, client, generator, monkeypatch
    ):
        class WriteOnlyFailure(FakeCollection):
            async def find_one(self, query):
                return None

            async def update_one(self, filter_, update, upsert=False):
                raise PyMongoError("write failed")

        monkeypatch.setattr(module, "get_patches", lambda: WriteOnlyFailure())
        response = client.post("/scan/patch", json=FINDING)
        assert response.status_code == 200
        assert response.json()["cached"] is False


# ------------------------------------------------------------ rate limiting


class TestRateLimit:
    def test_requests_beyond_the_window_are_rejected_with_429(
        self, client, collection, generator
    ):
        limit = module._limiter.max_requests
        for _ in range(limit):
            assert client.post("/scan/patch", json=FINDING).status_code == 200

        blocked = client.post("/scan/patch", json=FINDING)
        assert blocked.status_code == 429
        detail = blocked.json()["detail"]
        # 600s window: minutes, not raw seconds.
        assert detail == (
            f"Rate limit exceeded: {limit} requests per 10 minutes. "
            "Try again in 10 minutes."
        )
        # The header is untouched by the message formatting: RFC 9110 says
        # seconds, and a client parses it.
        assert blocked.headers["Retry-After"].isdigit()

    def test_the_limit_caps_calls_to_the_paid_api(self, client, collection, generator):
        """Every request past the cap must cost nothing, which means it has to
        be refused before generate_patch runs -- varying identifier is exactly
        how an attacker would otherwise force unlimited cache misses."""
        limit = module._limiter.max_requests
        for index in range(limit + 15):
            client.post(
                "/scan/patch", json={**FINDING, "identifier": f"rsa.variant{index}"}
            )
        assert generator.calls == limit

    def test_reset_clears_the_window(self, client, collection, generator):
        for _ in range(module._limiter.max_requests):
            client.post("/scan/patch", json=FINDING)
        assert client.post("/scan/patch", json=FINDING).status_code == 429

        module._limiter.reset()
        assert client.post("/scan/patch", json=FINDING).status_code == 200

    def test_patch_has_its_own_bucket_not_the_explainers(self):
        """A heavier call gets its own quota: exhausting patches must not
        lock the developer out of explanations, or the reverse."""
        from routers import explain_router

        assert module._limiter is not explain_router._limiter
        assert module._limiter.max_requests < explain_router._limiter.max_requests

    def test_a_rejected_request_does_not_consume_the_explain_budget(
        self, client, collection, generator
    ):
        from routers import explain_router

        explain_router._limiter.reset()
        for _ in range(module._limiter.max_requests + 5):
            client.post("/scan/patch", json=FINDING)
        assert explain_router._limiter._hits == {}

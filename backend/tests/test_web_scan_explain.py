"""Route-level tests for POST /web-scan/explain.

The website counterpart of /scan/explain, and a separate endpoint on purpose:
a TLS cipher suite, a certificate and a missing HTTP header have no
code_snippet, no fix_snippet, no file and no line, so reaching the code-finding
endpoint would mean fabricating every field its prompt is built around.

What is tested here is the endpoint's own behaviour and, just as importantly,
its separation from the endpoint it was modelled on:

  * a successful explanation, with OpenRouter stubbed;
  * the cache -- a second identical request must not buy a second completion,
    and must not be served from the code-finding cache either;
  * the rate limit: its own bucket, its own count, and provably not
    /scan/explain's -- exhausting one must leave the other untouched;
  * authentication, which /scan/explain does not require and this does.

Mongo and OpenRouter are both replaced, as in test_explain_router.py: the two
collections are in-memory fakes and the explainers are stubs that count calls.
Nothing here touches a network or a database.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pymongo.errors import PyMongoError

from ai_explainer import AIExplainerError
from auth import get_current_user
from routers import explain_router as explain_module
from routers import web_scan_router as module
from routers.web_scan_router import WebFindingExplainRequest, _explain_cache_key

SCAN_USER = {"_id": "507f1f77bcf86cd799439011", "email": "owner@qlint.dev"}
SECOND_USER = {"_id": "507f1f77bcf86cd799439099", "email": "other@qlint.dev"}

# A TLS finding, in the shape /web-scan returns one.
FINDING = {
    "category": "TLS",
    "severity": "Medium",
    "asset": "ECDHE",
    "type": "Key Exchange",
    "status": "Quantum-vulnerable",
    "algorithm": "ECDH",
    "key_size": "256",
    "quantum_risk": "Broken by Shor's algorithm on a cryptographically relevant quantum computer.",
    "recommendation": "Adopt a hybrid X25519MLKEM768 key exchange when your TLS terminator supports it.",
}

# A header finding: no algorithm at all, which is the shape that proves the
# request model does not require one.
HEADER_FINDING = {
    "category": "HTTP Header",
    "severity": "Medium",
    "asset": "Strict-Transport-Security",
    "type": "HTTP Security Header",
    "status": "Missing",
    "observed_value": None,
    "recommendation": "Add a Strict-Transport-Security header with a max-age of at least 31536000.",
}

# A JavaScript finding: an algorithm and no asset, the mirror image.
JS_FINDING = {
    "category": "JavaScript",
    "severity": "critical",
    "algorithm": "RSA",
    "recommendation": "Replace with ML-KEM (FIPS 203)",
}

# What /scan/explain takes. Deliberately different in shape -- it is the thing
# this endpoint exists not to be.
CODE_FINDING = {
    "algorithm": "RSA",
    "severity": "critical",
    "code_snippet": "private_key = rsa.generate_private_key(key_size=2048)",
    "fix_snippet": "kem = oqs.KeyEncapsulation('ML-KEM-768')",
}


def request_model(**overrides) -> WebFindingExplainRequest:
    return WebFindingExplainRequest(**{**FINDING, **overrides})


class FakeCollection:
    """The two Motor calls the cache makes, over a dict."""

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
    def __init__(self, result=("A website explanation.", "openai/gpt-4o-mini"), error=None):
        self.result = result
        self.error = error
        self.calls = 0
        self.findings: list[dict] = []

    async def __call__(self, finding, client):
        self.calls += 1
        self.findings.append(finding)
        if self.error:
            raise self.error
        return self.result


@pytest.fixture
def collection(monkeypatch):
    """The website-explanation collection, faked."""
    fake = FakeCollection()
    monkeypatch.setattr(module, "get_web_explanations", lambda: fake)
    return fake


@pytest.fixture
def code_collection(monkeypatch):
    """The code-finding collection, faked, so the two can be told apart."""
    fake = FakeCollection()
    monkeypatch.setattr(explain_module, "get_explanations", lambda: fake)
    return fake


@pytest.fixture
def explainer(monkeypatch):
    stub = StubExplainer()
    monkeypatch.setattr(module, "explain_web_finding", stub)
    return stub


@pytest.fixture
def code_explainer(monkeypatch):
    stub = StubExplainer(result=("A code explanation.", "openai/gpt-4o-mini"))
    monkeypatch.setattr(explain_module, "explain_finding", stub)
    return stub


@pytest.fixture
def app():
    """Both routers, so the two endpoints' buckets can be compared directly.

    Every limiter is reset around each test: they are process-global, so
    without this one test's requests would count against the next one's.
    """
    for limiter in (module._explain_limiter, explain_module._limiter):
        limiter.reset()
    application = FastAPI()
    application.include_router(module.router)
    application.include_router(explain_module.router)
    application.state.openrouter = None  # both explainers are stubbed
    yield application
    for limiter in (module._explain_limiter, explain_module._limiter):
        limiter.reset()


@pytest.fixture
def client(app):
    app.dependency_overrides[get_current_user] = lambda: SCAN_USER
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def explain(client, finding=None):
    return client.post("/web-scan/explain", json=finding or FINDING)


# --------------------------------------------------------------- cache key


class TestTheCacheKey:
    def test_it_is_stable_across_repeated_calls(self):
        assert len({_explain_cache_key(request_model()) for _ in range(5)}) == 1

    def test_it_changes_with_the_status(self):
        """Present-and-weak and missing-entirely are different findings about
        the same header and deserve different explanations."""
        assert _explain_cache_key(request_model()) != _explain_cache_key(
            request_model(status="Present")
        )

    def test_it_changes_with_the_severity(self):
        assert _explain_cache_key(request_model()) != _explain_cache_key(
            request_model(severity="Low")
        )

    def test_it_changes_with_the_category(self):
        """The same asset name can appear in two domains; what it means does
        not carry across."""
        assert _explain_cache_key(request_model()) != _explain_cache_key(
            request_model(category="Certificate")
        )

    def test_it_changes_with_the_recommendation(self):
        assert _explain_cache_key(request_model()) != _explain_cache_key(
            request_model(recommendation="Do something else entirely.")
        )

    def test_two_sites_with_the_same_finding_share_one_key(self):
        """Nothing identifying a site is in the key, and nothing should be:
        the explanation never names one, so two sites missing the same header
        deserve one answer and should cost one completion between them."""
        assert _explain_cache_key(request_model()) == _explain_cache_key(
            request_model()
        )


# ------------------------------------------------------------------ route


class TestTheRoute:
    def test_a_miss_calls_the_model_and_stores_the_result(
        self, client, collection, explainer
    ):
        response = explain(client)
        assert response.status_code == 200
        assert response.json() == {
            "explanation": "A website explanation.",
            "model": "openai/gpt-4o-mini",
            "cached": False,
        }
        assert explainer.calls == 1
        assert len(collection.docs) == 1

    def test_the_finding_reaches_the_explainer_intact(
        self, client, collection, explainer
    ):
        explain(client)
        sent = explainer.findings[0]
        assert sent["asset"] == "ECDHE"
        assert sent["algorithm"] == "ECDH"
        assert sent["quantum_risk"] == FINDING["quantum_risk"]
        assert sent["recommendation"] == FINDING["recommendation"]

    def test_a_header_finding_with_no_algorithm_is_accepted(
        self, client, collection, explainer
    ):
        """A missing Strict-Transport-Security names no algorithm. /scan/explain
        would have refused it with a 422; that is the whole reason this endpoint
        exists."""
        assert explain(client, HEADER_FINDING).status_code == 200
        assert explainer.calls == 1

    def test_a_javascript_finding_with_no_asset_is_accepted(
        self, client, collection, explainer
    ):
        assert explain(client, JS_FINDING).status_code == 200
        assert explainer.calls == 1

    def test_a_passing_finding_is_explained_rather_than_refused(
        self, client, collection, explainer
    ):
        """"Why this one is fine" is a thing a reader needs said. An Acceptable
        finding is not an error case."""
        passing = {**FINDING, "severity": "Info", "status": "Acceptable"}
        assert explain(client, passing).status_code == 200
        assert explainer.calls == 1

    def test_a_finding_missing_the_required_fields_is_a_422(
        self, client, collection, explainer
    ):
        response = client.post("/web-scan/explain", json={"asset": "ECDHE"})
        assert response.status_code == 422
        assert explainer.calls == 0

    def test_an_explainer_error_maps_to_502(self, client, collection, monkeypatch):
        monkeypatch.setattr(
            module,
            "explain_web_finding",
            StubExplainer(error=AIExplainerError("OpenRouter returned 401")),
        )
        response = explain(client)
        assert response.status_code == 502
        assert "OpenRouter returned 401" in response.json()["detail"]

    def test_nothing_is_cached_when_the_model_fails(
        self, client, collection, monkeypatch
    ):
        monkeypatch.setattr(
            module,
            "explain_web_finding",
            StubExplainer(error=AIExplainerError("truncated")),
        )
        explain(client)
        assert collection.docs == {}


# ------------------------------------------------------------------ cache


class TestTheCache:
    def test_a_second_identical_request_does_not_call_openrouter_again(
        self, client, collection, explainer
    ):
        first = explain(client)
        second = explain(client)

        assert first.json()["cached"] is False
        assert second.json()["cached"] is True
        assert second.json()["explanation"] == "A website explanation."
        # The point of the whole mechanism: one completion, two answers.
        assert explainer.calls == 1

    def test_a_different_finding_is_a_miss_not_a_hit(
        self, client, collection, explainer
    ):
        explain(client)
        explain(client, {**FINDING, "status": "Acceptable"})
        assert explainer.calls == 2
        assert len(collection.docs) == 2

    def test_a_doc_without_an_explanation_is_treated_as_a_miss(
        self, client, collection, explainer
    ):
        collection.docs[_explain_cache_key(request_model())] = {
            "model": "openai/gpt-4o-mini"
        }
        response = explain(client)
        assert response.status_code == 200
        assert response.json()["cached"] is False
        assert explainer.calls == 1

    def test_a_stored_entry_carries_a_thirty_day_expiry(
        self, client, collection, explainer
    ):
        explain(client)
        doc = next(iter(collection.docs.values()))
        assert module.EXPLANATION_CACHE_TTL_DAYS == 30
        assert (doc["expires_at"] - doc["created_at"]).days == 30

    def test_a_lookup_failure_still_serves_the_request(
        self, client, explainer, monkeypatch
    ):
        monkeypatch.setattr(
            module, "get_web_explanations", lambda: FakeCollection(fail_with=PyMongoError)
        )
        response = explain(client)
        assert response.status_code == 200
        assert explainer.calls == 1

    def test_a_store_failure_still_returns_the_explanation(
        self, client, explainer, monkeypatch
    ):
        class WriteOnlyFailure(FakeCollection):
            async def find_one(self, query):
                return None

            async def update_one(self, filter_, update, upsert=False):
                raise PyMongoError("write failed")

        monkeypatch.setattr(module, "get_web_explanations", lambda: WriteOnlyFailure())
        assert explain(client).status_code == 200


class TestTheTwoCachesAreSeparate:
    def test_a_website_explanation_is_not_written_to_the_code_cache(
        self, client, collection, code_collection, explainer
    ):
        explain(client)
        assert len(collection.docs) == 1
        assert code_collection.docs == {}

    def test_a_code_explanation_is_not_written_to_the_website_cache(
        self, client, collection, code_collection, code_explainer
    ):
        assert client.post("/scan/explain", json=CODE_FINDING).status_code == 200
        assert len(code_collection.docs) == 1
        assert collection.docs == {}

    def test_the_two_read_different_collections(self):
        """Stated as an accessor rather than a discriminator field, following
        get_patches. Asserting the names differ is what stops a later edit
        pointing both at one collection."""
        from database import get_explanations, get_web_explanations

        assert get_explanations is not get_web_explanations


# ------------------------------------------------------------ rate limiting


class TestTheRateLimit:
    def test_it_is_twenty_requests_per_ten_minutes(self):
        assert module._explain_limiter.max_requests == 20
        # The same window /scan/explain uses, so the two behave alike.
        assert module._explain_limiter.window_seconds == 600
        assert explain_module._limiter.window_seconds == 600

    def test_requests_beyond_the_window_are_rejected_with_429(
        self, client, collection, explainer
    ):
        limit = module._explain_limiter.max_requests
        for index in range(limit):
            # Varying the finding so every request is a cache miss: a cached
            # answer must still count against the window.
            assert explain(
                client, {**FINDING, "status": f"Variant {index}"}
            ).status_code == 200

        blocked = explain(client, {**FINDING, "status": "One too many"})
        assert blocked.status_code == 429
        assert blocked.json()["detail"] == (
            f"Rate limit exceeded: {limit} requests per 10 minutes. "
            "Try again in 10 minutes."
        )
        assert blocked.headers["Retry-After"].isdigit()

    def test_the_limit_caps_calls_to_the_paid_api(
        self, client, collection, explainer
    ):
        limit = module._explain_limiter.max_requests
        for index in range(limit + 10):
            explain(client, {**FINDING, "status": f"Variant {index}"})
        assert explainer.calls == limit

    def test_it_is_counted_per_account_not_per_address(
        self, app, collection, explainer
    ):
        """Render's proxy collapses every visitor onto one internal address, so
        an address-keyed limit here would be a limit on the whole site. Two
        accounts arriving from the same TestClient get separate allowances."""
        limit = module._explain_limiter.max_requests
        app.dependency_overrides[get_current_user] = lambda: SCAN_USER
        first = TestClient(app)
        for index in range(limit):
            assert first.post(
                "/web-scan/explain", json={**FINDING, "status": f"V{index}"}
            ).status_code == 200
        assert first.post("/web-scan/explain", json=FINDING).status_code == 429

        app.dependency_overrides[get_current_user] = lambda: SECOND_USER
        assert TestClient(app).post(
            "/web-scan/explain", json=FINDING
        ).status_code == 200
        app.dependency_overrides.clear()


class TestTheTwoBucketsAreIndependent:
    def test_exhausting_this_route_leaves_scan_explain_untouched(
        self, client, collection, code_collection, explainer, code_explainer
    ):
        limit = module._explain_limiter.max_requests
        for index in range(limit + 5):
            explain(client, {**FINDING, "status": f"Variant {index}"})
        assert explain(client).status_code == 429

        # The code-finding endpoint has spent nothing.
        assert client.post("/scan/explain", json=CODE_FINDING).status_code == 200
        assert code_explainer.calls == 1

    def test_exhausting_scan_explain_leaves_this_route_untouched(
        self, client, collection, code_collection, explainer, code_explainer
    ):
        limit = explain_module._limiter.max_requests
        for index in range(limit):
            assert client.post(
                "/scan/explain", json={**CODE_FINDING, "identifier": f"rsa.v{index}"}
            ).status_code == 200
        assert client.post("/scan/explain", json=CODE_FINDING).status_code == 429

        assert explain(client).status_code == 200
        assert explainer.calls == 1

    def test_they_are_two_distinct_limiter_objects(self):
        assert module._explain_limiter is not explain_module._limiter

    def test_the_combined_scan_bucket_is_not_spent_by_an_explanation(
        self, client, collection, explainer
    ):
        """The four scan buckets in this router are the expensive ones -- five
        combined scans a day. Explaining a finding must not spend one."""
        before = dict(module._combined_limiter._hits)
        explain(client)
        assert dict(module._combined_limiter._hits) == before


# ------------------------------------------------------------ authentication


class TestTheRouteRequiresASession:
    def test_a_request_with_no_token_is_401(self, app, collection, explainer):
        response = TestClient(app).post("/web-scan/explain", json=FINDING)
        assert response.status_code == 401
        assert response.json()["detail"] == "Not authenticated"
        assert explainer.calls == 0

    def test_a_request_with_a_junk_token_is_401(self, app, collection, explainer):
        response = TestClient(app).post(
            "/web-scan/explain",
            json=FINDING,
            headers={"Authorization": "Bearer not-a-real-jwt"},
        )
        assert response.status_code == 401
        assert explainer.calls == 0

    def test_an_unauthenticated_request_does_not_spend_the_rate_limit(
        self, app, collection, explainer
    ):
        """rate_limit_by_user resolves the session before touching the window,
        so unauthenticated noise cannot spend a real account's allowance."""
        unauthenticated = TestClient(app)
        for _ in range(module._explain_limiter.max_requests + 5):
            assert unauthenticated.post(
                "/web-scan/explain", json=FINDING
            ).status_code == 401

        app.dependency_overrides[get_current_user] = lambda: SCAN_USER
        try:
            assert TestClient(app).post(
                "/web-scan/explain", json=FINDING
            ).status_code == 200
        finally:
            app.dependency_overrides.clear()

    def test_scan_explain_still_needs_no_session(
        self, app, code_collection, code_explainer
    ):
        """Unchanged by this addition, and deliberately so: that route has no
        session to name, which is why it is keyed by address."""
        assert TestClient(app).post(
            "/scan/explain", json=CODE_FINDING
        ).status_code == 200

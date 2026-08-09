"""End-to-end tests for the GitHub OAuth callback.

The callback answers 303 whatever happens, because a browser has to be
redirected either way. That made success and failure indistinguishable in the
access log -- the symptom that hid a stopped MongoDB behind two lines of
"303" for a whole debugging session. These tests pin the distinction: each
failure mode has to come back with its own error code, so the reason survives
the redirect.
"""

import httpx
import pytest
from pymongo.errors import ServerSelectionTimeoutError

import routers.oauth_router as oauth


class FakeUsers:
    """Stand-in for the motor users collection."""

    def __init__(self, existing=None, error=None):
        self.existing = existing
        self.error = error
        self.inserted = []
        self.updated = []

    async def find_one(self, query):
        if self.error:
            raise self.error
        return self.existing

    async def update_one(self, query, update):
        if self.error:
            raise self.error
        self.updated.append((query, update))

    async def insert_one(self, document):
        if self.error:
            raise self.error
        self.inserted.append(document)


def _transport(token_payload=None, user_status=200, user_payload=None):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith(oauth.TOKEN_URL):
            return httpx.Response(
                200,
                json=token_payload
                if token_payload is not None
                else {"access_token": "gho_test"},
            )
        if url.startswith(oauth.EMAILS_API_URL):
            return httpx.Response(200, json=[{"email": "dev@example.com", "primary": True}])
        if url.startswith(oauth.USER_API_URL):
            return httpx.Response(
                user_status,
                json=user_payload if user_payload is not None else {"login": "octocat"},
            )
        return httpx.Response(404, json={})

    return httpx.MockTransport(handler)


@pytest.fixture
def github(monkeypatch):
    """Route the router's httpx client at a mock transport.

    The real class is captured once, before any patching, so a test that
    installs a second transport subclasses the original rather than the
    previous stand-in -- otherwise the first transport wins every later call.
    """
    real = httpx.AsyncClient

    def install(**kwargs):
        transport = _transport(**kwargs)

        class Patched(real):
            def __init__(self, *args, **kw):
                kw["transport"] = transport
                super().__init__(*args, **kw)

        monkeypatch.setattr(httpx, "AsyncClient", Patched)

    return install


@pytest.fixture(autouse=True)
def credentials(monkeypatch):
    monkeypatch.setattr(oauth, "GITHUB_CLIENT_ID", "test_id")
    monkeypatch.setattr(oauth, "GITHUB_CLIENT_SECRET", "test_secret")


def _error_code(response) -> str | None:
    location = response.headers["location"]
    if "github_error=" not in location:
        return None
    return location.split("github_error=")[1].split("&")[0]


async def _callback(monkeypatch, users, **github_kwargs):
    monkeypatch.setattr(oauth, "get_users", lambda: users)
    return await oauth.github_callback(code="code", state="state", authorization=None)


@pytest.mark.asyncio
async def test_new_account_is_created_and_handed_a_token(monkeypatch, github):
    github()
    users = FakeUsers(existing=None)
    response = await _callback(monkeypatch, users)

    assert response.status_code == 303
    assert "github_token=" in response.headers["location"]
    assert _error_code(response) is None
    assert len(users.inserted) == 1
    assert users.inserted[0]["email"] == "dev@example.com"
    assert users.inserted[0]["github_connected"] is True


@pytest.mark.asyncio
async def test_returning_account_is_updated_not_duplicated(monkeypatch, github):
    github()
    users = FakeUsers(existing={"_id": "abc", "email": "dev@example.com"})
    response = await _callback(monkeypatch, users)

    assert "github_token=" in response.headers["location"]
    assert users.inserted == []
    assert len(users.updated) == 1


@pytest.mark.asyncio
async def test_database_outage_is_reported_as_db_unavailable(monkeypatch, github):
    """The regression this suite exists for.

    Every step with GitHub succeeds, so the log shows the same 303 it shows on
    success; only the error code says the account write never happened.
    """
    github()
    users = FakeUsers(error=ServerSelectionTimeoutError("connection refused"))
    response = await _callback(monkeypatch, users)

    assert response.status_code == 303
    assert "github_token=" not in response.headers["location"]
    assert _error_code(response) == "db_unavailable"


@pytest.mark.asyncio
async def test_rejected_code_is_reported_as_token_exchange_failed(monkeypatch, github):
    github(token_payload={"error": "bad_verification_code"})
    response = await _callback(monkeypatch, FakeUsers())
    assert _error_code(response) == "token_exchange_failed"


@pytest.mark.asyncio
async def test_unreadable_profile_is_reported_separately(monkeypatch, github):
    github(user_status=401, user_payload={"message": "Bad credentials"})
    response = await _callback(monkeypatch, FakeUsers())
    assert _error_code(response) == "profile_unavailable"


@pytest.mark.asyncio
async def test_missing_code_is_reported_separately(monkeypatch):
    monkeypatch.setattr(oauth, "get_users", lambda: FakeUsers())
    response = await oauth.github_callback(code=None, state="s", authorization=None)
    assert _error_code(response) == "no_code"


@pytest.mark.asyncio
async def test_unconfigured_server_says_so(monkeypatch):
    monkeypatch.setattr(oauth, "GITHUB_CLIENT_ID", None)
    monkeypatch.setattr(oauth, "get_users", lambda: FakeUsers())
    response = await oauth.github_callback(code="code", state="s", authorization=None)
    assert _error_code(response) == "not_configured"


@pytest.mark.asyncio
async def test_every_failure_mode_has_a_distinct_code(monkeypatch, github):
    """No two failures may collapse onto one code again."""
    codes = []

    github()
    codes.append(
        _error_code(
            await _callback(
                monkeypatch, FakeUsers(error=ServerSelectionTimeoutError("down"))
            )
        )
    )
    github(token_payload={"error": "bad_verification_code"})
    codes.append(_error_code(await _callback(monkeypatch, FakeUsers())))
    github(user_status=401)
    codes.append(_error_code(await _callback(monkeypatch, FakeUsers())))

    assert len(set(codes)) == len(codes), f"failure modes share a code: {codes}"
    assert None not in codes

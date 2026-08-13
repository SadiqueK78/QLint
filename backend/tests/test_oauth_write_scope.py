"""The write connection has to be genuinely separate from the read one.

Not "stored in a different variable" separate -- separate in every way that
could expose a user who never asked for write access:

- the sign-in flow must not request a scope that can push,
- the write flow must ask for the narrowest scope that can,
- the two tokens must live in different fields,
- connecting one must not set the other, and disconnecting one must not clear
  the other,
- a state minted for one account must not be usable to attach a token to
  another.

Each of those is one test below, because each of them is a way this feature
could quietly become "we upgraded everyone's token".
"""

import httpx
import pytest
from pymongo.errors import ServerSelectionTimeoutError

import routers.oauth_router as oauth
from models import user_to_response


class FakeUsers:
    def __init__(self, matched=1, error=None):
        self.matched = matched
        self.error = error
        self.updated = []
        self.inserted = []

    async def find_one(self, query):
        if self.error:
            raise self.error
        return None

    async def update_one(self, query, update):
        if self.error:
            raise self.error
        self.updated.append((query, update))

        class Result:
            matched_count = self.matched

        return Result()

    async def insert_one(self, document):
        if self.error:
            raise self.error
        self.inserted.append(document)


def _transport(scope="public_repo", token="gho_write"):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith(oauth.TOKEN_URL):
            return httpx.Response(200, json={"access_token": token, "scope": scope})
        if url.startswith(oauth.EMAILS_API_URL):
            return httpx.Response(200, json=[{"email": "dev@example.com", "primary": True}])
        if url.startswith(oauth.USER_API_URL):
            return httpx.Response(200, json={"login": "octocat", "email": "dev@example.com"})
        return httpx.Response(404, json={})

    return httpx.MockTransport(handler)


@pytest.fixture
def github(monkeypatch):
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


def _param(response, name) -> str | None:
    location = response.headers["location"]
    if f"{name}=" not in location:
        return None
    return location.split(f"{name}=")[1].split("&")[0]


def _write_fields(users: FakeUsers) -> dict:
    return users.updated[-1][1]["$set"]


# ------------------------------------------------------------------- scopes


class TestScopesAreSeparate:
    def test_sign_in_does_not_ask_for_a_scope_that_can_push(self):
        """public_repo is documented by GitHub as read/write access to code.
        Asking for it during sign-in gave every scanning user a token that
        could push to their repositories, which is exactly what the separate
        write connection exists to avoid."""
        assert "public_repo" not in oauth.OAUTH_SCOPE
        assert "repo" not in oauth.OAUTH_SCOPE.split()
        assert oauth.OAUTH_SCOPE == "read:user"

    def test_the_write_flow_asks_for_the_narrowest_scope_that_can_push(self):
        """public_repo is the narrowest OAuth App scope covering create-branch,
        create-commit and create-pull-request. `repo` would additionally hand
        over every private repository the user can see."""
        assert oauth.WRITE_OAUTH_SCOPE == "public_repo"

    def test_the_two_flows_do_not_request_the_same_scope(self):
        assert set(oauth.OAUTH_SCOPE.split()) & set(
            oauth.WRITE_OAUTH_SCOPE.split()
        ) == set()

    @pytest.mark.asyncio
    async def test_the_authorize_url_carries_the_write_scope_and_a_signed_state(self):
        result = await oauth.github_write_authorize(user={"email": "dev@example.com"})
        assert "scope=public_repo" in result["authorize_url"]
        assert oauth._write_state_email(
            result["authorize_url"].split("state=")[1].split("&")[0]
        ) == "dev@example.com"

    def test_a_broader_grant_still_satisfies_the_requirement(self):
        """A user who granted `repo` has more than public_repo, not less."""
        assert oauth._has_write_scope({"repo"})
        assert oauth._has_write_scope({"public_repo"})
        assert not oauth._has_write_scope({"read:user"})
        assert not oauth._has_write_scope(set())


# ------------------------------------------------------------- token storage


class TestTokensAreStoredSeparately:
    @pytest.mark.asyncio
    async def test_connecting_write_never_writes_the_sign_in_token_field(
        self, monkeypatch, github
    ):
        github()
        users = FakeUsers()
        monkeypatch.setattr(oauth, "get_users", lambda: users)

        response = await oauth._complete_write_connect("dev@example.com", "code")

        assert _param(response, "github_write") == "connected"
        fields = _write_fields(users)
        assert fields[oauth.WRITE_TOKEN_FIELD] == "gho_write"
        assert fields[oauth.WRITE_CONNECTED_FIELD] is True
        assert "github_access_token" not in fields
        assert "github_connected" not in fields

    @pytest.mark.asyncio
    async def test_connecting_write_never_issues_a_session(
        self, monkeypatch, github
    ):
        """A write connection is not a way to sign in."""
        github()
        monkeypatch.setattr(oauth, "get_users", lambda: FakeUsers())
        response = await oauth._complete_write_connect("dev@example.com", "code")
        assert "github_token=" not in response.headers["location"]

    @pytest.mark.asyncio
    async def test_signing_in_never_writes_the_write_token_field(
        self, monkeypatch, github
    ):
        github()
        users = FakeUsers()
        monkeypatch.setattr(oauth, "get_users", lambda: users)

        await oauth.github_callback(code="code", state="random", authorization=None)

        written = users.inserted[0] if users.inserted else _write_fields(users)
        assert oauth.WRITE_TOKEN_FIELD not in written
        assert oauth.WRITE_CONNECTED_FIELD not in written

    def test_the_write_token_is_not_part_of_any_user_response(self):
        """The flag travels to the browser; the credential never does."""
        response = user_to_response(
            {
                "_id": "1",
                "email": "dev@example.com",
                "created_at": "2026-01-01",
                "github_write_token": "gho_secret",
                "github_write_connected": True,
                "github_access_token": "gho_read",
            }
        )
        assert response.github_write_connected is True
        assert "gho_secret" not in response.model_dump_json()
        assert "gho_read" not in response.model_dump_json()


class TestDisconnectingOneLeavesTheOther:
    @pytest.mark.asyncio
    async def test_write_disconnect_clears_only_the_write_fields(self, monkeypatch):
        users = FakeUsers()
        monkeypatch.setattr(oauth, "get_users", lambda: users)

        await oauth.github_write_disconnect(user={"_id": "abc"})

        fields = _write_fields(users)
        assert fields[oauth.WRITE_TOKEN_FIELD] is None
        assert fields[oauth.WRITE_CONNECTED_FIELD] is False
        assert "github_access_token" not in fields
        assert "github_connected" not in fields

    @pytest.mark.asyncio
    async def test_read_disconnect_clears_only_the_read_fields(self, monkeypatch):
        users = FakeUsers()
        monkeypatch.setattr(oauth, "get_users", lambda: users)

        await oauth.github_disconnect(user={"_id": "abc"})

        fields = _write_fields(users)
        assert fields["github_access_token"] is None
        assert fields["github_connected"] is False
        assert oauth.WRITE_TOKEN_FIELD not in fields
        assert oauth.WRITE_CONNECTED_FIELD not in fields


# -------------------------------------------------------------- state safety


class TestStateBinding:
    def test_an_unsigned_state_is_not_a_write_state(self):
        """The sign-in flow's random hex must keep landing on the sign-in
        path, not on the one that stores a write token."""
        assert oauth._write_state_email("a1b2c3d4e5f6a7b8") is None
        assert oauth._write_state_email(None) is None
        assert oauth._write_state_email("") is None

    def test_a_plain_session_token_is_not_a_write_state(self):
        """A user's own JWT must not double as consent to attach a write
        token: it carries no write purpose."""
        from auth import create_access_token

        assert oauth._write_state_email(create_access_token({"sub": "dev@e.com"})) is None

    def test_a_forged_state_is_rejected(self):
        from jose import jwt

        forged = jwt.encode(
            {"sub": "victim@example.com", "purpose": oauth.WRITE_STATE_PURPOSE},
            "not-the-server-secret",
            algorithm="HS256",
        )
        assert oauth._write_state_email(forged) is None

    def test_a_write_state_round_trips_to_the_account_that_asked(self):
        assert oauth._write_state_email(oauth._write_state("dev@example.com")) == (
            "dev@example.com"
        )

    @pytest.mark.asyncio
    async def test_the_callback_routes_a_write_state_to_the_write_path(
        self, monkeypatch, github
    ):
        github()
        users = FakeUsers()
        monkeypatch.setattr(oauth, "get_users", lambda: users)

        response = await oauth.github_callback(
            code="code",
            state=oauth._write_state("dev@example.com"),
            authorization=None,
        )

        assert _param(response, "github_write") == "connected"
        assert "github_token=" not in response.headers["location"]


# ------------------------------------------------------------ failure modes


class TestWriteConnectFailures:
    @pytest.mark.asyncio
    async def test_a_grant_without_the_write_scope_is_not_stored(
        self, monkeypatch, github
    ):
        """Storing it would look connected and fail only at the moment a pull
        request is attempted."""
        github(scope="read:user")
        users = FakeUsers()
        monkeypatch.setattr(oauth, "get_users", lambda: users)

        response = await oauth._complete_write_connect("dev@example.com", "code")

        assert _param(response, "github_write_error") == "scope_denied"
        assert users.updated == []

    @pytest.mark.asyncio
    async def test_a_rejected_code_is_reported_on_the_write_channel(
        self, monkeypatch, github
    ):
        github()
        monkeypatch.setattr(oauth, "_exchange_code_payload", _none)
        monkeypatch.setattr(oauth, "get_users", lambda: FakeUsers())
        response = await oauth._complete_write_connect("dev@example.com", "code")
        assert _param(response, "github_write_error") == "token_exchange_failed"

    @pytest.mark.asyncio
    async def test_a_database_outage_is_reported_not_swallowed(
        self, monkeypatch, github
    ):
        github()
        monkeypatch.setattr(
            oauth, "get_users", lambda: FakeUsers(error=ServerSelectionTimeoutError("x"))
        )
        response = await oauth._complete_write_connect("dev@example.com", "code")
        assert _param(response, "github_write_error") == "db_unavailable"

    @pytest.mark.asyncio
    async def test_a_state_naming_no_known_account_stores_nothing(
        self, monkeypatch, github
    ):
        github()
        users = FakeUsers(matched=0)
        monkeypatch.setattr(oauth, "get_users", lambda: users)
        response = await oauth._complete_write_connect("ghost@example.com", "code")
        assert _param(response, "github_write_error") == "unknown_account"

    @pytest.mark.asyncio
    async def test_a_write_callback_without_a_code_says_so(self, monkeypatch):
        monkeypatch.setattr(oauth, "get_users", lambda: FakeUsers())
        response = await oauth.github_callback(
            code=None, state=oauth._write_state("dev@example.com"), authorization=None
        )
        assert _param(response, "github_write_error") == "no_code"

    @pytest.mark.asyncio
    async def test_write_errors_never_land_on_the_sign_in_channel(
        self, monkeypatch, github
    ):
        """A failed write connection must not read as a failed sign-in and
        must not blank the banner the sign-in flow uses."""
        github(scope="read:user")
        monkeypatch.setattr(oauth, "get_users", lambda: FakeUsers())
        response = await oauth._complete_write_connect("dev@example.com", "code")
        assert "github_error=" not in response.headers["location"]


async def _none(client, code):
    return None

"""Unit tests for password hashing, JWT handling, and the auth models.

These cover the pure functions only — the session routes are exercised against
a live MongoDB, which the rest of the suite deliberately does not require. The
one exception is the retired email/password pair at the bottom, which reaches
no database by design and so can be tested outright.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwt
from pydantic import ValidationError

import auth
from models import UserRegister, UserResponse, user_to_response
from routers.auth_router import DISCONTINUED, router as auth_router


def test_hash_password_is_salted_and_verifiable():
    hashed = auth.hash_password("hunter2hunter2")
    assert hashed != "hunter2hunter2"
    assert auth.verify_password("hunter2hunter2", hashed)
    # A second hash of the same password uses a fresh salt.
    assert auth.hash_password("hunter2hunter2") != hashed


def test_verify_password_rejects_wrong_password_and_garbage_hash():
    hashed = auth.hash_password("hunter2hunter2")
    assert not auth.verify_password("wrongpassword", hashed)
    assert not auth.verify_password("hunter2hunter2", "not-a-bcrypt-hash")


def test_password_longer_than_bcrypt_limit_still_round_trips():
    long_password = "a" * 200
    hashed = auth.hash_password(long_password)
    assert auth.verify_password(long_password, hashed)


def test_create_and_decode_access_token():
    token = auth.create_access_token({"sub": "user@example.com"})
    payload = auth.decode_access_token(token)
    assert payload["sub"] == "user@example.com"
    assert "exp" in payload


def test_decode_access_token_returns_none_for_invalid_tokens():
    assert auth.decode_access_token("not.a.token") is None
    assert auth.decode_access_token("") is None
    # Correct shape, wrong signing key.
    foreign = jwt.encode({"sub": "a@b.dev"}, "another-secret", algorithm="HS256")
    assert auth.decode_access_token(foreign) is None


def test_decode_access_token_returns_none_when_expired():
    expired = jwt.encode(
        {"sub": "a@b.dev", "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
        auth.JWT_SECRET,
        algorithm=auth.JWT_ALGORITHM,
    )
    assert auth.decode_access_token(expired) is None


def test_public_user_drops_the_password_hash():
    user = {"_id": 1, "email": "a@b.dev", "password_hash": "secret"}
    assert "password_hash" not in auth.public_user(user)
    assert auth.public_user(user)["email"] == "a@b.dev"


def test_to_object_id_returns_none_for_malformed_ids():
    assert auth.to_object_id("nope") is None
    assert auth.to_object_id("6a6de8541e0cc2c4a20cf646") is not None


@pytest.mark.parametrize("email", ["a@b.dev", "First.Last+tag@sub.example.com"])
def test_user_register_accepts_valid_emails(email):
    assert UserRegister(email=email, password="longenough").email == email.lower()


@pytest.mark.parametrize(
    "email", ["notanemail", "no@tld", "@nothing.dev", "spaces in@mail.dev", ""]
)
def test_user_register_rejects_invalid_emails(email):
    with pytest.raises(ValidationError):
        UserRegister(email=email, password="longenough")


def test_user_register_rejects_short_passwords():
    with pytest.raises(ValidationError):
        UserRegister(email="a@b.dev", password="short")


def test_user_to_response_tags_naive_timestamps_as_utc():
    response = user_to_response(
        {
            "_id": "abc",
            "email": "a@b.dev",
            "created_at": datetime(2026, 7, 19, 22, 32),
            "scan_count": 3,
        }
    )
    assert isinstance(response, UserResponse)
    assert response.created_at == "2026-07-19T22:32:00+00:00"
    assert response.scan_count == 3


# ------------------------------------------- retired email/password endpoints


@pytest.fixture
def auth_client():
    """The auth router alone. No database is wired up on purpose.

    Nothing these two routes do can reach Mongo any more, and a fixture that
    provided one would hide a regression where they started trying to.
    """
    app = FastAPI()
    app.include_router(auth_router)
    return TestClient(app)


class TestEmailPasswordIsRetired:
    """Both routes answer 410 Gone and do nothing else.

    They stay mounted only because the frontend deploys separately: a browser
    still running the previous bundle can post here after this ships, and it
    should get an explanation rather than a bare 404 from an unknown route.
    """

    @pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
    def test_the_route_is_gone_not_missing(self, auth_client, path):
        response = auth_client.post(
            path, json={"email": "a@b.dev", "password": "longenough"}
        )
        assert response.status_code == 410
        assert response.json()["detail"] == DISCONTINUED

    @pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
    def test_the_message_points_at_github(self, auth_client, path):
        detail = auth_client.post(path, json={}).json()["detail"]
        assert "discontinued" in detail.lower()
        assert "GitHub" in detail

    @pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"email": "a@b.dev"},
            {"email": "not-an-email", "password": "x"},
            {"email": "a@b.dev", "password": "short"},
            {"unexpected": "shape"},
        ],
    )
    def test_any_body_gets_the_same_answer(self, auth_client, path, payload):
        """Including bodies the old models would have rejected with a 422.

        An old frontend posting a seven-character password must be told the
        feature is gone, not told about a password length rule that no longer
        exists anywhere.
        """
        response = auth_client.post(path, json=payload)
        assert response.status_code == 410
        assert response.json()["detail"] == DISCONTINUED

    @pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
    def test_no_token_is_ever_issued(self, auth_client, path):
        """The old routes answered with a session. These must not."""
        body = auth_client.post(
            path, json={"email": "a@b.dev", "password": "longenough"}
        ).json()
        assert "access_token" not in body
        assert "user" not in body

    def test_the_routes_no_longer_touch_the_database(self, auth_client, monkeypatch):
        """A stub that still called Mongo would fail closed on a cold start."""
        import routers.auth_router as module

        def explode():
            raise AssertionError("the retired routes must not reach the database")

        # get_users is no longer imported here at all; this asserts that, and
        # catches a re-import that quietly brings the old behaviour back.
        assert not hasattr(module, "get_users")
        monkeypatch.setattr(module, "get_users", explode, raising=False)
        assert auth_client.post("/auth/login", json={}).status_code == 410

    def test_the_session_routes_are_untouched(self, auth_client):
        """GitHub OAuth issues the JWT; /auth/me and /auth/logout still serve it.

        Without a bearer token both answer 401, which is the same behaviour
        they had before -- what matters is that they are still mounted and are
        not part of the retirement.
        """
        assert auth_client.get("/auth/me").status_code == 401
        assert auth_client.post("/auth/logout").status_code == 401

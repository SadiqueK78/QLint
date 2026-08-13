"""GitHub OAuth: connect an account, or sign in with GitHub entirely.

The connected account's OAuth token is stored on the user document and used
for that user's scans, so they never have to paste a personal access token.

Two connections live here, and they are deliberately not the same connection.

The sign-in flow asks for read:user and nothing else. Reading a public
repository's tree and file contents needs no repository scope at all, so the
scan path never had a reason to hold one -- it asked for public_repo until
F29, and public_repo is documented by GitHub as "read/write access to code
... for public repositories". A user who only ever wanted their repositories
scanned was holding a token that could push to them. It now asks for the
scope it actually uses.

The write flow (F29, one-click migration pull requests) is what asks for
public_repo, from its own button, and stores the result in its own field. The
two tokens never mix: nothing on the scan path reads github_write_token, and
nothing on the pull request path reads github_access_token. Disconnecting one
leaves the other alone. A user who never presses "Connect write access" never
holds a token that can change anything.
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import RedirectResponse
from jose import jwt
from pymongo.errors import PyMongoError

from auth import (
    JWT_ALGORITHM,
    JWT_SECRET,
    create_access_token,
    decode_access_token,
    get_current_user,
    user_from_token,
)
from database import get_users

load_dotenv()

# Every failure below ends as a 303 to the frontend, which is what a browser
# needs but what makes the access log useless for debugging: the success and
# failure redirects are the same status to the same host. So each failure is
# logged here with its actual cause, and carries a distinct code to the UI.
logger = logging.getLogger(__name__)

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_OAUTH_REDIRECT_URI = os.getenv(
    "GITHUB_OAUTH_REDIRECT_URI", "http://localhost:8000/auth/github/callback"
)
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5174").rstrip("/")

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_API_URL = "https://api.github.com/user"
EMAILS_API_URL = "https://api.github.com/user/emails"

# Sign-in and scanning. read:user is the whole list on purpose: the scanner
# reads public repositories, and GitHub needs no repository scope for that.
OAUTH_SCOPE = "read:user"

# Pull request creation. public_repo is the narrowest OAuth App scope that
# covers create-branch, create-commit and create-pull-request -- GitHub
# defines it as read/write access to code for *public* repositories, and
# there is no finer-grained OAuth App scope for those three operations. The
# only alternative, `repo`, would additionally hand over every private
# repository the user can see, so it is not the default; an operator whose
# users need private repositories can opt in through the environment and
# accept that trade knowingly.
WRITE_OAUTH_SCOPE = os.getenv("GITHUB_WRITE_OAUTH_SCOPE", "public_repo")

# Fields on the user document. Named here so pr_router reads the write token
# through one definition rather than a string literal that could drift.
WRITE_TOKEN_FIELD = "github_write_token"
WRITE_CONNECTED_FIELD = "github_write_connected"

# The write handshake rides the same registered callback URL as sign-in --
# GitHub OAuth Apps allow exactly one, and requiring operators to re-register
# it would break every existing deployment. The two flows are told apart by a
# signed state parameter instead, which also gives the write flow the CSRF
# protection the sign-in flow never had: an attacker cannot mint a state that
# names someone else's account without the server's JWT secret.
WRITE_STATE_PURPOSE = "github_write_connect"
WRITE_STATE_TTL_MINUTES = 10

router = APIRouter(prefix="/auth/github")


def _frontend_redirect(**params: str) -> RedirectResponse:
    # 303 so the browser follows the redirect with a GET.
    return RedirectResponse(url=f"{FRONTEND_URL}/?{urlencode(params)}", status_code=303)


@router.get("/login")
async def github_login():
    """Send the browser to GitHub's consent screen."""
    if not GITHUB_CLIENT_ID:
        raise HTTPException(
            status_code=500,
            detail="GITHUB_CLIENT_ID is not configured. Add it to backend/.env",
        )
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_OAUTH_REDIRECT_URI,
        "scope": OAUTH_SCOPE,
        # Generated per request. Not verified on the way back — see F12 notes.
        "state": secrets.token_hex(8),
    }
    return RedirectResponse(url=f"{AUTHORIZE_URL}?{urlencode(params)}", status_code=303)


def _write_state(email: str) -> str:
    """A short-lived signed state naming the account the write token is for.

    Signed with the app's own JWT secret, so the callback can trust the email
    inside it without a session cookie or a server-side state table -- and so
    a state minted for one account cannot be replayed against another.
    """
    payload = {
        "sub": email,
        "purpose": WRITE_STATE_PURPOSE,
        "nonce": secrets.token_hex(8),
        "exp": datetime.now(timezone.utc)
        + timedelta(minutes=WRITE_STATE_TTL_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _write_state_email(state: str | None) -> str | None:
    """The account a write-purpose state belongs to, or None if it is not one."""
    if not state:
        return None
    payload = decode_access_token(state)
    if not payload or payload.get("purpose") != WRITE_STATE_PURPOSE:
        return None
    return payload.get("sub")


@router.post("/write/authorize")
async def github_write_authorize(user: dict = Depends(get_current_user)):
    """Hand back the GitHub consent URL for the write connection.

    A POST returning a URL rather than a redirect the browser follows: the
    caller's JWT stays in the Authorization header instead of being written
    into a query string that would end up in access logs and Referer headers.
    The frontend navigates to what this returns.
    """
    if not GITHUB_CLIENT_ID:
        raise HTTPException(
            status_code=500,
            detail="GITHUB_CLIENT_ID is not configured. Add it to backend/.env",
        )
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_OAUTH_REDIRECT_URI,
        "scope": WRITE_OAUTH_SCOPE,
        "state": _write_state(user["email"]),
    }
    return {
        "authorize_url": f"{AUTHORIZE_URL}?{urlencode(params)}",
        "scope": WRITE_OAUTH_SCOPE,
    }


@router.get("/write/disconnect")
async def github_write_disconnect(user: dict = Depends(get_current_user)):
    """Forget the write token. The read/sign-in connection is untouched."""
    await get_users().update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                WRITE_TOKEN_FIELD: None,
                "github_write_username": None,
                "github_write_scope": None,
                WRITE_CONNECTED_FIELD: False,
            }
        },
    )
    return {"write_disconnected": True}


async def _exchange_code_payload(
    client: httpx.AsyncClient, code: str
) -> dict | None:
    """Trade the one-time code for GitHub's full token response.

    The write flow needs the `scope` field alongside the token: GitHub decides
    what it actually granted, and a user can uncheck permissions on the
    consent screen. Storing a token that turned out not to carry the write
    scope would move the failure to the moment a pull request is attempted.
    """
    try:
        response = await client.post(
            TOKEN_URL,
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": GITHUB_OAUTH_REDIRECT_URI,
            },
            headers={"Accept": "application/json"},
        )
    except httpx.HTTPError as exc:
        logger.error("OAuth token exchange could not reach GitHub: %s", exc)
        return None
    if response.status_code != 200:
        logger.error(
            "OAuth token exchange returned HTTP %s from GitHub", response.status_code
        )
        return None
    payload = response.json()
    # GitHub answers 200 with an {"error": ...} body for a bad or expired code.
    if not payload.get("access_token"):
        logger.error(
            "OAuth token exchange was refused by GitHub: %s (%s). Check that "
            "GITHUB_CLIENT_SECRET matches GITHUB_CLIENT_ID and that the app's "
            "callback URL is %s",
            payload.get("error"),
            payload.get("error_description"),
            GITHUB_OAUTH_REDIRECT_URI,
        )
        return None
    return payload


async def _exchange_code(client: httpx.AsyncClient, code: str) -> str | None:
    """The sign-in flow's view of the exchange: just the token."""
    payload = await _exchange_code_payload(client, code)
    return payload["access_token"] if payload else None


def _granted_scopes(payload: dict) -> set[str]:
    """The scopes GitHub says it granted, as a set."""
    raw = payload.get("scope") or ""
    return {item.strip() for item in raw.split(",") if item.strip()}


def _has_write_scope(granted: set[str]) -> bool:
    """Does what GitHub granted actually cover branch/commit/PR creation?

    `repo` is a superset of `public_repo`, so a user who granted the broader
    scope satisfies the narrower requirement. Anything else does not.
    """
    if WRITE_OAUTH_SCOPE in granted:
        return True
    return WRITE_OAUTH_SCOPE == "public_repo" and "repo" in granted


async def _fetch_profile(client: httpx.AsyncClient, token: str) -> dict | None:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    try:
        response = await client.get(USER_API_URL, headers=headers)
        if response.status_code != 200:
            return None
        profile = response.json()

        if not profile.get("email"):
            # Public email is hidden; try the emails endpoint, then fall back
            # to GitHub's own noreply address so the account still has a key.
            try:
                emails = await client.get(EMAILS_API_URL, headers=headers)
                if emails.status_code == 200:
                    entries = emails.json()
                    primary = next(
                        (e for e in entries if e.get("primary") and e.get("email")),
                        None,
                    ) or next((e for e in entries if e.get("email")), None)
                    if primary:
                        profile["email"] = primary["email"]
            except httpx.HTTPError:
                pass
        if not profile.get("email") and profile.get("login"):
            profile["email"] = f"{profile['login']}@users.noreply.github.com"
    except httpx.HTTPError:
        return None
    return profile


async def _complete_write_connect(email: str, code: str) -> RedirectResponse:
    """Store a write token on the account the signed state named.

    Deliberately narrow: it writes the github_write_* fields and nothing else.
    It never touches github_access_token, never creates an account, and never
    issues a JWT -- the user was already signed in when they asked for this,
    and a write connection is not a way to sign in.
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        payload = await _exchange_code_payload(client, code)
        if not payload:
            return _frontend_redirect(github_write_error="token_exchange_failed")

        granted = _granted_scopes(payload)
        if not _has_write_scope(granted):
            # The consent screen let them through without the scope this
            # feature needs. Storing the token anyway would look connected and
            # fail at the moment a pull request is attempted.
            logger.warning(
                "GitHub write connection for %s granted %s, which does not "
                "cover %s",
                email,
                sorted(granted) or ["nothing"],
                WRITE_OAUTH_SCOPE,
            )
            return _frontend_redirect(github_write_error="scope_denied")

        profile = await _fetch_profile(client, payload["access_token"])

    try:
        result = await get_users().update_one(
            {"email": email},
            {
                "$set": {
                    WRITE_TOKEN_FIELD: payload["access_token"],
                    "github_write_username": (profile or {}).get("login"),
                    "github_write_scope": ",".join(sorted(granted)),
                    WRITE_CONNECTED_FIELD: True,
                    "github_write_connected_at": datetime.now(timezone.utc),
                }
            },
        )
    except PyMongoError as exc:
        logger.error(
            "GitHub write connection for %s failed at the database step: %s",
            email,
            exc,
        )
        return _frontend_redirect(github_write_error="db_unavailable")
    if result.matched_count == 0:
        logger.error("GitHub write connection named an unknown account: %s", email)
        return _frontend_redirect(github_write_error="unknown_account")

    logger.info("GitHub write access connected for %s", email)
    return _frontend_redirect(github_write="connected")


@router.get("/callback")
async def github_callback(
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    authorization: str | None = Header(default=None),
):
    """Complete the OAuth handshake and hand a JWT back to the frontend.

    One registered callback URL serves both flows, because GitHub OAuth Apps
    allow exactly one. The signed state decides which: a write-purpose state
    means the user pressed "Connect write access", and that path never issues
    a session or touches the sign-in token.
    """
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        logger.error(
            "GitHub sign-in is not configured: set GITHUB_CLIENT_ID and "
            "GITHUB_CLIENT_SECRET in backend/.env"
        )
        return _frontend_redirect(github_error="not_configured")

    write_email = _write_state_email(state)
    if write_email:
        if not code:
            logger.warning("GitHub write callback was hit without a code")
            return _frontend_redirect(github_write_error="no_code")
        try:
            return await _complete_write_connect(write_email, code)
        except Exception:
            logger.exception("Unexpected failure while connecting write access")
            return _frontend_redirect(github_write_error="server_error")

    if not code:
        logger.warning("GitHub callback was hit without a code parameter")
        return _frontend_redirect(github_error="no_code")

    async with httpx.AsyncClient(timeout=30.0) as client:
        access_token = await _exchange_code(client, code)
        if not access_token:
            return _frontend_redirect(github_error="token_exchange_failed")

        profile = await _fetch_profile(client, access_token)

    if not profile or not profile.get("email"):
        logger.error(
            "GitHub accepted the code but the profile could not be read; "
            "the token may lack the %s scope",
            OAUTH_SCOPE,
        )
        return _frontend_redirect(github_error="profile_unavailable")

    email = profile["email"].strip().lower()
    github_fields = {
        "github_access_token": access_token,
        "github_username": profile.get("login"),
        "github_connected": True,
    }

    users = get_users()

    # An API client may connect GitHub to the account it is already signed in
    # as by passing its bearer token through; browsers never do this.
    current = None
    if authorization and authorization.startswith("Bearer "):
        current = await user_from_token(authorization.split(" ", 1)[1].strip())

    try:
        if current:
            await users.update_one({"_id": current["_id"]}, {"$set": github_fields})
            token_email = current["email"]
        else:
            existing = await users.find_one({"email": email})
            if existing:
                await users.update_one({"_id": existing["_id"]}, {"$set": github_fields})
            else:
                await users.insert_one(
                    {
                        "email": email,
                        "password_hash": None,  # GitHub-only account
                        "created_at": datetime.now(timezone.utc),
                        "scan_count": 0,
                        "role": "user",
                        **github_fields,
                    }
                )
            token_email = email
    except PyMongoError as exc:
        # The handshake with GitHub succeeded; only the account write failed.
        # Reported separately because the fix is "start MongoDB", not "try
        # signing in again", and the two are indistinguishable from the log.
        logger.error(
            "GitHub sign-in for %s failed at the database step: %s. Is MongoDB "
            "running at the configured MONGODB_URI?",
            email,
            exc,
        )
        return _frontend_redirect(github_error="db_unavailable")
    except Exception:
        logger.exception("Unexpected failure while completing GitHub sign-in")
        return _frontend_redirect(github_error="server_error")

    jwt_token = create_access_token({"sub": token_email})
    logger.info("GitHub sign-in completed for %s", token_email)
    return _frontend_redirect(github_token=jwt_token, github_user=token_email)


@router.get("/disconnect")
async def github_disconnect(user: dict = Depends(get_current_user)):
    """Forget the stored OAuth token for the signed-in account."""
    await get_users().update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "github_access_token": None,
                "github_username": None,
                "github_connected": False,
            }
        },
    )
    return {"disconnected": True}

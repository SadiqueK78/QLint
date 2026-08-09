"""GitHub OAuth: connect an account, or sign in with GitHub entirely.

The connected account's OAuth token is stored on the user document and used
for that user's scans, so they never have to paste a personal access token.
"""

import logging
import os
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import RedirectResponse
from pymongo.errors import PyMongoError

from auth import create_access_token, get_current_user, user_from_token
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
OAUTH_SCOPE = "public_repo read:user"

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


async def _exchange_code(client: httpx.AsyncClient, code: str) -> str | None:
    """Trade the one-time code for an OAuth access token."""
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
    return payload["access_token"]


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


@router.get("/callback")
async def github_callback(
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    authorization: str | None = Header(default=None),
):
    """Complete the OAuth handshake and hand a JWT back to the frontend."""
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        logger.error(
            "GitHub sign-in is not configured: set GITHUB_CLIENT_ID and "
            "GITHUB_CLIENT_SECRET in backend/.env"
        )
        return _frontend_redirect(github_error="not_configured")
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

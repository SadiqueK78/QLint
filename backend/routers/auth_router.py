"""Session lookup and logout, plus two retired email/password endpoints.

Signing in happens entirely through GitHub OAuth now; oauth_router owns that
flow and issues the JWT. What is left here is the session pair every signed-in
client uses -- /auth/me and /auth/logout -- and the two routes that used to
create and check passwords, kept as deliberate errors rather than deleted. See
the comment above them for why.
"""

from fastapi import APIRouter, Depends, HTTPException

from auth import get_current_user
from models import UserResponse, user_to_response

router = APIRouter(prefix="/auth")

# ---------------------------------------------------------------------------
# Retired: email/password authentication.
#
# These two routes still exist, still answer, and no longer do anything. They
# are a temporary stub, and the reason is deployment ordering: the backend and
# the frontend are separate Render services with no guaranteed order, so a
# browser running the previous frontend bundle can post here for a while after
# this ships. Deleting the routes outright would answer that with FastAPI's
# bare 404 "Not Found", which reads as a broken server rather than a retired
# feature.
#
# 410 Gone is the accurate status: the resource existed, its removal is
# intentional, and it is not coming back. A client that gets one has an answer
# it can show a user without guessing.
#
# FOLLOW-UP CLEANUP, once both services have been live on this change long
# enough that no old bundle is still in a browser somewhere -- delete together:
#   * these two routes and DISCONTINUED below
#   * models.UserRegister and models.UserLogin, which nothing else constructs
#   * auth.hash_password, auth.verify_password and auth.pwd_context, whose only
#     remaining callers are their own tests (auth.create_access_token stays --
#     oauth_router issues every session token with it)
#   * passlib[bcrypt] from requirements.txt, once the three above are gone
#   * the password_hash field on models.UserDocument
#
# Deliberately no request model on either route: validating a body first would
# answer a malformed old-frontend request with a 422 about a password length
# rule that no longer exists, instead of the one message that is true.
# ---------------------------------------------------------------------------

DISCONTINUED = (
    "Email and password sign-in has been discontinued. Please sign in with "
    "GitHub instead."
)


@router.post("/register", status_code=410)
async def register():
    """Retired. See the comment above: 410, no account is created."""
    raise HTTPException(status_code=410, detail=DISCONTINUED)


@router.post("/login", status_code=410)
async def login():
    """Retired. See the comment above: 410, no credentials are checked."""
    raise HTTPException(status_code=410, detail=DISCONTINUED)


@router.get("/me", response_model=UserResponse)
async def me(user: dict = Depends(get_current_user)):
    return user_to_response(user)


@router.post("/logout")
async def logout(user: dict = Depends(get_current_user)):
    # JWTs are stateless — the client drops the token. No server-side blocklist.
    return {"message": "logged out"}

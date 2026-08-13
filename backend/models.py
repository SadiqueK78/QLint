"""Pydantic request/response models for auth, users, and the scan cache."""

import re
from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$")


class UserRegister(BaseModel):
    email: str
    password: str = Field(min_length=8)

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not EMAIL_RE.match(value):
            raise ValueError("Invalid email address")
        return value


class UserLogin(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class UserDocument(BaseModel):
    """Shape of a document in the `users` collection.

    Declared for reference — MongoDB writes go through plain dicts, and every
    reader treats the optional fields as absent-means-default so accounts
    created before a field existed keep working.
    """

    email: str
    password_hash: str | None = None  # None for GitHub-only accounts
    created_at: datetime
    scan_count: int = 0
    role: str = "user"
    github_access_token: str | None = None
    github_username: str | None = None
    github_connected: bool = False
    # F29's write connection, kept in its own fields rather than widened onto
    # the ones above. An account can hold either, both, or neither, and
    # disconnecting one must not disturb the other.
    github_write_token: str | None = None
    github_write_username: str | None = None
    github_write_scope: str | None = None
    github_write_connected: bool = False


class UserResponse(BaseModel):
    id: str
    email: str
    created_at: str
    scan_count: int
    role: str = "user"
    github_connected: bool = False
    github_username: str | None = None
    # Whether the pull request feature is reachable for this account. The
    # token itself is never part of any response.
    github_write_connected: bool = False
    github_write_username: str | None = None
    github_write_scope: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class ScanCacheEntry(BaseModel):
    repo_url: str
    scanned_by: str
    result: dict
    created_at: datetime
    expires_at: datetime


def user_to_response(user: dict) -> UserResponse:
    """Map a MongoDB user document onto the public UserResponse shape."""
    created_at = user.get("created_at")
    if isinstance(created_at, datetime):
        # Mongo hands back naive UTC datetimes; tag them so clients do not
        # read the timestamp as local time.
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        created_at = created_at.isoformat()
    return UserResponse(
        id=str(user["_id"]),
        email=user["email"],
        created_at=str(created_at),
        scan_count=int(user.get("scan_count", 0)),
        # Accounts created before roles existed are plain users.
        role=user.get("role", "user"),
        github_connected=bool(user.get("github_connected", False)),
        github_username=user.get("github_username"),
        github_write_connected=bool(user.get("github_write_connected", False)),
        github_write_username=user.get("github_write_username"),
        github_write_scope=user.get("github_write_scope"),
    )

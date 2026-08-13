"""Repository scanning endpoints, backed by a MongoDB result cache."""

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Awaitable

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pymongo import DESCENDING
from pymongo.errors import PyMongoError

from auth import get_current_user
from database import get_scans, get_users
from github_client import (
    GitHubError,
    InvalidRepoURLError,
    InvalidTokenError,
    RepoNotFoundError,
    check_rate_limit,
    get_repo_files,
    parse_repo_url,
)
from cbom_converter import convert_to_cbom
from sarif_converter import convert_to_sarif
from scanner_engine import ScanCancelled, scan_repository

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
SCAN_CACHE_TTL_HOURS = int(os.getenv("SCAN_CACHE_TTL_HOURS", "24"))

# nginx's "client closed request". Nobody reads this status -- by definition
# the socket is gone -- but it keeps an abandoned scan out of the 2xx and 5xx
# buckets in any access log, where it would otherwise read as either a
# successful scan or a server fault.
CLIENT_CLOSED_REQUEST = 499

router = APIRouter()


class ScanRequest(BaseModel):
    repo_url: str
    force_refresh: bool = False
    github_token: str | None = None


def _require_token() -> str:
    if not GITHUB_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="GITHUB_TOKEN is not configured. Add it to backend/.env",
        )
    return GITHUB_TOKEN


def _resolve_token(body: ScanRequest, user: dict | None) -> str:
    """Pick the GitHub credential for this scan.

    A token pasted into the form wins, then the signed-in user's connected
    GitHub account, then the server-wide token from the environment.
    """
    if body.github_token:
        return body.github_token.strip()
    if user and user.get("github_connected") and user.get("github_access_token"):
        return user["github_access_token"]
    return _require_token()


async def _github_call(coro: Awaitable):
    """Await a github_client/scanner_engine coroutine, mapping errors to HTTP."""
    try:
        return await coro
    except HTTPException:
        raise  # already an HTTP error (e.g. 429 from rate limiting)
    except InvalidRepoURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except RepoNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except GitHubError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502, detail=f"GitHub API request failed: {exc}"
        ) from exc


def _canonical_url(repo_url: str) -> str:
    """Normalize a repo URL so cache keys survive .git suffixes and trailing slashes."""
    try:
        owner, repo = parse_repo_url(repo_url)
    except InvalidRepoURLError:
        return repo_url.strip()
    return f"https://github.com/{owner}/{repo}"


def _iso(value) -> str | None:
    if isinstance(value, datetime):
        # Mongo returns naive UTC datetimes; tag them so the client parses correctly.
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return value


async def _cache_lookup(repo_url: str) -> dict | None:
    """Newest non-expired cache entry for this repo, or None."""
    try:
        return await get_scans().find_one(
            {"repo_url": repo_url, "expires_at": {"$gt": datetime.now(timezone.utc)}},
            sort=[("created_at", DESCENDING)],
        )
    except PyMongoError:
        return None  # cache is an optimization, never a hard dependency


async def _cache_store(repo_url: str, result: dict, user: dict) -> str | None:
    """Store the scan and return its id, or None if the write did not happen.

    Every scan has an owner now that /scan requires a session, so the entry is
    always attributed; older documents from the anonymous era keep their
    "anonymous" scanned_by and null user_id, which the reads below still handle.
    """
    now = datetime.now(timezone.utc)
    entry = {
        "repo_url": repo_url,
        "scanned_by": user["email"],
        "user_id": str(user["_id"]),
        "result": result,
        "created_at": now,
        "expires_at": now + timedelta(hours=SCAN_CACHE_TTL_HOURS),
    }
    try:
        inserted = await get_scans().insert_one(entry)
        await get_users().update_one({"_id": user["_id"]}, {"$inc": {"scan_count": 1}})
        return str(inserted.inserted_id)
    except PyMongoError:
        return None  # a failed cache write must not fail the scan


# The download formats /scan can render instead of the normal report shape,
# mapped to (converter, file extension). Adding one here is all it takes: the
# Query pattern, the cached path and the fresh path all read this table.
_DOWNLOAD_FORMATS = {
    "sarif": (convert_to_sarif, "sarif"),
    "cbom": (convert_to_cbom, "cbom.json"),
}
_FORMAT_PATTERN = "^(?:sarif|cbom)$"


def _download_response(report: dict, repo_url: str, format: str) -> JSONResponse:
    """Render a report as a downloadable SARIF or CBOM file.

    Named after the repo rather than a scan id: a cache hit belonging to another
    user, or a scan whose cache write failed, has no id to name the file with.
    """
    convert, extension = _DOWNLOAD_FORMATS[format]
    slug = repo_url.rstrip("/").rsplit("/", 2)[-2:]
    name = "-".join(part for part in slug if part) or "report"
    return JSONResponse(
        content=convert(report),
        headers={
            "Content-Disposition": (
                f'attachment; filename="qlint-scan-{name}.{extension}"'
            )
        },
    )


@router.post("/scan")
async def scan(
    request: Request,
    body: ScanRequest,
    # Scanning is a signed-in action: it spends GitHub quota, can be pointed at
    # a private repo through a caller-supplied token, and writes a row every
    # admin aggregate counts. get_current_user 401s when the bearer token is
    # missing, expired, or names a user that no longer exists.
    user: dict = Depends(get_current_user),
    format: str | None = Query(
        default=None,
        pattern=_FORMAT_PATTERN,
        description="Set to 'sarif' for SARIF 2.1.0, or 'cbom' for a "
        "CycloneDX 1.6 cryptography bill of materials, instead of the normal "
        "report shape. Cached scans convert without re-scanning.",
    ),
):
    token = _resolve_token(body, user)
    repo_url = _canonical_url(body.repo_url)

    if not body.force_refresh:
        cached = await _cache_lookup(repo_url)
        if cached:
            result = dict(cached["result"])
            if format:
                # Neither download format carries cache metadata, so return
                # the findings as they were stored rather than annotating them.
                return _download_response(result, repo_url, format)
            result["cached"] = True
            result["cached_at"] = _iso(cached["created_at"])
            result["cache_expires_at"] = _iso(cached["expires_at"])
            # The cache is shared across users, so only hand back the scan id
            # when this user owns the entry — /hndl/calculate and the history
            # routes will not resolve someone else's id anyway. An entry the
            # owner has deleted is skipped for the same reason: its result is
            # still a valid cache hit, but handing back the id would put a scan
            # they hid back in front of them behind a link that 404s.
            if (
                cached.get("user_id") == str(user["_id"])
                and cached.get("deleted_at") is None
            ):
                result["scan_id"] = str(cached["_id"])
            return result

    start = time.perf_counter()
    try:
        # Starlette does not cancel this handler when the client goes away, so
        # without a check the scan runs to completion and stores a result
        # nobody asked for any more -- measured, not assumed. is_disconnected()
        # polls the ASGI receive channel for the http.disconnect uvicorn posts
        # when the socket closes, which covers all three ways a client leaves:
        # the Cancel button's AbortController, a closed tab, and a navigation.
        report = await _github_call(
            scan_repository(
                body.repo_url,
                token,
                request.app.state.github,
                should_cancel=request.is_disconnected,
            )
        )
    except ScanCancelled:
        # No cleanup to do, and that is by design rather than luck:
        # _cache_store below is the only writer on this path, and it runs after
        # scan_repository returns. Leaving by exception means the insert never
        # happens, so an abandoned scan leaves no document behind at all --
        # there is no partial state for a later scan to trip over.
        return JSONResponse(
            status_code=CLIENT_CLOSED_REQUEST,
            content={"detail": "Scan cancelled by the client"},
        )
    report["scan_duration_seconds"] = round(time.perf_counter() - start, 2)
    report["cached"] = False

    scan_id = await _cache_store(repo_url, report, user)
    if format:
        return _download_response(report, repo_url, format)
    # None when the cache write failed (Mongo down): the scan itself succeeded,
    # but there is no stored document for that id to resolve against.
    if scan_id:
        report["scan_id"] = scan_id
    return report


# Gated like /scan itself: the preview reads the repository's file tree from
# GitHub, so leaving it open would hand out exactly the reconnaissance step the
# scan gate exists to withhold.
@router.post("/scan/preview", dependencies=[Depends(get_current_user)])
async def scan_preview(request: Request, body: ScanRequest):
    token = _require_token()
    client = request.app.state.github
    try:
        owner, repo = parse_repo_url(body.repo_url)
    except InvalidRepoURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    files = await _github_call(get_repo_files(body.repo_url, token, client=client))
    rate = await _github_call(check_rate_limit(token, client=client))
    return {
        "repo": f"{owner}/{repo}",
        "files_found": len(files),
        # Kept so anything built against the pre-F13 shape keeps working.
        "python_files_found": sum(1 for f in files if f["language"] == "python"),
        "languages": sorted({f["language"] for f in files}),
        "files": files,
        "rate_limit_remaining": rate["remaining"],
    }


# Deliberately left open, unlike the two routes above: it reads nothing about
# any repository, only the server's own GitHub quota, and the landing page shows
# it before anyone has signed in.
@router.get("/scan/status")
async def scan_status(request: Request):
    token = _require_token()
    return await _github_call(check_rate_limit(token, client=request.app.state.github))

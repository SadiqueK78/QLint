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

from auth import get_optional_user
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
from sarif_converter import convert_to_sarif
from scanner_engine import scan_repository

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
SCAN_CACHE_TTL_HOURS = int(os.getenv("SCAN_CACHE_TTL_HOURS", "24"))

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


async def _cache_store(repo_url: str, result: dict, user: dict | None) -> str | None:
    """Store the scan and return its id, or None if the write did not happen."""
    now = datetime.now(timezone.utc)
    entry = {
        "repo_url": repo_url,
        "scanned_by": user["email"] if user else "anonymous",
        "user_id": str(user["_id"]) if user else None,
        "result": result,
        "created_at": now,
        "expires_at": now + timedelta(hours=SCAN_CACHE_TTL_HOURS),
    }
    try:
        inserted = await get_scans().insert_one(entry)
        if user:
            await get_users().update_one({"_id": user["_id"]}, {"$inc": {"scan_count": 1}})
        return str(inserted.inserted_id)
    except PyMongoError:
        return None  # a failed cache write must not fail the scan


def _sarif_response(report: dict, repo_url: str) -> JSONResponse:
    """Render a report as a downloadable SARIF file.

    Named after the repo rather than a scan id: this path also serves anonymous
    scans, which are stored without an owner and have no id to hand back.
    """
    slug = repo_url.rstrip("/").rsplit("/", 2)[-2:]
    name = "-".join(part for part in slug if part) or "report"
    return JSONResponse(
        content=convert_to_sarif(report),
        headers={
            "Content-Disposition": f'attachment; filename="qlint-scan-{name}.sarif"'
        },
    )


@router.post("/scan")
async def scan(
    request: Request,
    body: ScanRequest,
    user: dict | None = Depends(get_optional_user),
    format: str | None = Query(
        default=None,
        pattern="^sarif$",
        description="Set to 'sarif' to receive SARIF 2.1.0 instead of the "
        "normal report shape. Cached scans convert without re-scanning.",
    ),
):
    token = _resolve_token(body, user)
    repo_url = _canonical_url(body.repo_url)

    if not body.force_refresh:
        cached = await _cache_lookup(repo_url)
        if cached:
            result = dict(cached["result"])
            if format == "sarif":
                # SARIF carries no cache metadata, so return the findings as
                # they were stored rather than annotating them.
                return _sarif_response(result, repo_url)
            result["cached"] = True
            result["cached_at"] = _iso(cached["created_at"])
            result["cache_expires_at"] = _iso(cached["expires_at"])
            # The cache is shared across users, so only hand back the scan id
            # when this user owns the entry — /hndl/calculate and the history
            # routes will not resolve someone else's id anyway.
            if user and cached.get("user_id") == str(user["_id"]):
                result["scan_id"] = str(cached["_id"])
            return result

    start = time.perf_counter()
    report = await _github_call(
        scan_repository(body.repo_url, token, request.app.state.github)
    )
    report["scan_duration_seconds"] = round(time.perf_counter() - start, 2)
    report["cached"] = False

    scan_id = await _cache_store(repo_url, report, user)
    if format == "sarif":
        return _sarif_response(report, repo_url)
    # Anonymous scans are stored without an owner, so their id resolves for
    # nobody; leave it off rather than handing out one that always 404s.
    if scan_id and user:
        report["scan_id"] = scan_id
    return report


@router.post("/scan/preview")
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


@router.get("/scan/status")
async def scan_status(request: Request):
    token = _require_token()
    return await _github_call(check_rate_limit(token, client=request.app.state.github))

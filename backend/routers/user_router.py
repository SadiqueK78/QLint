"""Per-user scan history."""

import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pymongo import DESCENDING
from pymongo.errors import PyMongoError

from auth import get_current_user, to_object_id
from database import VISIBLE_SCAN, get_scans
from cbom_converter import convert_to_cbom
from github_client import InvalidRepoURLError, manifest_fetcher, parse_repo_url
from sarif_converter import convert_to_sarif
from sbom_converter import generate_sbom

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

router = APIRouter(prefix="/user")

DB_UNAVAILABLE = "Database unavailable. Is MongoDB running on port 27017?"


def _iso(value) -> str | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return value


SEVERITY_RANK = {"critical": 0, "warning": 1, "safe": 2, "info": 3}


def _algo_severity(result: dict) -> dict:
    """Highest severity seen per algorithm, so history pills match the results view."""
    worst: dict[str, str] = {}
    for findings in (result.get("findings_by_file") or {}).values():
        for finding in findings:
            algorithm = finding.get("algorithm")
            severity = finding.get("severity")
            if algorithm is None or severity not in SEVERITY_RANK:
                continue
            current = worst.get(algorithm)
            if current is None or SEVERITY_RANK[severity] < SEVERITY_RANK[current]:
                worst[algorithm] = severity
    return worst


def _summarize(entry: dict) -> dict:
    """Reduce a stored scan to the fields the history list needs."""
    result = entry.get("result") or {}
    return {
        "id": str(entry["_id"]),
        "repo_url": entry.get("repo_url", ""),
        "pqc_readiness_score": result.get("pqc_readiness_score", 0),
        "total_findings": result.get("total_findings", 0),
        "scanned_files": result.get("scanned_files", 0),
        "algorithms_found": result.get("algorithms_found", []),
        "algo_severity": _algo_severity(result),
        "created_at": _iso(entry.get("created_at")),
        "cached": bool(result.get("cached", False)),
    }


@router.get("/scans")
async def list_scans(
    user: dict = Depends(get_current_user),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=10, ge=1, le=50),
):
    scans = get_scans()
    # VISIBLE_SCAN drops the scans this user has hidden. `total` is therefore
    # the size of the list being paginated, not the account's lifetime scan
    # count -- the two diverge as soon as anything is deleted.
    query = {"user_id": str(user["_id"]), **VISIBLE_SCAN}
    try:
        total = await scans.count_documents(query)
        cursor = (
            scans.find(query)
            .sort("created_at", DESCENDING)
            .skip((page - 1) * limit)
            .limit(limit)
        )
        entries = await cursor.to_list(length=limit)
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=DB_UNAVAILABLE) from exc

    pages = (total + limit - 1) // limit
    return {
        "scans": [_summarize(entry) for entry in entries],
        "total": total,
        "page": page,
        "pages": pages,
    }


async def _owned_scan(scan_id: str, user: dict) -> dict:
    """Fetch a scan the caller may read and has not hidden, or 404.

    Ownership here means one thing and nothing else: whether this QLint
    account is the account whose /scan call created this document, which is
    what the stored user_id records. Who owns the scanned repository on GitHub
    plays no part in it and must not -- QLint exists to scan public
    repositories that belong to other people, so a user's own scan of
    paramiko/paramiko is as much their scan record as one of their own code.

    The user_id filter is what keeps one user from reading another's scan: a
    scan owned by someone else is indistinguishable from a missing one. An
    admin is exempt, because operating the service means being able to open
    what the service stored.

    A scan the owner has deleted reads as missing for everyone, admin
    included. The document survives for the admin aggregates, but the delete
    button's promise is that the report itself stops being served, and an
    export route is exactly a way of serving it.
    """
    object_id = to_object_id(scan_id)
    if object_id is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    query = {"_id": object_id, **VISIBLE_SCAN}
    if user.get("role", "user") != "admin":
        query["user_id"] = str(user["_id"])
    try:
        entry = await get_scans().find_one(query)
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=DB_UNAVAILABLE) from exc
    if not entry:
        raise HTTPException(status_code=404, detail="Scan not found")
    return entry


def _repo_parts(entry: dict) -> tuple[str, str]:
    """The (owner, repo) a stored scan was run against.

    Read from the stored repo_url, which _canonical_url normalized on the way
    in, and from the report's own "repo" field as a fallback for documents
    written before that normalization.
    """
    try:
        return parse_repo_url(entry.get("repo_url") or "")
    except InvalidRepoURLError:
        pass
    name = ((entry.get("result") or {}).get("repo") or "").strip("/")
    if name.count("/") == 1 and all(part for part in name.split("/")):
        owner, repo = name.split("/")
        return owner, repo
    raise HTTPException(
        status_code=422,
        detail="This scan has no GitHub repository to build an SBOM from",
    )


def _github_token(user: dict) -> str:
    """The credential to read the scanned repository's manifests with.

    The caller's connected GitHub account first, so a scan of a private
    repository can still be inventoried, then the server-wide token. Same
    precedence as scanning itself, minus the per-request token that only the
    scan form collects.
    """
    if user.get("github_connected") and user.get("github_access_token"):
        return user["github_access_token"]
    if not GITHUB_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="GITHUB_TOKEN is not configured. Add it to backend/.env",
        )
    return GITHUB_TOKEN


@router.get("/scans/{scan_id}/full")
async def get_scan_full(scan_id: str, user: dict = Depends(get_current_user)):
    entry = await _owned_scan(scan_id, user)
    result = dict(entry.get("result") or {})
    result["scan_id"] = str(entry["_id"])
    result["created_at"] = _iso(entry.get("created_at"))
    return result


@router.get("/scans/{scan_id}/sarif")
async def get_scan_sarif(scan_id: str, user: dict = Depends(get_current_user)):
    """The same report as /full, rendered as SARIF 2.1.0 for external tooling.

    Served as a download so a browser hitting this URL saves a .sarif file
    rather than rendering the JSON inline.
    """
    entry = await _owned_scan(scan_id, user)
    sarif = convert_to_sarif(entry.get("result") or {})
    return JSONResponse(
        content=sarif,
        headers={
            "Content-Disposition": (
                f'attachment; filename="qlint-scan-{scan_id}.sarif"'
            )
        },
    )


@router.get("/scans/{scan_id}/cbom")
async def get_scan_cbom(scan_id: str, user: dict = Depends(get_current_user)):
    """The same report as /full, rendered as a CycloneDX 1.6 CBOM.

    The sibling of /sarif, and gated by the same ownership check. Where SARIF
    answers "what is wrong and where", the CBOM is the cryptographic inventory
    a migration programme tracks progress against.

    Served as a download so a browser hitting this URL saves the file rather
    than rendering the JSON inline.
    """
    entry = await _owned_scan(scan_id, user)
    cbom = convert_to_cbom(entry.get("result") or {})
    return JSONResponse(
        content=cbom,
        headers={
            "Content-Disposition": (
                f'attachment; filename="qlint-scan-{scan_id}.cbom.json"'
            )
        },
    )


@router.get("/scans/{scan_id}/sbom")
async def get_scan_sbom(
    scan_id: str, request: Request, user: dict = Depends(get_current_user)
):
    """The scanned repository's software dependencies, as a CycloneDX 1.6 SBOM.

    The third export, and the only one not derived from the stored report: a
    CBOM inventories the cryptography QLint found in the code, an SBOM
    inventories the libraries the repository declares it depends on. That
    lives in the repository's manifests, not in the scan, so it is read from
    GitHub now -- which also means the answer describes the repository as it
    stands rather than as it stood when the scan ran.

    Gated by the same scan-record ownership check as /sarif and /cbom.
    """
    entry = await _owned_scan(scan_id, user)
    result = entry.get("result") or {}
    owner, repo = _repo_parts(entry)
    sbom = await generate_sbom(
        owner,
        repo,
        result.get("languages_scanned") or [],
        manifest_fetcher(
            owner, repo, _github_token(user), request.app.state.github
        ),
    )
    return JSONResponse(
        content=sbom,
        headers={
            "Content-Disposition": (
                f'attachment; filename="qlint-scan-{scan_id}.sbom.json"'
            )
        },
    )


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str, user: dict = Depends(get_current_user)):
    """Hide a scan from the caller's history. The document is kept.

    A soft delete, on purpose: this collection is also what /admin/stats and
    /admin/scans count, so removing the document would let any user silently
    reduce the operator's view of total usage. The scan stops existing for its
    owner -- it leaves their list and can no longer be opened, exported, or
    scored -- while the record of the run survives for the aggregates.

    Purging data for real is deliberately not reachable from here. If erasure
    is ever needed (a GDPR request, say), it belongs in an explicit admin-only
    route, not behind a user's tidy-up button.
    """
    object_id = to_object_id(scan_id)
    if object_id is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        # user_id keeps one user from deleting another's scan; VISIBLE_SCAN
        # makes a second delete a 404 rather than quietly rewriting the
        # timestamp on a scan that was already hidden.
        result = await get_scans().update_one(
            {"_id": object_id, "user_id": str(user["_id"]), **VISIBLE_SCAN},
            {
                "$set": {
                    "deleted_at": datetime.now(timezone.utc),
                    "deleted_by_user": True,
                }
            },
        )
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=DB_UNAVAILABLE) from exc
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True}

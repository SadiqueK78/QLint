"""Per-user scan history."""

import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pymongo import DESCENDING
from pymongo.errors import PyMongoError

from auth import get_current_user, to_object_id
from database import SCAN_TYPE_REPOSITORY, SCAN_TYPE_WEBSITE, VISIBLE_SCAN, get_scans
from cbom_converter import convert_to_cbom, convert_website_to_cbom
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
    """Reduce a stored scan to the fields the history list needs.

    Both kinds of scan pass through here. The five report fields below are
    shared -- a website scan's combined report carries pqc_readiness_score,
    total_findings and algorithms_found under the same names a repository
    report does, which is what lets one history list hold both -- and the two
    that are not shared are additions rather than reinterpretations.

    scan_type says which kind this row is, and target_url holds for a website
    what repo_url holds for a repository. repo_url is left empty for a website
    scan rather than filled with the site's URL: they are not the same thing,
    and a caller that reads repo_url must never be handed something that is not
    a repository. A row written before scan_type existed has no such field and
    is a repository scan by definition, which is what the default says.

    scanned_files and algo_severity stay repository-shaped and come back 0 and
    {} for a website: neither has a meaning for a live site, and inventing one
    would be worse than an empty value a renderer can hide.
    """
    result = entry.get("result") or {}
    return {
        "id": str(entry["_id"]),
        "scan_type": entry.get("scan_type", SCAN_TYPE_REPOSITORY),
        "repo_url": entry.get("repo_url", ""),
        "target_url": entry.get("target_url", ""),
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


def _is_website(entry: dict) -> bool:
    """Whether a stored scan is a website scan rather than a repository scan.

    Read from scan_type, with anything else -- including the absent field on
    every document written before website scanning existed -- meaning a
    repository scan.
    """
    return entry.get("scan_type") == SCAN_TYPE_WEBSITE


@router.get("/scans/{scan_id}/sarif")
async def get_scan_sarif(scan_id: str, user: dict = Depends(get_current_user)):
    """The same report as /full, rendered as SARIF 2.1.0 for external tooling.

    Served as a download so a browser hitting this URL saves a .sarif file
    rather than rendering the JSON inline.

    Repository scans only, and that is a property of SARIF rather than a gap
    here. Every SARIF result is a physical location in an artifact -- a file
    and a line -- which is what a code scanner produces and what Code Scanning
    annotates a pull request from. A live website has no artifact to point at.
    The converter would not fail on one; it would emit a document full of
    locations that do not exist, which is worse. CBOM is the export that
    applies to a website scan, and /cbom below serves it.
    """
    entry = await _owned_scan(scan_id, user)
    if _is_website(entry):
        raise HTTPException(
            status_code=422,
            detail=(
                "SARIF describes results at file locations in source code, "
                "which a website scan does not have. Download this scan as a "
                "CBOM instead."
            ),
        )
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

    The one export that serves both kinds of scan, and the only one that could:
    a CBOM answers "what cryptography is here", which is a question a live
    website answers as readily as a checkout does. The difference is only where
    an occurrence points -- a file and a line for a repository, the scanned URL
    or a script's URL for a website -- so the two converters share everything
    below that and produce the same CycloneDX 1.6 shape.
    """
    entry = await _owned_scan(scan_id, user)
    result = entry.get("result") or {}
    if _is_website(entry):
        cbom = convert_website_to_cbom(result, entry.get("target_url") or "")
    else:
        cbom = convert_to_cbom(result)
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

    Repository scans only, for the reason in the paragraph above rather than a
    new one: an SBOM is an inventory of the dependencies a repository's
    manifests declare, and a live website has no manifests. _repo_parts would
    reach the same 422 by way of a website scan having no repo_url to parse,
    but arriving there by accident would tell the caller the scan "has no
    GitHub repository", which reads like a fixable problem with their scan.
    Saying what is actually true is the better answer.
    """
    entry = await _owned_scan(scan_id, user)
    if _is_website(entry):
        raise HTTPException(
            status_code=422,
            detail=(
                "An SBOM inventories the dependencies a repository declares in "
                "its manifests, which a website scan has no access to. "
                "Download this scan as a CBOM instead."
            ),
        )
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

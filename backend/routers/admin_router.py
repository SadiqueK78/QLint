"""Admin-only usage dashboard: aggregate stats, user list, scan list.

Every query here reads the scans collection unfiltered, deliberately. A user's
delete button is a soft delete (database.VISIBLE_SCAN) that hides a scan from
their own history without removing the document, precisely so that what an
operator sees does not move when a user tidies up their list. Do not add
VISIBLE_SCAN to the queries below: total_scans, the per-repo and per-algorithm
aggregates, and the severity totals are meant to describe everything QLint has
ever run.
"""

import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from pymongo import DESCENDING
from pymongo.errors import PyMongoError

from auth import get_admin_user, to_object_id
from database import get_scans, get_users

load_dotenv()

ADMIN_SECRET = os.getenv("ADMIN_SECRET")

router = APIRouter(prefix="/admin")

DB_UNAVAILABLE = "Database unavailable. Is MongoDB running on port 27017?"
TOP_N = 5
SEVERITY_RANK = {"critical": 0, "warning": 1, "safe": 2, "info": 3}


class MakeAdminRequest(BaseModel):
    email: str
    secret: str


def _iso(value) -> str | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return value


def _worst(severities: list[str]) -> str:
    """The most serious severity in the list, defaulting to info."""
    ranked = [s for s in severities if s in SEVERITY_RANK]
    if not ranked:
        return "info"
    return min(ranked, key=lambda s: SEVERITY_RANK[s])


@router.post("/make-admin")
async def make_admin(body: MakeAdminRequest):
    """One-time bootstrap: promote an account using the ADMIN_SECRET.

    Deliberately unauthenticated so the very first admin can be created, but
    useless without the shared secret from the environment.
    """
    if not ADMIN_SECRET:
        raise HTTPException(
            status_code=500,
            detail="ADMIN_SECRET is not configured. Add it to backend/.env",
        )
    if body.secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Invalid admin secret")

    email = body.email.strip().lower()
    try:
        result = await get_users().update_one(
            {"email": email}, {"$set": {"role": "admin"}}
        )
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=DB_UNAVAILABLE) from exc
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"email": email, "role": "admin"}


@router.get("/stats")
async def stats(admin: dict = Depends(get_admin_user)):
    users = get_users()
    scans = get_scans()
    now = datetime.now(timezone.utc)
    start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = now - timedelta(days=7)

    try:
        total_users = await users.count_documents({})
        total_scans = await scans.count_documents({})
        scans_today = await scans.count_documents({"created_at": {"$gte": start_of_day}})
        scans_this_week = await scans.count_documents({"created_at": {"$gte": week_ago}})
        # Stored scans are always fresh runs (cache hits never create a
        # document), so "cached" here counts entries still inside their TTL —
        # the reports a repeat scan would be served from cache right now.
        cached_scans = await scans.count_documents({"expires_at": {"$gt": now}})

        most_scanned = await scans.aggregate(
            [
                {"$group": {"_id": "$repo_url", "scan_count": {"$sum": 1}}},
                {"$sort": {"scan_count": DESCENDING, "_id": 1}},
                {"$limit": TOP_N},
            ]
        ).to_list(length=TOP_N)

        top_users = await users.find(
            {}, {"email": 1, "scan_count": 1}
        ).sort("scan_count", DESCENDING).limit(TOP_N).to_list(length=TOP_N)

        # findings_by_file is an object keyed by path, so convert it to an
        # array before unwinding down to individual findings.
        algorithms = await scans.aggregate(
            [
                {"$project": {"files": {"$objectToArray": "$result.findings_by_file"}}},
                {"$unwind": "$files"},
                {"$unwind": "$files.v"},
                {"$match": {"files.v.severity": {"$ne": "info"}}},
                {
                    "$group": {
                        "_id": "$files.v.algorithm",
                        "count": {"$sum": 1},
                        "severities": {"$addToSet": "$files.v.severity"},
                    }
                },
                {"$sort": {"count": DESCENDING, "_id": 1}},
                {"$limit": TOP_N},
            ]
        ).to_list(length=TOP_N)

        severity_rows = await scans.aggregate(
            [
                {
                    "$group": {
                        "_id": None,
                        "critical": {"$sum": "$result.severity_summary.critical"},
                        "warning": {"$sum": "$result.severity_summary.warning"},
                        "safe": {"$sum": "$result.severity_summary.safe"},
                        "info": {"$sum": "$result.severity_summary.info"},
                    }
                }
            ]
        ).to_list(length=1)
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=DB_UNAVAILABLE) from exc

    totals = severity_rows[0] if severity_rows else {}
    return {
        "total_users": total_users,
        "total_scans": total_scans,
        "scans_today": scans_today,
        "scans_this_week": scans_this_week,
        "cached_scans": cached_scans,
        "most_scanned_repos": [
            {"repo_url": row["_id"] or "", "scan_count": row["scan_count"]}
            for row in most_scanned
        ],
        "top_users": [
            {"email": row.get("email", ""), "scan_count": int(row.get("scan_count", 0))}
            for row in top_users
        ],
        "algorithms_most_found": [
            {
                "algorithm": row["_id"],
                "count": row["count"],
                "severity": _worst(row.get("severities", [])),
            }
            for row in algorithms
            if row["_id"]
        ],
        "severity_totals": {
            "critical": int(totals.get("critical") or 0),
            "warning": int(totals.get("warning") or 0),
            "safe": int(totals.get("safe") or 0),
            "info": int(totals.get("info") or 0),
        },
    }


@router.get("/users")
async def list_users(
    admin: dict = Depends(get_admin_user),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
):
    users = get_users()
    try:
        total = await users.count_documents({})
        rows = await (
            users.find({}, {"password_hash": 0})
            .sort("created_at", DESCENDING)
            .skip((page - 1) * limit)
            .limit(limit)
            .to_list(length=limit)
        )
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=DB_UNAVAILABLE) from exc

    return {
        "users": [
            {
                "id": str(row["_id"]),
                "email": row.get("email", ""),
                "role": row.get("role", "user"),
                "scan_count": int(row.get("scan_count", 0)),
                "created_at": _iso(row.get("created_at")),
            }
            for row in rows
        ],
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit,
    }


@router.get("/scans")
async def list_all_scans(
    admin: dict = Depends(get_admin_user),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
):
    scans = get_scans()
    try:
        total = await scans.count_documents({})
        rows = await (
            scans.find({})
            .sort("created_at", DESCENDING)
            .skip((page - 1) * limit)
            .limit(limit)
            .to_list(length=limit)
        )
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=DB_UNAVAILABLE) from exc

    entries = []
    for row in rows:
        result = row.get("result") or {}
        entries.append(
            {
                "id": str(row["_id"]),
                "repo_url": row.get("repo_url", ""),
                "scanned_by": row.get("scanned_by", "anonymous"),
                "pqc_readiness_score": result.get("pqc_readiness_score", 0),
                "total_findings": result.get("total_findings", 0),
                "cached": bool(result.get("cached", False)),
                # Still counted and still listed, but no longer in its owner's
                # history. Surfaced so the admin view can tell the two apart.
                "hidden_by_user": bool(row.get("deleted_at")),
                "created_at": _iso(row.get("created_at")),
            }
        )
    return {
        "scans": entries,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit,
    }


@router.delete("/users/{user_id}")
async def delete_user(user_id: str, admin: dict = Depends(get_admin_user)):
    object_id = to_object_id(user_id)
    if object_id is None:
        raise HTTPException(status_code=404, detail="User not found")
    if str(admin["_id"]) == user_id:
        raise HTTPException(
            status_code=400, detail="You cannot delete your own account"
        )

    try:
        target = await get_users().find_one({"_id": object_id})
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
        # The one real erasure path in QLint, and an admin-only, explicit one:
        # removing an account takes its scans with it. A user's own delete
        # button never reaches this -- it only sets deleted_at.
        await get_scans().delete_many({"user_id": user_id})
        await get_users().delete_one({"_id": object_id})
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=DB_UNAVAILABLE) from exc
    return {"deleted": True}

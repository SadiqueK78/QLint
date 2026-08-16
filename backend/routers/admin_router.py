"""Admin-only usage dashboard: aggregate stats, user list, scan list.

No query here filters on visibility, deliberately. A user's delete button is a
soft delete (database.VISIBLE_SCAN) that hides a scan from their own history
without removing the document, precisely so that what an operator sees does not
move when a user tidies up their list. Do not add VISIBLE_SCAN to the queries
below: total_scans, the per-repo and per-algorithm aggregates, and the severity
totals are meant to describe everything QLint has ever run.

Several of them do filter on scan_type, which is a different thing and not a
weakening of the above. The collection holds website scans as well as
repository scans, and the two report shapes do not carry the same fields --
repo_url, result.findings_by_file and result.severity_summary belong to a
repository scan, target_url and a flat result.findings list to a website one.
A query reads the shape it is about. The counts that are genuinely about "how
much has this service done" -- total_scans, scans_today, scans_this_week --
stay unfiltered and count both kinds, because both kinds are scans.

Which way a given aggregate goes is a question about what the number means,
answered one at a time rather than by a rule:

  * most_scanned_repos and most_scanned_websites are two lists because they
    group on two different fields. Neither is a filtered view of the other.
  * algorithms_most_found is one list built from two pipelines, because "which
    algorithms is this platform finding" is one question: RSA in a source file
    and RSA on a certificate are the same detection twice.
  * severity_totals stays repository-only, because a website report has no
    severity_summary to add.
"""

import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from pymongo import DESCENDING
from pymongo.errors import PyMongoError

from auth import get_admin_user, to_object_id
from database import (
    REPOSITORY_SCAN,
    SCAN_TYPE_REPOSITORY,
    WEBSITE_SCAN,
    get_scans,
    get_users,
)

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


def _merge_algorithms(*grouped: list[dict]) -> list[dict]:
    """One ranked top-N list from several per-shape algorithm aggregates.

    The counts arrive as separate pipelines because repository and website
    reports store their findings differently, but "most detected algorithms" is
    a question about the platform, not about a report shape: RSA found in code
    and RSA found on a certificate are the same algorithm being detected twice,
    and the dashboard says so with one row.

    Neither input is truncated to TOP_N before it gets here, and that is the
    point of merging in Python rather than taking the top five of each. An
    algorithm sitting sixth in both lists can outrank a fifth-placed one once
    the two are added, so slicing first would produce a ranking that is wrong
    in exactly the cases the merge exists for. The lists are small enough to
    add in full -- their length is bounded by the number of algorithms
    CRYPTO_DB knows, not by the number of scans.

    Rows with no algorithm name are dropped rather than grouped under a blank
    label: a finding that names nothing (an HTTP header finding, say) is not an
    algorithm detection.
    """
    counts: dict[str, int] = {}
    severities: dict[str, list[str]] = {}
    for rows in grouped:
        for row in rows:
            name = row.get("_id")
            if not name:
                continue
            counts[name] = counts.get(name, 0) + int(row.get("count") or 0)
            severities.setdefault(name, []).extend(row.get("severities") or [])

    # Ties break on the name, so the order is stable between requests rather
    # than following whichever pipeline happened to answer first.
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [
        {
            "algorithm": name,
            "count": count,
            "severity": _worst(severities.get(name, [])),
        }
        for name, count in ranked[:TOP_N]
    ]


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

        # Repository scans only, and the $match is the whole reason: this
        # groups on repo_url, which a website scan does not have. Without it
        # every website scan ever run would collapse into a single _id: null
        # row that renders as a blank repository and can outrank real ones.
        most_scanned = await scans.aggregate(
            [
                {"$match": dict(REPOSITORY_SCAN)},
                {"$group": {"_id": "$repo_url", "scan_count": {"$sum": 1}}},
                {"$sort": {"scan_count": DESCENDING, "_id": 1}},
                {"$limit": TOP_N},
            ]
        ).to_list(length=TOP_N)

        # The website half of the same question, and deliberately a second
        # aggregate rather than a widening of the one above. The two group on
        # different fields -- repo_url and target_url -- so there is no single
        # pipeline that answers both without inventing a merged key, and the
        # dashboard asks them as two questions anyway: a repository and a site
        # are not ranked against each other in one list.
        most_scanned_sites = await scans.aggregate(
            [
                {"$match": dict(WEBSITE_SCAN)},
                {"$group": {"_id": "$target_url", "scan_count": {"$sum": 1}}},
                {"$sort": {"scan_count": DESCENDING, "_id": 1}},
                {"$limit": TOP_N},
            ]
        ).to_list(length=TOP_N)

        top_users = await users.find(
            {}, {"email": 1, "scan_count": 1}
        ).sort("scan_count", DESCENDING).limit(TOP_N).to_list(length=TOP_N)

        # "Most detected algorithms" is one question about the whole platform,
        # and it takes two pipelines to answer because the two report shapes
        # store their findings differently. Neither pipeline is the whole
        # answer; they are merged below.
        #
        # This one is the repository half. findings_by_file is an object keyed
        # by path, so convert it to an array before unwinding down to
        # individual findings -- and it stays matched to repository scans for
        # the reason it always was: a website report has no findings_by_file,
        # and $objectToArray on a field that is not there is a server error,
        # not an empty result.
        repository_algorithms = await scans.aggregate(
            [
                {"$match": dict(REPOSITORY_SCAN)},
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
            ]
        ).to_list(length=None)

        # The website half. A website report carries a flat result.findings
        # array -- no per-file grouping, because a TLS cipher suite or a
        # response header is not tied to a file -- so this unwinds one level
        # instead of two and never touches $objectToArray.
        #
        # Two fields need a fallback, and both are about the three domains a
        # website report merges:
        #
        #   canonical_algorithm is CRYPTO_DB's name for whatever the scanner
        #   observed, and it is what makes this mergeable with the repository
        #   counts at all: a TLS key exchange reports as "ECDH" where the code
        #   scanner reports the same primitive as "ECC". Grouping on the raw
        #   name would rank one algorithm as two rows. Falling back to
        #   `algorithm` covers a finding CRYPTO_DB does not recognise.
        #
        #   db_severity is CRYPTO_DB's verdict, which is the vocabulary the
        #   repository half counts in and the one _worst() ranks. TLS findings
        #   carry it alongside their own "how broken is this site today"
        #   severity; JavaScript findings are rated on CRYPTO_DB's axis
        #   natively and carry only `severity`. Taking the first that exists
        #   gets both right.
        #
        # Header findings fall out on their own: they name no algorithm, so the
        # null _id is dropped in the merge below, exactly as an unnamed
        # repository finding is.
        website_algorithms = await scans.aggregate(
            [
                {"$match": dict(WEBSITE_SCAN)},
                {"$unwind": "$result.findings"},
                {
                    "$project": {
                        "algorithm": {
                            "$ifNull": [
                                "$result.findings.canonical_algorithm",
                                "$result.findings.algorithm",
                            ]
                        },
                        "severity": {
                            "$ifNull": [
                                "$result.findings.db_severity",
                                "$result.findings.severity",
                            ]
                        },
                    }
                },
                {"$match": {"severity": {"$ne": "info"}}},
                {
                    "$group": {
                        "_id": "$algorithm",
                        "count": {"$sum": 1},
                        "severities": {"$addToSet": "$severity"},
                    }
                },
                {"$sort": {"count": DESCENDING, "_id": 1}},
            ]
        ).to_list(length=None)

        algorithms = _merge_algorithms(repository_algorithms, website_algorithms)

        # Repository scans only, so this total keeps meaning exactly what it
        # meant before websites existed. result.severity_summary is a
        # repository report's field; a website report has no such key, so an
        # unfiltered $sum would quietly add zero per website today and start
        # mixing two different counts the moment a website report grows one.
        severity_rows = await scans.aggregate(
            [
                {"$match": dict(REPOSITORY_SCAN)},
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
        "most_scanned_websites": [
            {"target_url": row["_id"] or "", "scan_count": row["scan_count"]}
            for row in most_scanned_sites
        ],
        "top_users": [
            {"email": row.get("email", ""), "scan_count": int(row.get("scan_count", 0))}
            for row in top_users
        ],
        # Already ranked, already trimmed to TOP_N, and already free of
        # unnamed rows: see _merge_algorithms.
        "algorithms_most_found": algorithms,
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
        # Deliberately unfiltered, like every other read in this file: an
        # operator's list of what the service has run means all of it. What is
        # added is the two fields that say which kind each row is. repo_url
        # keeps its exact meaning and stays empty for a website scan rather
        # than being filled with the site's URL -- a column named repo_url
        # holding https://example.com is worse than an empty one, because
        # nothing downstream can tell it apart from a real repository.
        scan_type = row.get("scan_type", SCAN_TYPE_REPOSITORY)
        entries.append(
            {
                "id": str(row["_id"]),
                "scan_type": scan_type,
                "repo_url": row.get("repo_url", ""),
                "target_url": row.get("target_url", ""),
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

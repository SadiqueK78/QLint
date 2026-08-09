"""AI-generated plain-English explanations for individual scan findings.

One endpoint, /scan/explain: the frontend sends the finding object it already
has (from a completed /scan), and gets back a short natural-language write-up
from an OpenRouter-hosted model. Results are cached in Mongo by a hash of the
finding's *content* -- the algorithm and severity, and the flagged code itself
-- rather than by file/line, so two identical lines of RSA share one cached
explanation and one OpenRouter call, while two different lines never do.

Each completion costs money, so the route is rate limited per client address.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from pymongo.errors import PyMongoError

from ai_explainer import AIExplainerError, explain_finding
from database import get_explanations
from rate_limit import RateLimiter, rate_limit

router = APIRouter()

EXPLANATION_CACHE_TTL_DAYS = 30

# Generous enough to explain every finding on a large report by hand, tight
# enough that a script cannot run up an OpenRouter bill.
_limiter = RateLimiter(max_requests=30, window_seconds=600)


class FindingExplainRequest(BaseModel):
    algorithm: str
    severity: str
    attack_vector: str | None = None
    replacement: str | None = None
    replacement_reason: str | None = None
    identifier: str | None = None
    match_type: str | None = None
    language: str | None = None
    quantum_vulnerable: bool | None = None
    classical_vulnerable: bool | None = None
    file: str | None = None
    line: int | None = None
    # The BEFORE/AFTER pair the explanation is grounded in. code_snippet is the
    # flagged source line the scanner captured; fix_snippet is the replacement
    # it recommends. Both are produced by every scanner, and both used to be
    # dropped here -- the model never saw a line of the user's actual code.
    code_snippet: str | None = None
    fix_snippet: str | None = None


def _cache_key(finding: FindingExplainRequest) -> str:
    """Hash everything the prompt is built from, the code included.

    file/line stay out on purpose: two identical lines of RSA deserve the same
    explanation wherever they live. But everything the model actually reads is
    in the hash -- above all code_snippet -- because an explanation keyed on
    the algorithm alone would be served back for a different file's code and
    would confidently name functions that file does not contain.
    """
    payload = {
        "algorithm": finding.algorithm,
        "severity": finding.severity,
        "attack_vector": finding.attack_vector,
        "identifier": finding.identifier,
        "match_type": finding.match_type,
        "language": finding.language,
        "code_snippet": finding.code_snippet,
        "fix_snippet": finding.fix_snippet,
    }
    raw = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


async def _cache_lookup(key: str) -> dict | None:
    try:
        return await get_explanations().find_one(
            {"key": key, "expires_at": {"$gt": datetime.now(timezone.utc)}}
        )
    except PyMongoError:
        return None  # cache is an optimization, never a hard dependency


async def _cache_store(key: str, explanation: str, model: str) -> None:
    now = datetime.now(timezone.utc)
    try:
        await get_explanations().update_one(
            {"key": key},
            {
                "$set": {
                    "key": key,
                    "explanation": explanation,
                    "model": model,
                    "created_at": now,
                    "expires_at": now + timedelta(days=EXPLANATION_CACHE_TTL_DAYS),
                }
            },
            upsert=True,
        )
    except PyMongoError:
        pass  # a failed cache write must not fail the request


@router.post("/scan/explain", dependencies=[Depends(rate_limit(_limiter))])
async def explain(body: FindingExplainRequest, request: Request):
    key = _cache_key(body)

    # A doc missing its explanation is treated as a miss rather than served as
    # an empty answer, so a partial write cannot poison the cache for 30 days.
    cached = await _cache_lookup(key)
    if cached and cached.get("explanation"):
        return {
            "explanation": cached["explanation"],
            "model": cached.get("model"),
            "cached": True,
        }

    try:
        explanation, model = await explain_finding(
            body.model_dump(), request.app.state.openrouter
        )
    except AIExplainerError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    await _cache_store(key, explanation, model)
    return {"explanation": explanation, "model": model, "cached": False}

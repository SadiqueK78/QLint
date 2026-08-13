"""AI-generated migration patches for individual scan findings.

One endpoint, /scan/patch: the frontend sends a finding it already has from a
completed /scan, and gets back a unified diff showing the minimal change from
the flagged code to a quantum-safe replacement. The sibling of
routers/explain_router.py, and deliberately the same shape -- content-keyed
Mongo cache with a TTL, a per-client rate limit, PyMongoError never fatal.

Two things differ, both on purpose. code_snippet and fix_snippet are required
rather than optional: an explanation without code is merely generic, but a
patch without code is a fabricated diff against lines that may not exist, so
this endpoint refuses instead of guessing. And the rate limit is its own
window, not a share of the explainer's -- a patch is a longer completion at a
larger token cap, so it gets its own, tighter budget rather than letting patch
traffic exhaust the quota for explanations.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel, ValidationError, field_validator
from pymongo.errors import PyMongoError

from database import get_patches
from patch_generator import PatchGeneratorError, generate_patch
from rate_limit import RateLimiter, rate_limit

router = APIRouter()

PATCH_CACHE_TTL_DAYS = 30

# Tighter than the explainer's 30/10min: a patch is a 600-token completion
# against a longer prompt, so the same number of requests costs meaningfully
# more. Its own limiter rather than a shared one means a client working
# through patches cannot lock itself out of explanations, or the reverse.
_limiter = RateLimiter(max_requests=15, window_seconds=600)


class FindingPatchRequest(BaseModel):
    algorithm: str
    severity: str
    # Required, unlike FindingExplainRequest. These two are what the diff is
    # built from: code_snippet is the flagged source line the scanner
    # captured, fix_snippet the replacement direction from CRYPTO_DB.
    code_snippet: str
    fix_snippet: str
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

    @field_validator("code_snippet", "fix_snippet")
    @classmethod
    def must_carry_code(cls, value: str) -> str:
        # A present-but-blank snippet grounds a patch exactly as badly as an
        # absent one, so both are refused by the same rule.
        if not value.strip():
            raise ValueError("must not be empty")
        return value


def _cache_key(finding: FindingPatchRequest, grounding: str | None = None) -> str:
    """Hash everything the prompt is built from, the code included.

    Wide from the start: F22 shipped this narrower, keyed on algorithm and
    severity alone, and served one finding's answer for another finding's
    code. file/line still stay out -- two identical vulnerable lines deserve
    the same patch wherever they live -- but every field the model reads is in
    the hash, above all the two snippets.

    grounding is the real file excerpt the pull request path puts in the
    prompt. It has to be in the key for the same reason everything else is:
    it changes the prompt, so it changes the answer. A patch generated blind
    for the results view describes a file the model never saw and generally
    will not apply, so serving it to the pull request path -- which is where
    "will not apply" turns into a skipped finding -- would keep F29's bug
    alive in the cache for the full 30 days. Keying on the excerpt also means
    a patch is only reused while the surrounding code it was written against
    is still the surrounding code.
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
        "grounding": grounding,
    }
    raw = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


async def _cache_lookup(key: str) -> dict | None:
    try:
        return await get_patches().find_one(
            {"key": key, "expires_at": {"$gt": datetime.now(timezone.utc)}}
        )
    except PyMongoError:
        return None  # cache is an optimization, never a hard dependency


async def _cache_store(key: str, patch: str, model: str) -> None:
    now = datetime.now(timezone.utc)
    try:
        await get_patches().update_one(
            {"key": key},
            {
                "$set": {
                    "key": key,
                    "patch": patch,
                    "model": model,
                    "created_at": now,
                    "expires_at": now + timedelta(days=PATCH_CACHE_TTL_DAYS),
                }
            },
            upsert=True,
        )
    except PyMongoError:
        pass  # a failed cache write must not fail the request


def _parse_body(raw: dict) -> FindingPatchRequest:
    """Validate by hand so a missing snippet is a 400, not FastAPI's 422.

    422 is the right code for a body FastAPI could not parse, but "you did not
    send the code to patch" is a specific, actionable client mistake that the
    caller has to fix by sending a different payload -- and the frontend needs
    to tell the developer which field was missing, not print a validation
    trace. Declaring the fields required on the model still keeps them
    required in the OpenAPI schema.
    """
    try:
        return FindingPatchRequest.model_validate(raw)
    except ValidationError as exc:
        missing = sorted({str(error["loc"][-1]) for error in exc.errors()})
        raise HTTPException(
            status_code=400,
            detail=(
                "Cannot generate a patch: "
                + ", ".join(missing)
                + " missing or empty. A patch must be grounded in the "
                "finding's real code_snippet and fix_snippet."
            ),
        ) from exc


@router.post("/scan/patch", dependencies=[Depends(rate_limit(_limiter))])
async def patch(request: Request, raw: dict = Body(...)):
    body = _parse_body(raw)
    key = _cache_key(body)

    # A doc missing its patch is treated as a miss rather than served as an
    # empty diff, so a partial write cannot poison the cache for 30 days.
    cached = await _cache_lookup(key)
    if cached and cached.get("patch"):
        return {
            "patch": cached["patch"],
            "model": cached.get("model"),
            "cached": True,
        }

    try:
        patch_text, model = await generate_patch(
            body.model_dump(), request.app.state.openrouter
        )
    except PatchGeneratorError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    await _cache_store(key, patch_text, model)
    return {"patch": patch_text, "model": model, "cached": False}

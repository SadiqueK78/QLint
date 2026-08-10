"""Harvest Now, Decrypt Later risk scoring over a stored scan result."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from pymongo.errors import PyMongoError

from auth import get_current_user, to_object_id
from database import VISIBLE_SCAN, get_scans
from hndl_calculator import (
    CRQC_SCENARIOS,
    DATA_SENSITIVITY_PROFILES,
    calculate_hndl_risk,
)

router = APIRouter(prefix="/hndl")

DB_UNAVAILABLE = "Database unavailable. Is MongoDB running on port 27017?"


class HNDLRequest(BaseModel):
    scan_id: str
    data_sensitivity: str
    crqc_scenario: str = "moderate"


@router.get("/profiles")
async def profiles():
    """Selector options for the calculator. Public: no scan data is involved."""
    return {
        "data_sensitivity_profiles": DATA_SENSITIVITY_PROFILES,
        "crqc_scenarios": CRQC_SCENARIOS,
    }


@router.post("/calculate")
async def calculate(body: HNDLRequest, user: dict = Depends(get_current_user)):
    object_id = to_object_id(body.scan_id)
    if object_id is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        # The user_id filter is what stops one user scoring another's scan;
        # a scan owned by someone else is indistinguishable from a missing one.
        # VISIBLE_SCAN gives a scan its owner deleted the same treatment: this
        # is a user-facing read, so a hidden scan is not scoreable either.
        entry = await get_scans().find_one(
            {"_id": object_id, "user_id": str(user["_id"]), **VISIBLE_SCAN}
        )
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=DB_UNAVAILABLE) from exc
    if not entry:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        result = calculate_hndl_risk(
            entry.get("result") or {},
            body.data_sensitivity,
            body.crqc_scenario,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    result["scan_id"] = str(entry["_id"])
    result["repo_url"] = entry.get("repo_url", "")
    return result

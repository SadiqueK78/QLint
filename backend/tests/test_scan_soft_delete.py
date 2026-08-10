"""DELETE /user/scans/{id} hides a scan; it does not remove the document.

The point of these tests is the seam between two views of one collection: the
user's history, which must respect a delete, and the admin aggregates, which
must not. A hard delete satisfies the first and silently breaks the second --
any user could shrink the operator's usage numbers just by tidying their list.
"""

from datetime import datetime, timezone

import pytest
from bson import ObjectId
from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth import get_admin_user, get_current_user
from routers import admin_router as admin_module
from routers import hndl_router as hndl_module
from routers import user_router as user_module
from routers.admin_router import router as admin_router
from routers.hndl_router import router as hndl_router
from routers.user_router import router as user_router

OWNER_ID = "652f1f77bcf86cd799439011"
OTHER_ID = "652f1f77bcf86cd799439022"
SCAN_IDS = [
    "652f1f77bcf86cd7994390a1",
    "652f1f77bcf86cd7994390a2",
    "652f1f77bcf86cd7994390a3",
]


def _scan(scan_id: str, user_id: str = OWNER_ID) -> dict:
    return {
        "_id": ObjectId(scan_id),
        "repo_url": f"https://github.com/acme/repo-{scan_id[-1]}",
        "user_id": user_id,
        "scanned_by": "owner@qlint.dev",
        "created_at": datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc),
        "result": {
            "pqc_readiness_score": 40,
            "total_findings": 7,
            "scanned_files": 12,
            "algorithms_found": ["RSA"],
            "severity_summary": {"critical": 7, "warning": 0, "safe": 0, "info": 0},
            "findings_by_file": {"A.java": [{"algorithm": "RSA", "severity": "critical"}]},
        },
    }


def _matches(document: dict, query: dict) -> bool:
    for key, value in query.items():
        assert not isinstance(value, dict), f"the fake does not do operators: {key}"
        # document.get(key) is None for an absent field, which is exactly how
        # MongoDB treats a null equality match -- scans stored before soft
        # delete existed have no deleted_at and stay visible.
        if document.get(key) != value:
            return False
    return True


class FakeCursor:
    def __init__(self, documents):
        self.documents = documents

    def sort(self, *args, **kwargs):
        return self

    def skip(self, count):
        return FakeCursor(self.documents[count:])

    def limit(self, count):
        return FakeCursor(self.documents[:count])

    async def to_list(self, length=None):
        return self.documents[:length]


class FakeScans:
    """Enough of a Motor collection for the history and admin scan routes."""

    def __init__(self, documents):
        self.documents = documents

    async def find_one(self, query, **kwargs):
        for document in self.documents:
            if _matches(document, query):
                return document
        return None

    def find(self, query, projection=None):
        return FakeCursor([d for d in self.documents if _matches(d, query)])

    async def count_documents(self, query):
        return sum(1 for d in self.documents if _matches(d, query))

    async def update_one(self, query, update):
        for document in self.documents:
            if _matches(document, query):
                document.update(update["$set"])
                return type("Result", (), {"matched_count": 1, "modified_count": 1})()
        return type("Result", (), {"matched_count": 0, "modified_count": 0})()


@pytest.fixture
def collection():
    return FakeScans([_scan(scan_id) for scan_id in SCAN_IDS])


@pytest.fixture
def owner(monkeypatch, collection):
    """A client signed in as the owner, over one shared fake collection."""
    for module in (user_module, hndl_module, admin_module):
        monkeypatch.setattr(module, "get_scans", lambda: collection)
    app = FastAPI()
    app.include_router(user_router)
    app.include_router(hndl_router)
    app.include_router(admin_router)
    app.dependency_overrides[get_current_user] = lambda: {
        "_id": OWNER_ID,
        "email": "owner@qlint.dev",
    }
    app.dependency_overrides[get_admin_user] = lambda: {
        "_id": OTHER_ID,
        "email": "admin@qlint.dev",
        "role": "admin",
    }
    yield TestClient(app), app, collection
    app.dependency_overrides.clear()


def _history(client) -> list[str]:
    response = client.get("/user/scans")
    assert response.status_code == 200
    return [scan["id"] for scan in response.json()["scans"]]


class TestSoftDeleteHidesFromTheUser:
    def test_delete_removes_the_scan_from_the_history_list(self, owner):
        client, _, _ = owner
        assert _history(client) == SCAN_IDS

        assert client.delete(f"/user/scans/{SCAN_IDS[1]}").status_code == 200
        assert _history(client) == [SCAN_IDS[0], SCAN_IDS[2]]

    def test_the_list_total_tracks_the_deletions(self, owner):
        """What the header count renders from: total must follow the list."""
        client, _, _ = owner
        for index, scan_id in enumerate(SCAN_IDS):
            body = client.get("/user/scans").json()
            assert body["total"] == len(body["scans"]) == len(SCAN_IDS) - index
            client.delete(f"/user/scans/{scan_id}")
        body = client.get("/user/scans").json()
        assert body["total"] == 0
        assert body["scans"] == []

    def test_the_document_survives_the_delete(self, owner):
        client, _, collection = owner
        client.delete(f"/user/scans/{SCAN_IDS[0]}")

        assert len(collection.documents) == len(SCAN_IDS)
        stored = collection.documents[0]
        assert stored["deleted_by_user"] is True
        assert isinstance(stored["deleted_at"], datetime)
        # The report itself is untouched: this is a visibility change.
        assert stored["result"]["total_findings"] == 7

    def test_a_deleted_scan_cannot_be_reopened(self, owner):
        client, _, _ = owner
        client.delete(f"/user/scans/{SCAN_IDS[0]}")
        response = client.get(f"/user/scans/{SCAN_IDS[0]}/full")
        assert response.status_code == 404
        assert response.json()["detail"] == "Scan not found"

    def test_a_deleted_scan_cannot_be_exported_as_sarif(self, owner):
        client, _, _ = owner
        client.delete(f"/user/scans/{SCAN_IDS[0]}")
        assert client.get(f"/user/scans/{SCAN_IDS[0]}/sarif").status_code == 404

    def test_a_deleted_scan_cannot_be_scored_for_hndl_risk(self, owner):
        client, _, _ = owner
        client.delete(f"/user/scans/{SCAN_IDS[0]}")
        response = client.post(
            "/hndl/calculate",
            json={"scan_id": SCAN_IDS[0], "data_sensitivity": "financial_records"},
        )
        assert response.status_code == 404

    def test_deleting_twice_is_a_404_not_a_second_write(self, owner):
        client, _, collection = owner
        assert client.delete(f"/user/scans/{SCAN_IDS[0]}").status_code == 200
        first_stamp = collection.documents[0]["deleted_at"]
        assert client.delete(f"/user/scans/{SCAN_IDS[0]}").status_code == 404
        assert collection.documents[0]["deleted_at"] == first_stamp

    def test_a_user_cannot_delete_someone_elses_scan(self, owner):
        client, app, collection = owner
        app.dependency_overrides[get_current_user] = lambda: {
            "_id": OTHER_ID,
            "email": "stranger@qlint.dev",
        }
        assert client.delete(f"/user/scans/{SCAN_IDS[0]}").status_code == 404
        assert "deleted_at" not in collection.documents[0]

    def test_scans_stored_before_soft_delete_existed_are_still_visible(self, owner):
        """No deleted_at field at all must read as "not deleted"."""
        client, _, collection = owner
        assert all("deleted_at" not in d for d in collection.documents)
        assert _history(client) == SCAN_IDS


class TestAdminVisibilityIsUnaffected:
    """The core requirement: a user hiding scans must not move admin's numbers."""

    def test_admin_scan_total_is_unchanged_by_user_deletions(self, owner):
        client, _, collection = owner
        before = client.get("/admin/scans").json()["total"]
        assert before == len(SCAN_IDS)

        for scan_id in SCAN_IDS:
            assert client.delete(f"/user/scans/{scan_id}").status_code == 200

        assert _history(client) == []
        after = client.get("/admin/scans").json()["total"]
        assert after == before

    def test_admin_still_lists_every_scan_after_the_user_hides_them(self, owner):
        client, _, _ = owner
        client.delete(f"/user/scans/{SCAN_IDS[0]}")
        rows = client.get("/admin/scans").json()["scans"]
        assert [row["id"] for row in rows] == SCAN_IDS
        hidden = {row["id"]: row["hidden_by_user"] for row in rows}
        assert hidden[SCAN_IDS[0]] is True
        assert hidden[SCAN_IDS[1]] is False

    @pytest.mark.asyncio
    async def test_the_total_scans_query_is_unfiltered(self, collection):
        """count_documents({}) is the exact query /admin/stats runs.

        Asserted against the collection directly because the rest of /stats is
        an aggregation pipeline; what matters here is that the filter is empty.
        """
        before = await collection.count_documents({})
        await collection.update_one(
            {"_id": ObjectId(SCAN_IDS[0])},
            {"$set": {"deleted_at": datetime.now(timezone.utc), "deleted_by_user": True}},
        )
        assert await collection.count_documents({}) == before
        # ...while the user's own history query does drop it.
        from database import VISIBLE_SCAN

        assert await collection.count_documents(
            {"user_id": OWNER_ID, **VISIBLE_SCAN}
        ) == before - 1

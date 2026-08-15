"""Who may download a scan's reports, in every format.

The rule these lock in has one input: the scan record's own stored user_id,
which is the account whose /scan call created the document. Who owns the
scanned repository on GitHub is not part of it and must never become part of
it -- QLint's whole purpose is scanning public repositories that belong to
other people, so "you do not own paramiko/paramiko" can never be a reason to
withhold your own scan of it.

The bug these were written against did not look like that from the outside.
Downloads failed for public repositories the user did not own on GitHub and
worked for repositories they did, which reads like a permission check on repo
ownership. It was not one. The scan cache is shared across accounts, so a user
who scanned a repository somebody else had already scanned was served that
cached result and given no scan id of their own -- and with no id, the UI fell
back to a route that could not authenticate, so every download failed. A
repository you own on GitHub is simply one nobody else has scanned, which is
why those kept working. The tests below cover both halves: the ownership check
itself, and the cache path that used to leave a user without a record to point
it at.
"""

from datetime import datetime, timedelta, timezone

import pytest
from bson import ObjectId
from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth import get_current_user
from routers import scan_router as scan_module
from routers import user_router as user_module
from routers.scan_router import router as scan_router
from routers.user_router import router as user_router

# Two accounts, neither of which owns the repository they both scan.
USER_A = {"_id": "652f1f77bcf86cd799439011", "email": "a@qlint.dev"}
USER_B = {"_id": "652f1f77bcf86cd799439022", "email": "b@qlint.dev"}
ADMIN = {"_id": "652f1f77bcf86cd799439033", "email": "admin@qlint.dev",
         "role": "admin"}

PUBLIC_REPO = "https://github.com/paramiko/paramiko"
A_SCAN_ID = "652f1f77bcf86cd7994390a1"
B_SCAN_ID = "652f1f77bcf86cd7994390b1"

# The formats a saved scan can be downloaded in. /full is the plain report the
# frontend no longer shows a button for and the backend still serves.
FORMATS = ["full", "sarif", "cbom", "sbom"]

REQUIREMENTS_TXT = "paramiko==3.5.0\ncryptography>=42.0\n"


def _result() -> dict:
    return {
        "repo": "paramiko/paramiko",
        "pqc_readiness_score": 42,
        "total_findings": 3,
        "scanned_files": 18,
        "algorithms_found": ["RSA"],
        "languages_scanned": ["python"],
        "severity_summary": {"critical": 3, "warning": 0, "safe": 0, "info": 0},
        "findings_by_file": {
            "paramiko/rsakey.py": [
                {
                    "file": "paramiko/rsakey.py",
                    "line": 24,
                    "algorithm": "RSA",
                    "severity": "critical",
                    "quantum_vulnerable": True,
                }
            ]
        },
    }


def _scan(scan_id: str, user: dict, expired: bool = False) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "_id": ObjectId(scan_id),
        "repo_url": PUBLIC_REPO,
        "user_id": user["_id"],
        "scanned_by": user["email"],
        "result": _result(),
        "created_at": now,
        "expires_at": now - timedelta(hours=1) if expired else now + timedelta(hours=24),
        "deleted_at": None,
    }


def _matches(document: dict, query: dict) -> bool:
    for key, value in query.items():
        if isinstance(value, dict):
            if "$gt" in value:
                stored = document.get(key)
                if stored is None or stored <= value["$gt"]:
                    return False
                continue
            raise AssertionError(f"the fake does not do this operator: {key}")
        if document.get(key) != value:
            return False
    return True


class FakeScans:
    def __init__(self, documents: list[dict]):
        self.documents = documents

    async def find_one(self, query, sort=None, **kwargs):
        hits = [d for d in self.documents if _matches(d, query)]
        if sort:
            hits.sort(key=lambda d: d.get("created_at"), reverse=True)
        return hits[0] if hits else None

    async def insert_one(self, entry):
        stored = {**entry, "_id": ObjectId()}
        self.documents.append(stored)
        return type("Result", (), {"inserted_id": stored["_id"]})()


class FakeUsers:
    async def update_one(self, *args, **kwargs):
        return type("Result", (), {"matched_count": 1, "modified_count": 1})()


def _fake_manifest_fetcher(owner, repo, token, client=None):
    """Stands in for the GitHub read the SBOM route does at download time."""

    async def fetch(path: str):
        return REQUIREMENTS_TXT if path == "requirements.txt" else None

    return fetch


@pytest.fixture
def collection():
    return FakeScans([_scan(A_SCAN_ID, USER_A), _scan(B_SCAN_ID, USER_B)])


@pytest.fixture
def api(monkeypatch, collection):
    """The user and scan routers over one shared fake collection."""
    monkeypatch.setattr(user_module, "get_scans", lambda: collection)
    monkeypatch.setattr(scan_module, "get_scans", lambda: collection)
    monkeypatch.setattr(scan_module, "get_users", lambda: FakeUsers())
    monkeypatch.setattr(user_module, "manifest_fetcher", _fake_manifest_fetcher)
    monkeypatch.setattr(scan_module, "manifest_fetcher", _fake_manifest_fetcher)
    monkeypatch.setattr(user_module, "GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(scan_module, "GITHUB_TOKEN", "test-token")

    app = FastAPI()
    app.include_router(user_router)
    app.include_router(scan_router)
    app.state.github = None  # the fake fetcher never uses it
    signed_in = {"user": USER_A}
    app.dependency_overrides[get_current_user] = lambda: signed_in["user"]

    def sign_in_as(user: dict):
        signed_in["user"] = user

    yield TestClient(app), sign_in_as, collection
    app.dependency_overrides.clear()


class TestTheOwnerCanDownloadEveryFormat:
    @pytest.mark.parametrize("format", FORMATS)
    def test_owner_downloads_their_own_scan(self, api, format):
        client, sign_in_as, _ = api
        sign_in_as(USER_A)
        response = client.get(f"/user/scans/{A_SCAN_ID}/{format}")
        assert response.status_code == 200, response.text
        assert response.json()

    def test_the_repository_owner_on_github_is_never_consulted(self, api):
        """paramiko/paramiko belongs to neither account. Both still download."""
        client, sign_in_as, _ = api
        for user, scan_id in ((USER_A, A_SCAN_ID), (USER_B, B_SCAN_ID)):
            sign_in_as(user)
            for format in FORMATS:
                assert client.get(f"/user/scans/{scan_id}/{format}").status_code == 200


class TestAnotherUserIsRejected:
    @pytest.mark.parametrize("format", FORMATS)
    def test_a_different_account_cannot_download_someone_elses_scan(
        self, api, format
    ):
        client, sign_in_as, _ = api
        sign_in_as(USER_B)
        response = client.get(f"/user/scans/{A_SCAN_ID}/{format}")
        # 404, not 403: the established convention here is that a scan you do
        # not own is indistinguishable from one that does not exist.
        assert response.status_code == 404
        assert response.json()["detail"] == "Scan not found"

    @pytest.mark.parametrize("format", FORMATS)
    def test_the_same_repository_scanned_twice_stays_separated(self, api, format):
        """The reported bug's exact shape, from the other side.

        One repository, neither account's own on GitHub, scanned separately by
        both. Each account downloads its own record and only its own.
        """
        client, sign_in_as, _ = api

        sign_in_as(USER_A)
        assert client.get(f"/user/scans/{A_SCAN_ID}/{format}").status_code == 200
        assert client.get(f"/user/scans/{B_SCAN_ID}/{format}").status_code == 404

        sign_in_as(USER_B)
        assert client.get(f"/user/scans/{B_SCAN_ID}/{format}").status_code == 200
        assert client.get(f"/user/scans/{A_SCAN_ID}/{format}").status_code == 404

    def test_a_malformed_scan_id_is_a_404_rather_than_a_500(self, api):
        client, sign_in_as, _ = api
        sign_in_as(USER_A)
        for format in FORMATS:
            assert client.get(f"/user/scans/not-an-id/{format}").status_code == 404


class TestAdminCanDownloadAnything:
    @pytest.mark.parametrize("format", FORMATS)
    def test_admin_downloads_any_users_scan(self, api, format):
        client, sign_in_as, _ = api
        sign_in_as(ADMIN)
        assert client.get(f"/user/scans/{A_SCAN_ID}/{format}").status_code == 200
        assert client.get(f"/user/scans/{B_SCAN_ID}/{format}").status_code == 200

    def test_a_hidden_scan_stays_hidden_from_the_admin_export_too(self, api):
        """The delete button's promise outranks the admin's reach here.

        The document survives for the admin aggregates, which is what
        /admin/scans reads. Serving its report back would undo the one thing
        the user asked for.
        """
        client, sign_in_as, collection = api
        collection.documents[0]["deleted_at"] = datetime.now(timezone.utc)
        sign_in_as(ADMIN)
        assert client.get(f"/user/scans/{A_SCAN_ID}/cbom").status_code == 404


class TestScansWithNoStoredRecord:
    """The download path for a scan that has no id to address.

    A cache write that failed leaves the scan with no document, so there is no
    ownership to check -- the format is rendered from the report the caller
    was just handed.
    """

    @pytest.fixture
    def fresh_scan(self, monkeypatch, api):
        client, sign_in_as, collection = api

        async def fake_scan(*args, **kwargs):
            return _result()

        async def store_nothing(*args, **kwargs):
            return None  # Mongo unavailable: the scan runs, nothing is stored

        monkeypatch.setattr(scan_module, "scan_repository", fake_scan)
        monkeypatch.setattr(scan_module, "_cache_store", store_nothing)
        return client, sign_in_as, collection

    @pytest.mark.parametrize("format", ["sarif", "cbom", "sbom"])
    def test_the_format_path_serves_a_scan_with_no_record(self, fresh_scan, format):
        client, sign_in_as, _ = fresh_scan
        sign_in_as(USER_A)
        response = client.post(
            f"/scan?format={format}", json={"repo_url": PUBLIC_REPO}
        )
        assert response.status_code == 200, response.text
        assert "attachment" in response.headers["content-disposition"]

    def test_the_sbom_from_that_path_describes_the_scanned_repository(
        self, fresh_scan
    ):
        client, sign_in_as, _ = fresh_scan
        sign_in_as(USER_A)
        body = client.post(
            "/scan?format=sbom", json={"repo_url": PUBLIC_REPO}
        ).json()
        assert body["metadata"]["component"]["name"] == "paramiko/paramiko"
        assert any(c["name"] == "paramiko" for c in body["components"])


class TestCacheHitsGetTheirOwnRecord:
    """The half of the bug that produced a scan with no downloadable id."""

    @pytest.fixture
    def scan_only(self, monkeypatch, api):
        client, sign_in_as, collection = api

        async def unexpected(*args, **kwargs):
            raise AssertionError("a cache hit must not re-scan the repository")

        monkeypatch.setattr(scan_module, "scan_repository", unexpected)
        return client, sign_in_as, collection

    def test_a_user_served_another_users_cached_result_gets_an_id(self, scan_only):
        client, sign_in_as, collection = scan_only
        # B's scan of paramiko is the newest entry; A now scans the same repo.
        sign_in_as(USER_A)
        before = len(collection.documents)

        body = client.post("/scan", json={"repo_url": PUBLIC_REPO}).json()

        assert body["cached"] is True
        assert body["scan_id"], "a cache hit must still leave the user a record"
        assert body["scan_id"] not in (A_SCAN_ID, B_SCAN_ID)
        assert len(collection.documents) == before + 1

    def test_that_id_downloads_in_every_format(self, scan_only):
        client, sign_in_as, _ = scan_only
        sign_in_as(USER_A)
        scan_id = client.post("/scan", json={"repo_url": PUBLIC_REPO}).json()[
            "scan_id"
        ]
        for format in FORMATS:
            response = client.get(f"/user/scans/{scan_id}/{format}")
            assert response.status_code == 200, f"{format}: {response.text}"

    def test_the_new_record_belongs_to_the_user_who_asked_for_it(self, scan_only):
        client, sign_in_as, collection = scan_only
        sign_in_as(USER_A)
        client.post("/scan", json={"repo_url": PUBLIC_REPO})
        stored = collection.documents[-1]
        assert stored["user_id"] == USER_A["_id"]
        assert stored["scanned_by"] == USER_A["email"]
        # ...and nobody else can download it.
        sign_in_as(USER_B)
        assert (
            client.get(f"/user/scans/{stored['_id']}/cbom").status_code == 404
        )

    def test_a_users_own_cached_scan_is_not_duplicated(self, scan_only):
        client, sign_in_as, collection = scan_only
        sign_in_as(USER_B)
        before = len(collection.documents)
        body = client.post("/scan", json={"repo_url": PUBLIC_REPO}).json()
        assert body["scan_id"] == B_SCAN_ID
        assert len(collection.documents) == before

    def test_the_copy_does_not_extend_how_long_the_result_is_cached(
        self, scan_only
    ):
        client, sign_in_as, collection = scan_only
        original = next(
            d for d in collection.documents if str(d["_id"]) == B_SCAN_ID
        )
        sign_in_as(USER_A)
        client.post("/scan", json={"repo_url": PUBLIC_REPO})
        assert collection.documents[-1]["expires_at"] == original["expires_at"]

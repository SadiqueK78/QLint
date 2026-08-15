"""A scan that nobody is waiting for must stop, and must leave nothing behind.

Two seams are covered here. In scanner_engine, a cancelled scan has to stop
issuing GitHub requests and raise rather than return a short report. In
scan_router, a disconnected client has to end the request before _cache_store
runs -- which is the only thing standing between an abandoned scan and an
orphaned document in MongoDB.

Starlette does not cancel a request handler when the client goes away, so none
of this is automatic: without the explicit checks the scan runs to completion
and stores its result. These tests are what keep that from coming back.
"""

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import scanner_engine
from auth import get_current_user
from routers import scan_router as scan_module
from routers.scan_router import CLIENT_CLOSED_REQUEST
from routers.scan_router import router as scan_router
from scanner_engine import CANCEL_CHECK_EVERY_FILES, ScanCancelled, _CancelWatch

RSA_SOURCE = "from cryptography.hazmat.primitives.asymmetric import rsa\n"

SCAN_USER = {"_id": "507f1f77bcf86cd799439011", "email": "owner@qlint.dev"}


class FakeRepo:
    """A repo of `count` identical files that records what was actually read."""

    def __init__(self, count: int):
        self.paths = [f"src/mod_{index:03d}.py" for index in range(count)]
        self.fetched: list[str] = []

    def install(self, monkeypatch):
        async def check_rate_limit(token, client=None):
            return {"remaining": 4990, "reset_at": "2026-08-10 12:00:00 UTC"}

        async def get_repo_files(repo_url, token, client=None):
            return list(self.paths)

        async def get_file_content(owner, repo, path, token, client=None):
            self.fetched.append(path)
            return RSA_SOURCE

        monkeypatch.setattr(scanner_engine, "check_rate_limit", check_rate_limit)
        monkeypatch.setattr(scanner_engine, "get_repo_files", get_repo_files)
        monkeypatch.setattr(scanner_engine, "get_file_content", get_file_content)
        return self


def run(coro):
    return asyncio.run(coro)


def scan(should_cancel=None):
    return scanner_engine.scan_repository(
        "https://github.com/acme/demo", "token", None, should_cancel=should_cancel
    )


def canceller(*answers):
    """A should_cancel returning each answer in turn, then repeating the last."""
    remaining = list(answers)
    calls = []

    async def should_cancel():
        answer = remaining.pop(0) if len(remaining) > 1 else remaining[0]
        calls.append(answer)
        return answer

    should_cancel.calls = calls
    return should_cancel


class TestTheHappyPathIsUnchanged:
    """Cancellation is opt-in and free; a scan nobody cancels behaves as before."""

    def test_a_scan_without_a_cancel_callback_still_completes(self, monkeypatch):
        repo = FakeRepo(25).install(monkeypatch)
        report = run(scan())
        assert report["scanned_files"] == 25
        assert len(repo.fetched) == 25
        assert "RSA" in report["algorithms_found"]

    def test_a_callback_that_never_cancels_changes_nothing(self, monkeypatch):
        repo = FakeRepo(25).install(monkeypatch)
        report = run(scan(should_cancel=canceller(False)))
        assert report["scanned_files"] == 25
        assert len(repo.fetched) == 25

    def test_an_empty_repo_still_reports_rather_than_cancelling(self, monkeypatch):
        FakeRepo(0).install(monkeypatch)
        report = run(scan(should_cancel=canceller(False)))
        assert report["scanned_files"] == 0
        assert report["pqc_readiness_score"] == 100


class TestCancellationStopsTheWork:
    def test_cancelling_before_the_fetch_phase_reads_no_files_at_all(
        self, monkeypatch
    ):
        """The check after the tree call: no per-file quota is spent."""
        repo = FakeRepo(50).install(monkeypatch)
        with pytest.raises(ScanCancelled):
            run(scan(should_cancel=canceller(True)))
        assert repo.fetched == []

    def test_cancelling_mid_fetch_leaves_most_files_unread(self, monkeypatch):
        """False at the gate, True from the first in-loop check onward."""
        repo = FakeRepo(200).install(monkeypatch)
        with pytest.raises(ScanCancelled):
            run(scan(should_cancel=canceller(False, True)))
        # The fetches already in flight finish; everything queued behind the
        # cancel returns without touching the network.
        assert len(repo.fetched) < 200
        assert len(repo.fetched) <= 3 * CANCEL_CHECK_EVERY_FILES

    def test_a_cancelled_scan_raises_instead_of_returning_a_short_report(
        self, monkeypatch
    ):
        """The important half: no partial report can reach a caller that stores it."""
        FakeRepo(50).install(monkeypatch)
        with pytest.raises(ScanCancelled) as exc:
            run(scan(should_cancel=canceller(True)))
        assert "acme/demo" in str(exc.value)


class TestPollingIsRateLimited:
    def test_the_callback_is_polled_per_batch_not_per_file(self, monkeypatch):
        FakeRepo(100).install(monkeypatch)
        should_cancel = canceller(False)
        run(scan(should_cancel=should_cancel))
        # One forced check before the fetch phase, then one per batch.
        expected = 1 + 100 // CANCEL_CHECK_EVERY_FILES
        assert len(should_cancel.calls) == expected
        assert len(should_cancel.calls) < 100

    def test_the_watch_latches_and_stops_polling_once_cancelled(self):
        should_cancel = canceller(True)
        watch = _CancelWatch(should_cancel, every=1)
        assert run(watch.check()) is True
        for _ in range(10):
            assert run(watch.check()) is True
        assert len(should_cancel.calls) == 1

    def test_a_watch_without_a_callback_never_cancels(self):
        watch = _CancelWatch(None)
        assert run(watch.check(force=True)) is False
        assert watch.polls == 0


@pytest.fixture
def scan_app(monkeypatch):
    """The real scan router, with GitHub and Mongo faked out but no session.

    scan_repository is the real one, so the router's should_cancel wiring is
    genuinely exercised rather than stubbed.
    """
    repo = FakeRepo(60).install(monkeypatch)
    monkeypatch.setattr(scan_module, "GITHUB_TOKEN", "test-token")

    stored: list[dict] = []

    async def cache_lookup(repo_url):
        return None

    async def cache_store(repo_url, result, user, expires_at=None):
        stored.append(
            {
                "repo_url": repo_url,
                "result": result,
                "user": user,
                "expires_at": expires_at,
            }
        )
        return "652f1f77bcf86cd7994390a1"

    monkeypatch.setattr(scan_module, "_cache_lookup", cache_lookup)
    monkeypatch.setattr(scan_module, "_cache_store", cache_store)

    app = FastAPI()
    app.include_router(scan_router)
    app.state.github = None
    return app, stored, repo


@pytest.fixture
def scan_client(scan_app):
    """The same app, with every request authenticated: /scan now requires it."""
    app, stored, repo = scan_app
    app.dependency_overrides[get_current_user] = lambda: SCAN_USER
    yield TestClient(app), stored, repo
    app.dependency_overrides.clear()


class TestTheRouterRequiresASession:
    """Scanning is gated: no bearer token, no scan, and no work done.

    The assertions on `repo` and `stored` are the point -- a 401 that arrived
    after the repository had already been read would leak exactly what the gate
    exists to withhold, and would spend the GitHub quota doing it.
    """

    def test_scan_without_a_token_is_401(self, scan_app):
        app, stored, repo = scan_app
        response = TestClient(app).post(
            "/scan", json={"repo_url": "https://github.com/acme/demo"}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Not authenticated"
        assert stored == []
        assert repo.fetched == []

    def test_scan_with_a_junk_token_is_401(self, scan_app):
        app, stored, repo = scan_app
        response = TestClient(app).post(
            "/scan",
            json={"repo_url": "https://github.com/acme/demo"},
            headers={"Authorization": "Bearer not-a-real-jwt"},
        )
        assert response.status_code == 401
        assert stored == []
        assert repo.fetched == []

    def test_preview_without_a_token_is_401(self, scan_app):
        app, _, repo = scan_app
        response = TestClient(app).post(
            "/scan/preview", json={"repo_url": "https://github.com/acme/demo"}
        )
        assert response.status_code == 401
        assert repo.fetched == []

    def test_a_signed_in_scan_is_attributed_to_that_user(self, scan_client):
        client, stored, _ = scan_client
        response = client.post(
            "/scan", json={"repo_url": "https://github.com/acme/demo"}
        )
        assert response.status_code == 200
        assert stored[0]["user"] == SCAN_USER


class TestTheRouterOnClientDisconnect:
    def test_a_connected_client_gets_a_normal_report_and_a_stored_scan(
        self, scan_client
    ):
        client, stored, repo = scan_client
        response = client.post(
            "/scan", json={"repo_url": "https://github.com/acme/demo"}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["scanned_files"] == 60
        assert body["cached"] is False
        assert "scan_duration_seconds" in body
        assert len(repo.fetched) == 60
        assert len(stored) == 1

    def test_a_disconnected_client_writes_nothing_to_mongodb(
        self, scan_client, monkeypatch
    ):
        """The check this whole change exists for.

        Before the disconnect handling, the handler ran to completion and
        called _cache_store, leaving a document behind for a scan whose reader
        had already gone.
        """
        client, stored, repo = scan_client

        async def gone(self):
            return True

        monkeypatch.setattr("starlette.requests.Request.is_disconnected", gone)

        response = client.post(
            "/scan", json={"repo_url": "https://github.com/acme/demo"}
        )
        assert response.status_code == CLIENT_CLOSED_REQUEST
        assert stored == []
        assert repo.fetched == []

    def test_the_router_polls_the_request_rather_than_a_stub(
        self, scan_client, monkeypatch
    ):
        """Prove the callback reaching scanner_engine is the live request's."""
        client, _, _ = scan_client
        polled = []

        async def watched(self):
            polled.append(self.url.path)
            return False

        monkeypatch.setattr("starlette.requests.Request.is_disconnected", watched)

        response = client.post(
            "/scan", json={"repo_url": "https://github.com/acme/demo"}
        )
        assert response.status_code == 200
        assert polled and set(polled) == {"/scan"}

    def test_a_cache_hit_is_answered_without_consulting_the_client(
        self, scan_client, monkeypatch
    ):
        """A cached scan does no work, so there is nothing to cancel."""
        client, stored, repo = scan_client

        async def cached(repo_url):
            return {
                "_id": "652f1f77bcf86cd7994390a1",
                "user_id": None,
                "deleted_at": None,
                "created_at": None,
                "expires_at": None,
                "result": {"repo": "acme/demo", "scanned_files": 3},
            }

        monkeypatch.setattr(scan_module, "_cache_lookup", cached)

        async def gone(self):
            return True

        monkeypatch.setattr("starlette.requests.Request.is_disconnected", gone)

        response = client.post(
            "/scan", json={"repo_url": "https://github.com/acme/demo"}
        )
        assert response.status_code == 200
        assert response.json()["cached"] is True
        # The point of the test: no GitHub work was done, so a disconnect had
        # nothing to cancel.
        assert repo.fetched == []
        # The cached entry belongs to nobody (user_id None), so the caller is
        # given a scan record of their own holding the same result -- the fix
        # for downloads failing on a repository somebody else had scanned. It
        # is a Mongo write, not a scan: still nothing for a cancel to stop.
        assert len(stored) == 1
        assert stored[0]["result"] == {"repo": "acme/demo", "scanned_files": 3}

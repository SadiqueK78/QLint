"""Unit tests for the pure helpers behind the scan cache and history routes,
plus route-level tests for the HNDL calculator endpoints."""

from datetime import datetime, timezone

import pytest
from bson import ObjectId
from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth import get_current_user
from routers import hndl_router as hndl_module
from routers.hndl_router import router as hndl_router
from routers.scan_router import _canonical_url, _iso
from routers.user_router import _algo_severity, _summarize


def test_canonical_url_normalizes_cache_keys():
    canonical = "https://github.com/psf/requests"
    for variant in [
        "https://github.com/psf/requests",
        "https://github.com/psf/requests/",
        "https://github.com/psf/requests.git",
        "https://github.com/psf/requests.git/",
    ]:
        assert _canonical_url(variant) == canonical


def test_canonical_url_passes_unparseable_input_through():
    # Deep links and junk are left alone; the scan itself rejects them with a
    # 400, so they must not silently collapse onto another repo's cache key.
    assert _canonical_url("  not a url  ") == "not a url"
    deep = "https://github.com/psf/requests/tree/main"
    assert _canonical_url(deep) == deep


def test_iso_tags_naive_datetimes_as_utc():
    assert _iso(datetime(2026, 7, 19, 22, 32)) == "2026-07-19T22:32:00+00:00"
    aware = datetime(2026, 7, 19, 22, 32, tzinfo=timezone.utc)
    assert _iso(aware) == "2026-07-19T22:32:00+00:00"
    assert _iso(None) is None


def test_algo_severity_keeps_the_worst_severity_per_algorithm():
    result = {
        "findings_by_file": {
            "a.py": [
                {"algorithm": "RSA", "severity": "warning"},
                {"algorithm": "RSA", "severity": "critical"},
            ],
            "b.py": [
                {"algorithm": "SHA-256", "severity": "warning"},
                {"algorithm": "hashlib", "severity": "bogus"},
            ],
        }
    }
    assert _algo_severity(result) == {"RSA": "critical", "SHA-256": "warning"}


def test_summarize_returns_only_history_fields():
    entry = {
        "_id": "abc",
        "repo_url": "https://github.com/psf/requests",
        "created_at": datetime(2026, 7, 19, 22, 32),
        "result": {
            "pqc_readiness_score": 42,
            "total_findings": 2,
            "scanned_files": 18,
            "algorithms_found": ["RSA"],
            "cached": False,
            "findings_by_file": {"a.py": [{"algorithm": "RSA", "severity": "critical"}]},
        },
    }
    summary = _summarize(entry)
    assert summary["id"] == "abc"
    assert summary["pqc_readiness_score"] == 42
    assert summary["algo_severity"] == {"RSA": "critical"}
    assert summary["created_at"] == "2026-07-19T22:32:00+00:00"
    # The full report must never ride along in the list response.
    assert "findings_by_file" not in summary


def test_summarize_tolerates_a_missing_result_blob():
    summary = _summarize({"_id": "abc", "repo_url": "u", "created_at": None})
    assert summary["pqc_readiness_score"] == 0
    assert summary["algorithms_found"] == []
    assert summary["cached"] is False


# --------------------------------------------------------------- HNDL routes
#
# Mounted on a bare app rather than main.app so the tests never open a Mongo
# connection through the lifespan handler. The scans collection is faked.

OWNER_ID = "507f1f77bcf86cd799439011"
OTHER_ID = "507f1f77bcf86cd799439022"
SCAN_ID = "652f1f77bcf86cd799439033"

STORED_SCAN = {
    "_id": ObjectId(SCAN_ID),
    "repo_url": "https://github.com/golang-jwt/jwt",
    "user_id": OWNER_ID,
    "result": {
        "severity_summary": {"critical": 72, "warning": 4, "safe": 8, "info": 0},
        "total_findings": 84,
    },
}


class FakeScans:
    """Just enough of a Motor collection for the one query the router makes."""

    def __init__(self, documents):
        self.documents = documents

    async def find_one(self, query):
        for document in self.documents:
            if all(document.get(key) == value for key, value in query.items()):
                return document
        return None


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(hndl_module, "get_scans", lambda: FakeScans([STORED_SCAN]))
    app = FastAPI()
    app.include_router(hndl_router)
    return TestClient(app), app


@pytest.fixture
def signed_in(client):
    """The same client, with requests authenticated as the scan's owner."""
    test_client, app = client
    app.dependency_overrides[get_current_user] = lambda: {
        "_id": OWNER_ID,
        "email": "owner@qlint.dev",
    }
    yield test_client
    app.dependency_overrides.clear()


def test_profiles_returns_both_dicts_without_auth(client):
    test_client, _ = client
    response = test_client.get("/hndl/profiles")
    assert response.status_code == 200
    body = response.json()
    assert "healthcare_records" in body["data_sensitivity_profiles"]
    assert body["data_sensitivity_profiles"]["healthcare_records"] == {
        "label": "Healthcare Records",
        "shelf_life_years": 50,
    }
    assert set(body["crqc_scenarios"]) == {"aggressive", "moderate", "conservative"}
    assert body["crqc_scenarios"]["moderate"]["years_from_now"] == 10


def test_calculate_requires_a_jwt(client):
    test_client, _ = client
    response = test_client.post(
        "/hndl/calculate",
        json={"scan_id": SCAN_ID, "data_sensitivity": "healthcare_records"},
    )
    assert response.status_code == 401


def test_calculate_returns_the_full_result_for_an_owned_scan(signed_in):
    response = signed_in.post(
        "/hndl/calculate",
        json={
            "scan_id": SCAN_ID,
            "data_sensitivity": "healthcare_records",
            "crqc_scenario": "moderate",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["exposed"] is True
    assert body["migration_time_years"] == 3.0
    assert body["risk_window_years"] == 7.0
    assert body["data_sensitivity_label"] == "Healthcare Records"
    assert len(body["all_scenarios"]) == 3
    assert body["scan_id"] == SCAN_ID
    assert body["verdict"] and body["recommendation"]


def test_calculate_defaults_to_the_moderate_scenario(signed_in):
    response = signed_in.post(
        "/hndl/calculate",
        json={"scan_id": SCAN_ID, "data_sensitivity": "api_keys"},
    )
    assert response.status_code == 200
    assert response.json()["crqc_scenario"] == "moderate"


def test_calculate_404s_on_another_users_scan(client):
    test_client, app = client
    app.dependency_overrides[get_current_user] = lambda: {
        "_id": OTHER_ID,
        "email": "stranger@qlint.dev",
    }
    response = test_client.post(
        "/hndl/calculate",
        json={"scan_id": SCAN_ID, "data_sensitivity": "healthcare_records"},
    )
    app.dependency_overrides.clear()
    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"


def test_calculate_404s_on_an_unknown_or_malformed_scan_id(signed_in):
    for scan_id in ["652f1f77bcf86cd799439099", "not-an-object-id"]:
        response = signed_in.post(
            "/hndl/calculate",
            json={"scan_id": scan_id, "data_sensitivity": "api_keys"},
        )
        assert response.status_code == 404


def test_calculate_400s_on_an_invalid_data_sensitivity(signed_in):
    response = signed_in.post(
        "/hndl/calculate",
        json={"scan_id": SCAN_ID, "data_sensitivity": "nuclear_codes"},
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "nuclear_codes" in detail
    assert "healthcare_records" in detail  # the valid options are listed


def test_calculate_400s_on_an_invalid_crqc_scenario(signed_in):
    response = signed_in.post(
        "/hndl/calculate",
        json={
            "scan_id": SCAN_ID,
            "data_sensitivity": "api_keys",
            "crqc_scenario": "tomorrow",
        },
    )
    assert response.status_code == 400
    assert "tomorrow" in response.json()["detail"]


# --------------------------------------------------------- benchmark router

# benchmark_router imports cleanly with or without liboqs (it guards the
# import and answers 503 instead), so these run on the native Windows venv too.
from fastapi import HTTPException

from routers import benchmark_router as benchmark_module
from routers.benchmark_router import router as benchmark_router


@pytest.fixture
def benchmark_client():
    app = FastAPI()
    app.include_router(benchmark_router)
    return TestClient(app)


@pytest.mark.parametrize(
    "value,allowed,parameter",
    [
        ("ML-KEM-999", benchmark_module.KEM_ALGORITHMS, "kem_algorithm"),
        ("Kyber768", benchmark_module.KEM_ALGORITHMS, "kem_algorithm"),
        ("Dilithium3", benchmark_module.SIG_ALGORITHMS, "sig_algorithm"),
        ("", benchmark_module.SIG_ALGORITHMS, "sig_algorithm"),
    ],
)
def test_validate_400s_and_lists_the_valid_options(value, allowed, parameter):
    with pytest.raises(HTTPException) as exc:
        benchmark_module._validate(value, allowed, parameter)
    assert exc.value.status_code == 400
    detail = exc.value.detail
    assert parameter in detail
    for option in allowed:
        assert option in detail


@pytest.mark.parametrize(
    "value,allowed",
    [
        ("ML-KEM-512", benchmark_module.KEM_ALGORITHMS),
        ("ML-KEM-1024", benchmark_module.KEM_ALGORITHMS),
        ("ML-DSA-87", benchmark_module.SIG_ALGORITHMS),
    ],
)
def test_validate_passes_every_offered_level_through(value, allowed):
    assert benchmark_module._validate(value, allowed, "kem_algorithm") == value


def test_the_defaults_are_themselves_valid_choices():
    # A default outside its own allow-list would 400 every unparameterized call.
    assert benchmark_module.DEFAULT_KEM_ALGORITHM in benchmark_module.KEM_ALGORITHMS
    assert benchmark_module.DEFAULT_SIG_ALGORITHM in benchmark_module.SIG_ALGORITHMS


@pytest.mark.skipif(
    not benchmark_module.BENCHMARK_AVAILABLE,
    reason="liboqs is not available in this environment; run from WSL",
)
def test_run_rejects_an_unknown_algorithm_before_measuring_anything(
    benchmark_client,
):
    response = benchmark_client.get(
        "/benchmark/run", params={"iterations": 1, "kem_algorithm": "ML-KEM-999"}
    )
    assert response.status_code == 400
    assert "ML-KEM-768" in response.json()["detail"]


@pytest.mark.skipif(
    not benchmark_module.BENCHMARK_AVAILABLE,
    reason="liboqs is not available in this environment; run from WSL",
)
def test_run_measures_the_requested_levels_not_the_defaults(benchmark_client):
    response = benchmark_client.get(
        "/benchmark/run",
        params={
            "iterations": 1,
            "kem_algorithm": "ML-KEM-1024",
            "sig_algorithm": "ML-DSA-87",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert [r["algorithm"] for r in body["kem_results"]] == ["ML-KEM-1024"]
    # The sizes, not just the labels: this is what proves a different algorithm
    # actually ran rather than the default run being relabeled.
    assert body["kem_results"][0]["public_key_bytes"] == 1568
    assert body["sig_results"][0]["algorithm"] == "ML-DSA-87"
    assert body["sig_results"][0]["signature_bytes"] == 4627
    # The classical baseline is fixed and comes along unchanged.
    assert [r["algorithm"] for r in body["sig_results"][1:]] == [
        "RSA-2048",
        "ECDSA-P256",
    ]


@pytest.mark.skipif(
    not benchmark_module.BENCHMARK_AVAILABLE,
    reason="liboqs is not available in this environment; run from WSL",
)
def test_run_still_defaults_to_the_768_65_pair(benchmark_client):
    response = benchmark_client.get("/benchmark/run", params={"iterations": 1})
    assert response.status_code == 200
    body = response.json()
    assert body["kem_results"][0]["algorithm"] == "ML-KEM-768"
    assert body["sig_results"][0]["algorithm"] == "ML-DSA-65"


# ------------------------------------------------------------- SARIF download
#
# Same bare-app + fake-collection setup as the HNDL routes above.

from routers import user_router as user_module
from routers.user_router import router as user_router

SARIF_SCAN = {
    "_id": ObjectId(SCAN_ID),
    "repo_url": "https://github.com/golang-jwt/jwt",
    "user_id": OWNER_ID,
    "result": {
        "findings_by_file": {
            "auth\\login.py": [
                {
                    "file": "auth\\login.py",
                    "line": 12,
                    "col": 0,
                    "algorithm": "RSA",
                    "severity": "critical",
                }
            ],
            "utils/hash.py": [
                {
                    "file": "utils/hash.py",
                    "line": 3,
                    "col": 4,
                    "algorithm": "MD5",
                    "severity": "critical",
                }
            ],
        }
    },
}


@pytest.fixture
def sarif_client(monkeypatch):
    monkeypatch.setattr(user_module, "get_scans", lambda: FakeScans([SARIF_SCAN]))
    app = FastAPI()
    app.include_router(user_router)
    return TestClient(app), app


@pytest.fixture
def sarif_owner(sarif_client):
    test_client, app = sarif_client
    app.dependency_overrides[get_current_user] = lambda: {
        "_id": OWNER_ID,
        "email": "owner@qlint.dev",
    }
    yield test_client
    app.dependency_overrides.clear()


def test_sarif_returns_a_valid_log_for_an_owned_scan(sarif_owner):
    response = sarif_owner.get(f"/user/scans/{SCAN_ID}/sarif")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "2.1.0"
    assert body["$schema"].endswith("sarif-schema-2.1.0.json")

    run = body["runs"][0]
    assert run["tool"]["driver"]["name"] == "QLint"
    assert len(run["results"]) == 2
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert {result["ruleId"] for result in run["results"]} <= rule_ids

    # The stored path uses Windows separators; the SARIF URI must not.
    uris = [
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for result in run["results"]
    ]
    assert sorted(uris) == ["auth/login.py", "utils/hash.py"]


def test_sarif_sends_a_download_filename(sarif_owner):
    response = sarif_owner.get(f"/user/scans/{SCAN_ID}/sarif")
    disposition = response.headers["content-disposition"]
    assert "attachment" in disposition
    assert f"qlint-scan-{SCAN_ID}.sarif" in disposition
    assert response.headers["content-type"].startswith("application/json")


def test_sarif_requires_a_jwt(sarif_client):
    test_client, _ = sarif_client
    response = test_client.get(f"/user/scans/{SCAN_ID}/sarif")
    assert response.status_code == 401


def test_sarif_404s_on_another_users_scan(sarif_client):
    test_client, app = sarif_client
    app.dependency_overrides[get_current_user] = lambda: {
        "_id": OTHER_ID,
        "email": "stranger@qlint.dev",
    }
    response = test_client.get(f"/user/scans/{SCAN_ID}/sarif")
    app.dependency_overrides.clear()
    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"


def test_sarif_404s_on_an_unknown_or_malformed_scan_id(sarif_owner):
    for scan_id in ["652f1f77bcf86cd799439099", "not-an-object-id"]:
        response = sarif_owner.get(f"/user/scans/{scan_id}/sarif")
        assert response.status_code == 404


def test_sarif_of_a_scan_with_no_findings_is_still_a_valid_log(
    sarif_client, monkeypatch
):
    test_client, app = sarif_client
    empty = {**SARIF_SCAN, "result": {}}
    monkeypatch.setattr(user_module, "get_scans", lambda: FakeScans([empty]))
    app.dependency_overrides[get_current_user] = lambda: {
        "_id": OWNER_ID,
        "email": "owner@qlint.dev",
    }
    response = test_client.get(f"/user/scans/{SCAN_ID}/sarif")
    app.dependency_overrides.clear()
    assert response.status_code == 200
    run = response.json()["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"]  # the catalog ships regardless

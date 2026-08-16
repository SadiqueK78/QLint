"""The combined Level 1 website scan: POST /web-scan.

Phase 4. The three scans of Phases 1-3 run together against one target and
come back as one report, and almost everything worth testing here is about the
seams between them rather than about any one scan -- those have their own
files, and this one does not re-test them.

What is specific to this phase, in the order the tests come:

  * The merge. Every finding from all three domains in one list, each carrying
    the category it came from, and a readiness score computed over the lot by
    the same function that scores a repository scan.
  * Partial failure. One scan failing is a 200 carrying the other two plus a
    scan_errors entry, because two thirds of a report is still a report. All
    three failing is an error, because nothing is.
  * The rate limit, and above all what it does *not* touch. The endpoint calls
    the three scan functions directly rather than issuing HTTP requests to
    this router's own three endpoints, and the reason is exactly measurable:
    over HTTP, a combined scan would spend one of the caller's TLS scans, one
    header check and one JavaScript scan out of three separate allowances.
    Several tests below assert those three buckets stay at zero.
  * Storage. Website scans share the scans collection with repository scans,
    so the reads that mean "repositories" have to keep meaning that. The admin
    aggregate tests run a mixed collection through a pipeline evaluator rather
    than asserting on the pipeline's shape: a $match that is present but wrong
    passes a shape assertion.
  * The CBOM extension, including a golden document proving the repository
    path produces exactly what it produced before this phase touched the file.

Mocking follows the three prior files, at the same depth and for the same
reason -- the resolver is replaced at socket.getaddrinfo so ssrf_guard's real
parsing and address checking run on every target, and only the three outbound
seams are faked. Nothing here touches the network. The one thing that is new
is that all three seams are faked at once, because one request now uses all
three: tls_scanner._handshake, httpx.AsyncClient.get (the header scan) and
httpx.AsyncClient.stream (the JavaScript scan).
"""

import json
import socket
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from bson import ObjectId
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pymongo import DESCENDING

import cbom_converter
import tls_scanner
from auth import get_admin_user, get_current_user
from cbom_converter import convert_to_cbom, convert_website_to_cbom
from database import REPOSITORY_SCAN, SCAN_TYPE_REPOSITORY, SCAN_TYPE_WEBSITE
from routers import admin_router as admin_module
from routers import hndl_router as hndl_module
from routers import user_router as user_module
from routers import web_scan_router as web_scan_module
from routers.admin_router import router as admin_router
from routers.hndl_router import router as hndl_router
from routers.user_router import router as user_router
from routers.web_scan_router import (
    CATEGORY_CERTIFICATE,
    CATEGORY_HTTP_HEADER,
    CATEGORY_JAVASCRIPT,
    CATEGORY_TLS,
)
from routers.web_scan_router import router as web_scan_router

SCAN_USER = {"_id": "507f1f77bcf86cd799439011", "email": "owner@qlint.dev"}
SECOND_USER = {"_id": "507f1f77bcf86cd799439099", "email": "other@qlint.dev"}

TARGET = "https://example.com"
TARGET_HOST = "example.com"
PUBLIC_IP = "93.184.216.34"

CDN_HOST = "cdn.example.net"
CDN_IP = "151.101.1.44"

# A public name that resolves onto the private network. Used only to make all
# three scans fail the same way at once -- the guard's own behaviour is tested
# exhaustively in test_ssrf_guard.py and is not re-tested here.
INTERNAL_HOST = "internal.example.net"
INTERNAL_IP = "10.0.0.5"
INTERNAL_TARGET = f"https://{INTERNAL_HOST}"

# Detectable and distinct, so a merged finding can be traced to its domain.
INLINE_VULNERABLE = "const key = new NodeRSA({ b: 2048 });"      # -> RSA
EXTERNAL_VULNERABLE = "const ec = crypto.createECDH('secp256k1');"  # -> ECC
BENIGN = "window.addEventListener('load', function () { return 1; });"


# ---------------------------------------------------------------------------
# A real certificate, built once
# ---------------------------------------------------------------------------


def _certificate(key, days_valid=90):
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, TARGET_HOST),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QLint Test"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "QLint CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
        .public_bytes(Encoding.DER)
    )


_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_CERT_DER = _certificate(_RSA_KEY)


# ---------------------------------------------------------------------------
# The fake site: all three seams at once
# ---------------------------------------------------------------------------

# Every header the scan checks, set to something it accepts, so a well
# configured site contributes five Info findings and costs the score nothing.
# That is what makes the score arithmetic below legible: with the headers out
# of the way, every point deducted comes from a named piece of cryptography.
GOOD_HEADERS = {
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
}

DEFAULT_HTML = f"""<!doctype html>
<html><head>
  <script src="https://{CDN_HOST}/analytics.js"></script>
</head><body>
  <script>{INLINE_VULNERABLE}</script>
</body></html>"""


class _StreamContext:
    """client.stream() is an async context manager, so the fake is one."""

    def __init__(self, response=None, error=None):
        self._response = response
        self._error = error

    async def __aenter__(self):
        if self._error is not None:
            raise self._error
        return self._response

    async def __aexit__(self, *exc_info):
        return False


class _StreamResponse:
    def __init__(self, body: bytes, content_type: str, status_code: int = 200):
        self.status_code = status_code
        self.headers = httpx.Headers(
            {"content-type": content_type, "content-length": str(len(body))}
        )
        self._body = body

    async def aiter_bytes(self):
        yield self._body


class FakeSite:
    """DNS, the TLS handshake, the header GET and every script stream.

    One object rather than three, because a combined scan uses all three seams
    in one request and the tests need to fail exactly one of them at a time.
    Each `*_error` attribute fails precisely one domain and leaves the others
    working, which is what the partial-failure tests are about.
    """

    def __init__(
        self,
        html: str = DEFAULT_HTML,
        scripts: dict | None = None,
        headers: dict | None = None,
        addresses: dict | None = None,
        handshake_error: Exception | None = None,
        header_error: Exception | None = None,
        page_error: Exception | None = None,
        protocol: str = "TLSv1.3",
        cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        certificate_der: bytes = RSA_CERT_DER,
    ):
        self.html = html
        self.scripts = dict(
            scripts
            if scripts is not None
            else {f"https://{CDN_HOST}/analytics.js": EXTERNAL_VULNERABLE}
        )
        self.headers = dict(GOOD_HEADERS if headers is None else headers)
        self.addresses = dict(
            addresses
            or {
                TARGET_HOST: [PUBLIC_IP],
                CDN_HOST: [CDN_IP],
                INTERNAL_HOST: [INTERNAL_IP],
            }
        )
        self.handshake_error = handshake_error
        self.header_error = header_error
        self.page_error = page_error
        self.protocol = protocol
        self.cipher = cipher
        self.certificate_der = certificate_der

        self.resolutions: list[str] = []
        self.connections: list[tuple[str, str]] = []
        self.header_requests: list[str] = []
        self.streamed: list[str] = []

    def install(self, monkeypatch) -> "FakeSite":
        def _getaddrinfo(host, port, *args, **kwargs):
            self.resolutions.append(host)
            answers = []
            for address in self.addresses.get(host, [PUBLIC_IP]):
                answers.append(
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))
                )
            return answers

        def _handshake(ip_address, hostname, verify=True):
            self.connections.append((ip_address, hostname))
            if self.handshake_error is not None:
                raise self.handshake_error
            return {
                "protocol_raw": self.protocol,
                "cipher_name": self.cipher[0],
                "cipher_bits": self.cipher[2],
                "key_exchange_group": None,
                "certificate_der": self.certificate_der,
                "peer_ip": ip_address,
            }

        async def _get(client_self, url, **kwargs):
            host = dict(kwargs.get("headers") or {}).get("Host") or httpx.URL(url).host
            self.header_requests.append(host)
            if self.header_error is not None:
                raise self.header_error
            return httpx.Response(
                200,
                headers=self.headers,
                request=httpx.Request("GET", url),
            )

        def _stream(client_self, method, url, **kwargs):
            parsed = httpx.URL(url)
            host = dict(kwargs.get("headers") or {}).get("Host") or parsed.host
            logical = f"https://{host}{parsed.raw_path.decode()}"
            self.streamed.append(logical)
            if logical == f"{TARGET}/" or host == INTERNAL_HOST:
                if self.page_error is not None:
                    return _StreamContext(error=self.page_error)
                return _StreamContext(
                    _StreamResponse(
                        self.html.encode("utf-8"), "text/html; charset=utf-8"
                    )
                )
            source = self.scripts.get(logical)
            if source is None:
                return _StreamContext(
                    _StreamResponse(b"", "text/javascript", status_code=404)
                )
            return _StreamContext(
                _StreamResponse(source.encode("utf-8"), "text/javascript")
            )

        monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)
        monkeypatch.setattr(tls_scanner, "_handshake", _handshake)
        monkeypatch.setattr(httpx.AsyncClient, "get", _get)
        monkeypatch.setattr(httpx.AsyncClient, "stream", _stream)
        return self


# ---------------------------------------------------------------------------
# A fake scans collection, enough for the storage the endpoint does
# ---------------------------------------------------------------------------


class _InsertResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class _UpdateResult:
    def __init__(self, matched=1):
        self.matched_count = matched
        self.modified_count = matched


class RecordingScans:
    """Records what the endpoint stored, and hands back a real ObjectId."""

    def __init__(self):
        self.documents: list[dict] = []

    async def insert_one(self, document):
        stored = dict(document)
        stored["_id"] = ObjectId()
        self.documents.append(stored)
        return _InsertResult(stored["_id"])


class RecordingUsers:
    def __init__(self):
        self.updates: list[tuple] = []

    async def update_one(self, query, update):
        self.updates.append((query, update))
        return _UpdateResult()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_limiters():
    """All four buckets. Most tests here fill one deliberately."""
    limiters = (
        web_scan_module._combined_limiter,
        web_scan_module._js_limiter,
        web_scan_module._headers_limiter,
        web_scan_module._limiter,
    )
    for limiter in limiters:
        limiter.reset()
    yield
    for limiter in limiters:
        limiter.reset()


@pytest.fixture(autouse=True)
def storage(monkeypatch):
    """The scans collection, faked. Every combined scan writes one document."""
    scans = RecordingScans()
    users = RecordingUsers()
    monkeypatch.setattr(web_scan_module, "get_scans", lambda: scans)
    monkeypatch.setattr(web_scan_module, "get_users", lambda: users)
    return scans, users


@pytest.fixture
def site(monkeypatch):
    return FakeSite().install(monkeypatch)


@pytest.fixture
def app():
    application = FastAPI()
    application.include_router(web_scan_router)
    return application


@pytest.fixture
def client(app):
    app.dependency_overrides[get_current_user] = lambda: SCAN_USER
    yield TestClient(app)
    app.dependency_overrides.clear()


def scan(client, url=TARGET):
    return client.post("/web-scan", json={"url": url})


def by_category(body) -> dict[str, list]:
    grouped: dict[str, list] = {}
    for finding in body["findings"]:
        grouped.setdefault(finding["category"], []).append(finding)
    return grouped


# The score the default fake site earns, spelled out rather than asserted as
# "whatever came back". get_severity_score deducts 15 per critical finding and
# 7 per warning, over the CRYPTO_DB severity of every merged finding:
#
#   TLS 1.3 protocol            safe      -0
#   ECDHE key exchange (ECC)    critical  -15
#   AES-256 cipher suite        safe      -0
#   RSA-2048 public key         critical  -15
#   SHA256withRSA signature     warning   -7
#   five correct HTTP headers   safe      -0   (Info -> safe)
#   RSA in the inline script    critical  -15
#   ECC in the CDN script       critical  -15
#
# 100 - 15 - 15 - 7 - 15 - 15 = 33.
EXPECTED_SCORE = 33


# ---------------------------------------------------------------------------
# All three succeed
# ---------------------------------------------------------------------------


class TestAllThreeScansSucceed:
    def test_the_scan_returns_200(self, client, site):
        assert scan(client).status_code == 200

    def test_all_three_scans_actually_ran(self, client, site):
        scan(client)
        assert site.connections == [(PUBLIC_IP, TARGET_HOST)]
        assert site.header_requests == [TARGET_HOST]
        assert f"{TARGET}/" in site.streamed

    def test_scan_errors_is_present_and_empty(self, client, site):
        """Present rather than absent on the clean path: a missing key makes a
        clean scan and an old client indistinguishable exactly where it
        matters."""
        body = scan(client).json()
        assert "scan_errors" in body
        assert body["scan_errors"] == []

    def test_every_finding_carries_a_category(self, client, site):
        for finding in scan(client).json()["findings"]:
            assert finding["category"] in {
                CATEGORY_TLS,
                CATEGORY_CERTIFICATE,
                CATEGORY_HTTP_HEADER,
                CATEGORY_JAVASCRIPT,
            }

    def test_all_four_categories_are_represented(self, client, site):
        grouped = by_category(scan(client).json())
        assert set(grouped) == {
            CATEGORY_TLS,
            CATEGORY_CERTIFICATE,
            CATEGORY_HTTP_HEADER,
            CATEGORY_JAVASCRIPT,
        }

    def test_the_transport_findings_are_tagged_tls(self, client, site):
        grouped = by_category(scan(client).json())
        assert {finding["type"] for finding in grouped[CATEGORY_TLS]} == {
            "Protocol",
            "Key Exchange",
            "Cipher Suite",
        }

    def test_the_certificate_findings_are_tagged_certificate(self, client, site):
        """The TLS scan produces both, and they are two categories rather than
        one because they are two different things to fix: a cipher suite is a
        server configuration change, a certificate is a reissue."""
        grouped = by_category(scan(client).json())
        assert {finding["type"] for finding in grouped[CATEGORY_CERTIFICATE]} == {
            "Public Key",
            "Signature Algorithm",
        }

    def test_the_header_findings_are_tagged_http_header(self, client, site):
        grouped = by_category(scan(client).json())
        assert len(grouped[CATEGORY_HTTP_HEADER]) == 5
        assert {finding["asset"] for finding in grouped[CATEGORY_HTTP_HEADER]} == {
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
        }

    def test_the_javascript_findings_are_tagged_javascript(self, client, site):
        grouped = by_category(scan(client).json())
        assert {finding["algorithm"] for finding in grouped[CATEGORY_JAVASCRIPT]} == {
            "RSA",
            "ECC",
        }

    def test_a_javascript_finding_keeps_the_source_it_came_from(self, client, site):
        grouped = by_category(scan(client).json())
        assert {finding["file"] for finding in grouped[CATEGORY_JAVASCRIPT]} == {
            "inline script #1",
            f"https://{CDN_HOST}/analytics.js",
        }

    def test_the_merged_list_is_every_finding_from_all_three(self, client, site):
        body = scan(client).json()
        grouped = by_category(body)
        assert len(body["findings"]) == sum(len(rows) for rows in grouped.values())
        # 5 TLS/Certificate + 5 headers + 2 JavaScript.
        assert len(body["findings"]) == 12
        assert body["total_findings"] == 12

    def test_the_categories_are_added_not_substituted(self, client, site):
        """Every finding keeps the shape its own scanner produced. A renderer
        already written for one of the three endpoints must not need changing."""
        grouped = by_category(scan(client).json())
        for finding in grouped[CATEGORY_TLS]:
            assert set(finding) >= {"asset", "type", "status", "severity",
                                    "recommendation", "quantum_risk", "db_severity"}
        for finding in grouped[CATEGORY_HTTP_HEADER]:
            assert set(finding) >= {"asset", "type", "status", "severity",
                                    "recommendation", "observed_value", "present"}
        for finding in grouped[CATEGORY_JAVASCRIPT]:
            assert set(finding) >= {"file", "line", "language", "algorithm",
                                    "severity", "quantum_vulnerable"}

    def test_the_readiness_score_is_computed_over_every_domain(self, client, site):
        assert scan(client).json()["pqc_readiness_score"] == EXPECTED_SCORE

    def test_the_score_uses_the_shared_scoring_function(self, client, site):
        """Not a re-implementation: get_severity_score is what a repository
        scan and a TLS scan are scored by, so a site and a codebase land on one
        scale. Proved by feeding it the same severities by hand."""
        from vulnerability_db import get_severity_score

        assert EXPECTED_SCORE == get_severity_score(
            [{"severity": severity} for severity in
             ["safe", "critical", "safe", "critical", "warning",
              "safe", "safe", "safe", "safe", "safe",
              "critical", "critical"]]
        )

    def test_a_missing_security_header_costs_the_score_seven_points(
        self, monkeypatch, client
    ):
        """The one domain whose severities are not CRYPTO_DB's. A header
        finding has to be translated before it can be scored, and this is the
        translation being exercised end to end rather than asserted as a
        table."""
        headers = dict(GOOD_HEADERS)
        headers.pop("referrer-policy")
        FakeSite(headers=headers).install(monkeypatch)
        assert scan(client).json()["pqc_readiness_score"] == EXPECTED_SCORE - 7

    def test_a_correctly_configured_header_costs_the_score_nothing(
        self, client, site
    ):
        body = scan(client).json()
        header_findings = by_category(body)[CATEGORY_HTTP_HEADER]
        assert all(finding["severity"] == "Info" for finding in header_findings)
        assert body["pqc_readiness_score"] == EXPECTED_SCORE

    def test_the_score_never_goes_below_zero(self, monkeypatch, client):
        FakeSite(
            headers={},
            html="<script>%s</script>" % INLINE_VULNERABLE,
            protocol="TLSv1",
            cipher=("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLSv1", 112),
        ).install(monkeypatch)
        assert scan(client).json()["pqc_readiness_score"] == 0


class TestTheJavaScriptInventory:
    """`javascript_references` is inventory, not findings, and stays separate."""

    def test_the_reference_inventory_is_its_own_field(self, client, site):
        body = scan(client).json()
        sources = {reference["source"] for reference in body["javascript_references"]}
        assert sources == {"inline script #1", f"https://{CDN_HOST}/analytics.js"}

    def test_the_inventory_is_the_shape_the_javascript_endpoint_produces(
        self, client, site
    ):
        for reference in scan(client).json()["javascript_references"]:
            assert set(reference) == {
                "kind", "url", "raw_src", "type", "source",
                "scanned", "skip_reason", "size_bytes",
            }
            assert "_text" not in reference

    def test_references_are_not_merged_into_the_findings_list(self, client, site):
        """A page referencing eleven clean scripts has said something. Folding
        the inventory into findings would turn "nothing wrong" into "nothing
        there"."""
        body = scan(client).json()
        assert all("skip_reason" not in finding for finding in body["findings"])

    def test_a_page_with_no_findings_still_reports_its_references(
        self, monkeypatch, client
    ):
        FakeSite(
            html=f'<script src="https://{CDN_HOST}/vendor.js"></script>',
            scripts={f"https://{CDN_HOST}/vendor.js": BENIGN},
        ).install(monkeypatch)
        body = scan(client).json()
        assert by_category(body).get(CATEGORY_JAVASCRIPT) is None
        assert len(body["javascript_references"]) == 1
        assert body["javascript_references"][0]["scanned"] is True


class TestTheNonFindingDetail:
    """What each scan observed but did not judge, carried alongside."""

    def test_the_negotiated_transport_is_reported(self, client, site):
        body = scan(client).json()
        assert body["tls"]["protocol"] == "TLS 1.3"
        assert body["tls"]["cipher_suite"] == "TLS_AES_256_GCM_SHA384"

    def test_the_certificate_is_reported(self, client, site):
        body = scan(client).json()
        assert body["certificate"]["public_key_algorithm"] == "RSA"
        assert body["certificate"]["public_key_size_bits"] == 2048
        assert body["certificate_trusted"] is True

    def test_the_target_and_the_host_are_named(self, client, site):
        body = scan(client).json()
        assert body["url"] == TARGET
        assert body["host"] == TARGET_HOST
        assert body["scanned_at"]

    def test_the_summary_counts_by_category(self, client, site):
        summary = scan(client).json()["summary"]
        assert summary["total_findings"] == 12
        assert summary["by_category"] == {
            CATEGORY_TLS: 3,
            CATEGORY_CERTIFICATE: 2,
            CATEGORY_HTTP_HEADER: 5,
            CATEGORY_JAVASCRIPT: 2,
        }
        assert summary["scans_failed"] == []

    def test_the_algorithms_found_list_names_the_real_exposure(self, client, site):
        """Canonical CRYPTO_DB names, not the three domains' own spellings. The
        key exchange reports "ECDH" and the script reports "ECC" for the same
        primitive; the certificate signature reports "SHA256withRSA" where a
        code scan reports "SHA-256". Left raw, one asset would fill two pills
        in the history list."""
        assert scan(client).json()["algorithms_found"] == ["ECC", "RSA", "SHA-256"]

    def test_the_safe_assets_are_not_listed_as_exposure(self, client, site):
        found = scan(client).json()["algorithms_found"]
        assert "AES-256" not in found  # a 256-bit cipher is not an exposure
        assert "TLS 1.3" not in found


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


class TestTheThreeScansRunConcurrently:
    def test_the_endpoint_gathers_rather_than_awaiting_in_sequence(self):
        """Nothing any of the three does depends on another's result, and run
        one after another the response would take as long as all three added
        together. Asserted on the source because the alternative -- timing
        three mocked scans -- measures the mock."""
        import inspect

        source = inspect.getsource(web_scan_module.scan_website)
        assert "asyncio.gather(" in source
        assert "return_exceptions=True" in source

    @pytest.mark.asyncio
    async def test_the_three_scans_overlap_in_time(self, monkeypatch, storage):
        """The behavioural half: three scans each sleeping are not additive.

        The scan functions are replaced with ones that record when they were
        entered and left, so overlap is read off the intervals rather than off
        a total that a fast machine could pass either way.
        """
        import asyncio

        events: list[tuple[str, str]] = []

        def _slow(name, result):
            async def run(url):
                events.append(("enter", name))
                await asyncio.sleep(0.05)
                events.append(("exit", name))
                return result

            return run

        monkeypatch.setattr(
            web_scan_module, "scan_url", _slow("tls", {"host": TARGET_HOST, "findings": []})
        )
        monkeypatch.setattr(
            web_scan_module, "header_scan_url", _slow("headers", {"findings": []})
        )
        monkeypatch.setattr(
            web_scan_module, "js_scan_url", _slow("js", {"findings": [], "references": []})
        )

        await web_scan_module.scan_website(
            web_scan_module.WebScanRequest(url=TARGET), SCAN_USER
        )
        # All three entered before any of them left. Sequential execution
        # cannot produce this ordering.
        assert [name for kind, name in events if kind == "enter"] == [
            "tls",
            "headers",
            "js",
        ]
        assert events[3][0] == "exit"


# ---------------------------------------------------------------------------
# Partial failure
# ---------------------------------------------------------------------------


class TestOneScanFails:
    """A 200 with what worked, and a scan_errors entry for what did not."""

    @pytest.fixture
    def tls_broken(self, monkeypatch):
        return FakeSite(
            handshake_error=ConnectionRefusedError(111, "Connection refused")
        ).install(monkeypatch)

    def test_the_response_is_still_200(self, client, tls_broken):
        assert scan(client).status_code == 200

    def test_the_two_surviving_scans_are_reported_in_full(self, client, tls_broken):
        grouped = by_category(scan(client).json())
        assert len(grouped[CATEGORY_HTTP_HEADER]) == 5
        assert len(grouped[CATEGORY_JAVASCRIPT]) == 2

    def test_the_failed_domains_contribute_no_findings(self, client, tls_broken):
        grouped = by_category(scan(client).json())
        assert CATEGORY_TLS not in grouped
        assert CATEGORY_CERTIFICATE not in grouped

    def test_scan_errors_names_the_scan_that_failed(self, client, tls_broken):
        errors = scan(client).json()["scan_errors"]
        assert [error["scan"] for error in errors] == [CATEGORY_TLS]

    def test_scan_errors_carries_the_scanners_own_message(self, client, tls_broken):
        """Not a message composed here: the sentence tls_scanner writes for a
        refused connection, which is the same sentence /web-scan/tls would have
        returned for the same failure."""
        error = scan(client).json()["scan_errors"][0]
        assert error["error"] == f"{TARGET_HOST} refused the connection on port 443."

    def test_the_score_is_computed_over_what_survived(self, client, tls_broken):
        # The five correct headers cost nothing; the two JavaScript findings
        # are critical. 100 - 15 - 15 = 70.
        assert scan(client).json()["pqc_readiness_score"] == 70

    def test_the_summary_says_which_scans_ran_and_which_did_not(
        self, client, tls_broken
    ):
        summary = scan(client).json()["summary"]
        assert summary["scans_run"] == [CATEGORY_HTTP_HEADER, CATEGORY_JAVASCRIPT]
        assert summary["scans_failed"] == [CATEGORY_TLS]

    def test_the_tls_detail_block_is_absent_rather_than_null(
        self, client, tls_broken
    ):
        body = scan(client).json()
        assert "tls" not in body
        assert "certificate" not in body

    def test_a_failed_header_scan_leaves_the_other_two(self, monkeypatch, client):
        FakeSite(header_error=httpx.ConnectError("refused")).install(monkeypatch)
        body = scan(client).json()
        grouped = by_category(body)
        assert set(grouped) == {CATEGORY_TLS, CATEGORY_CERTIFICATE, CATEGORY_JAVASCRIPT}
        assert [error["scan"] for error in body["scan_errors"]] == [
            CATEGORY_HTTP_HEADER
        ]
        assert "Could not connect to example.com" in body["scan_errors"][0]["error"]

    def test_a_failed_javascript_scan_leaves_the_other_two(self, monkeypatch, client):
        FakeSite(page_error=httpx.ConnectError("refused")).install(monkeypatch)
        body = scan(client).json()
        grouped = by_category(body)
        assert set(grouped) == {
            CATEGORY_TLS,
            CATEGORY_CERTIFICATE,
            CATEGORY_HTTP_HEADER,
        }
        assert [error["scan"] for error in body["scan_errors"]] == [CATEGORY_JAVASCRIPT]

    def test_a_failed_javascript_scan_leaves_an_empty_inventory(
        self, monkeypatch, client
    ):
        FakeSite(page_error=httpx.ConnectError("refused")).install(monkeypatch)
        assert scan(client).json()["javascript_references"] == []

    def test_two_of_the_three_failing_is_still_a_200(self, monkeypatch, client):
        FakeSite(
            handshake_error=ConnectionRefusedError(111, "Connection refused"),
            page_error=httpx.ConnectError("refused"),
        ).install(monkeypatch)
        response = scan(client)
        assert response.status_code == 200
        body = response.json()
        assert [error["scan"] for error in body["scan_errors"]] == [
            CATEGORY_TLS,
            CATEGORY_JAVASCRIPT,
        ]
        assert set(by_category(body)) == {CATEGORY_HTTP_HEADER}
        assert body["pqc_readiness_score"] == 100


# ---------------------------------------------------------------------------
# Total failure
# ---------------------------------------------------------------------------


class TestEveryScanFails:
    """The one case with no report in it, so the one case that is an error."""

    def test_three_upstream_failures_are_a_502(self, monkeypatch, client):
        FakeSite(
            handshake_error=ConnectionRefusedError(111, "Connection refused"),
            header_error=httpx.ConnectError("refused"),
            page_error=httpx.ConnectError("refused"),
        ).install(monkeypatch)
        response = scan(client)
        assert response.status_code == 502

    def test_the_detail_names_every_scan_and_why_it_failed(self, monkeypatch, client):
        FakeSite(
            handshake_error=ConnectionRefusedError(111, "Connection refused"),
            header_error=httpx.ConnectError("refused"),
            page_error=httpx.ConnectError("refused"),
        ).install(monkeypatch)
        detail = scan(client).json()["detail"]
        assert f"{CATEGORY_TLS}:" in detail
        assert f"{CATEGORY_HTTP_HEADER}:" in detail
        assert f"{CATEGORY_JAVASCRIPT}:" in detail
        assert "refused the connection on port 443" in detail

    def test_a_blocked_target_is_a_400_stated_once(self, client, site):
        """All three refuse the same URL for the same reason, so repeating the
        sentence three times would be noise rather than information."""
        response = scan(client, INTERNAL_TARGET)
        assert response.status_code == 400
        detail = response.json()["detail"]
        assert detail.count("10.0.0.5") == 1

    def test_a_blocked_target_never_opens_a_connection(self, client, site):
        scan(client, INTERNAL_TARGET)
        assert site.connections == []
        assert site.header_requests == []
        assert site.streamed == []

    def test_a_malformed_url_is_a_400(self, client, site):
        assert scan(client, "http://example.com").status_code == 400
        assert scan(client, "not-a-url").status_code == 400

    def test_nothing_is_stored_when_every_scan_failed(self, monkeypatch, client, storage):
        FakeSite(
            handshake_error=ConnectionRefusedError(111, "Connection refused"),
            header_error=httpx.ConnectError("refused"),
            page_error=httpx.ConnectError("refused"),
        ).install(monkeypatch)
        scan(client)
        scans, _ = storage
        assert scans.documents == []

    def test_an_unexpected_internal_failure_is_a_500_not_a_502(
        self, monkeypatch, client, site
    ):
        """A fault in this server must not be filed as somebody else's outage.

        The message is the generic one and carries nothing internal, which is
        the never-raises-unhandled guarantee the router already makes for its
        three single-purpose endpoints.
        """
        async def _boom(url):
            raise RuntimeError("secret internal detail /srv/qlint")

        monkeypatch.setattr(web_scan_module, "scan_url", _boom)
        monkeypatch.setattr(web_scan_module, "header_scan_url", _boom)
        monkeypatch.setattr(web_scan_module, "js_scan_url", _boom)
        response = scan(client)
        assert response.status_code == 500
        assert "secret internal detail" not in response.json()["detail"]
        assert "/srv/qlint" not in response.json()["detail"]


# ---------------------------------------------------------------------------
# The rate limit, and the three buckets it must not touch
# ---------------------------------------------------------------------------


class TestTheRateLimit:
    def test_the_window_is_five_scans_per_twenty_four_hours(self):
        assert web_scan_module._combined_limiter.max_requests == 5
        assert web_scan_module._combined_limiter.window_seconds == 86400

    def test_the_window_closes_after_five_scans(self, client, site):
        for _ in range(5):
            assert scan(client).status_code == 200
        blocked = scan(client)
        assert blocked.status_code == 429
        detail = blocked.json()["detail"]
        # format_duration's output, not raw seconds: the window is a day and
        # "5 requests per 86400 seconds" is not a sentence anybody reads.
        assert detail.startswith("Rate limit exceeded: 5 requests per 1 day.")
        assert "86400" not in detail
        assert "1440 minutes" not in detail

    def test_the_429_carries_a_retry_after_header_in_seconds(self, client, site):
        for _ in range(5):
            scan(client)
        blocked = scan(client)
        assert int(blocked.headers["Retry-After"]) > 0

    def test_the_window_is_keyed_on_the_account_id(self, client, site):
        scan(client)
        assert list(web_scan_module._combined_limiter._hits) == [
            f"user:{SCAN_USER['_id']}"
        ]

    def test_two_accounts_each_get_their_own_allowance(self, app, site):
        app.dependency_overrides[get_current_user] = lambda: SCAN_USER
        try:
            for _ in range(5):
                assert TestClient(app).post(
                    "/web-scan", json={"url": TARGET}
                ).status_code == 200
            assert TestClient(app).post(
                "/web-scan", json={"url": TARGET}
            ).status_code == 429

            app.dependency_overrides[get_current_user] = lambda: SECOND_USER
            assert TestClient(app).post(
                "/web-scan", json={"url": TARGET}
            ).status_code == 200
        finally:
            app.dependency_overrides.clear()

    def test_the_route_is_limited_per_user_not_per_address(self):
        """Render's proxy collapses every visitor onto one internal address, so
        an address-keyed limit here would be a limit on the whole site."""
        import inspect

        source = inspect.getsource(web_scan_module)
        assert "rate_limit_by_user(_combined_limiter)" in source
        assert "rate_limit(_combined_limiter)" not in source


class TestTheCombinedScanSpendsNoOtherBucket:
    """The architectural requirement, measured rather than asserted.

    If this endpoint reached its three siblings over HTTP, each combined scan
    would run their rate-limit dependencies too -- so five combined scans, the
    whole daily allowance, would also have silently spent five TLS scans, five
    header checks and five JavaScript scans out of allowances the caller never
    knowingly used. Calling the scan functions directly is what makes the three
    buckets below stay empty.
    """

    def test_the_four_limiters_are_four_distinct_objects(self):
        limiters = (
            web_scan_module._combined_limiter,
            web_scan_module._js_limiter,
            web_scan_module._headers_limiter,
            web_scan_module._limiter,
        )
        assert len({id(limiter) for limiter in limiters}) == 4
        assert web_scan_module._combined_limiter.max_requests == 5
        assert web_scan_module._js_limiter.max_requests == 15
        assert web_scan_module._headers_limiter.max_requests == 20
        assert web_scan_module._limiter.max_requests == 10

    def test_one_combined_scan_leaves_all_three_buckets_at_zero(self, client, site):
        assert scan(client).status_code == 200
        assert web_scan_module._limiter._hits == {}
        assert web_scan_module._headers_limiter._hits == {}
        assert web_scan_module._js_limiter._hits == {}

    def test_the_whole_combined_allowance_leaves_all_three_at_zero(
        self, client, site
    ):
        for _ in range(5):
            assert scan(client).status_code == 200
        assert scan(client).status_code == 429

        assert web_scan_module._limiter._hits == {}
        assert web_scan_module._headers_limiter._hits == {}
        assert web_scan_module._js_limiter._hits == {}

    def test_the_three_endpoints_still_have_their_full_allowance_afterwards(
        self, client, site
    ):
        """The other half of the claim: not merely that the counters read zero,
        but that the endpoints they belong to still admit a full window."""
        for _ in range(5):
            assert scan(client).status_code == 200

        for _ in range(10):
            assert client.post(
                "/web-scan/tls", json={"url": TARGET}
            ).status_code == 200
        assert client.post("/web-scan/tls", json={"url": TARGET}).status_code == 429

        for _ in range(20):
            assert client.post(
                "/web-scan/headers", json={"url": TARGET}
            ).status_code == 200
        assert client.post("/web-scan/headers", json={"url": TARGET}).status_code == 429

        for _ in range(15):
            assert client.post(
                "/web-scan/javascript", json={"url": TARGET}
            ).status_code == 200
        assert (
            client.post("/web-scan/javascript", json={"url": TARGET}).status_code == 429
        )

    def test_exhausting_the_combined_bucket_does_not_block_the_three(
        self, client, site
    ):
        for _ in range(5):
            scan(client)
        assert scan(client).status_code == 429
        assert client.post("/web-scan/tls", json={"url": TARGET}).status_code == 200
        assert client.post("/web-scan/headers", json={"url": TARGET}).status_code == 200
        assert (
            client.post("/web-scan/javascript", json={"url": TARGET}).status_code == 200
        )

    def test_exhausting_all_three_does_not_block_the_combined_scan(
        self, client, site
    ):
        """And the converse. The combined endpoint has its own allowance, so a
        caller who has used up their individual scans can still run one."""
        for _ in range(10):
            client.post("/web-scan/tls", json={"url": TARGET})
        for _ in range(20):
            client.post("/web-scan/headers", json={"url": TARGET})
        for _ in range(15):
            client.post("/web-scan/javascript", json={"url": TARGET})

        assert client.post("/web-scan/tls", json={"url": TARGET}).status_code == 429
        assert web_scan_module._combined_limiter._hits == {}
        assert scan(client).status_code == 200

    def test_the_router_has_no_http_client_to_call_itself_with(self):
        """The structural guarantee behind all of the above: this module
        imports no HTTP client and no test client, so there is nothing in it
        that could issue a request to its own routes even by accident."""
        import inspect

        source = inspect.getsource(web_scan_module)
        assert "import httpx" not in source
        assert "AsyncClient" not in source
        assert "TestClient" not in source

    def test_a_partial_failure_spends_no_other_bucket_either(
        self, monkeypatch, client
    ):
        FakeSite(
            handshake_error=ConnectionRefusedError(111, "Connection refused")
        ).install(monkeypatch)
        assert scan(client).status_code == 200
        assert web_scan_module._limiter._hits == {}
        assert web_scan_module._headers_limiter._hits == {}
        assert web_scan_module._js_limiter._hits == {}

    def test_the_combined_bucket_is_not_shared_with_the_ai_endpoints(self):
        from routers import explain_router, patch_router

        assert web_scan_module._combined_limiter is not explain_router._limiter
        assert web_scan_module._combined_limiter is not patch_router._limiter


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class TestTheRouteRequiresASession:
    def test_a_request_with_no_token_is_401_and_does_nothing(self, app, site):
        response = TestClient(app).post("/web-scan", json={"url": TARGET})
        assert response.status_code == 401
        assert response.json()["detail"] == "Not authenticated"
        assert site.resolutions == []
        assert site.connections == []
        assert site.header_requests == []
        assert site.streamed == []

    def test_a_request_with_a_junk_token_is_401(self, app, site):
        response = TestClient(app).post(
            "/web-scan",
            json={"url": TARGET},
            headers={"Authorization": "Bearer not-a-real-jwt"},
        )
        assert response.status_code == 401
        assert site.connections == []

    def test_an_unauthenticated_request_does_not_spend_the_rate_limit(self, app, site):
        """rate_limit_by_user resolves the session before it touches the
        window, so unauthenticated noise cannot exhaust a real account's five
        scans a day."""
        unauthenticated = TestClient(app)
        for _ in range(10):
            assert unauthenticated.post(
                "/web-scan", json={"url": TARGET}
            ).status_code == 401
        assert web_scan_module._combined_limiter._hits == {}

    def test_an_unauthenticated_request_stores_nothing(self, app, site, storage):
        TestClient(app).post("/web-scan", json={"url": TARGET})
        scans, _ = storage
        assert scans.documents == []


# ---------------------------------------------------------------------------
# The router
# ---------------------------------------------------------------------------


class TestTheRouterIsRegistered:
    def test_this_file_owns_the_complete_set_of_web_scan_routes(self):
        """The newest phase's test file asserts the whole set, so that adding
        an endpoint means editing the newest file rather than every older one.
        The three earlier files each assert only their own path and hand this
        assertion forward.
        """
        paths = {
            route.path for route in web_scan_router.routes if hasattr(route, "path")
        }
        assert paths == {
            "/web-scan",
            "/web-scan/tls",
            "/web-scan/headers",
            "/web-scan/javascript",
        }

    def test_the_endpoint_only_answers_post(self):
        methods = {
            route.path: route.methods
            for route in web_scan_router.routes
            if hasattr(route, "path")
        }
        assert methods["/web-scan"] == {"POST"}

    def test_the_request_body_is_the_same_shape_as_the_other_three(self, client, site):
        assert client.post("/web-scan", json={}).status_code == 422
        assert client.post("/web-scan", json={"url": None}).status_code == 422


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


class TestTheScanIsStored:
    def test_one_document_is_written_per_scan(self, client, site, storage):
        scan(client)
        scans, _ = storage
        assert len(scans.documents) == 1

    def test_the_document_is_marked_as_a_website_scan(self, client, site, storage):
        scan(client)
        scans, _ = storage
        assert scans.documents[0]["scan_type"] == SCAN_TYPE_WEBSITE

    def test_the_target_is_stored_in_target_url_not_repo_url(
        self, client, site, storage
    ):
        """A field named repo_url holding https://example.com is worse than no
        field at all: nothing downstream could tell it from a repository."""
        scan(client)
        document = storage[0].documents[0]
        assert document["target_url"] == TARGET
        assert "repo_url" not in document

    def test_the_document_is_owned_by_the_caller(self, client, site, storage):
        scan(client)
        document = storage[0].documents[0]
        assert document["user_id"] == str(SCAN_USER["_id"])
        assert document["scanned_by"] == SCAN_USER["email"]
        assert isinstance(document["created_at"], datetime)

    def test_the_stored_result_is_the_report_that_was_returned(
        self, client, site, storage
    ):
        body = scan(client).json()
        stored = storage[0].documents[0]["result"]
        assert stored["findings"] == body["findings"]
        assert stored["pqc_readiness_score"] == body["pqc_readiness_score"]
        assert stored["scan_errors"] == body["scan_errors"]

    def test_the_document_carries_no_expiry(self, client, site, storage):
        """expires_at means "a repeat scan may be served from this document",
        and nothing serves a website scan from cache -- a live site is exactly
        the thing whose answer should not be a day old. Setting it would only
        inflate the admin dashboard's cached_scans count."""
        scan(client)
        assert "expires_at" not in storage[0].documents[0]

    def test_the_response_carries_the_id_the_export_is_addressed_by(
        self, client, site, storage
    ):
        body = scan(client).json()
        assert body["scan_id"] == str(storage[0].documents[0]["_id"])

    def test_the_account_scan_count_is_incremented(self, client, site, storage):
        scan(client)
        _, users = storage
        assert users.updates == [
            ({"_id": SCAN_USER["_id"]}, {"$inc": {"scan_count": 1}})
        ]

    def test_a_failed_write_costs_the_id_not_the_report(
        self, monkeypatch, client, site
    ):
        from pymongo.errors import PyMongoError

        class Broken:
            async def insert_one(self, document):
                raise PyMongoError("mongo is down")

        monkeypatch.setattr(web_scan_module, "get_scans", lambda: Broken())
        response = scan(client)
        assert response.status_code == 200
        assert "scan_id" not in response.json()
        assert response.json()["pqc_readiness_score"] == EXPECTED_SCORE

    def test_a_partial_scan_is_stored_with_its_errors(self, monkeypatch, client, storage):
        FakeSite(
            handshake_error=ConnectionRefusedError(111, "Connection refused")
        ).install(monkeypatch)
        scan(client)
        stored = storage[0].documents[0]["result"]
        assert [error["scan"] for error in stored["scan_errors"]] == [CATEGORY_TLS]


# ---------------------------------------------------------------------------
# A minimal MongoDB aggregation evaluator
# ---------------------------------------------------------------------------
#
# The admin dashboard's numbers come out of aggregation pipelines, and the
# question this phase has to answer about them is behavioural: with a mix of
# repository and website documents in one collection, does each pipeline still
# produce the right answer? Asserting on the shape of the pipeline cannot
# answer it -- a $match that is present but matches the wrong thing passes a
# shape assertion and fails in production.
#
# So the fake below runs the pipelines. It supports exactly the stages
# /admin/stats uses and refuses anything else, and $objectToArray raises on a
# non-document input the way MongoDB does, which is what makes "a website scan
# reaching that stage" a test failure rather than an empty row.


class _PipelineUnsupported(Exception):
    pass


def _resolve(document, path: str):
    current = document
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _assign(document: dict, path: str, value) -> dict:
    parts = path.split(".")
    updated = dict(document)
    target = updated
    for part in parts[:-1]:
        child = dict(target.get(part) or {})
        target[part] = child
        target = child
    target[parts[-1]] = value
    return updated


def _condition_holds(value, condition) -> bool:
    if not isinstance(condition, dict):
        return value == condition
    for operator, operand in condition.items():
        if operator == "$ne":
            if value == operand:
                return False
        elif operator == "$eq":
            if value != operand:
                return False
        elif operator == "$gt":
            if value is None or not value > operand:
                return False
        elif operator == "$gte":
            if value is None or not value >= operand:
                return False
        else:
            raise _PipelineUnsupported(operator)
    return True


def _expression(document, expression):
    if isinstance(expression, str) and expression.startswith("$"):
        return _resolve(document, expression[1:])
    if isinstance(expression, dict):
        if set(expression) == {"$objectToArray"}:
            value = _expression(document, expression["$objectToArray"])
            if value is None or not isinstance(value, dict):
                # What the server does: "$objectToArray requires a document
                # input". A pipeline that reaches this on a website scan is a
                # bug, and this is the line that says so.
                raise _PipelineUnsupported(
                    "$objectToArray on a non-document input"
                )
            return [{"k": key, "v": item} for key, item in value.items()]
        raise _PipelineUnsupported(str(expression))
    return expression


def run_pipeline(documents: list[dict], pipeline: list[dict]) -> list[dict]:
    rows = [dict(document) for document in documents]
    for stage in pipeline:
        (name, spec), = stage.items()
        if name == "$match":
            rows = [
                row
                for row in rows
                if all(
                    _condition_holds(_resolve(row, key), condition)
                    for key, condition in spec.items()
                )
            ]
        elif name == "$project":
            rows = [
                {
                    "_id": row.get("_id"),
                    **{
                        field: _expression(row, value)
                        for field, value in spec.items()
                    },
                }
                for row in rows
            ]
        elif name == "$unwind":
            path = spec[1:] if isinstance(spec, str) else spec["path"][1:]
            unwound = []
            for row in rows:
                values = _resolve(row, path)
                if not isinstance(values, list):
                    continue  # $unwind drops a missing or null path
                for value in values:
                    unwound.append(_assign(row, path, value))
            rows = unwound
        elif name == "$group":
            buckets: dict = {}
            order: list = []
            for row in rows:
                key = _expression(row, spec["_id"])
                marker = json.dumps(key, default=str)
                if marker not in buckets:
                    buckets[marker] = {"_id": key, "_rows": []}
                    order.append(marker)
                buckets[marker]["_rows"].append(row)
            grouped = []
            for marker in order:
                bucket = buckets[marker]
                output = {"_id": bucket["_id"]}
                for field, accumulator in spec.items():
                    if field == "_id":
                        continue
                    (operator, operand), = accumulator.items()
                    if operator == "$sum":
                        if isinstance(operand, (int, float)):
                            output[field] = operand * len(bucket["_rows"])
                        else:
                            output[field] = sum(
                                value
                                for value in (
                                    _expression(row, operand)
                                    for row in bucket["_rows"]
                                )
                                if isinstance(value, (int, float))
                            )
                    elif operator == "$addToSet":
                        seen = []
                        for row in bucket["_rows"]:
                            value = _expression(row, operand)
                            if value not in seen:
                                seen.append(value)
                        output[field] = seen
                    else:
                        raise _PipelineUnsupported(operator)
                grouped.append(output)
            rows = grouped
        elif name == "$sort":
            for field, direction in reversed(list(spec.items())):
                rows.sort(
                    key=lambda row, field=field: (
                        row.get(field) is None,
                        row.get(field),
                    ),
                    reverse=direction == DESCENDING,
                )
        elif name == "$limit":
            rows = rows[:spec]
        else:
            raise _PipelineUnsupported(name)
    return rows


class _AggregateCursor:
    def __init__(self, rows):
        self.rows = rows

    async def to_list(self, length=None):
        return self.rows[:length]


class _FindCursor:
    def __init__(self, documents):
        self.documents = documents

    def sort(self, *args, **kwargs):
        return self

    def skip(self, count):
        return _FindCursor(self.documents[count:])

    def limit(self, count):
        return _FindCursor(self.documents[:count])

    async def to_list(self, length=None):
        return self.documents[:length]


class MixedScans:
    """A scans collection holding both kinds of document."""

    def __init__(self, documents):
        self.documents = documents
        self.pipelines: list[list[dict]] = []

    async def count_documents(self, query):
        return sum(
            1
            for document in self.documents
            if all(
                _condition_holds(_resolve(document, key), condition)
                for key, condition in query.items()
            )
        )

    def aggregate(self, pipeline):
        self.pipelines.append(pipeline)
        return _AggregateCursor(run_pipeline(self.documents, pipeline))

    def find(self, query, projection=None):
        return _FindCursor(
            [
                document
                for document in self.documents
                if all(
                    _condition_holds(_resolve(document, key), condition)
                    for key, condition in query.items()
                )
            ]
        )

    async def find_one(self, query, **kwargs):
        for document in self.documents:
            if all(
                _condition_holds(_resolve(document, key), condition)
                for key, condition in query.items()
            ):
                return document
        return None


class FakeUsers:
    def __init__(self, documents):
        self.documents = documents

    async def count_documents(self, query):
        return len(self.documents)

    def find(self, query, projection=None):
        return _FindCursor(self.documents)


REPO_SCAN_IDS = ["652f1f77bcf86cd7994390a1", "652f1f77bcf86cd7994390a2"]
WEBSITE_SCAN_ID = "652f1f77bcf86cd7994390b1"
LEGACY_SCAN_ID = "652f1f77bcf86cd7994390c1"

NOW = datetime.now(timezone.utc)


def _repo_document(scan_id: str, repo: str, legacy: bool = False) -> dict:
    """A stored repository scan. `legacy` omits scan_type entirely.

    That second shape is the one that matters most here: every document written
    before this phase has no scan_type field, and a filter spelled
    {"scan_type": "repository"} would silently drop all of them from the admin
    aggregates. This is the document that catches it.
    """
    document = {
        "_id": ObjectId(scan_id),
        "repo_url": repo,
        "user_id": str(SCAN_USER["_id"]),
        "scanned_by": SCAN_USER["email"],
        "created_at": NOW,
        "expires_at": NOW + timedelta(hours=24),
        "result": {
            "repo": repo.rsplit("/", 2)[-2] + "/" + repo.rsplit("/", 1)[-1],
            "pqc_readiness_score": 40,
            "total_findings": 2,
            "scanned_files": 9,
            "algorithms_found": ["RSA"],
            "severity_summary": {"critical": 2, "warning": 1, "safe": 0, "info": 0},
            "findings_by_file": {
                "auth.py": [
                    {"file": "auth.py", "line": 3, "algorithm": "RSA",
                     "severity": "critical", "quantum_vulnerable": True},
                    {"file": "auth.py", "line": 8, "algorithm": "SHA-256",
                     "severity": "warning"},
                ]
            },
        },
    }
    if not legacy:
        document["scan_type"] = SCAN_TYPE_REPOSITORY
    return document


WEBSITE_RESULT = {
    "url": TARGET,
    "host": TARGET_HOST,
    "scanned_at": "2026-08-16T10:00:00+00:00",
    "pqc_readiness_score": EXPECTED_SCORE,
    "total_findings": 3,
    "algorithms_found": ["ECC", "RSA"],
    "scan_errors": [],
    "javascript_references": [],
    "findings": [
        {"asset": "TLS 1.3", "type": "Protocol", "purpose": "TLS Connection",
         "algorithm": "TLS 1.3", "severity": "Low", "db_severity": "safe",
         "quantum_vulnerable": False, "category": CATEGORY_TLS},
        {"asset": "ECDHE", "type": "Key Exchange", "purpose": "TLS Connection",
         "algorithm": "ECDH", "severity": "Medium", "db_severity": "critical",
         "quantum_vulnerable": True, "category": CATEGORY_TLS},
        {"asset": "RSA-2048", "type": "Public Key", "purpose": "TLS Certificate",
         "algorithm": "RSA", "severity": "Medium", "db_severity": "critical",
         "quantum_vulnerable": True, "category": CATEGORY_CERTIFICATE},
        {"asset": "Referrer-Policy", "type": "HTTP Security Header",
         "purpose": "HTTP Response", "severity": "Low",
         "category": CATEGORY_HTTP_HEADER},
        {"file": f"https://{CDN_HOST}/analytics.js", "line": 1, "algorithm": "ECC",
         "language": "javascript", "severity": "critical",
         "quantum_vulnerable": True, "category": CATEGORY_JAVASCRIPT},
        {"file": "inline script #1", "line": 1, "algorithm": "RSA",
         "language": "javascript", "severity": "critical",
         "quantum_vulnerable": True, "category": CATEGORY_JAVASCRIPT},
    ],
}


def _website_document() -> dict:
    return {
        "_id": ObjectId(WEBSITE_SCAN_ID),
        "scan_type": SCAN_TYPE_WEBSITE,
        "target_url": TARGET,
        "user_id": str(SCAN_USER["_id"]),
        "scanned_by": SCAN_USER["email"],
        "created_at": NOW,
        "result": dict(WEBSITE_RESULT),
    }


@pytest.fixture
def mixed_collection():
    """Two repository scans, one of them written before scan_type existed, and
    one website scan. The mix the aggregates now have to survive."""
    return MixedScans(
        [
            _repo_document(REPO_SCAN_IDS[0], "https://github.com/acme/alpha"),
            _repo_document(REPO_SCAN_IDS[1], "https://github.com/acme/alpha"),
            _repo_document(
                LEGACY_SCAN_ID, "https://github.com/acme/legacy", legacy=True
            ),
            _website_document(),
        ]
    )


@pytest.fixture
def admin_client(monkeypatch, mixed_collection):
    users = FakeUsers(
        [{"_id": ObjectId(), "email": SCAN_USER["email"], "scan_count": 4}]
    )
    for module in (admin_module, user_module, hndl_module):
        monkeypatch.setattr(module, "get_scans", lambda: mixed_collection)
    monkeypatch.setattr(admin_module, "get_users", lambda: users)

    application = FastAPI()
    application.include_router(admin_router)
    application.include_router(user_router)
    application.include_router(hndl_router)
    application.dependency_overrides[get_admin_user] = lambda: {
        "_id": "652f1f77bcf86cd7994390ff",
        "email": "admin@qlint.dev",
        "role": "admin",
    }
    application.dependency_overrides[get_current_user] = lambda: SCAN_USER
    yield TestClient(application)
    application.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# The admin aggregates over a mixed collection
# ---------------------------------------------------------------------------


class TestTheEvaluatorItself:
    """The fake has to be trustworthy before the tests using it are.

    Two properties in particular: it runs $match against dotted paths, and it
    refuses $objectToArray on a document that has no such field -- which is
    the behaviour that turns "the pipeline reaches a website scan" into a test
    failure instead of an empty result nobody notices.
    """

    def test_object_to_array_refuses_a_missing_field(self):
        with pytest.raises(_PipelineUnsupported):
            run_pipeline(
                [{"result": {}}],
                [{"$project": {"files": {"$objectToArray": "$result.no_such_key"}}}],
            )

    def test_ne_matches_documents_where_the_field_is_absent(self):
        """MongoDB semantics, and the whole reason REPOSITORY_SCAN is spelled
        with $ne: a document from before scan_type existed must still count."""
        rows = run_pipeline(
            [{"n": 1}, {"n": 2, "scan_type": "website"},
             {"n": 3, "scan_type": "repository"}],
            [{"$match": dict(REPOSITORY_SCAN)}],
        )
        assert [row["n"] for row in rows] == [1, 3]

    def test_group_sum_and_sort_agree_with_the_server(self):
        rows = run_pipeline(
            [{"k": "a"}, {"k": "b"}, {"k": "a"}],
            [
                {"$group": {"_id": "$k", "n": {"$sum": 1}}},
                {"$sort": {"n": DESCENDING, "_id": 1}},
            ],
        )
        assert rows == [{"_id": "a", "n": 2}, {"_id": "b", "n": 1}]


class TestAdminStatsWithAMixedCollection:
    def test_the_endpoint_answers_at_all(self, admin_client):
        """The blunt one, and not a trivial one: an unfiltered $objectToArray
        over a website scan is a server error, so this failing is the shape a
        missed $match takes."""
        assert admin_client.get("/admin/stats").status_code == 200

    def test_most_scanned_repos_contains_no_website(self, admin_client):
        body = admin_client.get("/admin/stats").json()
        urls = [row["repo_url"] for row in body["most_scanned_repos"]]
        assert TARGET not in urls
        assert "" not in urls
        assert all(url.startswith("https://github.com/") for url in urls)

    def test_most_scanned_repos_counts_repositories_correctly(self, admin_client):
        body = admin_client.get("/admin/stats").json()
        assert body["most_scanned_repos"] == [
            {"repo_url": "https://github.com/acme/alpha", "scan_count": 2},
            {"repo_url": "https://github.com/acme/legacy", "scan_count": 1},
        ]

    def test_a_scan_stored_before_scan_type_existed_is_still_counted(
        self, admin_client
    ):
        """The regression this phase could most easily have introduced: a
        filter of {"scan_type": "repository"} would have dropped every
        document written before this field, silently shrinking the operator's
        history."""
        body = admin_client.get("/admin/stats").json()
        urls = [row["repo_url"] for row in body["most_scanned_repos"]]
        assert "https://github.com/acme/legacy" in urls

    def test_the_algorithm_aggregate_is_unchanged_by_the_website_scan(
        self, admin_client
    ):
        body = admin_client.get("/admin/stats").json()
        assert body["algorithms_most_found"] == [
            {"algorithm": "RSA", "count": 3, "severity": "critical"},
            {"algorithm": "SHA-256", "count": 3, "severity": "warning"},
        ]

    def test_the_website_scans_javascript_findings_do_not_leak_in(self, admin_client):
        """The website report has ECC findings; the repository scans do not.
        An unfiltered pipeline that somehow read them would show ECC here."""
        body = admin_client.get("/admin/stats").json()
        assert "ECC" not in [row["algorithm"] for row in body["algorithms_most_found"]]

    def test_the_severity_totals_count_repository_scans_only(self, admin_client):
        body = admin_client.get("/admin/stats").json()
        assert body["severity_totals"] == {
            "critical": 6,
            "warning": 3,
            "safe": 0,
            "info": 0,
        }

    def test_the_repository_only_aggregates_all_filter_on_scan_type(
        self, admin_client, mixed_collection
    ):
        """Three pipelines, three $match stages, and each one is the first
        stage -- a filter after $objectToArray would already have failed."""
        admin_client.get("/admin/stats")
        assert len(mixed_collection.pipelines) == 3
        for pipeline in mixed_collection.pipelines:
            assert pipeline[0] == {"$match": dict(REPOSITORY_SCAN)}

    def test_the_total_counts_include_both_kinds(self, admin_client):
        """Not everything is filtered, and that is the point of filtering only
        what needs it: "how much has this service run" means both kinds."""
        body = admin_client.get("/admin/stats").json()
        assert body["total_scans"] == 4
        assert body["scans_today"] == 4
        assert body["scans_this_week"] == 4

    def test_cached_scans_counts_only_what_can_be_served_from_cache(
        self, admin_client
    ):
        """A website scan is stored without expires_at, so it can never match
        this count -- no filter needed, and none added."""
        assert admin_client.get("/admin/stats").json()["cached_scans"] == 3


class TestAdminScanListWithAMixedCollection:
    def test_every_scan_is_listed_whatever_its_kind(self, admin_client):
        body = admin_client.get("/admin/scans").json()
        assert body["total"] == 4
        assert len(body["scans"]) == 4

    def test_each_row_says_which_kind_it_is(self, admin_client):
        rows = {row["id"]: row for row in admin_client.get("/admin/scans").json()["scans"]}
        assert rows[WEBSITE_SCAN_ID]["scan_type"] == SCAN_TYPE_WEBSITE
        assert rows[REPO_SCAN_IDS[0]]["scan_type"] == SCAN_TYPE_REPOSITORY

    def test_a_legacy_document_reads_as_a_repository_scan(self, admin_client):
        rows = {row["id"]: row for row in admin_client.get("/admin/scans").json()["scans"]}
        assert rows[LEGACY_SCAN_ID]["scan_type"] == SCAN_TYPE_REPOSITORY

    def test_a_website_row_carries_its_target_and_an_empty_repo_url(
        self, admin_client
    ):
        rows = {row["id"]: row for row in admin_client.get("/admin/scans").json()["scans"]}
        assert rows[WEBSITE_SCAN_ID]["target_url"] == TARGET
        assert rows[WEBSITE_SCAN_ID]["repo_url"] == ""

    def test_a_repository_row_is_unchanged(self, admin_client):
        rows = {row["id"]: row for row in admin_client.get("/admin/scans").json()["scans"]}
        row = rows[REPO_SCAN_IDS[0]]
        assert row["repo_url"] == "https://github.com/acme/alpha"
        assert row["target_url"] == ""
        assert row["pqc_readiness_score"] == 40
        assert row["total_findings"] == 2


# ---------------------------------------------------------------------------
# The user-facing history listing
# ---------------------------------------------------------------------------


class TestScanHistoryWithAMixedCollection:
    def test_both_kinds_appear_in_the_history(self, admin_client):
        body = admin_client.get("/user/scans").json()
        assert body["total"] == 4
        assert {row["id"] for row in body["scans"]} == {
            *REPO_SCAN_IDS,
            LEGACY_SCAN_ID,
            WEBSITE_SCAN_ID,
        }

    def test_a_website_row_is_labelled_and_carries_its_target(self, admin_client):
        rows = {row["id"]: row for row in admin_client.get("/user/scans").json()["scans"]}
        row = rows[WEBSITE_SCAN_ID]
        assert row["scan_type"] == SCAN_TYPE_WEBSITE
        assert row["target_url"] == TARGET
        assert row["repo_url"] == ""

    def test_a_website_row_carries_the_numbers_the_list_renders(self, admin_client):
        """The shared report fields are why one list can hold both kinds: a
        combined website report names pqc_readiness_score, total_findings and
        algorithms_found exactly as a repository report does."""
        rows = {row["id"]: row for row in admin_client.get("/user/scans").json()["scans"]}
        row = rows[WEBSITE_SCAN_ID]
        assert row["pqc_readiness_score"] == EXPECTED_SCORE
        assert row["total_findings"] == 3
        assert row["algorithms_found"] == ["ECC", "RSA"]

    def test_the_repository_shaped_fields_are_empty_rather_than_invented(
        self, admin_client
    ):
        rows = {row["id"]: row for row in admin_client.get("/user/scans").json()["scans"]}
        row = rows[WEBSITE_SCAN_ID]
        assert row["scanned_files"] == 0
        assert row["algo_severity"] == {}

    def test_a_repository_row_is_unchanged(self, admin_client):
        rows = {row["id"]: row for row in admin_client.get("/user/scans").json()["scans"]}
        row = rows[REPO_SCAN_IDS[0]]
        assert row["scan_type"] == SCAN_TYPE_REPOSITORY
        assert row["repo_url"] == "https://github.com/acme/alpha"
        assert row["target_url"] == ""
        assert row["scanned_files"] == 9
        assert row["algo_severity"] == {"RSA": "critical", "SHA-256": "warning"}

    def test_a_legacy_row_reads_as_a_repository_scan(self, admin_client):
        rows = {row["id"]: row for row in admin_client.get("/user/scans").json()["scans"]}
        assert rows[LEGACY_SCAN_ID]["scan_type"] == SCAN_TYPE_REPOSITORY

    def test_a_website_scan_can_be_opened_in_full(self, admin_client):
        body = admin_client.get(f"/user/scans/{WEBSITE_SCAN_ID}/full").json()
        assert body["url"] == TARGET
        assert body["scan_id"] == WEBSITE_SCAN_ID


class TestTheExportsThatDoNotApplyToAWebsite:
    """Refused with a reason, rather than answered with something meaningless."""

    def test_sarif_is_refused_for_a_website_scan(self, admin_client):
        response = admin_client.get(f"/user/scans/{WEBSITE_SCAN_ID}/sarif")
        assert response.status_code == 422
        assert "file locations in source code" in response.json()["detail"]
        assert "CBOM" in response.json()["detail"]

    def test_sbom_is_refused_for_a_website_scan(self, admin_client):
        response = admin_client.get(f"/user/scans/{WEBSITE_SCAN_ID}/sbom")
        assert response.status_code == 422
        assert "manifests" in response.json()["detail"]

    def test_the_hndl_calculator_refuses_a_website_scan(self, admin_client):
        """It would not crash -- it would return a confident "no exposure" for
        a site whose ECDHE handshake is the textbook harvest-now target. A
        wrong answer delivered calmly is the worst outcome available."""
        response = admin_client.post(
            "/hndl/calculate",
            json={"scan_id": WEBSITE_SCAN_ID, "data_sensitivity": "personal_data"},
        )
        assert response.status_code == 422
        assert "repository scan" in response.json()["detail"]

    def test_sarif_still_works_for_a_repository_scan(self, admin_client):
        response = admin_client.get(f"/user/scans/{REPO_SCAN_IDS[0]}/sarif")
        assert response.status_code == 200
        assert response.json()["version"] == "2.1.0"

    def test_the_hndl_calculator_still_works_for_a_repository_scan(
        self, admin_client
    ):
        response = admin_client.post(
            "/hndl/calculate",
            json={"scan_id": REPO_SCAN_IDS[0], "data_sensitivity": "personal_data"},
        )
        assert response.status_code == 200
        assert response.json()["repo_url"] == "https://github.com/acme/alpha"


# ---------------------------------------------------------------------------
# The CBOM extension
# ---------------------------------------------------------------------------


class TestTheRepositoryCbomIsUnchanged:
    """A golden document, captured from the converter as it stood before this
    phase touched the file. Everything except the two fields that are new on
    every call -- the random serialNumber and the timestamp -- has to match."""

    REPORT = {
        "repo": "acme/demo",
        "created_at": "2026-08-16T00:00:00Z",
        "findings_by_file": {
            "auth.py": [{"file": "auth.py", "line": 12, "algorithm": "RSA",
                         "severity": "critical", "quantum_vulnerable": True}],
            "hash.py": [{"file": "hash.py", "line": 9, "algorithm": "SHA-512",
                         "severity": "safe", "quantum_vulnerable": False}],
            "old.py": [
                {"file": "old.py", "line": 3, "algorithm": "MD5",
                 "severity": "critical", "quantum_vulnerable": True},
                {"file": "old.py", "line": 4, "algorithm": "AES-256",
                 "severity": "safe", "quantum_vulnerable": False},
            ],
            "lib.py": [{"file": "lib.py", "line": 1,
                        "algorithm": "hashlib (requires deeper inspection)",
                        "severity": "info"}],
        },
    }

    GOLDEN_COMPONENTS = [
        {
            "type": "cryptographic-asset",
            "bom-ref": "crypto/aes-256",
            "name": "AES-256",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "block-cipher",
                    "parameterSetIdentifier": "256",
                    "executionEnvironment": "software-plain-ram",
                    "implementationPlatform": "generic",
                    "cryptoFunctions": ["encrypt", "decrypt"],
                },
            },
            "evidence": {"occurrences": [{"location": "old.py", "line": 4}]},
        },
        {
            "type": "cryptographic-asset",
            "bom-ref": "crypto/md5",
            "name": "MD5",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "hash",
                    "executionEnvironment": "software-plain-ram",
                    "implementationPlatform": "generic",
                    "cryptoFunctions": ["digest"],
                    "nistQuantumSecurityLevel": 0,
                },
            },
            "evidence": {"occurrences": [{"location": "old.py", "line": 3}]},
        },
        {
            "type": "cryptographic-asset",
            "bom-ref": "crypto/rsa",
            "name": "RSA",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "signature",
                    "executionEnvironment": "software-plain-ram",
                    "implementationPlatform": "generic",
                    "cryptoFunctions": [
                        "keygen", "encrypt", "decrypt", "sign", "verify",
                    ],
                    "nistQuantumSecurityLevel": 0,
                },
            },
            "evidence": {"occurrences": [{"location": "auth.py", "line": 12}]},
        },
        {
            "type": "cryptographic-asset",
            "bom-ref": "crypto/sha-512",
            "name": "SHA-512",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "hash",
                    "parameterSetIdentifier": "512",
                    "executionEnvironment": "software-plain-ram",
                    "implementationPlatform": "generic",
                    "cryptoFunctions": ["digest"],
                },
            },
            "evidence": {"occurrences": [{"location": "hash.py", "line": 9}]},
        },
    ]

    def test_the_document_matches_the_golden_output_exactly(self):
        produced = convert_to_cbom(self.REPORT)
        produced.pop("serialNumber")
        assert produced == {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "timestamp": "2026-08-16T00:00:00Z",
                "tools": [
                    {
                        "vendor": "QLint",
                        "name": "QLint",
                        "version": cbom_converter.QLINT_VERSION,
                        "externalReferences": [
                            {"type": "website", "url": cbom_converter.REPO_URL}
                        ],
                    }
                ],
                "component": {"type": "application", "name": "acme/demo"},
            },
            "components": self.GOLDEN_COMPONENTS,
        }

    def test_the_shared_primitive_table_did_not_gain_a_website_only_entry(self):
        """The website path needs a primitive for ChaCha20, which no code
        scanner ever produces. Adding it to the shared table would have changed
        what a repository scan converts to, so it lives in its own."""
        assert "ChaCha20" not in cbom_converter._PRIMITIVES
        assert cbom_converter._WEBSITE_PRIMITIVES["ChaCha20"] == "stream-cipher"

    def test_an_empty_report_is_still_a_valid_empty_document(self):
        assert convert_to_cbom({})["components"] == []


class TestTheWebsiteCbom:
    @pytest.fixture
    def cbom(self):
        return convert_website_to_cbom(WEBSITE_RESULT, TARGET)

    def _component(self, cbom, name):
        return next(c for c in cbom["components"] if c["name"] == name)

    def test_it_is_a_cyclonedx_1_6_document(self, cbom):
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert cbom["serialNumber"].startswith("urn:uuid:")

    def test_the_subject_is_the_site_that_was_scanned(self, cbom):
        assert cbom["metadata"]["component"]["name"] == TARGET

    def test_the_subject_falls_back_to_the_reports_own_url(self):
        """A stored report converts without the caller carrying the URL too."""
        assert (
            convert_website_to_cbom(WEBSITE_RESULT)["metadata"]["component"]["name"]
            == TARGET
        )

    def test_the_timestamp_is_when_the_scan_ran(self, cbom):
        assert cbom["metadata"]["timestamp"] == "2026-08-16T10:00:00+00:00"

    def test_every_component_is_a_cryptographic_asset(self, cbom):
        for component in cbom["components"]:
            assert component["type"] == "cryptographic-asset"
            assert component["cryptoProperties"]["assetType"] == "algorithm"

    def test_the_components_are_the_algorithms_the_scan_named(self, cbom):
        assert [c["name"] for c in cbom["components"]] == ["ECC", "RSA"]

    def test_a_tls_finding_is_located_by_the_target_url(self, cbom):
        """No file and no line: neither exists for a live handshake, and a
        location of "unknown" or line 1 would be an assertion nobody measured."""
        occurrences = self._component(cbom, "RSA")["evidence"]["occurrences"]
        assert {"location": TARGET} in occurrences
        assert all("line" not in occurrence for occurrence in occurrences)

    def test_a_javascript_finding_is_located_by_the_script_url(self, cbom):
        occurrences = self._component(cbom, "ECC")["evidence"]["occurrences"]
        assert {"location": f"https://{CDN_HOST}/analytics.js"} in occurrences

    def test_the_key_exchange_and_the_script_collapse_into_one_ecc_component(
        self, cbom
    ):
        """The handshake's ECDH and the script's ECC are the same primitive
        under two names, resolved through CRYPTO_DB exactly as the repository
        path resolves a raw identifier -- so they are one component seen in two
        places, in location order."""
        assert self._component(cbom, "ECC")["evidence"]["occurrences"] == [
            {"location": f"https://{CDN_HOST}/analytics.js"},
            {"location": TARGET},
        ]

    def test_an_inline_script_finding_is_located_by_its_position(self, cbom):
        occurrences = self._component(cbom, "RSA")["evidence"]["occurrences"]
        assert {"location": "inline script #1"} in occurrences

    def test_the_tls_and_javascript_occurrences_collapse_into_one_component(
        self, cbom
    ):
        """The certificate's RSA key and the script's RSA usage are one asset
        seen in two places, which is exactly what a bill of materials says."""
        occurrences = self._component(cbom, "RSA")["evidence"]["occurrences"]
        assert occurrences == [
            {"location": TARGET},
            {"location": "inline script #1"},
        ]

    def test_a_quantum_exposed_asset_carries_security_level_zero(self, cbom):
        for name in ("RSA", "ECC"):
            properties = self._component(cbom, name)["cryptoProperties"][
                "algorithmProperties"
            ]
            assert properties["nistQuantumSecurityLevel"] == 0

    def test_a_header_finding_is_not_a_cryptographic_asset(self, cbom):
        """A missing Referrer-Policy is a security finding, not a part. A bill
        of materials listing it would be listing something that does not
        exist."""
        assert "Referrer-Policy" not in [c["name"] for c in cbom["components"]]

    def test_a_protocol_version_is_not_filed_as_an_algorithm(self, cbom):
        """CycloneDX models a protocol with its own assetType, which this phase
        does not add. Filing TLS 1.3 as an algorithm with primitive "unknown"
        would be a worse answer than leaving it out -- and nothing is lost:
        the key exchange and cipher suite are components in their own right."""
        assert "TLS 1.3" not in [c["name"] for c in cbom["components"]]

    def test_every_emitted_enum_value_is_one_the_schema_defines(self, cbom):
        for component in cbom["components"]:
            properties = component["cryptoProperties"]["algorithmProperties"]
            assert properties["primitive"] in cbom_converter.CDX_PRIMITIVES
            for function in properties.get("cryptoFunctions", []):
                assert function in cbom_converter.CDX_CRYPTO_FUNCTIONS

    def test_a_chacha20_cipher_gets_its_primitive(self):
        report = {
            "url": TARGET,
            "findings": [
                {"asset": "TLS_CHACHA20_POLY1305_SHA256", "type": "Cipher Suite",
                 "algorithm": "ChaCha20", "severity": "Low", "db_severity": "safe",
                 "quantum_vulnerable": False, "category": CATEGORY_TLS},
            ],
        }
        component = convert_website_to_cbom(report)["components"][0]
        properties = component["cryptoProperties"]["algorithmProperties"]
        assert component["name"] == "ChaCha20"
        assert properties["primitive"] == "stream-cipher"
        assert "nistQuantumSecurityLevel" not in properties

    def test_it_never_raises_on_a_malformed_report(self):
        for report in ({}, {"findings": "nonsense"}, {"findings": [None, 1, "x"]}):
            document = convert_website_to_cbom(report, TARGET)
            assert document["bomFormat"] == "CycloneDX"
        assert convert_website_to_cbom({}, TARGET)["components"] == []

    def test_the_document_is_json_serializable(self, cbom):
        json.dumps(cbom)


class TestTheCbomDownloadRoute:
    def test_a_website_scan_downloads_as_a_website_cbom(self, admin_client):
        response = admin_client.get(f"/user/scans/{WEBSITE_SCAN_ID}/cbom")
        assert response.status_code == 200
        body = response.json()
        assert body["metadata"]["component"]["name"] == TARGET
        assert [c["name"] for c in body["components"]] == ["ECC", "RSA"]
        assert body["components"][0]["evidence"]["occurrences"] == [
            {"location": f"https://{CDN_HOST}/analytics.js"},
            {"location": TARGET},
        ]

    def test_a_repository_scan_downloads_as_a_repository_cbom(self, admin_client):
        response = admin_client.get(f"/user/scans/{REPO_SCAN_IDS[0]}/cbom")
        assert response.status_code == 200
        body = response.json()
        assert body["metadata"]["component"]["name"] == "acme/alpha"
        rsa = next(c for c in body["components"] if c["name"] == "RSA")
        # Still a file and a line: the repository path is untouched.
        assert rsa["evidence"]["occurrences"] == [
            {"location": "auth.py", "line": 3}
        ]

    def test_both_are_served_as_a_download(self, admin_client):
        for scan_id in (WEBSITE_SCAN_ID, REPO_SCAN_IDS[0]):
            response = admin_client.get(f"/user/scans/{scan_id}/cbom")
            assert response.headers["content-disposition"] == (
                f'attachment; filename="qlint-scan-{scan_id}.cbom.json"'
            )

    def test_a_scan_that_is_not_the_callers_is_not_downloadable(
        self, monkeypatch, mixed_collection
    ):
        for module in (user_module,):
            monkeypatch.setattr(module, "get_scans", lambda: mixed_collection)
        application = FastAPI()
        application.include_router(user_router)
        application.dependency_overrides[get_current_user] = lambda: SECOND_USER
        try:
            client = TestClient(application)
            assert client.get(f"/user/scans/{WEBSITE_SCAN_ID}/cbom").status_code == 404
        finally:
            application.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# End to end: scan, then export
# ---------------------------------------------------------------------------


class TestAScanConvertsToACbom:
    """The whole path in one test: what the endpoint returns is what the
    converter is given, so a change to the report shape that breaks the export
    fails here rather than in production."""

    def test_a_live_report_converts_to_a_populated_cbom(self, client, site):
        report = scan(client).json()
        cbom = convert_website_to_cbom(report, report["url"])
        names = [component["name"] for component in cbom["components"]]
        assert names == ["AES-256", "ECC", "RSA", "SHA-256"]

    def test_every_occurrence_names_a_real_web_location(self, client, site):
        report = scan(client).json()
        cbom = convert_website_to_cbom(report, report["url"])
        locations = {
            occurrence["location"]
            for component in cbom["components"]
            for occurrence in component["evidence"]["occurrences"]
        }
        assert locations == {
            TARGET,
            "inline script #1",
            f"https://{CDN_HOST}/analytics.js",
        }
        assert "unknown" not in locations

    def test_no_occurrence_claims_a_line_number(self, client, site):
        report = scan(client).json()
        cbom = convert_website_to_cbom(report, report["url"])
        for component in cbom["components"]:
            for occurrence in component["evidence"]["occurrences"]:
                assert "line" not in occurrence

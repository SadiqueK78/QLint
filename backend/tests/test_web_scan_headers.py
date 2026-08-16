"""HTTP security header scanning: POST /web-scan/headers.

Structured like test_web_scan_tls.py, and mocking at the same depth: the
resolver is replaced at socket.getaddrinfo so ssrf_guard's real parsing and
address checking run, and only the outbound HTTP call itself is faked. Nothing
here touches the network.

What this file deliberately does *not* do is re-test the SSRF blocklist. That
validator is shared with the TLS endpoint and now lives in ssrf_guard.py with
its own exhaustive test file; duplicating the range table here would mean two
copies to update and no more safety. One test proves this endpoint is wired to
the guard, which is the part that could actually regress.
"""

import socket

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth import get_current_user
from routers import web_scan_router as web_scan_module
from routers.web_scan_router import router as web_scan_router

SCAN_USER = {"_id": "507f1f77bcf86cd799439011", "email": "owner@qlint.dev"}
SECOND_USER = {"_id": "507f1f77bcf86cd799439099", "email": "other@qlint.dev"}

TARGET = "https://example.com"
TARGET_HOST = "example.com"
PUBLIC_IP = "93.184.216.34"

# A full set of correctly configured headers, as a well-run site sends them.
GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
}

ALL_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


class FakeSite:
    """Stands in for DNS and the one outbound GET, recording what was attempted.

    `requests` is the attribute that matters for the SSRF test: a target that
    should be refused must leave it empty, because a refusal that arrives after
    the request was sent is not a refusal.
    """

    def __init__(
        self,
        headers=None,
        status_code=200,
        addresses=(PUBLIC_IP,),
        error=None,
        resolve_error=None,
    ):
        self.headers = dict(headers if headers is not None else GOOD_HEADERS)
        self.status_code = status_code
        self.addresses = list(addresses)
        self.error = error
        self.resolve_error = resolve_error
        self.resolutions: list[str] = []
        self.requests: list[dict] = []

    def install(self, monkeypatch):
        def _getaddrinfo(host, port, *args, **kwargs):
            self.resolutions.append(host)
            if self.resolve_error is not None:
                raise self.resolve_error
            answers = []
            for address in self.addresses:
                if ":" in address:
                    answers.append(
                        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, port, 0, 0))
                    )
                else:
                    answers.append(
                        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))
                    )
            return answers

        async def _get(client_self, url, **kwargs):
            self.requests.append(
                {
                    "url": str(url),
                    "headers": dict(kwargs.get("headers") or {}),
                    "extensions": dict(kwargs.get("extensions") or {}),
                    "follow_redirects": client_self.follow_redirects,
                    "timeout": client_self.timeout,
                }
            )
            if self.error is not None:
                raise self.error
            return httpx.Response(
                self.status_code, headers=self.headers, request=httpx.Request("GET", url)
            )

        monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)
        monkeypatch.setattr(httpx.AsyncClient, "get", _get)
        return self


@pytest.fixture
def site(monkeypatch):
    return FakeSite().install(monkeypatch)


@pytest.fixture(autouse=True)
def reset_limiters():
    """Both buckets, because several tests here deliberately fill one."""
    web_scan_module._headers_limiter.reset()
    web_scan_module._limiter.reset()
    yield
    web_scan_module._headers_limiter.reset()
    web_scan_module._limiter.reset()


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
    return client.post("/web-scan/headers", json={"url": url})


def by_asset(body):
    return {finding["asset"]: finding for finding in body["findings"]}


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


class TestAFullyConfiguredSite:
    def test_every_header_present_and_correct_is_all_acceptable_and_info(
        self, client, site
    ):
        response = scan(client)
        assert response.status_code == 200
        findings = by_asset(response.json())

        assert sorted(findings) == sorted(ALL_HEADERS)
        for header in ALL_HEADERS:
            assert findings[header]["status"] == "Acceptable", header
            assert findings[header]["severity"] == "Info", header

    def test_passing_findings_carry_a_confirmation_not_a_fix_instruction(
        self, client, site
    ):
        findings = by_asset(scan(client).json())
        assert findings["X-Frame-Options"]["recommendation"] == "Correctly configured."
        assert findings["Referrer-Policy"]["recommendation"] == "Correctly configured."

    def test_every_finding_uses_the_shared_finding_shape(self, client, site):
        for finding in scan(client).json()["findings"]:
            assert set(finding) >= {
                "asset",
                "type",
                "purpose",
                "status",
                "severity",
                "recommendation",
            }
            assert finding["type"] == "HTTP Security Header"
            assert finding["recommendation"]

    def test_the_observed_values_are_reported_back(self, client, site):
        findings = by_asset(scan(client).json())
        assert findings["X-Content-Type-Options"]["observed_value"] == "nosniff"
        assert findings["X-Frame-Options"]["present"] is True

    def test_the_report_names_the_host_and_the_address_it_used(self, client, site):
        body = scan(client).json()
        assert body["host"] == TARGET_HOST
        assert body["port"] == 443
        assert body["scanned_ip"] == PUBLIC_IP
        assert body["status_code"] == 200

    def test_the_summary_counts_what_was_found(self, client, site):
        summary = scan(client).json()["summary"]
        assert summary["total_findings"] == 5
        assert summary["headers_present"] == 5
        assert summary["headers_missing"] == 0
        assert summary["by_severity"] == {"Info": 5}

    def test_a_non_200_response_is_still_scanned(self, client, monkeypatch):
        """Headers on a 404 are still the site's headers."""
        FakeSite(status_code=404).install(monkeypatch)
        body = scan(client).json()
        assert body["status_code"] == 404
        assert len(body["findings"]) == 5

    def test_header_matching_is_case_insensitive(self, client, monkeypatch):
        """HTTP header names are case-insensitive and real servers vary."""
        FakeSite(
            headers={
                "STRICT-TRANSPORT-SECURITY": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "NOSNIFF",
                "x-frame-options": "sameorigin",
                "Referrer-Policy": "no-referrer",
            }
        ).install(monkeypatch)
        findings = by_asset(scan(client).json())
        for header in ALL_HEADERS:
            assert findings[header]["status"] == "Acceptable", header


# ---------------------------------------------------------------------------
# Missing and misconfigured
# ---------------------------------------------------------------------------


class TestASiteWithNoSecurityHeaders:
    @pytest.fixture
    def bare(self, monkeypatch):
        return FakeSite(headers={}).install(monkeypatch)

    def test_all_five_findings_are_still_produced(self, client, bare):
        body = scan(client).json()
        assert len(body["findings"]) == 5
        assert sorted(by_asset(body)) == sorted(ALL_HEADERS)

    @pytest.mark.parametrize(
        "header,severity",
        [
            ("Strict-Transport-Security", "Medium"),
            ("Content-Security-Policy", "Medium"),
            ("X-Content-Type-Options", "Low"),
            ("X-Frame-Options", "Low"),
            ("Referrer-Policy", "Low"),
        ],
    )
    def test_each_missing_header_has_the_expected_status_and_severity(
        self, client, bare, header, severity
    ):
        finding = by_asset(scan(client).json())[header]
        assert finding["status"] == "Missing"
        assert finding["severity"] == severity
        assert finding["present"] is False
        assert finding["observed_value"] is None

    def test_the_missing_hsts_recommendation_says_what_to_add_and_why(
        self, client, bare
    ):
        recommendation = by_asset(scan(client).json())[
            "Strict-Transport-Security"
        ]["recommendation"]
        assert "Add a Strict-Transport-Security header" in recommendation
        assert "180 days" in recommendation
        assert "downgrade" in recommendation

    def test_the_summary_reflects_a_bare_site(self, client, bare):
        summary = scan(client).json()["summary"]
        assert summary["headers_present"] == 0
        assert summary["headers_missing"] == 5
        assert summary["by_severity"] == {"Medium": 2, "Low": 3}


class TestHSTSMaxAge:
    def _hsts(self, client, monkeypatch, value):
        FakeSite(headers={**GOOD_HEADERS, "strict-transport-security": value}).install(
            monkeypatch
        )
        return by_asset(scan(client).json())["Strict-Transport-Security"]

    @pytest.mark.parametrize("max_age", [0, 1, 3600, 86400, 15551999])
    def test_a_max_age_below_180_days_is_a_weak_configuration(
        self, client, monkeypatch, max_age
    ):
        finding = self._hsts(client, monkeypatch, f"max-age={max_age}")
        assert finding["status"] == "Weak Configuration"
        assert finding["severity"] == "Low"
        assert str(max_age) in finding["recommendation"]
        assert "15552000" in finding["recommendation"]

    @pytest.mark.parametrize("max_age", [15552000, 31536000, 63072000])
    def test_a_max_age_at_or_above_180_days_is_acceptable(
        self, client, monkeypatch, max_age
    ):
        finding = self._hsts(client, monkeypatch, f"max-age={max_age}")
        assert finding["status"] == "Acceptable"
        assert finding["severity"] == "Info"

    @pytest.mark.parametrize(
        "value",
        [
            "max-age=31536000",
            "max-age=31536000; includeSubDomains",
            "includeSubDomains; max-age=31536000",
            "  MAX-AGE = 31536000 ; preload",
            'max-age="31536000"',
        ],
    )
    def test_the_directive_is_read_out_of_the_shapes_real_servers_send(
        self, client, monkeypatch, value
    ):
        assert self._hsts(client, monkeypatch, value)["status"] == "Acceptable"

    def test_an_unreadable_max_age_is_weak_rather_than_treated_as_zero(
        self, client, monkeypatch
    ):
        """"Unparseable" and "too short" deserve different advice."""
        finding = self._hsts(client, monkeypatch, "includeSubDomains")
        assert finding["status"] == "Weak Configuration"
        assert "no readable max-age" in finding["recommendation"]


class TestMisconfiguredValues:
    def _with(self, client, monkeypatch, header, value):
        FakeSite(headers={**GOOD_HEADERS, header: value}).install(monkeypatch)
        return by_asset(scan(client).json())

    @pytest.mark.parametrize("value", ["sniff", "none", "nosniff, nosniff", "1"])
    def test_x_content_type_options_must_be_exactly_nosniff(
        self, client, monkeypatch, value
    ):
        finding = self._with(client, monkeypatch, "x-content-type-options", value)[
            "X-Content-Type-Options"
        ]
        assert finding["status"] == "Misconfigured"
        assert finding["severity"] == "Low"
        assert "nosniff" in finding["recommendation"]

    @pytest.mark.parametrize("value", ["DENY", "SAMEORIGIN", "deny", "sameorigin"])
    def test_x_frame_options_accepts_deny_and_sameorigin_in_any_case(
        self, client, monkeypatch, value
    ):
        finding = self._with(client, monkeypatch, "x-frame-options", value)[
            "X-Frame-Options"
        ]
        assert finding["status"] == "Acceptable"
        assert finding["severity"] == "Info"

    @pytest.mark.parametrize("value", ["ALLOW-FROM https://example.com", "ALLOWALL", ""])
    def test_x_frame_options_rejects_values_browsers_ignore(
        self, client, monkeypatch, value
    ):
        finding = self._with(client, monkeypatch, "x-frame-options", value)[
            "X-Frame-Options"
        ]
        assert finding["status"] == "Misconfigured"
        assert finding["severity"] == "Low"

    def test_csp_presence_alone_passes_without_the_policy_being_judged(
        self, client, monkeypatch
    ):
        """Out of scope this phase, and the finding says so rather than implying
        the policy was evaluated."""
        finding = self._with(
            client, monkeypatch, "content-security-policy", "default-src *"
        )["Content-Security-Policy"]
        assert finding["status"] == "Acceptable"
        assert "directives are not evaluated" in finding["recommendation"]


# ---------------------------------------------------------------------------
# The shared SSRF guard
# ---------------------------------------------------------------------------


class TestTheSharedSSRFGuardProtectsThisEndpointToo:
    """One test that the wiring exists. The ranges are test_ssrf_guard.py's job."""

    def test_a_private_address_is_refused_before_any_request_is_made(
        self, client, monkeypatch
    ):
        fake = FakeSite(addresses=("127.0.0.1",)).install(monkeypatch)
        response = scan(client)
        assert response.status_code == 400
        # The refusal landed before the socket, which is the whole point.
        assert fake.requests == []

    def test_the_endpoint_calls_the_shared_guard_rather_than_its_own_copy(self):
        import inspect

        import header_scanner
        import ssrf_guard

        assert header_scanner.validate_target is ssrf_guard.validate_target
        source = inspect.getsource(header_scanner)
        # No second implementation of the blocklist grew here.
        for leftover in ("ipaddress", "is_private", "getaddrinfo"):
            assert leftover not in source

    def test_an_http_url_is_refused_by_the_shared_parser(self, client, site):
        response = scan(client, "http://example.com")
        assert response.status_code == 400
        assert site.resolutions == []
        assert site.requests == []


class TestTheRequestItself:
    def test_it_connects_to_the_validated_address_not_the_hostname(
        self, client, site
    ):
        """DNS rebinding defence, carried over from the TLS scan.

        httpx would resolve the name again; the guard already resolved it once
        and judged the answer, so the request is pinned to that address and the
        hostname travels as Host and SNI.
        """
        scan(client)
        assert len(site.requests) == 1
        request = site.requests[0]
        assert PUBLIC_IP in request["url"]
        assert request["headers"]["Host"] == TARGET_HOST
        assert request["extensions"]["sni_hostname"] == TARGET_HOST
        assert site.resolutions == [TARGET_HOST]

    def test_redirects_are_not_followed(self, client, site):
        """A redirect names a host the guard never judged."""
        scan(client)
        assert site.requests[0]["follow_redirects"] is False

    def test_exactly_one_request_is_made(self, client, site):
        scan(client)
        assert len(site.requests) == 1

    def test_the_timeout_is_ten_seconds(self, client, site):
        import header_scanner

        assert header_scanner.REQUEST_TIMEOUT_SECONDS == 10.0
        scan(client)
        assert site.requests[0]["timeout"].read == 10.0

    def test_the_path_of_the_supplied_url_is_the_one_requested(
        self, client, site
    ):
        scan(client, "https://example.com/some/page")
        assert site.requests[0]["url"].endswith("/some/page")


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------


class TestRequestFailuresAreReportedCleanly:
    def _assert_clean(self, response, expected=None):
        assert response.status_code == 502
        detail = response.json()["detail"]
        assert isinstance(detail, str) and detail
        assert TARGET_HOST in detail
        assert "Traceback" not in detail
        assert "header_scanner" not in detail
        if expected:
            assert expected.lower() in detail.lower()
        return detail

    def test_a_connection_error_is_a_clean_error(self, client, monkeypatch):
        FakeSite(
            error=httpx.ConnectError("refused", request=httpx.Request("GET", TARGET))
        ).install(monkeypatch)
        self._assert_clean(scan(client), "could not connect")

    def test_a_connect_timeout_is_a_clean_error(self, client, monkeypatch):
        FakeSite(
            error=httpx.ConnectTimeout("timed out", request=httpx.Request("GET", TARGET))
        ).install(monkeypatch)
        self._assert_clean(scan(client), "did not accept a connection")

    def test_a_read_timeout_is_a_clean_error(self, client, monkeypatch):
        FakeSite(
            error=httpx.ReadTimeout("slow", request=httpx.Request("GET", TARGET))
        ).install(monkeypatch)
        self._assert_clean(scan(client), "did not answer")

    def test_a_generic_transport_error_is_a_clean_error(self, client, monkeypatch):
        FakeSite(
            error=httpx.ProtocolError("bad", request=httpx.Request("GET", TARGET))
        ).install(monkeypatch)
        self._assert_clean(scan(client))

    def test_a_dns_failure_comes_from_the_shared_guard(self, client, monkeypatch):
        fake = FakeSite(
            resolve_error=socket.gaierror(-2, "Name or service not known")
        ).install(monkeypatch)
        detail = self._assert_clean(scan(client), "does not resolve")
        assert "DNS" in detail
        assert fake.requests == []

    def test_an_unexpected_exception_becomes_a_500_with_nothing_leaked(
        self, client, monkeypatch
    ):
        import header_scanner

        async def explode(url):
            raise RuntimeError("secret internal detail: /srv/qlint/config")

        monkeypatch.setattr(web_scan_module, "header_scan_url", explode)
        response = scan(client)
        assert response.status_code == 500
        assert "secret internal detail" not in response.json()["detail"]
        assert "/srv/qlint" not in response.json()["detail"]


# ---------------------------------------------------------------------------
# Authentication and rate limiting
# ---------------------------------------------------------------------------


class TestTheRouteRequiresASession:
    def test_a_request_with_no_token_is_401_and_does_nothing(self, app, site):
        response = TestClient(app).post("/web-scan/headers", json={"url": TARGET})
        assert response.status_code == 401
        assert response.json()["detail"] == "Not authenticated"
        assert site.resolutions == []
        assert site.requests == []

    def test_a_request_with_a_junk_token_is_401(self, app, site):
        response = TestClient(app).post(
            "/web-scan/headers",
            json={"url": TARGET},
            headers={"Authorization": "Bearer not-a-real-jwt"},
        )
        assert response.status_code == 401
        assert site.requests == []

    def test_an_unauthenticated_request_does_not_spend_the_rate_limit(self, app, site):
        unauthenticated = TestClient(app)
        for _ in range(web_scan_module._headers_limiter.max_requests + 5):
            assert unauthenticated.post(
                "/web-scan/headers", json={"url": TARGET}
            ).status_code == 401
        assert web_scan_module._headers_limiter._hits == {}


class TestTheRateLimit:
    def test_the_window_is_twenty_scans_per_twenty_four_hours(self):
        assert web_scan_module._headers_limiter.max_requests == 20
        assert web_scan_module._headers_limiter.window_seconds == 86400

    def test_the_window_closes_after_twenty_scans(self, client, site):
        for _ in range(20):
            assert scan(client).status_code == 200
        blocked = scan(client)
        assert blocked.status_code == 429
        detail = blocked.json()["detail"]
        # format_duration renders the day-long window, as it does for the TLS
        # endpoint -- no raw "1440 minutes" or "86400s".
        assert detail.startswith("Rate limit exceeded: 20 requests per 1 day.")
        assert "1440 minutes" not in detail
        assert "86400s" not in detail
        # The remaining wait is asserted loosely on purpose: it is the window
        # minus however long these twenty requests took, so it lands on "1 day"
        # or "24 hours" depending on machine speed. Pinning either one makes
        # this test fail on a slow day rather than on a real regression.
        assert "Try again in 1 day." in detail or "Try again in 24 hours." in detail

    def test_the_window_is_keyed_on_the_account_id(self, client, site):
        scan(client)
        assert list(web_scan_module._headers_limiter._hits) == [
            f"user:{SCAN_USER['_id']}"
        ]

    def test_two_accounts_each_get_their_own_allowance(self, app, site):
        app.dependency_overrides[get_current_user] = lambda: SCAN_USER
        try:
            for _ in range(20):
                assert TestClient(app).post(
                    "/web-scan/headers", json={"url": TARGET}
                ).status_code == 200
            assert TestClient(app).post(
                "/web-scan/headers", json={"url": TARGET}
            ).status_code == 429

            app.dependency_overrides[get_current_user] = lambda: SECOND_USER
            assert TestClient(app).post(
                "/web-scan/headers", json={"url": TARGET}
            ).status_code == 200
        finally:
            app.dependency_overrides.clear()


class TestTheTwoEndpointsHaveIndependentBuckets:
    """Exhausting one must not spend the other's allowance.

    They are separate limiters for a reason -- a header check is one GET, a TLS
    scan is a handshake and a certificate parse -- so sharing a bucket would
    make the cheaper operation pay the expensive one's price.
    """

    def test_they_are_not_the_same_limiter(self):
        assert web_scan_module._headers_limiter is not web_scan_module._limiter
        assert web_scan_module._headers_limiter.max_requests == 20
        assert web_scan_module._limiter.max_requests == 10

    def test_exhausting_the_header_limit_leaves_the_tls_allowance_intact(
        self, client, site, monkeypatch
    ):
        for _ in range(20):
            assert scan(client).status_code == 200
        assert scan(client).status_code == 429

        # The TLS endpoint's bucket was never touched.
        assert web_scan_module._limiter._hits == {}

        # And it still answers: a TLS scan, with its own handshake mocked out.
        import tls_scanner

        def _handshake(ip_address, hostname, verify=True):
            raise ConnectionRefusedError(111, "Connection refused")

        monkeypatch.setattr(tls_scanner, "_handshake", _handshake)
        tls_response = client.post("/web-scan/tls", json={"url": TARGET})
        # 502, not 429: the request was admitted and the (mocked) scan failed.
        assert tls_response.status_code == 502

    def test_exhausting_the_tls_limit_leaves_the_header_allowance_intact(
        self, client, site, monkeypatch
    ):
        import tls_scanner

        def _handshake(ip_address, hostname, verify=True):
            raise ConnectionRefusedError(111, "Connection refused")

        monkeypatch.setattr(tls_scanner, "_handshake", _handshake)
        for _ in range(web_scan_module._limiter.max_requests):
            client.post("/web-scan/tls", json={"url": TARGET})
        assert client.post("/web-scan/tls", json={"url": TARGET}).status_code == 429

        assert web_scan_module._headers_limiter._hits == {}
        assert scan(client).status_code == 200


class TestTheRouteIsRegistered:
    def test_both_web_scan_paths_are_declared(self):
        paths = {
            route.path for route in web_scan_router.routes if hasattr(route, "path")
        }
        assert paths == {"/web-scan/tls", "/web-scan/headers"}

    def test_main_still_mounts_the_router_once(self):
        """Read rather than imported: main pulls in oqs via benchmark_router."""
        from pathlib import Path

        source = (Path(__file__).resolve().parent.parent / "main.py").read_text(
            encoding="utf-8"
        )
        assert source.count("app.include_router(web_scan_router") == 1

"""JavaScript scanning of a live page: POST /web-scan/javascript.

Structured like test_web_scan_tls.py and test_web_scan_headers.py, and mocking
at the same depth: the resolver is replaced at socket.getaddrinfo so
ssrf_guard's real parsing and address checking run, and only the outbound HTTP
call itself is faked. Nothing here touches the network.

Two things differ from the header file's conventions, both forced by what this
phase actually does.

  * js_web_scanner streams its responses rather than calling client.get, because
    httpx has no maximum-response-size option and a page or a script must not be
    allowed to decide how much memory this process spends. So the fake replaces
    httpx.AsyncClient.stream, and a stream mock has to be an async context
    manager whose response exposes aiter_bytes() -- the simpler `.get`-returning
    coroutine the header tests use would never exercise the size limits at all.
  * One scan makes many requests, to many hosts. The fake therefore routes on
    the Host header rather than on the URL: every request is pinned to a
    guard-approved IP address before it is sent, so the URL says 93.184.216.34
    and only the Host header still says which site was meant.

What this file deliberately does *not* do is re-test the SSRF blocklist. That
validator is shared with the TLS and header endpoints and lives in ssrf_guard.py
with its own exhaustive test file. One test proves each external script URL is
put through the guard on its own, which is the part specific to this phase and
the part that could actually regress.

Two classes near the end are regression tests rather than behaviour tests, and
they use a real httpx.AsyncClient over httpx.MockTransport instead of the fake
below. They pin down the two mechanisms this module leans on that are not
obvious from reading httpx: that reassigning client.timeout on an already-open
client changes the timeout the *next* request carries, and that an exception
raised inside `async with client.stream(...)` escapes the context manager
instead of being swallowed by its cleanup. Faking client.stream cannot test
either one, because faking it is what removes the behaviour in question.
"""

import socket

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import js_web_scanner
from auth import get_current_user
from js_web_scanner import (
    MAX_EXTERNAL_SCRIPTS,
    MAX_SCRIPT_BYTES,
    SKIP_BLOCKED,
    SKIP_EXCLUDED_TYPE,
    SKIP_OVER_CAP,
    SKIP_TOO_LARGE,
)
from routers import web_scan_router as web_scan_module
from routers.web_scan_router import router as web_scan_router

SCAN_USER = {"_id": "507f1f77bcf86cd799439011", "email": "owner@qlint.dev"}
SECOND_USER = {"_id": "507f1f77bcf86cd799439099", "email": "other@qlint.dev"}

TARGET = "https://example.com"
TARGET_HOST = "example.com"
PUBLIC_IP = "93.184.216.34"

CDN_HOST = "cdn.example.net"
CDN_IP = "151.101.1.44"

# A public name that resolves onto the private network -- the whole reason this
# phase validates every script URL separately. Nothing about the name gives it
# away; only the address does, which is exactly the case the guard exists for.
INTERNAL_HOST = "metrics.example.net"
INTERNAL_IP = "10.0.0.5"

# Detectable, and detectably different from each other, so a finding can be
# traced back to the file it came from without ambiguity.
INLINE_VULNERABLE = "const key = new NodeRSA({ b: 2048 });"      # -> RSA
EXTERNAL_VULNERABLE = "const ec = crypto.createECDH('secp256k1');"  # -> ECC
BENIGN = "window.addEventListener('load', function () { return 1; });"

# Would produce two findings if anything ran it through js_scanner. It is data
# in a script tag, so nothing should.
LD_JSON = (
    '{"@context": "https://schema.org", "@type": "SoftwareApplication", '
    '"keywords": "ES256, jsrsasign"}'
)


# ---------------------------------------------------------------------------
# The fake site
# ---------------------------------------------------------------------------


class Resource:
    """One thing the fake server will serve, and how it will serve it.

    `declared_length` is separated from the body on purpose. "auto" is an honest
    server; an explicit int is a server that declares one size and sends
    another; None is a server that declares nothing at all, which is the case
    that forces the running-total check rather than the header check.
    """

    def __init__(
        self,
        body: bytes = b"",
        content_type: str = "text/javascript",
        status_code: int = 200,
        declared_length="auto",
        chunk_size: int = 64 * 1024,
        error: Exception | None = None,
    ):
        self.body = body
        self.content_type = content_type
        self.status_code = status_code
        self.declared_length = declared_length
        self.chunk_size = chunk_size
        self.error = error

    def headers(self) -> dict:
        headers = {}
        if self.content_type:
            headers["content-type"] = self.content_type
        if self.declared_length == "auto":
            headers["content-length"] = str(len(self.body))
        elif self.declared_length is not None:
            headers["content-length"] = str(self.declared_length)
        return headers

    def chunks(self):
        if not self.body:
            return [b""]
        return [
            self.body[i : i + self.chunk_size]
            for i in range(0, len(self.body), self.chunk_size)
        ]


def page(html: str, **kwargs) -> Resource:
    return Resource(html.encode("utf-8"), content_type="text/html; charset=utf-8", **kwargs)


def script(source: str, **kwargs) -> Resource:
    return Resource(source.encode("utf-8"), **kwargs)


class FakeResponse:
    """What `async with client.stream(...)` hands back."""

    def __init__(self, resource: Resource):
        self.status_code = resource.status_code
        self.headers = httpx.Headers(resource.headers())
        self._chunks = resource.chunks()

    async def aiter_bytes(self):
        for chunk in self._chunks:
            yield chunk


class _StreamContext:
    """client.stream() is used as an async context manager, so the fake is one.

    The `error` path raises out of __aenter__ rather than out of the body: a
    transport failure happens while the response is being opened, not while it
    is being read, and raising from the wrong place would let a bug in the
    module's error handling pass this file.
    """

    def __init__(self, response=None, error: Exception | None = None):
        self._response = response
        self._error = error

    async def __aenter__(self):
        if self._error is not None:
            raise self._error
        return self._response

    async def __aexit__(self, *exc_info):
        return False


class FakeSite:
    """Stands in for DNS and for every outbound stream, recording what was tried.

    `requests` is the attribute that matters for the SSRF tests: a URL that
    should be refused must leave no entry in it, because a refusal that arrives
    after the request was sent is not a refusal.
    """

    def __init__(
        self,
        resources: dict | None = None,
        addresses: dict | None = None,
        resolve_error: Exception | None = None,
    ):
        self.resources = dict(resources or {})
        self.addresses = dict(
            addresses
            or {
                TARGET_HOST: [PUBLIC_IP],
                CDN_HOST: [CDN_IP],
                INTERNAL_HOST: [INTERNAL_IP],
            }
        )
        self.resolve_error = resolve_error
        self.resolutions: list[str] = []
        self.requests: list[dict] = []

    # -- setup ------------------------------------------------------------

    def serve(self, url: str, resource: Resource) -> "FakeSite":
        self.resources[url] = resource
        return self

    def install(self, monkeypatch) -> "FakeSite":
        def _getaddrinfo(host, port, *args, **kwargs):
            self.resolutions.append(host)
            if self.resolve_error is not None:
                raise self.resolve_error
            answers = []
            for address in self.addresses.get(host, [PUBLIC_IP]):
                if ":" in address:
                    answers.append(
                        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, port, 0, 0))
                    )
                else:
                    answers.append(
                        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))
                    )
            return answers

        def _stream(client_self, method, url, **kwargs):
            headers = dict(kwargs.get("headers") or {})
            parsed = httpx.URL(url)
            # The request is pinned to an IP, so the Host header is the only
            # thing still saying which site this was meant for.
            hostname = headers.get("Host") or parsed.host
            logical = f"https://{hostname}{parsed.raw_path.decode()}"
            self.requests.append(
                {
                    "method": method,
                    "url": str(url),
                    "logical_url": logical,
                    "host": hostname,
                    "headers": headers,
                    "extensions": dict(kwargs.get("extensions") or {}),
                    "follow_redirects": client_self.follow_redirects,
                    "timeout": client_self.timeout,
                }
            )
            resource = self.resources.get(logical)
            if resource is None:
                return _StreamContext(FakeResponse(Resource(status_code=404)))
            if resource.error is not None:
                return _StreamContext(error=resource.error)
            return _StreamContext(FakeResponse(resource))

        monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)
        monkeypatch.setattr(httpx.AsyncClient, "stream", _stream)
        return self

    # -- inspection -------------------------------------------------------

    def fetched(self) -> list[str]:
        return [request["logical_url"] for request in self.requests]

    def scripts_fetched(self) -> list[str]:
        return [url for url in self.fetched() if url != TARGET + "/"]


# The page every default test scans: one external script with no findings, one
# inline script with a finding, one external script with a different finding,
# and a second inline script with none -- so inline numbering has to skip the
# externals to come out right.
DEFAULT_HTML = f"""<!doctype html>
<html><head>
  <script src="/vendor.js"></script>
  <script>{BENIGN}</script>
  <script src="https://{CDN_HOST}/analytics.js"></script>
</head><body>
  <script type="text/javascript">{INLINE_VULNERABLE}</script>
</body></html>"""


def default_site(monkeypatch, html: str = DEFAULT_HTML) -> FakeSite:
    return FakeSite(
        {
            f"{TARGET}/": page(html),
            f"{TARGET}/vendor.js": script(BENIGN),
            f"https://{CDN_HOST}/analytics.js": script(EXTERNAL_VULNERABLE),
        }
    ).install(monkeypatch)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def site(monkeypatch):
    return default_site(monkeypatch)


@pytest.fixture(autouse=True)
def reset_limiters():
    """All three buckets: several tests here deliberately fill one of them."""
    for limiter in (
        web_scan_module._js_limiter,
        web_scan_module._headers_limiter,
        web_scan_module._limiter,
    ):
        limiter.reset()
    yield
    for limiter in (
        web_scan_module._js_limiter,
        web_scan_module._headers_limiter,
        web_scan_module._limiter,
    ):
        limiter.reset()


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
    return client.post("/web-scan/javascript", json={"url": url})


def by_source(body) -> dict:
    references = {}
    for reference in body["references"]:
        references[reference["source"]] = reference
    return references


def findings_by_file(body) -> dict:
    grouped: dict[str, list] = {}
    for finding in body["findings"]:
        grouped.setdefault(finding["file"], []).append(finding)
    return grouped


# ---------------------------------------------------------------------------
# Inline and external together
# ---------------------------------------------------------------------------


class TestAPageWithInlineAndExternalScripts:
    """The core of the phase: two kinds of script, two findings, correctly
    attributed to the places they actually came from."""

    def test_both_the_inline_and_the_external_finding_are_reported(self, client, site):
        response = scan(client)
        assert response.status_code == 200
        algorithms = {finding["algorithm"] for finding in response.json()["findings"]}
        assert algorithms == {"RSA", "ECC"}

    def test_the_inline_finding_is_labelled_by_its_position_in_the_document(
        self, client, site
    ):
        """Two inline scripts on the page; the vulnerable one is the second."""
        grouped = findings_by_file(scan(client).json())
        assert "inline script #2" in grouped
        assert [f["algorithm"] for f in grouped["inline script #2"]] == ["RSA"]

    def test_inline_numbering_counts_inline_scripts_only_in_document_order(
        self, client, site
    ):
        """The externals sit between the two inline scripts and must not consume
        a number -- otherwise the vulnerable one would be called #4."""
        sources = [
            reference["source"]
            for reference in scan(client).json()["references"]
            if reference["kind"] == "inline"
        ]
        assert sources == ["inline script #1", "inline script #2"]

    def test_the_external_finding_is_labelled_by_the_url_it_came_from(
        self, client, site
    ):
        grouped = findings_by_file(scan(client).json())
        assert f"https://{CDN_HOST}/analytics.js" in grouped
        assert [
            f["algorithm"] for f in grouped[f"https://{CDN_HOST}/analytics.js"]
        ] == ["ECC"]

    def test_the_two_findings_are_not_attributed_to_each_others_sources(
        self, client, site
    ):
        grouped = findings_by_file(scan(client).json())
        assert set(grouped) == {"inline script #2", f"https://{CDN_HOST}/analytics.js"}

    def test_a_relative_src_is_resolved_against_the_page(self, client, site):
        references = by_source(scan(client).json())
        assert f"{TARGET}/vendor.js" in references
        assert references[f"{TARGET}/vendor.js"]["raw_src"] == "/vendor.js"

    def test_findings_have_the_same_shape_a_repository_scan_produces(
        self, client, site
    ):
        """Same producer, so the same object -- a renderer must not need to know
        whether a finding came from a checkout or from a live page."""
        for finding in scan(client).json()["findings"]:
            assert set(finding) >= {
                "file",
                "language",
                "line",
                "algorithm",
                "severity",
                "quantum_vulnerable",
                "replacement",
                "fix_snippet",
            }
            assert finding["language"] == "javascript"

    def test_every_script_the_page_mentions_appears_in_the_inventory(
        self, client, site
    ):
        references = by_source(scan(client).json())
        assert set(references) == {
            f"{TARGET}/vendor.js",
            "inline script #1",
            f"https://{CDN_HOST}/analytics.js",
            "inline script #2",
        }

    def test_the_scanned_scripts_are_marked_scanned_and_carry_their_size(
        self, client, site
    ):
        references = by_source(scan(client).json())
        for source in references:
            assert references[source]["scanned"] is True, source
            assert references[source]["skip_reason"] is None, source
        assert references[f"https://{CDN_HOST}/analytics.js"]["size_bytes"] == len(
            EXTERNAL_VULNERABLE
        )

    def test_the_source_text_never_leaves_the_backend(self, client, site):
        """The inventory says what was read, not what it said."""
        for reference in scan(client).json()["references"]:
            assert "_text" not in reference

    def test_the_report_names_the_host_and_the_address_it_used(self, client, site):
        body = scan(client).json()
        assert body["host"] == TARGET_HOST
        assert body["port"] == 443
        assert body["scanned_ip"] == PUBLIC_IP
        assert body["resolved_ips"] == [PUBLIC_IP]
        assert body["status_code"] == 200

    def test_the_summary_counts_the_inventory_and_the_findings_separately(
        self, client, site
    ):
        summary = scan(client).json()["summary"]
        assert summary["scripts_found"] == 4
        assert summary["inline_found"] == 2
        assert summary["external_found"] == 2
        assert summary["scripts_scanned"] == 4
        assert summary["scripts_skipped"] == 0
        assert summary["total_findings"] == 2
        assert summary["severity_summary"]["critical"] == 2
        assert summary["algorithms_found"] == ["ECC", "RSA"]

    def test_a_clean_page_is_a_200_with_an_inventory_and_no_findings(
        self, client, monkeypatch
    ):
        """An empty findings list and a full inventory is an answer, not a
        failure -- the two lists exist separately for exactly this case."""
        default_site(
            monkeypatch,
            f'<html><script src="/vendor.js"></script><script>{BENIGN}</script></html>',
        )
        body = scan(client).json()
        assert body["findings"] == []
        assert body["summary"]["scripts_scanned"] == 2
        assert body["notes"] == []

    def test_a_page_with_no_scripts_at_all_is_still_a_report(self, client, monkeypatch):
        default_site(monkeypatch, "<html><body><p>Nothing here.</p></body></html>")
        body = scan(client).json()
        assert body["references"] == []
        assert body["findings"] == []
        assert body["summary"]["scripts_found"] == 0

    def test_the_requests_are_pinned_to_the_validated_addresses(self, client, site):
        """DNS-rebinding defence, carried over from the two earlier phases and
        applied to script hosts too: httpx would resolve each name again, and
        the second answer need not match the one the guard judged."""
        scan(client)
        by_host = {request["host"]: request for request in site.requests}
        assert PUBLIC_IP in by_host[TARGET_HOST]["url"]
        assert CDN_IP in by_host[CDN_HOST]["url"]
        for hostname, request in by_host.items():
            assert request["headers"]["Host"] == hostname
            assert request["extensions"]["sni_hostname"] == hostname
            assert request["follow_redirects"] is False


# ---------------------------------------------------------------------------
# The external-script cap
# ---------------------------------------------------------------------------


class TestMoreExternalScriptsThanTheCapAllows:
    TOTAL = 25

    @pytest.fixture
    def crowded(self, monkeypatch):
        tags = "".join(
            f'<script src="https://{CDN_HOST}/s{index:02d}.js"></script>'
            for index in range(self.TOTAL)
        )
        resources = {f"{TARGET}/": page(f"<html><head>{tags}</head></html>")}
        for index in range(self.TOTAL):
            resources[f"https://{CDN_HOST}/s{index:02d}.js"] = script(
                EXTERNAL_VULNERABLE
            )
        return FakeSite(resources).install(monkeypatch)

    def test_the_cap_is_twenty(self):
        assert MAX_EXTERNAL_SCRIPTS == 20

    def test_only_the_first_twenty_are_actually_fetched(self, client, crowded):
        assert scan(client).status_code == 200
        assert len(crowded.scripts_fetched()) == MAX_EXTERNAL_SCRIPTS

    def test_the_twenty_fetched_are_the_first_twenty_in_document_order(
        self, client, crowded
    ):
        scan(client)
        assert crowded.scripts_fetched() == [
            f"https://{CDN_HOST}/s{index:02d}.js"
            for index in range(MAX_EXTERNAL_SCRIPTS)
        ]

    def test_the_response_notes_the_true_total_found_not_the_number_scanned(
        self, client, crowded
    ):
        body = scan(client).json()
        assert len(body["notes"]) == 1
        note = body["notes"][0]
        assert f"{self.TOTAL} external scripts were found" in note
        assert f"first {MAX_EXTERNAL_SCRIPTS}" in note
        assert f"{self.TOTAL - MAX_EXTERNAL_SCRIPTS} were not" in note

    def test_every_script_over_the_cap_is_still_inventoried_with_a_reason(
        self, client, crowded
    ):
        references = by_source(scan(client).json())
        assert len(references) == self.TOTAL
        for index in range(MAX_EXTERNAL_SCRIPTS, self.TOTAL):
            reference = references[f"https://{CDN_HOST}/s{index:02d}.js"]
            assert reference["skip_reason"] == SKIP_OVER_CAP
            assert reference["scanned"] is False

    def test_the_summary_reports_the_true_total_and_the_number_scanned(
        self, client, crowded
    ):
        summary = scan(client).json()["summary"]
        assert summary["external_found"] == self.TOTAL
        assert summary["scripts_scanned"] == MAX_EXTERNAL_SCRIPTS
        assert summary["scripts_skipped"] == self.TOTAL - MAX_EXTERNAL_SCRIPTS

    def test_findings_come_only_from_the_scripts_that_were_read(
        self, client, crowded
    ):
        grouped = findings_by_file(scan(client).json())
        assert len(grouped) == MAX_EXTERNAL_SCRIPTS
        assert f"https://{CDN_HOST}/s20.js" not in grouped

    def test_exactly_the_cap_is_not_over_the_cap(self, client, monkeypatch):
        """Twenty scripts must produce no note; the boundary is off-by-one bait."""
        tags = "".join(
            f'<script src="https://{CDN_HOST}/s{index:02d}.js"></script>'
            for index in range(MAX_EXTERNAL_SCRIPTS)
        )
        resources = {f"{TARGET}/": page(f"<html>{tags}</html>")}
        for index in range(MAX_EXTERNAL_SCRIPTS):
            resources[f"https://{CDN_HOST}/s{index:02d}.js"] = script(BENIGN)
        fake = FakeSite(resources).install(monkeypatch)
        body = scan(client).json()
        assert body["notes"] == []
        assert len(fake.scripts_fetched()) == MAX_EXTERNAL_SCRIPTS
        assert body["summary"]["scripts_skipped"] == 0


# ---------------------------------------------------------------------------
# The per-script size limit
# ---------------------------------------------------------------------------


class TestAnOversizedExternalScript:
    """One enormous bundle degrades the report. It must not fail it."""

    HTML = (
        f'<html><head><script src="https://{CDN_HOST}/huge.js"></script>'
        f'<script src="https://{CDN_HOST}/analytics.js"></script></head>'
        f"<body><script>{INLINE_VULNERABLE}</script></body></html>"
    )

    def _site(self, monkeypatch, huge: Resource) -> FakeSite:
        return FakeSite(
            {
                f"{TARGET}/": page(self.HTML),
                f"https://{CDN_HOST}/huge.js": huge,
                f"https://{CDN_HOST}/analytics.js": script(EXTERNAL_VULNERABLE),
            }
        ).install(monkeypatch)

    @pytest.fixture
    def honest(self, monkeypatch):
        """A server that declares the real, oversized length."""
        return self._site(
            monkeypatch, script("x" * (MAX_SCRIPT_BYTES + 1))
        )

    @pytest.fixture
    def undeclared(self, monkeypatch):
        """No content-length at all, so only the running total can catch it.

        This is the case the header check cannot see and the reason the fetch is
        streamed rather than read whole.
        """
        return self._site(
            monkeypatch,
            script(
                "x" * (MAX_SCRIPT_BYTES + 4096),
                declared_length=None,
                chunk_size=128 * 1024,
            ),
        )

    def test_the_limit_is_one_megabyte(self):
        assert MAX_SCRIPT_BYTES == 1024 * 1024

    def test_a_declared_oversize_is_skipped_and_the_scan_still_succeeds(
        self, client, honest
    ):
        response = scan(client)
        assert response.status_code == 200
        reference = by_source(response.json())[f"https://{CDN_HOST}/huge.js"]
        assert reference["skip_reason"] == SKIP_TOO_LARGE
        assert reference["scanned"] is False

    def test_an_undeclared_oversize_is_caught_by_the_running_total(
        self, client, undeclared
    ):
        response = scan(client)
        assert response.status_code == 200
        reference = by_source(response.json())[f"https://{CDN_HOST}/huge.js"]
        assert reference["skip_reason"] == SKIP_TOO_LARGE

    @pytest.mark.parametrize("fixture_name", ["honest", "undeclared"])
    def test_the_other_scripts_are_still_scanned_and_still_report(
        self, client, request, fixture_name
    ):
        request.getfixturevalue(fixture_name)
        body = scan(client).json()
        grouped = findings_by_file(body)
        assert set(grouped) == {
            "inline script #1",
            f"https://{CDN_HOST}/analytics.js",
        }
        assert body["summary"]["scripts_scanned"] == 2
        assert body["summary"]["scripts_skipped"] == 1

    def test_a_script_just_under_the_limit_is_read_in_full(self, client, monkeypatch):
        """The boundary from the other side: at the limit is not over it."""
        padding = MAX_SCRIPT_BYTES - len(EXTERNAL_VULNERABLE) - 1
        body_text = EXTERNAL_VULNERABLE + "\n" + ("/" * padding)
        self._site(monkeypatch, script(body_text, chunk_size=64 * 1024))
        reference = by_source(scan(client).json())[f"https://{CDN_HOST}/huge.js"]
        assert reference["skip_reason"] is None
        assert reference["size_bytes"] == MAX_SCRIPT_BYTES


# ---------------------------------------------------------------------------
# Script types that are not JavaScript
# ---------------------------------------------------------------------------


class TestScriptTagsThatAreNotJavaScript:
    """A script tag is a container, not a promise that the contents run.

    The payloads here are chosen so that scanning them *would* produce findings.
    A test whose excluded content is inert would pass whether the exclusion
    worked or not.
    """

    def _scan_with(self, client, monkeypatch, tag: str):
        html = f"<html><head>{tag}</head></html>"
        FakeSite(
            {
                f"{TARGET}/": page(html),
                f"https://{CDN_HOST}/data.js": script(EXTERNAL_VULNERABLE),
            }
        ).install(monkeypatch)
        return scan(client)

    def test_an_inline_ld_json_block_is_skipped_and_produces_no_findings(
        self, client, monkeypatch
    ):
        body = self._scan_with(
            client, monkeypatch, f'<script type="application/ld+json">{LD_JSON}</script>'
        ).json()
        assert body["findings"] == []
        reference = by_source(body)["inline script #1"]
        assert reference["skip_reason"] == SKIP_EXCLUDED_TYPE
        assert reference["scanned"] is False
        assert reference["type"] == "application/ld+json"

    def test_the_excluded_block_would_otherwise_have_produced_findings(self):
        """Proves the previous test is testing something."""
        from scanner_engine import scan_source

        assert scan_source("inline script #1", "javascript", LD_JSON)

    @pytest.mark.parametrize(
        "media_type",
        [
            "application/ld+json",
            "application/json",
            "text/template",
            "text/x-handlebars-template",
            "text/plain",
        ],
    )
    def test_a_non_executable_type_is_skipped(self, client, monkeypatch, media_type):
        body = self._scan_with(
            client, monkeypatch, f'<script type="{media_type}">{INLINE_VULNERABLE}</script>'
        ).json()
        assert body["findings"] == []
        assert by_source(body)["inline script #1"]["skip_reason"] == SKIP_EXCLUDED_TYPE

    def test_an_external_script_with_an_excluded_type_is_never_fetched(
        self, client, monkeypatch
    ):
        """Not fetching it is the point: an excluded type must cost no request."""
        html = (
            f'<html><script type="application/ld+json" '
            f'src="https://{CDN_HOST}/data.js"></script></html>'
        )
        fake = FakeSite(
            {
                f"{TARGET}/": page(html),
                f"https://{CDN_HOST}/data.js": script(EXTERNAL_VULNERABLE),
            }
        ).install(monkeypatch)
        body = scan(client).json()
        assert fake.scripts_fetched() == []
        assert body["findings"] == []
        assert (
            by_source(body)[f"https://{CDN_HOST}/data.js"]["skip_reason"]
            == SKIP_EXCLUDED_TYPE
        )

    @pytest.mark.parametrize(
        "media_type",
        [
            "",
            "text/javascript",
            "application/javascript",
            "module",
            "text/javascript; charset=utf-8",
            "TEXT/JavaScript",
            "  module  ",
        ],
    )
    def test_a_type_that_does_name_javascript_is_scanned(
        self, client, monkeypatch, media_type
    ):
        """Including the shapes real servers send: a charset parameter, odd case
        and stray whitespace all still name JavaScript."""
        attribute = f' type="{media_type}"' if media_type else ""
        body = self._scan_with(
            client, monkeypatch, f"<script{attribute}>{INLINE_VULNERABLE}</script>"
        ).json()
        assert [f["algorithm"] for f in body["findings"]] == ["RSA"]
        assert by_source(body)["inline script #1"]["skip_reason"] is None


# ---------------------------------------------------------------------------
# The shared SSRF guard, applied one level down
# ---------------------------------------------------------------------------


class TestEveryScriptUrlIsJudgedOnItsOwn:
    """The thing this phase adds to the guard's job.

    The page is public and passes; one of its <script src> attributes names a
    host that resolves onto the private network. Validating the page is not
    enough, and this is the test that says so. The blocklist itself is
    test_ssrf_guard.py's job and is not duplicated here.
    """

    HTML = (
        f'<html><head><script src="https://{INTERNAL_HOST}/collect.js"></script>'
        f'<script src="https://{CDN_HOST}/analytics.js"></script></head></html>'
    )

    @pytest.fixture
    def mixed(self, monkeypatch):
        return FakeSite(
            {
                f"{TARGET}/": page(self.HTML),
                f"https://{INTERNAL_HOST}/collect.js": script(EXTERNAL_VULNERABLE),
                f"https://{CDN_HOST}/analytics.js": script(EXTERNAL_VULNERABLE),
            }
        ).install(monkeypatch)

    def test_the_internal_script_is_never_requested(self, client, mixed):
        scan(client)
        assert f"https://{INTERNAL_HOST}/collect.js" not in mixed.fetched()
        assert INTERNAL_IP not in " ".join(request["url"] for request in mixed.requests)

    def test_the_refusal_names_the_address_and_the_rule_that_fired(
        self, client, mixed
    ):
        reference = by_source(scan(client).json())[
            f"https://{INTERNAL_HOST}/collect.js"
        ]
        assert reference["skip_reason"].startswith(SKIP_BLOCKED)
        assert INTERNAL_IP in reference["skip_reason"]
        assert "private address" in reference["skip_reason"]
        assert reference["scanned"] is False

    def test_one_blocked_script_does_not_fail_the_scan(self, client, mixed):
        """A blocked script is inventoried, not raised. The page still reports."""
        response = scan(client)
        assert response.status_code == 200
        body = response.json()
        assert findings_by_file(body).keys() == {f"https://{CDN_HOST}/analytics.js"}
        assert body["summary"]["scripts_scanned"] == 1
        assert body["summary"]["scripts_skipped"] == 1

    def test_the_module_uses_the_shared_guard_rather_than_its_own_copy(self):
        import inspect

        import ssrf_guard

        assert js_web_scanner.validate_target is ssrf_guard.validate_target
        source = inspect.getsource(js_web_scanner)
        # No second implementation of the blocklist grew here.
        for leftover in ("ipaddress", "is_private", "getaddrinfo"):
            assert leftover not in source

    def test_the_guard_is_called_once_for_the_page_and_once_per_script(
        self, client, mixed
    ):
        scan(client)
        assert mixed.resolutions == [TARGET_HOST, INTERNAL_HOST, CDN_HOST]

    def test_a_private_page_is_refused_before_anything_is_fetched(
        self, client, monkeypatch
    ):
        fake = FakeSite(
            {f"{TARGET}/": page(DEFAULT_HTML)},
            addresses={TARGET_HOST: ["127.0.0.1"]},
        ).install(monkeypatch)
        response = scan(client)
        assert response.status_code == 400
        assert fake.requests == []

    def test_an_http_url_is_refused_by_the_shared_parser(self, client, site):
        response = scan(client, "http://example.com")
        assert response.status_code == 400
        assert site.resolutions == []
        assert site.requests == []


# ---------------------------------------------------------------------------
# Page-level failures
# ---------------------------------------------------------------------------


class TestThePageItselfFailing:
    """A script that fails is inventoried. A page that fails leaves nothing to
    report on, so it is the one thing that becomes an error response."""

    def test_a_connection_failure_is_a_clean_502(self, client, monkeypatch):
        FakeSite(
            {
                f"{TARGET}/": Resource(
                    error=httpx.ConnectError(
                        "refused", request=httpx.Request("GET", TARGET)
                    )
                )
            }
        ).install(monkeypatch)
        response = scan(client)
        assert response.status_code == 502
        detail = response.json()["detail"]
        assert TARGET_HOST in detail
        assert "Traceback" not in detail
        assert "js_web_scanner" not in detail

    def test_a_dns_failure_comes_from_the_shared_guard(self, client, monkeypatch):
        fake = FakeSite(
            resolve_error=socket.gaierror(-2, "Name or service not known")
        ).install(monkeypatch)
        response = scan(client)
        assert response.status_code == 502
        assert "does not resolve" in response.json()["detail"]
        assert fake.requests == []

    def test_an_unexpected_exception_becomes_a_500_with_nothing_leaked(
        self, client, monkeypatch
    ):
        async def explode(url):
            raise RuntimeError("secret internal detail: /srv/qlint/config")

        monkeypatch.setattr(web_scan_module, "js_scan_url", explode)
        response = scan(client)
        assert response.status_code == 500
        assert "secret internal detail" not in response.json()["detail"]
        assert "/srv/qlint" not in response.json()["detail"]


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class TestTheRouteRequiresASession:
    def test_a_request_with_no_token_is_401_and_does_nothing(self, app, site):
        response = TestClient(app).post(
            "/web-scan/javascript", json={"url": TARGET}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Not authenticated"
        assert site.resolutions == []
        assert site.requests == []

    def test_a_request_with_a_junk_token_is_401(self, app, site):
        response = TestClient(app).post(
            "/web-scan/javascript",
            json={"url": TARGET},
            headers={"Authorization": "Bearer not-a-real-jwt"},
        )
        assert response.status_code == 401
        assert site.requests == []

    def test_an_unauthenticated_request_does_not_spend_the_rate_limit(self, app, site):
        unauthenticated = TestClient(app)
        for _ in range(web_scan_module._js_limiter.max_requests + 5):
            assert unauthenticated.post(
                "/web-scan/javascript", json={"url": TARGET}
            ).status_code == 401
        assert web_scan_module._js_limiter._hits == {}


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestTheRateLimit:
    def test_the_window_is_fifteen_scans_per_twenty_four_hours(self):
        assert web_scan_module._js_limiter.max_requests == 15
        assert web_scan_module._js_limiter.window_seconds == 86400

    def test_the_window_closes_after_fifteen_scans(self, client, site):
        for _ in range(15):
            assert scan(client).status_code == 200
        blocked = scan(client)
        assert blocked.status_code == 429
        detail = blocked.json()["detail"]
        assert detail.startswith("Rate limit exceeded: 15 requests per 1 day.")
        assert "1440 minutes" not in detail
        assert "86400s" not in detail
        # Loose on purpose, as in the header file: the remaining wait is the
        # window minus however long these fifteen scans took.
        assert "Try again in 1 day." in detail or "Try again in 24 hours." in detail

    def test_the_window_is_keyed_on_the_account_id(self, client, site):
        scan(client)
        assert list(web_scan_module._js_limiter._hits) == [f"user:{SCAN_USER['_id']}"]

    def test_two_accounts_each_get_their_own_allowance(self, app, site):
        app.dependency_overrides[get_current_user] = lambda: SCAN_USER
        try:
            for _ in range(15):
                assert TestClient(app).post(
                    "/web-scan/javascript", json={"url": TARGET}
                ).status_code == 200
            assert TestClient(app).post(
                "/web-scan/javascript", json={"url": TARGET}
            ).status_code == 429

            app.dependency_overrides[get_current_user] = lambda: SECOND_USER
            assert TestClient(app).post(
                "/web-scan/javascript", json={"url": TARGET}
            ).status_code == 200
        finally:
            app.dependency_overrides.clear()

    def test_the_route_is_limited_per_user_not_per_address(self):
        """Render's proxy collapses every visitor onto one internal address, so
        an address-keyed limit here would be a limit on the whole site at once."""
        import inspect

        source = inspect.getsource(web_scan_module)
        assert "rate_limit_by_user(_js_limiter)" in source
        assert "rate_limit(_js_limiter)" not in source


class TestTheThreeBucketsAreIndependent:
    """Three endpoints, three limiters, three separate allowances.

    They cost very different amounts to serve -- a header check is one GET, a
    TLS scan is a handshake and a certificate parse, and this one is up to
    twenty-one outbound connections -- so sharing a bucket would make the
    cheapest operation pay the most expensive one's price.
    """

    @staticmethod
    def _stub_tls(monkeypatch):
        """A TLS scan that is admitted and then fails, so a 502 means "not rate
        limited" and a 429 means it was."""
        import tls_scanner

        def _handshake(ip_address, hostname, verify=True):
            raise ConnectionRefusedError(111, "Connection refused")

        monkeypatch.setattr(tls_scanner, "_handshake", _handshake)

    def test_the_three_limiters_are_distinct_objects_with_distinct_allowances(self):
        limiters = (
            web_scan_module._js_limiter,
            web_scan_module._headers_limiter,
            web_scan_module._limiter,
        )
        assert len({id(limiter) for limiter in limiters}) == 3
        assert web_scan_module._js_limiter.max_requests == 15
        assert web_scan_module._headers_limiter.max_requests == 20
        assert web_scan_module._limiter.max_requests == 10

    def test_exhausting_the_javascript_limit_leaves_the_other_two_untouched(
        self, client, site, monkeypatch
    ):
        for _ in range(15):
            assert scan(client).status_code == 200
        assert scan(client).status_code == 429

        assert web_scan_module._headers_limiter._hits == {}
        assert web_scan_module._limiter._hits == {}

        # And both still answer. The header endpoint uses client.get, which this
        # file's fake does not patch, so it is stubbed here directly.
        async def _get(client_self, url, **kwargs):
            return httpx.Response(
                200, headers={}, request=httpx.Request("GET", url)
            )

        monkeypatch.setattr(httpx.AsyncClient, "get", _get)
        assert (
            client.post("/web-scan/headers", json={"url": TARGET}).status_code == 200
        )

        self._stub_tls(monkeypatch)
        # 502, not 429: the request was admitted and the (stubbed) scan failed.
        assert client.post("/web-scan/tls", json={"url": TARGET}).status_code == 502

    def test_exhausting_the_header_limit_leaves_the_javascript_allowance_intact(
        self, client, site, monkeypatch
    ):
        async def _get(client_self, url, **kwargs):
            return httpx.Response(
                200, headers={}, request=httpx.Request("GET", url)
            )

        monkeypatch.setattr(httpx.AsyncClient, "get", _get)
        for _ in range(web_scan_module._headers_limiter.max_requests):
            assert (
                client.post("/web-scan/headers", json={"url": TARGET}).status_code
                == 200
            )
        assert (
            client.post("/web-scan/headers", json={"url": TARGET}).status_code == 429
        )

        assert web_scan_module._js_limiter._hits == {}
        assert scan(client).status_code == 200

    def test_exhausting_the_tls_limit_leaves_the_javascript_allowance_intact(
        self, client, site, monkeypatch
    ):
        self._stub_tls(monkeypatch)
        for _ in range(web_scan_module._limiter.max_requests):
            client.post("/web-scan/tls", json={"url": TARGET})
        assert client.post("/web-scan/tls", json={"url": TARGET}).status_code == 429

        assert web_scan_module._js_limiter._hits == {}
        assert scan(client).status_code == 200

    def test_the_javascript_bucket_is_not_shared_with_the_ai_endpoints_either(self):
        from routers import explain_router, patch_router

        assert web_scan_module._js_limiter is not explain_router._limiter
        assert web_scan_module._js_limiter is not patch_router._limiter


# ---------------------------------------------------------------------------
# Two httpx mechanisms this module depends on
# ---------------------------------------------------------------------------


class _PinnedTarget:
    """The shape validate_target returns, enough of it for _fetch_bounded."""

    def __init__(self, url=f"https://{CDN_HOST}/app.js", address=CDN_IP):
        self.url = url
        self.address = address
        self.hostname = httpx.URL(url).host
        self.port = 443
        self.addresses = [address]


class _ChunkedStream(httpx.AsyncByteStream):
    """A response body that arrives in pieces, with no content-length."""

    def __init__(self, chunks):
        self._chunks = chunks

    async def __aiter__(self):
        for chunk in self._chunks:
            yield chunk


class TestTheTimeBudgetReachesTheWire:
    """_fetch_external_scripts reassigns client.timeout inside its loop, on a
    client that is already open, to hand each fetch only the time left in the
    overall budget. Whether that assignment affects anything is a property of
    httpx, not of this repository, so it is pinned down here against a real
    client rather than assumed.

    If httpx ever snapshots the timeout at construction, this test fails and the
    fix is to pass timeout= per request instead.
    """

    @pytest.mark.asyncio
    async def test_reassigning_client_timeout_changes_the_next_request(self):
        seen = []

        async def handler(request):
            seen.append(request.extensions.get("timeout"))
            return httpx.Response(200, content=b"var a = 1;")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport, timeout=15.0) as client:
            await js_web_scanner._fetch_bounded(client, _PinnedTarget(), 4096)
            client.timeout = httpx.Timeout(3.5)
            await js_web_scanner._fetch_bounded(client, _PinnedTarget(), 4096)

        assert seen[0]["read"] == 15.0
        assert seen[1]["read"] == 3.5, (
            "httpx did not pick up the reassigned client.timeout; the remaining "
            "time budget must be passed per request instead"
        )

    @pytest.mark.asyncio
    async def test_the_loop_hands_each_script_the_time_that_is_actually_left(
        self, monkeypatch
    ):
        """The same property, exercised through the real loop rather than
        directly: each successive fetch must be given strictly less time."""
        import time

        seen = []

        async def handler(request):
            seen.append(request.extensions["timeout"]["read"])
            return httpx.Response(
                200,
                headers={"content-type": "text/javascript"},
                content=EXTERNAL_VULNERABLE.encode(),
            )

        async def fake_validate(url):
            return _PinnedTarget(url)

        monkeypatch.setattr(
            js_web_scanner,
            "_client",
            lambda timeout: httpx.AsyncClient(
                timeout=timeout,
                transport=httpx.MockTransport(handler),
                follow_redirects=False,
            ),
        )
        monkeypatch.setattr(js_web_scanner, "validate_target", fake_validate)

        references = [
            {
                "kind": "external",
                "url": f"https://{CDN_HOST}/s{index}.js",
                "source": f"https://{CDN_HOST}/s{index}.js",
                "skip_reason": None,
                "size_bytes": None,
            }
            for index in range(3)
        ]
        deadline = time.monotonic() + js_web_scanner.OVERALL_TIMEOUT_SECONDS
        time_limited = await js_web_scanner._fetch_external_scripts(
            references, deadline
        )

        assert time_limited is False
        assert len(seen) == 3
        # Strictly decreasing: each fetch got the deadline's remainder, not the
        # whole budget over again.
        assert seen[0] > seen[1] > seen[2]
        assert all(value <= js_web_scanner.OVERALL_TIMEOUT_SECONDS for value in seen)

    @pytest.mark.asyncio
    async def test_a_deadline_already_past_skips_the_rest_and_says_so(
        self, monkeypatch
    ):
        import time

        async def fake_validate(url):  # pragma: no cover - must never be reached
            raise AssertionError("a script was validated after the budget expired")

        monkeypatch.setattr(js_web_scanner, "validate_target", fake_validate)
        references = [
            {
                "kind": "external",
                "url": f"https://{CDN_HOST}/late.js",
                "source": f"https://{CDN_HOST}/late.js",
                "skip_reason": None,
                "size_bytes": None,
            }
        ]
        time_limited = await js_web_scanner._fetch_external_scripts(
            references, time.monotonic() - 1
        )
        assert time_limited is True
        assert references[0]["skip_reason"] == js_web_scanner.SKIP_TIME_LIMIT


class TestTheSizeLimitEscapesTheStreamContext:
    """_fetch_bounded raises _TooLarge from inside `async with client.stream(...)`.

    httpx's stream() is an @asynccontextmanager with a `finally: await
    response.aclose()`, so an exception raised in the body travels back through
    a generator's athrow and past that cleanup. That it arrives at the caller
    intact -- rather than being swallowed, or replaced by whatever aclose()
    raises on a half-read stream -- is the thing being pinned down, and a fake
    context manager could not test it.
    """

    def _limit_case(self, handler, limit=1024):
        async def run():
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler)
            ) as client:
                return await js_web_scanner._fetch_bounded(
                    client, _PinnedTarget(), limit
                )

        return run

    @pytest.mark.asyncio
    async def test_an_honest_oversized_content_length_raises_too_large(self):
        async def handler(request):
            return httpx.Response(200, content=b"x" * 5000)

        with pytest.raises(js_web_scanner._TooLarge) as caught:
            await self._limit_case(handler)()
        assert caught.value.size == 5000

    @pytest.mark.asyncio
    async def test_a_body_streamed_past_the_limit_raises_from_inside_the_read(self):
        """No content-length at all, so the header check cannot fire and the
        exception has to escape from the middle of aiter_bytes()."""

        async def handler(request):
            return httpx.Response(
                200,
                headers={"content-type": "text/javascript"},
                stream=_ChunkedStream([b"y" * 400] * 10),
            )

        with pytest.raises(js_web_scanner._TooLarge):
            await self._limit_case(handler)()

    @pytest.mark.asyncio
    async def test_a_server_that_understates_its_length_is_still_caught(self):
        """content-length: 10 and a megabyte of body. The declared value is a
        hint, and the running total is the control."""

        async def handler(request):
            return httpx.Response(
                200,
                headers={"content-length": "10"},
                stream=_ChunkedStream([b"z" * 400] * 10),
            )

        with pytest.raises(js_web_scanner._TooLarge):
            await self._limit_case(handler)()

    @pytest.mark.asyncio
    async def test_an_unparseable_content_length_falls_through_to_the_total(self):
        async def handler(request):
            return httpx.Response(
                200,
                headers={"content-length": "not-a-number"},
                stream=_ChunkedStream([b"q" * 400] * 10),
            )

        with pytest.raises(js_web_scanner._TooLarge):
            await self._limit_case(handler)()

    @pytest.mark.asyncio
    async def test_a_body_within_the_limit_returns_normally(self):
        """The other half of the assertion: the guard must not fire on a file
        that is simply fine."""

        async def handler(request):
            return httpx.Response(
                200,
                headers={"content-type": "text/javascript; charset=utf-8"},
                content=EXTERNAL_VULNERABLE.encode(),
            )

        status_code, content_type, raw = await self._limit_case(handler)()
        assert status_code == 200
        assert content_type == "text/javascript; charset=utf-8"
        assert raw == EXTERNAL_VULNERABLE.encode()

    @pytest.mark.asyncio
    async def test_the_page_fetch_turns_too_large_into_a_scan_error(
        self, monkeypatch
    ):
        """_TooLarge is caught at both call sites, and the page's site turns it
        into the module's own error rather than letting it escape."""

        async def handler(request):
            return httpx.Response(200, content=b"<html>" + b"x" * 16)

        async def fake_validate(url):
            return _PinnedTarget(TARGET)

        monkeypatch.setattr(js_web_scanner, "validate_target", fake_validate)
        monkeypatch.setattr(
            js_web_scanner,
            "_client",
            lambda timeout: httpx.AsyncClient(
                timeout=timeout,
                transport=httpx.MockTransport(handler),
                follow_redirects=False,
            ),
        )
        monkeypatch.setattr(js_web_scanner, "MAX_PAGE_BYTES", 4)

        with pytest.raises(js_web_scanner.JSWebScanError) as caught:
            await js_web_scanner.scan_url(TARGET)
        assert "larger than" in str(caught.value)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestTheRouterIsRegistered:
    def test_the_javascript_route_is_registered(self):
        """Narrowed, as this test said it would be when a Phase 4 endpoint
        arrived. The whole-set assertion now lives in the newest phase's file,
        test_web_scan_combined.py, so adding an endpoint still means editing
        one file rather than every older one.
        """
        paths = {
            route.path for route in web_scan_router.routes if hasattr(route, "path")
        }
        assert "/web-scan/javascript" in paths

    def test_the_endpoint_only_answers_post(self):
        methods = {
            route.path: route.methods
            for route in web_scan_router.routes
            if hasattr(route, "path")
        }
        assert methods["/web-scan/javascript"] == {"POST"}

    def test_main_still_mounts_the_router_once(self):
        """Read rather than imported: main pulls in oqs via benchmark_router."""
        from pathlib import Path

        source = (Path(__file__).resolve().parent.parent / "main.py").read_text(
            encoding="utf-8"
        )
        assert source.count("app.include_router(web_scan_router") == 1

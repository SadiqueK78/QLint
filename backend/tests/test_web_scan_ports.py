"""The HTTPS port allowlist, across all three website scanners.

Every website scan used to be hardcoded to port 443 and refused a URL naming
any other. It now accepts five: 443, which is still what a URL naming no port
is scanned on, plus 4443, 8443, 9443 and 10443.

Two properties matter, and they pull in opposite directions:

  * The allowlist is small and closed. An arbitrary caller-chosen port would
    turn these scanners into a port scanner running from the backend's address
    -- which is reconnaissance, and gives away most of what ssrf_guard's
    address checks exist to protect. So a port outside the set is refused,
    and refused before a socket is opened.
  * The allowlist is *one* definition. Three scanners agreeing today because
    three separate lists happen to hold the same five numbers is not the same
    thing as three scanners sharing one list, and the difference only shows up
    the first time somebody edits one of them. The last class in this file
    proves the sharing by mutating ssrf_guard.ALLOWED_PORTS and watching all
    three scanners change their answer.

Mocking matches the four existing website-scan test files: socket.getaddrinfo
is replaced so ssrf_guard's real parsing and address checks run on every
target, and only the outbound seams are faked -- tls_scanner._handshake for the
TLS scan, httpx.AsyncClient.get for the header scan and httpx.AsyncClient.send
for the JavaScript scan. Nothing here touches the network.
"""

import socket

import httpx
import pytest

import header_scanner
import js_web_scanner
import ssrf_guard
import tls_scanner
from ssrf_guard import ALLOWED_PORTS, HTTPS_PORT, InvalidTargetURLError, parse_target

TARGET_HOST = "example.com"
PUBLIC_IP = "93.184.216.34"

# The five, spelled out rather than derived from ALLOWED_PORTS, so that a test
# reading "these five are accepted" is testing the allowlist rather than
# restating it. A change to the constant that this list does not agree with is
# a failure, which is the point.
EXPECTED_PORTS = [443, 4443, 8443, 9443, 10443]

# Ports deliberately outside it: the two most obvious HTTP ports, a database, a
# mail port and the SSH port. Every one of them is something an attacker would
# like to know is open, which is why none of them is scannable.
REJECTED_PORTS = [80, 22, 8080, 5432, 25, 3000, 9444]

PAGE = b"<html><body><script>var x = 1;</script></body></html>"


@pytest.fixture(autouse=True)
def resolver(monkeypatch):
    """Every name resolves to one public address, so the guard lets it past."""

    def _getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, port))]

    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)


class RecordingHandshake:
    """tls_scanner._handshake, faked, recording the port it was handed."""

    def __init__(self):
        self.ports: list[int] = []

    def install(self, monkeypatch):
        def _handshake(ip_address, hostname, verify=True, port=443):
            self.ports.append(port)
            return {
                "protocol_raw": "TLSv1.3",
                "cipher_name": "TLS_AES_256_GCM_SHA384",
                "cipher_bits": 256,
                "key_exchange_group": None,
                # No certificate: parse_certificate fails and the scan errors
                # out, which is fine. Every test in this file asserts on where
                # the connection went, not on what came back from it.
                "certificate_der": b"",
                "peer_ip": ip_address,
            }

        monkeypatch.setattr(tls_scanner, "_handshake", _handshake)
        return self


class RecordingHTTP:
    """httpx's two outbound seams, faked, recording the URL each was given."""

    def __init__(self):
        self.urls: list[httpx.URL] = []

    def install(self, monkeypatch):
        outer = self

        async def _get(self, url, **kwargs):
            outer.urls.append(httpx.URL(url))
            return httpx.Response(
                200, headers={"content-type": "text/html"}, content=PAGE
            )

        async def _send(self, request, **kwargs):
            outer.urls.append(request.url)
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content=PAGE,
                request=request,
            )

        monkeypatch.setattr(httpx.AsyncClient, "get", _get)
        monkeypatch.setattr(httpx.AsyncClient, "send", _send)
        return self


@pytest.fixture
def handshake(monkeypatch):
    return RecordingHandshake().install(monkeypatch)


@pytest.fixture
def http(monkeypatch):
    return RecordingHTTP().install(monkeypatch)


def _port_of(url: httpx.URL) -> int:
    """The port a request actually goes to.

    httpx.URL.port is None when the port is the scheme's default, so an https
    URL on 443 reports None rather than 443. That is httpx being tidy, not the
    request going somewhere else.
    """
    return url.port or 443


async def _run(scan, url):
    """Run one scanner and swallow anything it says about the target.

    Every test here asks where the scan went, or whether it was refused before
    it went anywhere. A scan that got as far as opening a connection has
    answered the question, and what the fake site then failed to produce is a
    different file's subject.
    """
    try:
        return await scan(url)
    except (
        tls_scanner.TLSScanError,
        header_scanner.HeaderScanError,
        js_web_scanner.JSWebScanError,
    ):
        return None


# ---------------------------------------------------------------------------
# The allowlist itself
# ---------------------------------------------------------------------------


class TestTheAllowlist:
    def test_it_holds_exactly_the_five_documented_ports(self):
        assert sorted(ALLOWED_PORTS) == EXPECTED_PORTS

    def test_443_is_the_default_for_a_url_naming_no_port(self):
        assert HTTPS_PORT == 443
        assert parse_target(f"https://{TARGET_HOST}").port == 443
        assert parse_target(f"https://{TARGET_HOST}/a/path?q=1").port == 443

    @pytest.mark.parametrize("port", EXPECTED_PORTS)
    def test_each_allowed_port_survives_parsing(self, port):
        assert parse_target(f"https://{TARGET_HOST}:{port}").port == port

    @pytest.mark.parametrize("port", REJECTED_PORTS)
    def test_each_rejected_port_is_refused(self, port):
        with pytest.raises(InvalidTargetURLError):
            parse_target(f"https://{TARGET_HOST}:{port}")

    def test_the_refusal_lists_every_allowed_port(self):
        """A caller told only "that port is not allowed" has to guess which
        are. The message names all five."""
        with pytest.raises(InvalidTargetURLError) as raised:
            parse_target(f"https://{TARGET_HOST}:8080")
        message = str(raised.value)
        for port in EXPECTED_PORTS:
            assert str(port) in message
        assert "8080" in message


# ---------------------------------------------------------------------------
# Each scanner, on each allowed port
# ---------------------------------------------------------------------------


class TestTheTLSScannerHonoursTheAllowlist:
    @pytest.mark.parametrize("port", EXPECTED_PORTS)
    @pytest.mark.asyncio
    async def test_an_allowed_port_is_the_port_the_socket_goes_to(
        self, port, handshake
    ):
        await _run(tls_scanner.scan_url, f"https://{TARGET_HOST}:{port}")
        assert handshake.ports == [port]

    @pytest.mark.asyncio
    async def test_no_port_named_means_443(self, handshake):
        await _run(tls_scanner.scan_url, f"https://{TARGET_HOST}")
        assert handshake.ports == [443]

    @pytest.mark.parametrize("port", REJECTED_PORTS)
    @pytest.mark.asyncio
    async def test_a_rejected_port_never_reaches_a_socket(self, port, handshake):
        with pytest.raises(InvalidTargetURLError) as raised:
            await tls_scanner.scan_url(f"https://{TARGET_HOST}:{port}")
        for allowed in EXPECTED_PORTS:
            assert str(allowed) in str(raised.value)
        assert handshake.ports == []


class TestTheHeaderScannerHonoursTheAllowlist:
    @pytest.mark.parametrize("port", EXPECTED_PORTS)
    @pytest.mark.asyncio
    async def test_an_allowed_port_is_the_port_the_request_goes_to(self, port, http):
        await _run(header_scanner.scan_url, f"https://{TARGET_HOST}:{port}")
        assert [_port_of(url) for url in http.urls] == [port]
        # And to the address the guard approved, not to a re-resolved name.
        assert http.urls[0].host == PUBLIC_IP

    @pytest.mark.asyncio
    async def test_no_port_named_means_443(self, http):
        await _run(header_scanner.scan_url, f"https://{TARGET_HOST}")
        assert [_port_of(url) for url in http.urls] == [443]

    @pytest.mark.parametrize("port", REJECTED_PORTS)
    @pytest.mark.asyncio
    async def test_a_rejected_port_never_reaches_a_request(self, port, http):
        with pytest.raises(InvalidTargetURLError) as raised:
            await header_scanner.scan_url(f"https://{TARGET_HOST}:{port}")
        for allowed in EXPECTED_PORTS:
            assert str(allowed) in str(raised.value)
        assert http.urls == []


class TestTheJavaScriptScannerHonoursTheAllowlist:
    @pytest.mark.parametrize("port", EXPECTED_PORTS)
    @pytest.mark.asyncio
    async def test_an_allowed_port_is_the_port_the_page_is_fetched_on(
        self, port, http
    ):
        await _run(js_web_scanner.scan_url, f"https://{TARGET_HOST}:{port}")
        assert _port_of(http.urls[0]) == port
        assert http.urls[0].host == PUBLIC_IP

    @pytest.mark.asyncio
    async def test_no_port_named_means_443(self, http):
        await _run(js_web_scanner.scan_url, f"https://{TARGET_HOST}")
        assert _port_of(http.urls[0]) == 443

    @pytest.mark.parametrize("port", REJECTED_PORTS)
    @pytest.mark.asyncio
    async def test_a_rejected_port_never_reaches_a_request(self, port, http):
        with pytest.raises(InvalidTargetURLError) as raised:
            await js_web_scanner.scan_url(f"https://{TARGET_HOST}:{port}")
        for allowed in EXPECTED_PORTS:
            assert str(allowed) in str(raised.value)
        assert http.urls == []


# ---------------------------------------------------------------------------
# One definition, not three that agree
# ---------------------------------------------------------------------------


class TestTheAllowlistIsSharedNotCopied:
    """The tests above would all pass against three separate hardcoded lists
    that happen to hold the same five numbers today. These do not.

    Each one edits the single definition in ssrf_guard and then asks a scanner
    what it does -- a scanner reading its own copy would ignore the edit.
    """

    @pytest.fixture
    def widened(self, monkeypatch):
        """9999 added to the one allowlist, for the duration of one test."""
        monkeypatch.setattr(
            ssrf_guard, "ALLOWED_PORTS", frozenset(ALLOWED_PORTS | {9999})
        )
        monkeypatch.setattr(
            ssrf_guard,
            "_ALLOWED_PORTS_TEXT",
            ", ".join(str(port) for port in sorted(ALLOWED_PORTS | {9999})),
        )

    @pytest.mark.asyncio
    async def test_widening_the_one_list_reaches_the_tls_scanner(
        self, widened, handshake
    ):
        await _run(tls_scanner.scan_url, f"https://{TARGET_HOST}:9999")
        assert handshake.ports == [9999]

    @pytest.mark.asyncio
    async def test_widening_the_one_list_reaches_the_header_scanner(
        self, widened, http
    ):
        await _run(header_scanner.scan_url, f"https://{TARGET_HOST}:9999")
        assert [_port_of(url) for url in http.urls] == [9999]

    @pytest.mark.asyncio
    async def test_widening_the_one_list_reaches_the_javascript_scanner(
        self, widened, http
    ):
        await _run(js_web_scanner.scan_url, f"https://{TARGET_HOST}:9999")
        assert _port_of(http.urls[0]) == 9999

    @pytest.mark.parametrize(
        "scan",
        [tls_scanner.scan_url, header_scanner.scan_url, js_web_scanner.scan_url],
    )
    @pytest.mark.asyncio
    async def test_narrowing_the_one_list_reaches_every_scanner(
        self, scan, monkeypatch, handshake, http
    ):
        """The direction that matters for security: removing a port from the
        one definition has to remove it from all three. A scanner holding its
        own copy would keep scanning a port that was just revoked."""
        monkeypatch.setattr(ssrf_guard, "ALLOWED_PORTS", frozenset({HTTPS_PORT}))
        with pytest.raises(InvalidTargetURLError):
            await scan(f"https://{TARGET_HOST}:8443")
        assert handshake.ports == []
        assert http.urls == []

    def test_no_scanner_defines_a_port_list_of_its_own(self):
        """The static half of the same claim, read off the source: none of the
        three names a port literal. They import HTTPS_PORT for the default and
        take everything else off the Target the guard hands them."""
        import inspect

        for module in (tls_scanner, header_scanner, js_web_scanner):
            source = inspect.getsource(module)
            for port in EXPECTED_PORTS:
                if port == HTTPS_PORT:
                    continue  # 443 appears in prose about the default
                assert str(port) not in source, (
                    f"{module.__name__} names port {port} itself; the "
                    "allowlist belongs in ssrf_guard alone"
                )

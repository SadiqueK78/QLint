"""The SSRF guard, tested directly rather than through whichever feature uses it.

This validator started inside tls_scanner.py and was tested through the TLS
endpoint. That was reasonable while TLS scanning was the only caller. It stopped
being reasonable when the HTTP security-header check needed the identical
decision: a control that two features depend on should not have its coverage
living inside one of them, because the day someone changes the TLS endpoint is
the day the header endpoint's protection quietly stops being tested.

So this file owns the exhaustive part -- every blocked range, every URL shape --
and the endpoint test files keep only enough to prove they are wired to it.

Two tests here arrived from test_web_scan_tls.py unchanged apart from the module
they patch: they always tested the validator's internals rather than the TLS
endpoint, which is exactly why they belong next to the validator now.
"""

import asyncio
import socket

import pytest

import ssrf_guard
from ssrf_guard import (
    BlockedTargetError,
    InvalidTargetURLError,
    TargetResolutionError,
    parse_target,
    resolve_and_validate,
    validate_target,
)

HOST = "example.com"
PUBLIC_IP = "93.184.216.34"
CLOUD_METADATA_IP = "169.254.169.254"


def resolving_to(monkeypatch, *addresses, error=None):
    """Point the resolver at a fixed answer, and record that it was consulted.

    Patched at socket.getaddrinfo rather than at ssrf_guard._resolve so that
    _resolve's own error mapping and de-duplication stay under test.
    """
    calls: list[str] = []

    def _getaddrinfo(host, port, *args, **kwargs):
        calls.append(host)
        if error is not None:
            raise error
        answers = []
        for address in addresses:
            if ":" in address:
                answers.append(
                    (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, port, 0, 0))
                )
            else:
                answers.append(
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))
                )
        return answers

    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)
    return calls


# ---------------------------------------------------------------------------
# URL parsing -- runs before anything touches the network
# ---------------------------------------------------------------------------


class TestParseTarget:
    def test_a_plain_https_url_parses(self):
        target = parse_target("https://example.com")
        assert target.hostname == "example.com"
        assert target.port == 443
        assert target.addresses == []  # nothing resolved yet

    def test_a_path_and_query_survive_on_the_url_but_do_not_affect_the_host(self):
        target = parse_target("https://example.com/admin?token=secret")
        assert target.hostname == "example.com"

    def test_an_http_url_is_refused(self):
        with pytest.raises(InvalidTargetURLError) as raised:
            parse_target("http://example.com")
        assert "https" in str(raised.value).lower()

    def test_a_url_with_no_scheme_is_refused_rather_than_assumed_https(self):
        """Guessing the scheme would connect somewhere nobody named."""
        with pytest.raises(InvalidTargetURLError) as raised:
            parse_target("example.com")
        assert "scheme" in str(raised.value).lower()

    @pytest.mark.parametrize(
        "url",
        [
            "ftp://example.com",
            "file:///etc/passwd",
            "gopher://example.com",
            "ws://example.com",
            "data:text/plain,hello",
        ],
    )
    def test_other_schemes_are_refused(self, url):
        with pytest.raises(InvalidTargetURLError):
            parse_target(url)

    @pytest.mark.parametrize("url", ["", "   ", "https://", "not a url", None, 42])
    def test_junk_input_raises_the_caller_s_fault_error(self, url):
        with pytest.raises(InvalidTargetURLError):
            parse_target(url)

    def test_credentials_in_the_authority_are_refused(self):
        """https://real.example.com@169.254.169.254/ reads as one host, resolves
        as another. The confusion is the attack, so the shape is refused."""
        with pytest.raises(InvalidTargetURLError):
            parse_target("https://real.example.com@169.254.169.254/")

    def test_a_port_outside_the_allowlist_is_refused(self):
        """8443 is now allowed -- see TestTheAllowedPorts. A port that is not
        in the allowlist is still refused, which is what stops this scanner
        being pointed at arbitrary ports on a host."""
        with pytest.raises(InvalidTargetURLError) as raised:
            parse_target("https://example.com:8080")
        assert "443" in str(raised.value)

    def test_an_explicit_443_is_accepted(self):
        assert parse_target("https://example.com:443").port == 443

    def test_a_trailing_dot_and_mixed_case_normalize(self):
        assert parse_target("https://ExAmPle.COM./").hostname == "example.com"

    def test_an_internationalised_name_becomes_its_idna_form(self):
        """The name checked, the name resolved and the SNI name must be one
        spelling, or the guard is judging something else's address."""
        assert parse_target("https://bücher.example").hostname == (
            "xn--bcher-kva.example"
        )

    @pytest.mark.parametrize(
        "host",
        [
            "localhost",
            "metadata",
            "metadata.google.internal",
            "metadata.goog",
            "instance-data",
            "foo.internal",
            "db.cluster.local",
            "printer.local",
            "server.lan",
            "thing.intranet",
            "host.corp",
            "box.private",
            "api.svc",
            "1.0.0.127.in-addr.arpa",
            "backend",
        ],
    )
    def test_an_internal_name_is_refused_without_being_resolved(self, host):
        with pytest.raises(BlockedTargetError):
            parse_target(f"https://{host}")

    @pytest.mark.parametrize(
        "host",
        [
            "localhost-tools.example.com",
            "internal-docs.example.com",
            "my.local.example.com",
            "metadata-service.example.com",
        ],
    )
    def test_a_public_name_that_merely_contains_an_internal_word_is_allowed(self, host):
        """Pattern matching is the advisory layer; it must not eat real names."""
        assert parse_target(f"https://{host}").hostname == host


# ---------------------------------------------------------------------------
# Address classification -- the actual control
# ---------------------------------------------------------------------------


class TestBlockedAddressRanges:
    """The exhaustive list. This is the reason the module exists."""

    @pytest.mark.parametrize(
        "ip,label",
        [
            ("10.0.0.1", "RFC 1918 10/8"),
            ("10.255.255.254", "RFC 1918 10/8 upper"),
            ("172.16.0.1", "RFC 1918 172.16/12"),
            ("172.31.255.254", "RFC 1918 172.16/12 upper"),
            ("192.168.0.1", "RFC 1918 192.168/16"),
            ("192.168.255.254", "RFC 1918 192.168/16 upper"),
            ("127.0.0.1", "loopback"),
            ("127.1.2.3", "loopback, non-obvious"),
            ("169.254.1.1", "link-local"),
            ("169.254.169.254", "cloud metadata"),
            ("0.0.0.0", "unspecified"),
            ("224.0.0.1", "multicast"),
            ("239.255.255.255", "multicast upper"),
            ("240.0.0.1", "reserved 240/4"),
            ("255.255.255.255", "broadcast"),
            ("100.64.0.1", "carrier-grade NAT"),
            ("192.0.2.1", "TEST-NET-1 documentation"),
            ("198.18.0.1", "benchmarking"),
            ("198.51.100.1", "TEST-NET-2 documentation"),
            ("203.0.113.1", "TEST-NET-3 documentation"),
        ],
    )
    def test_blocked_ipv4_ranges(self, monkeypatch, ip, label):
        resolving_to(monkeypatch, ip)
        with pytest.raises(BlockedTargetError, match="example.com"):
            resolve_and_validate(HOST)

    @pytest.mark.parametrize(
        "ip,label",
        [
            ("::1", "IPv6 loopback"),
            ("::", "IPv6 unspecified"),
            ("fe80::1", "IPv6 link-local"),
            ("fc00::1", "IPv6 unique-local"),
            ("fd00::1", "IPv6 unique-local fd"),
            ("ff02::1", "IPv6 multicast"),
            ("2001:db8::1", "IPv6 documentation"),
            ("::ffff:127.0.0.1", "IPv4-mapped loopback"),
            ("::ffff:169.254.169.254", "IPv4-mapped metadata"),
            ("::ffff:10.0.0.1", "IPv4-mapped RFC 1918"),
            ("::ffff:192.168.1.1", "IPv4-mapped RFC 1918 192.168"),
            ("2002:7f00:1::", "6to4-wrapped loopback"),
            ("2002:a00:1::", "6to4-wrapped 10/8"),
        ],
    )
    def test_blocked_ipv6_ranges(self, monkeypatch, ip, label):
        resolving_to(monkeypatch, ip)
        with pytest.raises(BlockedTargetError, match="example.com"):
            resolve_and_validate(HOST)

    @pytest.mark.parametrize("ip", [PUBLIC_IP, "8.8.8.8", "1.1.1.1", "2606:4700::1111"])
    def test_public_addresses_are_allowed(self, monkeypatch, ip):
        resolving_to(monkeypatch, ip)
        assert resolve_and_validate(HOST) == [ip]

    def test_the_metadata_address_is_named_in_its_own_message(self, monkeypatch):
        """"link-local" does not tell a user what nearly happened."""
        resolving_to(monkeypatch, CLOUD_METADATA_IP)
        with pytest.raises(BlockedTargetError) as raised:
            resolve_and_validate(HOST)
        assert CLOUD_METADATA_IP in str(raised.value)
        assert "metadata" in str(raised.value).lower()

    def test_the_reason_names_the_rule_that_fired(self, monkeypatch):
        resolving_to(monkeypatch, "10.0.0.1")
        with pytest.raises(BlockedTargetError) as raised:
            resolve_and_validate(HOST)
        assert "private" in str(raised.value)


class TestEveryAddressIsChecked:
    """A name only has to be *partly* internal to be dangerous."""

    def test_a_private_second_record_blocks_the_whole_name(self, monkeypatch):
        resolving_to(monkeypatch, PUBLIC_IP, "127.0.0.1")
        with pytest.raises(BlockedTargetError) as raised:
            resolve_and_validate(HOST)
        assert "127.0.0.1" in str(raised.value)

    def test_a_private_record_in_the_middle_is_caught(self, monkeypatch):
        resolving_to(monkeypatch, PUBLIC_IP, "8.8.8.8", CLOUD_METADATA_IP, "1.1.1.1")
        with pytest.raises(BlockedTargetError):
            resolve_and_validate(HOST)

    def test_a_private_record_last_is_caught(self, monkeypatch):
        resolving_to(monkeypatch, PUBLIC_IP, "8.8.8.8", "192.168.1.1")
        with pytest.raises(BlockedTargetError):
            resolve_and_validate(HOST)

    def test_an_all_public_answer_returns_every_address(self, monkeypatch):
        resolving_to(monkeypatch, PUBLIC_IP, "8.8.8.8")
        assert resolve_and_validate(HOST) == [PUBLIC_IP, "8.8.8.8"]

    def test_duplicate_answers_are_collapsed(self, monkeypatch):
        resolving_to(monkeypatch, PUBLIC_IP, PUBLIC_IP, "8.8.8.8")
        assert resolve_and_validate(HOST) == [PUBLIC_IP, "8.8.8.8"]


class TestResolutionFailures:
    def test_a_name_that_does_not_resolve_raises_a_resolution_error(self, monkeypatch):
        resolving_to(
            monkeypatch, error=socket.gaierror(-2, "Name or service not known")
        )
        with pytest.raises(TargetResolutionError) as raised:
            resolve_and_validate(HOST)
        assert "DNS" in str(raised.value)
        assert "does not resolve" in str(raised.value)

    def test_an_os_level_resolver_failure_is_also_a_resolution_error(self, monkeypatch):
        resolving_to(monkeypatch, error=OSError("resolver unavailable"))
        with pytest.raises(TargetResolutionError):
            resolve_and_validate(HOST)

    def test_an_empty_answer_is_a_resolution_error(self, monkeypatch):
        resolving_to(monkeypatch)
        with pytest.raises(TargetResolutionError) as raised:
            resolve_and_validate(HOST)
        assert "no usable IP address" in str(raised.value)

    def test_a_resolution_failure_is_not_a_block(self, monkeypatch):
        """They are different answers and map to different status codes."""
        resolving_to(monkeypatch, error=socket.gaierror(-2, "nope"))
        with pytest.raises(TargetResolutionError):
            resolve_and_validate(HOST)
        # ...and specifically not the refusal type.
        resolving_to(monkeypatch, error=socket.gaierror(-2, "nope"))
        with pytest.raises(Exception) as raised:
            resolve_and_validate(HOST)
        assert not isinstance(raised.value, BlockedTargetError)


# ---------------------------------------------------------------------------
# Relocated from test_web_scan_tls.py -- these always tested the validator
# ---------------------------------------------------------------------------


class TestRelocatedFromTheTLSSuite:
    """Unchanged apart from the module they patch.

    They were written against tls_scanner._resolve when the guard lived there.
    Their behaviour is identical against the relocated code, which is the point
    of running them here.
    """

    def test_resolve_and_validate_raises_before_returning_anything(self, monkeypatch):
        monkeypatch.setattr(ssrf_guard, "_resolve", lambda host: ["192.168.1.5"])
        with pytest.raises(BlockedTargetError):
            resolve_and_validate(HOST)

    def test_resolve_and_validate_returns_every_public_address(self, monkeypatch):
        monkeypatch.setattr(ssrf_guard, "_resolve", lambda host: [PUBLIC_IP, "8.8.8.8"])
        assert resolve_and_validate(HOST) == [PUBLIC_IP, "8.8.8.8"]


# ---------------------------------------------------------------------------
# The shared entry point
# ---------------------------------------------------------------------------


class TestValidateTarget:
    """The one call both features make. Parse, resolve and judge, in order."""

    def test_it_returns_a_target_carrying_the_approved_addresses(self, monkeypatch):
        resolving_to(monkeypatch, PUBLIC_IP, "8.8.8.8")
        target = asyncio.run(validate_target("https://example.com/path"))
        assert target.hostname == "example.com"
        assert target.port == 443
        assert target.addresses == [PUBLIC_IP, "8.8.8.8"]
        # `address` is what a caller connects to, so it must never be the name.
        assert target.address == PUBLIC_IP

    def test_a_bad_url_fails_before_the_resolver_is_consulted(self, monkeypatch):
        """The cheap check runs first: a malformed URL costs no DNS lookup."""
        calls = resolving_to(monkeypatch, PUBLIC_IP)
        with pytest.raises(InvalidTargetURLError):
            asyncio.run(validate_target("http://example.com"))
        assert calls == []

    def test_an_internal_name_fails_before_the_resolver_is_consulted(self, monkeypatch):
        calls = resolving_to(monkeypatch, PUBLIC_IP)
        with pytest.raises(BlockedTargetError):
            asyncio.run(validate_target("https://localhost"))
        assert calls == []

    def test_a_blocked_address_fails_after_exactly_one_resolution(self, monkeypatch):
        """One lookup, not one per address and not one per connection attempt:
        a second lookup is a second chance for DNS to answer differently."""
        calls = resolving_to(monkeypatch, PUBLIC_IP, "127.0.0.1")
        with pytest.raises(BlockedTargetError):
            asyncio.run(validate_target("https://example.com"))
        assert calls == ["example.com"]

    def test_the_name_is_resolved_exactly_once_on_the_happy_path(self, monkeypatch):
        calls = resolving_to(monkeypatch, PUBLIC_IP)
        asyncio.run(validate_target("https://example.com"))
        assert calls == ["example.com"]

    def test_it_does_not_block_the_event_loop_while_resolving(self, monkeypatch):
        """getaddrinfo blocks, so it has to run off the loop.

        Asserted by having the fake resolver observe that no running loop is
        visible from the thread it is called on.
        """
        seen: list[bool] = []

        def _getaddrinfo(host, port, *args, **kwargs):
            try:
                asyncio.get_running_loop()
                seen.append(True)
            except RuntimeError:
                seen.append(False)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, port))]

        monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)
        asyncio.run(validate_target("https://example.com"))
        assert seen == [False], "getaddrinfo ran on the event loop thread"


class TestTheExceptionHierarchy:
    """Both endpoints map these onto status codes, so the shape is load-bearing."""

    def test_refusals_and_resolution_failures_share_a_base(self):
        for error in (InvalidTargetURLError, BlockedTargetError, TargetResolutionError):
            assert issubclass(error, ssrf_guard.SSRFGuardError)

    def test_a_block_is_not_a_bad_url(self):
        """The router answers both with 400, but for different reasons, and
        conflating the types would make that choice accidental."""
        assert not issubclass(BlockedTargetError, InvalidTargetURLError)
        assert not issubclass(InvalidTargetURLError, BlockedTargetError)

    def test_the_guard_is_not_tls_specific_any_more(self):
        """The whole reason for the extraction, asserted rather than assumed."""
        import inspect

        source = inspect.getsource(ssrf_guard)
        assert "import ssl" not in source
        assert "cryptography" not in source

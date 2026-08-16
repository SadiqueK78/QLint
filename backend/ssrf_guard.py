"""Deciding whether the backend may connect to a URL a user supplied.

Every other outbound call in QLint goes to api.github.com, a host chosen at
build time. Level 1 scanning does not: a request body names the target, so a
request body decides where a socket goes. That is server-side request forgery,
and this module is the single control standing in front of it.

It began inside tls_scanner.py, which was the right place while TLS scanning
was the only feature making outbound connections. It is the wrong place the
moment a second feature needs the same decision -- a validator living in a file
named for TLS either gets imported from a module it has nothing to do with, or
gets reimplemented, and the second copy is the one that will be subtly wrong.
So it lives here, named for what it does rather than for its first caller.

The order of operations is the whole design:

    parse the URL  ->  resolve the name  ->  judge every resolved address
                   ->  connect to the address that was judged

The last step belongs to the caller, and it is the one that is easy to get
wrong. Resolving a name, deciding the answer is acceptable, and then handing
the *name* to a connection library means the name is resolved a second time,
and nothing says the second answer matches the first -- a DNS server the
attacker controls can return a public address to the check and 127.0.0.1 to
the connection a moment later. That is DNS rebinding, and it defeats a
validator that reads correctly line by line. `Target.addresses` exists so a
caller never has to re-resolve: connect to what is in there, carry the
hostname only for SNI and certificate verification.

Two layers guard the target, and they are not equal:

  * The real control is address classification (`_reject_blocked_address`).
    Every address the name resolves to is checked, not merely the first,
    because a name with an A record for a public host and a second A record
    for 127.0.0.1 would otherwise pass and then connect to whichever the OS
    picked.
  * Hostname pattern matching (`_reject_internal_hostname`) is a courtesy
    layer on top. It catches `localhost` and `*.internal` early with a clearer
    message, and it is bypassable by anyone who can publish DNS, which is why
    it is never the thing standing between a caller and the metadata service.

Scope is deliberately small, and shared by every caller: https only, and only
the handful of ports in ALLOWED_PORTS -- 443 for a URL that names none, plus
four conventional HTTPS alternatives. An arbitrary caller-chosen port is what
would turn this into a port scanner, so the set is fixed here and imported by
everything that connects. Redirect handling is the caller's business, but the
answer is the same
everywhere -- a redirect points at a host this module never judged, so
following one would mean the guard checked one target and the socket visited
another.
"""

import asyncio
import ipaddress
import re
import socket
from urllib.parse import urlsplit

# The port a URL that names none is scanned on, and the only one that was ever
# accepted before the allowlist below existed.
HTTPS_PORT = 443

# Every port any caller may talk to, defined once for all three scanners.
#
# An allowlist rather than "whatever the URL says", and the distinction is the
# whole control: a caller-chosen port turns a scanner into a port scanner that
# runs from the backend's address and reports the results back -- which is a
# reconnaissance technique in its own right, and would give away most of what
# the address checks below are here to protect.
#
# Five entries, and four of them are here because a site that terminates TLS
# somewhere other than 443 is a real thing rather than a hypothetical: 8443 is
# the conventional alternative, and 4443, 9443 and 10443 are the ones that turn
# up in front of admin interfaces and staging environments. What they have in
# common is that they are HTTPS ports by convention -- none of them is a
# database, an SSH daemon or a service-mesh sidecar, so the set says nothing
# useful to somebody mapping a host.
#
# This is the one definition. tls_scanner, header_scanner and js_web_scanner
# all reach the same answer by importing it, because three lists that happen to
# agree today are three lists that stop agreeing the first time one is edited.
ALLOWED_PORTS: frozenset[int] = frozenset({HTTPS_PORT, 4443, 8443, 9443, 10443})

# Sorted for the error message, so the sentence a caller reads lists the ports
# in a fixed order rather than whatever order the set iterates in today.
_ALLOWED_PORTS_TEXT = ", ".join(str(port) for port in sorted(ALLOWED_PORTS))


class SSRFGuardError(Exception):
    """Base for every refusal this module issues."""


class InvalidTargetURLError(SSRFGuardError):
    """The URL is not something QLint will accept. Caller's fault, so a 400."""


class BlockedTargetError(SSRFGuardError):
    """The target resolves somewhere this server must not connect to."""


class TargetResolutionError(SSRFGuardError):
    """The name could not be resolved. Not a refusal -- a failure to look up."""


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------

# Suffixes that name a network rather than a site. Advisory only -- see the
# module docstring on why this list is not the control.
_INTERNAL_SUFFIXES = (
    ".local",
    ".localhost",
    ".localdomain",
    ".internal",
    ".intranet",
    ".lan",
    ".corp",
    ".private",
    ".home.arpa",
    ".svc",
    ".svc.cluster.local",
    ".cluster.local",
    ".in-addr.arpa",
    ".ip6.arpa",
)

_INTERNAL_NAMES = {
    "localhost",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
}

# A hostname is a run of dot-separated labels. Checked before the name reaches
# the resolver so that nothing exotic (a trailing null, an embedded slash that
# survived parsing) is ever handed to getaddrinfo.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)


class Target:
    """A validated https://host:port a caller is cleared to connect to.

    `addresses` is empty until the name has been resolved and judged, and is
    the reason this is an object rather than a string: it carries the addresses
    the guard actually approved, so the caller connects to one of those instead
    of resolving the name again.

    `port` is one of ALLOWED_PORTS, defaulting to 443 for a URL that names no
    port. It is carried here rather than assumed by each scanner so that the
    port the guard approved is the port the socket goes to -- the same argument
    `addresses` exists for.
    """

    def __init__(self, hostname: str, url: str, port: int = HTTPS_PORT) -> None:
        self.hostname = hostname
        self.url = url
        self.port = port
        self.addresses: list[str] = []

    @property
    def address(self) -> str | None:
        """The address to connect to, or None if validation has not run."""
        return self.addresses[0] if self.addresses else None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Target({self.hostname}:{self.port}, addresses={self.addresses})"


def parse_target(raw_url: str) -> Target:
    """Turn a caller's string into a Target, or explain why it is not one.

    Nothing here touches the network; this runs before a name is resolved, so
    a malformed URL costs no DNS lookup.
    """
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise InvalidTargetURLError("Provide a URL to scan, for example https://example.com")

    text = raw_url.strip()

    # No scheme means no scan. Guessing https:// would be convenient and wrong:
    # the caller would never be told which target was actually inspected, and
    # "example.com:8080" parses as scheme "example.com" -- a silent default
    # turns that into a connection nobody asked for.
    if "://" not in text:
        raise InvalidTargetURLError(
            "The URL needs an explicit scheme. Supply the target as "
            f"https://{text} rather than {text}."
        )

    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise InvalidTargetURLError(f"That URL could not be parsed: {exc}") from exc

    scheme = (parts.scheme or "").lower()
    if scheme == "http":
        raise InvalidTargetURLError(
            "Only https:// targets are scanned. An http:// URL has no TLS "
            "layer -- nothing to inspect, and no protection for the request "
            "itself. Supply the https:// address of the same site."
        )
    if scheme != "https":
        raise InvalidTargetURLError(
            f"Unsupported scheme '{scheme or parts.scheme}'. QLint scans "
            "https:// URLs only."
        )

    # Credentials in the authority are a target-confusion trick, not a feature
    # anyone needs here: https://real.example.com@169.254.169.254/ reads as the
    # public host to a human and resolves as the metadata address.
    if parts.username is not None or parts.password is not None:
        raise InvalidTargetURLError(
            "Remove the credentials from the URL. QLint inspects a host's "
            "public configuration and never authenticates to it."
        )

    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidTargetURLError(f"That URL has an invalid port: {exc}") from exc
    if port is not None and port not in ALLOWED_PORTS:
        raise InvalidTargetURLError(
            f"Only ports {_ALLOWED_PORTS_TEXT} are scanned, and this URL asks "
            f"for port {port}. Drop the port from the URL to scan "
            f"{HTTPS_PORT}."
        )

    hostname = (parts.hostname or "").strip().rstrip(".").lower()
    if not hostname:
        raise InvalidTargetURLError("That URL has no hostname to connect to.")

    # An IPv6 literal never reaches _HOSTNAME_RE, so classify it as an address
    # here and let the address guard judge it like any other resolved answer.
    hostname = _to_ascii(hostname)
    if not _is_ip_literal(hostname) and not _HOSTNAME_RE.match(hostname):
        raise InvalidTargetURLError(f"'{hostname}' is not a valid hostname.")

    _reject_internal_hostname(hostname)
    # `port or HTTPS_PORT` rather than `port`: a URL naming no port parses as
    # None, and 443 is what "no port" has always meant here.
    return Target(hostname, text, port or HTTPS_PORT)


def _to_ascii(hostname: str) -> str:
    """The IDNA form of a name, so the resolver sees what the guard checked.

    Encoding here rather than leaving it to getaddrinfo keeps one spelling of
    the name throughout: the name that is pattern-checked, the name that is
    resolved and the SNI name sent in the handshake are the same bytes.
    """
    if hostname.isascii():
        return hostname
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidTargetURLError(
            f"'{hostname}' is not a hostname this scanner can resolve: {exc}"
        ) from exc


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _reject_internal_hostname(hostname: str) -> None:
    """The advisory layer: names that describe a private network.

    Deliberately runs before resolution so an obvious internal name fails with
    a message about the name. The address check afterwards is what actually
    holds, and it runs whether or not this one fired.
    """
    if hostname in _INTERNAL_NAMES or hostname.endswith(_INTERNAL_SUFFIXES):
        raise BlockedTargetError(
            f"'{hostname}' names an internal network rather than a public "
            "site, so it will not be scanned."
        )
    # A single label with no dot is a host on the local network, not a site on
    # the internet: ICANN does not delegate dotless names.
    if "." not in hostname and not _is_ip_literal(hostname):
        raise BlockedTargetError(
            f"'{hostname}' is not a fully qualified domain name, so it can "
            "only refer to a host on this server's own network."
        )


# ---------------------------------------------------------------------------
# Address classification -- the actual SSRF control
# ---------------------------------------------------------------------------


def _embedded_addresses(ip):
    """The IPv4 addresses an IPv6 address can be carrying inside it.

    ::ffff:127.0.0.1 is loopback wearing an IPv6 costume, and 2002::/16 and
    Teredo do the same thing with a public-looking prefix. Classifying only
    the outer address would wave all three through.
    """
    if not isinstance(ip, ipaddress.IPv6Address):
        return []
    embedded = []
    for candidate in (ip.ipv4_mapped, ip.sixtofour):
        if candidate is not None:
            embedded.append(candidate)
    teredo = ip.teredo
    if teredo is not None:
        embedded.extend(teredo)
    return embedded


def _blocked_reason(ip) -> str | None:
    """Why this address is off limits, or None if it is a public address."""
    # Named individually rather than collapsed into `not is_global` so that the
    # reason handed back says which rule fired -- and so that reading this
    # function tells you what is blocked without consulting the stdlib.
    checks = (
        (ip.is_loopback, "a loopback address"),
        (ip.is_private, "a private address"),
        (ip.is_link_local, "a link-local address"),
        (ip.is_reserved, "a reserved address"),
        (ip.is_multicast, "a multicast address"),
        (ip.is_unspecified, "an unspecified address"),
    )
    for failed, reason in checks:
        if failed:
            return reason
    # Everything the six flags above miss and the stdlib still considers
    # non-routable: carrier-grade NAT, the documentation ranges, benchmarking
    # space, 240.0.0.0/4. None of it hosts a site worth scanning, and all of it
    # can reach somewhere interesting from inside a hosting provider.
    if not ip.is_global:
        return "not a globally routable address"
    return None


def _reject_blocked_address(ip_text: str, hostname: str) -> None:
    """Raise unless this resolved address is one the server may connect to."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError as exc:
        raise BlockedTargetError(
            f"'{hostname}' resolved to something that is not an IP address."
        ) from exc

    for candidate in (ip, *_embedded_addresses(ip)):
        reason = _blocked_reason(candidate)
        if reason is None:
            continue
        # 169.254.169.254 is already caught by is_link_local; it is called out
        # by name because "link-local" does not tell a user what nearly
        # happened, and this is the address that makes SSRF worth exploiting.
        if str(candidate) == "169.254.169.254":
            raise BlockedTargetError(
                f"'{hostname}' resolves to 169.254.169.254, the cloud instance "
                "metadata endpoint. This scanner will not connect to it."
            )
        raise BlockedTargetError(
            f"'{hostname}' resolves to {ip}, which is {reason}. This scanner "
            "only connects to public internet hosts."
        )


def _resolve(hostname: str) -> list[str]:
    """Every address this name has, resolved once and returned in full.

    getaddrinfo rather than gethostbyname: it answers for both address
    families, and the guard needs the complete answer. A name whose first
    record is public and whose second is 127.0.0.1 must fail, so the caller
    checks all of these and connects only after all of them pass.
    """
    try:
        answers = socket.getaddrinfo(
            hostname, HTTPS_PORT, proto=socket.IPPROTO_TCP, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise TargetResolutionError(
            f"DNS lookup failed for '{hostname}': the name does not resolve "
            f"({exc.strerror or exc})."
        ) from exc
    except OSError as exc:
        raise TargetResolutionError(
            f"DNS lookup failed for '{hostname}': {exc}"
        ) from exc

    addresses: list[str] = []
    for family, _type, _proto, _canonname, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = sockaddr[0]
        if address not in addresses:
            addresses.append(address)

    if not addresses:
        raise TargetResolutionError(
            f"DNS lookup for '{hostname}' returned no usable IP address."
        )
    return addresses


def resolve_and_validate(hostname: str) -> list[str]:
    """Resolve a name and return its addresses, or raise before any connection.

    The whole list is validated. Returning early on the first acceptable
    address would mean a name only has to be *partly* public to be scanned.

    Blocking: this calls getaddrinfo. Async callers want validate_target.
    """
    addresses = _resolve(hostname)
    for address in addresses:
        _reject_blocked_address(address, hostname)
    return addresses


# ---------------------------------------------------------------------------
# The entry point every caller uses
# ---------------------------------------------------------------------------


async def validate_target(raw_url: str) -> Target:
    """Parse, resolve and judge a user-supplied URL. The one call to make.

    Returns a Target whose `addresses` are the ones the guard approved, so the
    caller can connect to `target.address` and send `target.hostname` as the
    SNI/Host name -- one resolution, no second chance for DNS to answer
    differently.

    Raises InvalidTargetURLError or BlockedTargetError for a target that will
    not be scanned (both a 400: see the router on why they are not told apart),
    and TargetResolutionError when the name simply does not resolve.

    The DNS lookup runs in a worker thread because getaddrinfo blocks, and a
    slow resolver must not stall the event loop for every other request.
    """
    target = parse_target(raw_url)
    target.addresses = await asyncio.to_thread(resolve_and_validate, target.hostname)
    return target

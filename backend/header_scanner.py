"""Level 1 scanning: which HTTP security headers a site actually sends.

The sibling of tls_scanner. That one asks what the transport negotiated; this
one asks what the application tells the browser to do once the transport is up.
Both point at a URL a user supplied, so both go through the same ssrf_guard
before a packet leaves -- this module contains no target validation of its own
and must not grow any.

Two decisions worth stating, because both look like omissions otherwise:

  * Every header checked produces a finding, pass or fail. A report that lists
    only problems cannot be distinguished from a report that failed to run, and
    "we checked X and it is fine" is the half a reader needs to trust the other
    half. It also matches tls_scanner, which lists every asset it inspected.
  * The request is pinned to the address the guard approved, exactly as the TLS
    handshake is. httpx would otherwise resolve the hostname again, and the
    second answer is not required to match the first -- that is DNS rebinding,
    and it is the one way a guard that reads correctly still lets a request
    reach 127.0.0.1. The hostname travels as the Host header and the SNI name,
    so certificate verification still happens against the name the user asked
    for.
"""

import httpx

from ssrf_guard import HTTPS_PORT, validate_target

# One bound for the whole thing: connect, handshake, request, response. Shorter
# than github_client's 30s because that talks to one known-good API and this
# talks to whatever a user typed -- a slow target must not hold a worker.
REQUEST_TIMEOUT_SECONDS = 10.0

# The minimum max-age worth having, in seconds: 180 days. Below this a browser
# forgets the pin sooner than most certificates rotate, which is the window a
# downgrade attack needs.
MIN_HSTS_MAX_AGE = 15552000

STATUS_ACCEPTABLE = "Acceptable"
STATUS_MISSING = "Missing"
STATUS_MISCONFIGURED = "Misconfigured"
STATUS_WEAK = "Weak Configuration"

SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Info"

FINDING_TYPE = "HTTP Security Header"


class HeaderScanError(Exception):
    """The request could not be made or completed. Nothing to report on."""


def _finding(
    header: str,
    status: str,
    severity: str,
    recommendation: str,
    value: str | None = None,
) -> dict:
    """One row, shaped like a TLS finding so both reports render the same way.

    `asset` is the header name and `type` is constant, which is what makes a
    pass and a failure the same shape -- the reader scans one column for status
    rather than inferring absence from a row that is not there.
    """
    return {
        "asset": header,
        "type": FINDING_TYPE,
        "purpose": "HTTP Response",
        "status": status,
        "severity": severity,
        "recommendation": recommendation,
        "observed_value": value,
        "present": value is not None,
    }


def _parse_max_age(value: str) -> int | None:
    """The max-age directive from an HSTS header, or None if it has none.

    Tolerant of the shapes real servers send: any order, any spacing, optional
    quotes, mixed case. A header whose max-age cannot be read is treated as
    absent rather than as zero, because "unparseable" and "too short" deserve
    different advice.
    """
    for directive in value.split(";"):
        name, _, raw = directive.partition("=")
        if name.strip().lower() != "max-age":
            continue
        raw = raw.strip().strip('"').strip()
        try:
            return int(raw)
        except ValueError:
            return None
    return None


def _check_hsts(headers) -> dict:
    value = headers.get("strict-transport-security")
    if value is None:
        return _finding(
            "Strict-Transport-Security",
            STATUS_MISSING,
            SEVERITY_MEDIUM,
            "Add a Strict-Transport-Security header with a max-age of at "
            "least 180 days to enforce HTTPS connections and prevent "
            "downgrade attacks.",
        )

    max_age = _parse_max_age(value)
    if max_age is None:
        return _finding(
            "Strict-Transport-Security",
            STATUS_WEAK,
            SEVERITY_LOW,
            "The Strict-Transport-Security header is present but carries no "
            "readable max-age, so browsers will not know how long to enforce "
            f"HTTPS. Set max-age={MIN_HSTS_MAX_AGE} (180 days) or more.",
            value,
        )
    if max_age < MIN_HSTS_MAX_AGE:
        return _finding(
            "Strict-Transport-Security",
            STATUS_WEAK,
            SEVERITY_LOW,
            f"Strict-Transport-Security is present but its max-age of "
            f"{max_age} seconds is below the recommended minimum of "
            f"{MIN_HSTS_MAX_AGE} (180 days). A short max-age leaves a window "
            "in which a browser will still try HTTP and can be downgraded. "
            f"Raise it to at least {MIN_HSTS_MAX_AGE}.",
            value,
        )
    return _finding(
        "Strict-Transport-Security",
        STATUS_ACCEPTABLE,
        SEVERITY_INFO,
        "Correctly configured.",
        value,
    )


def _check_csp(headers) -> dict:
    value = headers.get("content-security-policy")
    if value is None:
        return _finding(
            "Content-Security-Policy",
            STATUS_MISSING,
            SEVERITY_MEDIUM,
            "Add a Content-Security-Policy header to restrict where scripts, "
            "styles and other resources may be loaded from. Without one, an "
            "injected script runs with the page's full privileges.",
        )
    # Presence only in this phase. Parsing the policy is a real piece of work --
    # directive precedence, `unsafe-inline`, nonce and hash sources, the
    # fallbacks from default-src -- and a half-done version would confidently
    # pass a policy that permits everything, which is worse than not checking.
    return _finding(
        "Content-Security-Policy",
        STATUS_ACCEPTABLE,
        SEVERITY_INFO,
        "Correctly configured. Note that only the header's presence is "
        "checked in this phase; the policy's directives are not evaluated.",
        value,
    )


def _check_content_type_options(headers) -> dict:
    value = headers.get("x-content-type-options")
    if value is None:
        return _finding(
            "X-Content-Type-Options",
            STATUS_MISSING,
            SEVERITY_LOW,
            "Add 'X-Content-Type-Options: nosniff' so browsers respect the "
            "declared Content-Type instead of guessing it, which can turn an "
            "uploaded file into executable script.",
        )
    if value.strip().lower() != "nosniff":
        return _finding(
            "X-Content-Type-Options",
            STATUS_MISCONFIGURED,
            SEVERITY_LOW,
            f"X-Content-Type-Options is set to '{value}', which browsers "
            "ignore. The only valid value is 'nosniff'.",
            value,
        )
    return _finding(
        "X-Content-Type-Options",
        STATUS_ACCEPTABLE,
        SEVERITY_INFO,
        "Correctly configured.",
        value,
    )


# Superseded in modern practice by CSP's frame-ancestors directive, which is
# more expressive and is what browsers prefer where both are present. Checked
# anyway: it is explicitly on this phase's required list, it is still honoured
# by every current browser, and a site that sets neither is genuinely
# clickjackable. A site setting frame-ancestors but not this header will show a
# "Missing" row here -- correct as far as this check goes, and the reason the
# severity is Low rather than Medium.
_VALID_FRAME_OPTIONS = {"deny", "sameorigin"}


def _check_frame_options(headers) -> dict:
    value = headers.get("x-frame-options")
    if value is None:
        return _finding(
            "X-Frame-Options",
            STATUS_MISSING,
            SEVERITY_LOW,
            "Add 'X-Frame-Options: DENY' (or SAMEORIGIN if the site frames "
            "itself) to stop other sites embedding these pages in an iframe "
            "and tricking users into clicking them. The modern equivalent is "
            "a frame-ancestors directive in Content-Security-Policy; setting "
            "both is the safest option.",
        )
    if value.strip().lower() not in _VALID_FRAME_OPTIONS:
        return _finding(
            "X-Frame-Options",
            STATUS_MISCONFIGURED,
            SEVERITY_LOW,
            f"X-Frame-Options is set to '{value}', which is not a value "
            "browsers act on. Use DENY or SAMEORIGIN. (ALLOW-FROM is obsolete "
            "and ignored; use Content-Security-Policy frame-ancestors "
            "instead.)",
            value,
        )
    return _finding(
        "X-Frame-Options",
        STATUS_ACCEPTABLE,
        SEVERITY_INFO,
        "Correctly configured.",
        value,
    )


def _check_referrer_policy(headers) -> dict:
    value = headers.get("referrer-policy")
    if value is None:
        return _finding(
            "Referrer-Policy",
            STATUS_MISSING,
            SEVERITY_LOW,
            "Add a Referrer-Policy header, for example "
            "'strict-origin-when-cross-origin', so full URLs -- which often "
            "carry tokens or identifiers in the path or query -- are not sent "
            "to third-party sites in the Referer header.",
        )
    return _finding(
        "Referrer-Policy",
        STATUS_ACCEPTABLE,
        SEVERITY_INFO,
        "Correctly configured.",
        value,
    )


# Order is the report's order: the two Medium-severity headers first, then the
# three Low ones, so the list reads worst-first without needing a sort.
_CHECKS = (
    _check_hsts,
    _check_csp,
    _check_content_type_options,
    _check_frame_options,
    _check_referrer_policy,
)


def classify(headers) -> list[dict]:
    """One finding per header checked, pass or fail. Never a filtered list."""
    return [check(headers) for check in _CHECKS]


def summarize(findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {
        "total_findings": len(findings),
        "by_severity": counts,
        "headers_present": sum(1 for f in findings if f["present"]),
        "headers_missing": sum(1 for f in findings if f["status"] == STATUS_MISSING),
    }


def _describe_failure(exc: Exception, hostname: str, port: int = HTTPS_PORT) -> str:
    """One sentence naming what failed, with nothing internal in it.

    Mirrors tls_scanner's function of the same name, and exists for the same
    reason: a traceback reaching the browser says nothing useful about the site
    and something about this server.
    """
    if isinstance(exc, httpx.ConnectTimeout):
        return (
            f"{hostname} did not accept a connection within "
            f"{REQUEST_TIMEOUT_SECONDS:.0f} seconds."
        )
    if isinstance(exc, (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout)):
        return (
            f"{hostname} accepted the connection but did not answer within "
            f"{REQUEST_TIMEOUT_SECONDS:.0f} seconds, so the scan was abandoned."
        )
    if isinstance(exc, httpx.TimeoutException):
        return (
            f"The request to {hostname} timed out after "
            f"{REQUEST_TIMEOUT_SECONDS:.0f} seconds."
        )
    if isinstance(exc, httpx.ConnectError):
        return (
            f"Could not connect to {hostname} on port {port}: the host "
            "refused the connection or is unreachable."
        )
    if isinstance(exc, httpx.TooManyRedirects):  # pragma: no cover - redirects are off
        return f"{hostname} redirected the request, which this scan does not follow."
    if isinstance(exc, httpx.HTTPError):
        return f"The request to {hostname} failed: {type(exc).__name__}."
    return f"The header scan of {hostname} failed."


async def scan_url(raw_url: str) -> dict:
    """Validate the target, fetch it once, and report on its headers.

    Mirrors tls_scanner.scan_url deliberately, down to the name: the router
    treats the two the same way, and a reader who has understood one has
    understood the other.
    """
    # The shared guard. Identical call to the one tls_scanner makes -- this
    # module knows nothing about private ranges and must never learn.
    target = await validate_target(raw_url)

    try:
        response = await _fetch(target)
    except HeaderScanError:
        raise
    except Exception as exc:
        # As in tls_scanner: building the message must not itself raise, or the
        # handler meant to stop exceptions escaping becomes the one that leaks.
        try:
            detail = _describe_failure(exc, target.hostname, target.port)
        except Exception:  # pragma: no cover - the belt for the braces
            detail = f"The header scan of {target.hostname} failed."
        raise HeaderScanError(detail) from exc

    findings = classify(response.headers)
    return {
        "host": target.hostname,
        "port": target.port,
        "url": target.url,
        "resolved_ips": target.addresses,
        "scanned_ip": target.address,
        "status_code": response.status_code,
        "findings": findings,
        "summary": summarize(findings),
    }


# Built once, on first use, and shared by every scan.
#
# Not a micro-optimization: constructing an httpx.AsyncClient with the default
# `verify=True` builds a fresh SSL context and reads the whole CA bundle off
# disk, which measures at roughly one second per client on this project's
# dependencies. Paying that on every scan would make the request itself the
# fastest part of the operation. An SSLContext is configuration and is safe to
# share across clients and across event loops; the client is still per-scan,
# because httpx's connection pool is bound to the loop that created it.
_ssl_context = None


def _shared_ssl_context():
    global _ssl_context
    if _ssl_context is None:
        _ssl_context = httpx.create_ssl_context()
    return _ssl_context


async def _fetch(target) -> httpx.Response:
    """One GET, to the approved address, following nothing.

    The URL's host is replaced with the IP the guard cleared, and the real
    hostname is supplied as the Host header and the SNI name. That combination
    is what keeps this request on the address that was judged while leaving
    certificate verification pointed at the name the user asked for.
    """
    # target.port, not a constant: the guard approved this target on that
    # port -- 443 unless the URL named one of the other allowed ports -- and
    # the request has to go where the approval says.
    url = httpx.URL(target.url).copy_with(host=target.address, port=target.port)
    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT_SECONDS,
        verify=_shared_ssl_context(),
        # Not negotiable: a redirect names a host the guard never judged, so
        # following one would mean validating one target and visiting another.
        # The report describes the exact URL supplied, including a 301 for it.
        follow_redirects=False,
    ) as client:
        return await client.get(
            url,
            headers={"Host": target.hostname},
            extensions={"sni_hostname": target.hostname},
        )

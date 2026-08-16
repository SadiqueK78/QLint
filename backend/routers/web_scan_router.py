"""Level 1: scan a live website. Two views of one target.

  * POST /web-scan/tls      what the transport negotiated -- protocol, cipher
                            suite, certificate -- rated against CRYPTO_DB.
  * POST /web-scan/headers  what the application tells the browser to do once
                            the transport is up.

Level 2 -- everything else in QLint -- reads source code and only ever talks to
GitHub. This router is the only one that connects to a host a user names, which
makes it the only place where a request body decides where the backend's socket
goes. That is server-side request forgery in the plain sense, and the whole
shape of this file follows from it:

  * Both endpoints validate the target through ssrf_guard, which parses the
    URL, resolves it once and judges every address it gets back. That module
    holds the control and documents it; this one holds the HTTP concerns. It
    is one shared implementation on purpose -- a second copy of an SSRF
    blocklist is the copy that would be subtly wrong.
  * Both require a session, using the same get_current_user every other
    authenticated route uses. Not for accounting -- so that an outbound
    connection from this server's address is always attributable to an account.
  * Both are rate limited per account, in separate buckets, because the cost of
    a runaway loop here is not a bill. It is this server making thousands of
    connections to a third party that never asked to hear from it.
  * Neither follows redirects. A redirect names a host the guard never judged.

Both report the same finding shape -- asset, type, status, severity,
recommendation -- so one renderer draws either, and the TLS report additionally
carries CRYPTO_DB's quantum-risk vocabulary and the same 0-100 readiness score
a code scan produces.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import get_current_user
from header_scanner import HeaderScanError
from header_scanner import scan_url as header_scan_url
from rate_limit import RateLimiter, rate_limit_by_user
from ssrf_guard import (
    BlockedTargetError,
    InvalidTargetURLError,
    SSRFGuardError,
    TargetResolutionError,
)
from tls_scanner import TLSConnectionError, TLSScanError, scan_url

logger = logging.getLogger(__name__)

router = APIRouter()

# The longest window in the application by a wide margin, and for a different
# reason than any of the others. /scan/explain and /scan/patch spend money;
# create-pr writes to a repository. This one makes the backend open connections
# to hosts chosen by the caller. Left loose, one account could point the
# service at a target and have it deliver a steady stream of connections from a
# reputable address -- QLint would be the one that looks like it is doing the
# scanning, because it would be.
#
# So the window is a day, not ten minutes: a site's TLS configuration changes
# when somebody deploys a change to it, which is not an hourly event, and ten
# scans a day is enough to check a handful of sites and re-check them after a
# rollout. The tighter bound is what keeps a burst of scans from a single
# account from looking like reconnaissance to whoever is on the receiving end.
#
# Counted per account rather than per address, for the reason create-pr's
# limiter was fixed: the deployed backend sits behind Render's proxy, so every
# visitor arrives from one internal address and an address-keyed limit is a
# limit on the whole site at once. rate_limit_by_user also refuses an
# unauthenticated request with a 401 before the window is touched.
_limiter = RateLimiter(max_requests=10, window_seconds=86400)


# A separate bucket from the TLS scan's, deliberately: exhausting one must not
# spend the other. This check is the cheaper of the two -- one HTTP GET and a
# read of the response headers, with no handshake to complete and no
# certificate to parse -- so it gets twice the allowance over the same day-long
# window. What it shares with the TLS limiter is the thing that matters: it is
# counted per account, not per address, because Render's proxy collapses every
# visitor onto one internal address (see rate_limit.client_key).
_HEADERS_WINDOW_SECONDS = 86400
_headers_limiter = RateLimiter(max_requests=20, window_seconds=_HEADERS_WINDOW_SECONDS)


def _http_error(exc: Exception, url: str, what: str) -> HTTPException:
    """Map a scanner failure onto the response a client should see.

    Shared by both endpoints so the two cannot drift into answering the same
    class of failure with different status codes -- which would itself leak
    something, since the difference between "refused" and "unreachable" is
    exactly what an attacker probing the internal network wants to learn.
    """
    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, (InvalidTargetURLError, BlockedTargetError)):
        # 400 for both: a caller-supplied URL QLint will not accept. A blocked
        # target is deliberately not distinguished by status code from a
        # malformed one, so neither endpoint can be used as an oracle that maps
        # the internal network by watching which URLs get which code.
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(
        exc, (TargetResolutionError, TLSConnectionError, SSRFGuardError, TLSScanError)
    ):
        # The target was allowed and talking to it failed. 502 rather than 500:
        # nothing here is broken, the upstream host is unreachable or its TLS
        # is. The detail is the sentence the scanner composed for exactly this.
        return HTTPException(status_code=502, detail=str(exc))
    # The never-raises-unhandled guarantee, matching pr_router's. A stack trace
    # from a socket, a certificate parser or httpx must not reach a client: it
    # says nothing useful about the site and something about this server. The
    # full exception goes to the log instead.
    logger.exception("Unexpected failure while running a %s of %s", what, url)
    return HTTPException(
        status_code=500,
        detail=f"The {what} failed unexpectedly. Please try again.",
    )


class WebScanRequest(BaseModel):
    url: str


@router.post("/web-scan/tls", dependencies=[Depends(rate_limit_by_user(_limiter))])
async def scan_website_tls(body: WebScanRequest, user: dict = Depends(get_current_user)):
    """Inspect the TLS configuration a site actually serves, on port 443.

    No redirects are followed and no port other than 443 is contacted: the
    report describes the exact host that was asked for, or the request fails.
    Following a redirect would mean reporting on a host the caller never named
    and the address guard never judged -- the guard would be checking one
    target and the socket would be visiting another.
    """
    try:
        return await scan_url(body.url)
    except Exception as exc:
        raise _http_error(exc, body.url, "TLS scan") from exc


@router.post(
    "/web-scan/headers", dependencies=[Depends(rate_limit_by_user(_headers_limiter))]
)
async def scan_website_headers(
    body: WebScanRequest, user: dict = Depends(get_current_user)
):
    """Report which HTTP security headers a site sends, on port 443.

    Same request shape, same https-only rule and the same ssrf_guard as the TLS
    endpoint above -- the target validation is shared code, not a second
    implementation, because a second implementation is the one that would be
    subtly wrong.

    Every header checked appears in the response whether it passed or failed. A
    report listing only problems reads the same as a report that failed to run,
    and the passing rows are what let a reader trust the failing ones.
    """
    try:
        return await header_scan_url(body.url)
    except HeaderScanError as exc:
        # The target was allowed and the request to it failed. 502 for the same
        # reason the TLS endpoint uses it: this server is fine, the upstream is
        # not, and the detail is the sentence header_scanner composed.
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise _http_error(exc, body.url, "header scan") from exc

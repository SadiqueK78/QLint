"""Level 1: scan a live website's TLS and certificate configuration.

Level 2 -- everything else in QLint -- reads source code and only ever talks to
GitHub. This router is the first that connects to a host a user names, which
makes it the first place where a request body decides where the backend's
socket goes. That is server-side request forgery in the plain sense, and the
whole shape of this file follows from it:

  * The target is validated, resolved and address-checked in tls_scanner
    before a connection is attempted. That module holds the control and
    documents it; this one holds the HTTP concerns.
  * The route requires a session, using the same get_current_user the /scan
    endpoint uses. Not for accounting -- so that an outbound connection from
    this server's address is always attributable to an account.
  * It is rate limited per account, because the cost of a runaway loop here is
    not a bill. It is this server making thousands of connections to a third
    party that never asked to hear from it.

What comes back is a report in the same shape a code scan produces: findings
carrying CRYPTO_DB's severity and quantum-risk vocabulary, and the same 0-100
readiness score, so a site and a repository are read on one scale.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import get_current_user
from rate_limit import RateLimiter, rate_limit_by_user
from tls_scanner import (
    BlockedTargetError,
    InvalidTargetURLError,
    TLSConnectionError,
    TLSScanError,
    scan_url,
)

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
    except (InvalidTargetURLError, BlockedTargetError) as exc:
        # 400 for both: a caller-supplied URL this endpoint will not accept.
        # A blocked target is deliberately not distinguished by status code
        # from a malformed one, so the endpoint cannot be used as an oracle
        # that maps the internal network by watching which URLs get which code.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except TLSConnectionError as exc:
        # The target was allowed and talking to it failed. 502 rather than 500:
        # nothing here is broken, the upstream host is unreachable or its TLS
        # is. The detail is the sentence tls_scanner composed for exactly this.
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except TLSScanError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        # The never-raises-unhandled guarantee, matching pr_router's. A stack
        # trace from a socket or a certificate parser must not reach a client:
        # it says nothing useful about the site and something about this
        # server. The full exception goes to the log instead.
        logger.exception("Unexpected failure while scanning %s", body.url)
        raise HTTPException(
            status_code=500,
            detail="The TLS scan failed unexpectedly. Please try again.",
        ) from exc

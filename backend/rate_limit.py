"""A small in-process rate limiter for endpoints that cost money to serve.

Written for /scan/explain, which pays for an OpenRouter completion on every
cache miss and whose cache key includes client-supplied fields — so a caller
who varies `identifier` can force unlimited misses and unlimited spend. There
was nothing to reuse: benchmark_router.py says so in as many words ("The
project has no rate-limit middleware or decorator to reuse"), and scan_router
only reads GitHub's own quota, which is a different thing. This adds the
mechanism without adding a dependency.

Two ways to identify a caller, and the choice matters more than the numbers:

  * rate_limit() counts against the peer address. The only option on a route
    with no session, and weak behind a proxy -- see client_key.
  * rate_limit_by_user() counts against the signed-in account. Use this
    wherever the route already requires a session. An account id is issued by
    this application, cannot be spoofed by a header, and survives a proxy that
    collapses every visitor onto one address.

Scope, deliberately narrow: the window lives in this process's memory. It
resets on restart and is not shared between workers, so it is a cost ceiling
per process rather than a distributed quota. That is enough to stop one client
looping the endpoint; a multi-worker deployment that needs a hard global cap
should move this state into Mongo or Redis.
"""

import math
import time
from collections import defaultdict, deque

from fastapi import Depends, HTTPException, Request

from auth import get_current_user

# Above this many tracked clients, expired windows are swept before the next
# admission decision. Bounds memory without sweeping on every request.
_SWEEP_THRESHOLD = 1024

# Largest unit first: the first one the duration reaches is the one it is
# described in.
_DURATION_UNITS: tuple[tuple[int, str], ...] = (
    (86400, "day"),
    (3600, "hour"),
    (60, "minute"),
    (1, "second"),
)


def format_duration(seconds: float) -> str:
    """A duration in the largest unit that fits, for a message a human reads.

    Every window used to be described in minutes regardless of size, which was
    fine while the longest was an hour and became unreadable when web_scan
    arrived with a day: "10 requests per 1440 minutes. Try again in 86400s."

    Rounds up, which matters only for the "try again in" half. That number
    counts down as the window slides, so it is rarely a whole unit -- and
    rounding down would tell someone to come back before their allowance has
    actually refilled, which sends them straight into another 429. Overstating
    the wait by under a unit is the harmless direction. Every window currently
    configured (10 minutes, 1 hour, 1 day) divides exactly, so the window half
    of the message is unaffected either way.
    """
    for size, name in _DURATION_UNITS:
        if seconds >= size:
            count = math.ceil(seconds / size)
            return f"{count} {name}{'' if count == 1 else 's'}"
    return "1 second"  # sub-second, and "0 seconds" would read as "no wait"


class RateLimiter:
    """Sliding window of request timestamps, one window per client key."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _sweep(self, now: float) -> None:
        """Forget clients whose whole window has expired."""
        cutoff = now - self.window_seconds
        for key in [
            key
            for key, hits in self._hits.items()
            if not hits or hits[-1] <= cutoff
        ]:
            del self._hits[key]

    def check(self, key: str) -> None:
        """Record one request for key. Raises HTTP 429 when the window is full."""
        now = time.monotonic()
        if len(self._hits) > _SWEEP_THRESHOLD:
            self._sweep(now)

        hits = self._hits[key]
        cutoff = now - self.window_seconds
        while hits and hits[0] <= cutoff:
            hits.popleft()

        if len(hits) >= self.max_requests:
            retry_after = max(1, int(self.window_seconds - (now - hits[0])) + 1)
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Rate limit exceeded: {self.max_requests} requests per "
                    f"{format_duration(self.window_seconds)}. "
                    f"Try again in {format_duration(retry_after)}."
                ),
                # Stays raw seconds: Retry-After is defined by RFC 9110 as a
                # number of seconds or an HTTP-date, and it is parsed by
                # clients rather than read by people. Only the human sentence
                # above changes units.
                headers={"Retry-After": str(retry_after)},
            )
        hits.append(now)

    def reset(self) -> None:
        """Drop all state. For tests, and for an admin-triggered clear."""
        self._hits.clear()


def client_key(request: Request) -> str:
    """The identity a limit is counted against: the peer address.

    X-Forwarded-For is deliberately not trusted. A caller can set that header
    to anything, so honouring it would let the same client present a fresh
    identity per request and bypass the limit completely — worse than having
    no limit, because it would look like one was in place.

    The cost of that decision is real and worth stating plainly: behind a
    proxy this counts every visitor against the proxy's address. On the
    deployed service it does exactly that -- the platform terminates TLS and
    forwards over its own network, so every request arrives from one internal
    address and a limit keyed here is a limit on the whole site at once.

    So this is the fallback, for routes with no signed-in caller to name.
    Anything behind a session should use user_key/rate_limit_by_user instead.
    """
    return request.client.host if request.client else "unknown"


def user_key(user: dict) -> str:
    """The identity a limit is counted against: the QLint account.

    Namespaced so a bucket can never be shared between an account id and an
    address that happens to read the same way. The limiters are per-route
    today, so this is belt-and-braces rather than load-bearing.
    """
    return f"user:{user['_id']}"


def rate_limit(limiter: RateLimiter):
    """A dependency enforcing limiter per peer address.

    For routes with no authenticated caller. On a route that has one, prefer
    rate_limit_by_user: see client_key for why an address is the weaker
    identity behind a proxy.
    """

    def dependency(request: Request) -> None:
        limiter.check(client_key(request))

    return dependency


def rate_limit_by_user(limiter: RateLimiter):
    """A dependency enforcing limiter per authenticated account.

    Depending on get_current_user here rather than reading a user the route
    already resolved has two consequences worth naming. FastAPI caches a
    dependency per request, so the session is resolved once and shared with
    the endpoint's own parameter -- no second database read. And a request
    without a valid token is refused with a 401 before the window is touched,
    so unauthenticated noise can no longer spend a real account's allowance.
    """

    def dependency(user: dict = Depends(get_current_user)) -> None:
        limiter.check(user_key(user))

    return dependency

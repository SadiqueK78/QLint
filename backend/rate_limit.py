"""A small in-process rate limiter for endpoints that cost money to serve.

Written for /scan/explain, which pays for an OpenRouter completion on every
cache miss and whose cache key includes client-supplied fields — so a caller
who varies `identifier` can force unlimited misses and unlimited spend. There
was nothing to reuse: benchmark_router.py says so in as many words ("The
project has no rate-limit middleware or decorator to reuse"), and scan_router
only reads GitHub's own quota, which is a different thing. This adds the
mechanism without adding a dependency.

Scope, deliberately narrow: the window lives in this process's memory. It
resets on restart and is not shared between workers, so it is a cost ceiling
per process rather than a distributed quota. That is enough to stop one client
looping the endpoint; a multi-worker deployment that needs a hard global cap
should move this state into Mongo or Redis.
"""

import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

# Above this many tracked clients, expired windows are swept before the next
# admission decision. Bounds memory without sweeping on every request.
_SWEEP_THRESHOLD = 1024


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
                    f"{int(self.window_seconds // 60)} minutes. "
                    f"Try again in {retry_after}s."
                ),
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
    no limit, because it would look like one was in place. Behind a proxy this
    counts every user against the proxy's address; a deployment that
    terminates at a trusted proxy should read the forwarded address here and
    only from that proxy.
    """
    return request.client.host if request.client else "unknown"


def rate_limit(limiter: RateLimiter):
    """Build a FastAPI dependency that enforces limiter for a route."""

    def dependency(request: Request) -> None:
        limiter.check(client_key(request))

    return dependency

"""The shared rate limiter: its window arithmetic, and how it says no.

rate_limit.py had no test file of its own -- it was covered only through the
four routes that use it, each of which checked that a 429 happened and that the
message started with "Rate limit exceeded". That was enough while the longest
window was an hour. It stopped being enough when web_scan_router arrived with a
day-long one and the message read "10 requests per 1440 minutes. Try again in
86400s.": accurate, and nothing a person would want to read.

So this file pins the formatting directly, at the boundaries where a tier
changes, rather than leaving it inferred from whichever windows the routes
happen to be configured with today.
"""

import time

import pytest
from fastapi import HTTPException

from rate_limit import RateLimiter, client_key, format_duration, user_key

# Every window configured in the application, and what each one should read as.
# Kept here as literals rather than imported from the routers: the point is to
# notice if a window changes, not to follow it.
CONFIGURED_WINDOWS = [
    (600, "10 minutes"),
    (3600, "1 hour"),
    (86400, "1 day"),
]


class TestFormatDuration:
    @pytest.mark.parametrize(
        "seconds,expected",
        [
            # Seconds: under a minute.
            (1, "1 second"),
            (2, "2 seconds"),
            (59, "59 seconds"),
            # Minutes: a minute up to an hour.
            (60, "1 minute"),
            (120, "2 minutes"),
            (600, "10 minutes"),
            (3599, "60 minutes"),
            # Hours: an hour up to a day.
            (3600, "1 hour"),
            (7200, "2 hours"),
            (86399, "24 hours"),
            # Days: a day and beyond.
            (86400, "1 day"),
            (172800, "2 days"),
            (604800, "7 days"),
        ],
    )
    def test_the_unit_matches_the_size_of_the_duration(self, seconds, expected):
        assert format_duration(seconds) == expected

    @pytest.mark.parametrize(
        "seconds", [60, 3600, 86400]
    )
    def test_exactly_one_unit_is_singular(self, seconds):
        """"1 hours" is the tell that a plural was appended unconditionally."""
        assert format_duration(seconds).split()[0] == "1"
        assert not format_duration(seconds).endswith("s")

    def test_a_partial_unit_rounds_up_rather_than_down(self):
        """Rounding down would advise a retry before the allowance refills."""
        assert format_duration(5400) == "2 hours"  # 1.5h, not "1 hour"
        assert format_duration(90) == "2 minutes"  # 1.5m, not "1 minute"

    def test_a_sub_second_duration_still_reads_as_a_wait(self):
        assert format_duration(0.4) == "1 second"
        assert format_duration(0) == "1 second"


class TestTheMessage:
    @staticmethod
    def _refuse(max_requests, window_seconds):
        """Fill a window and return the HTTPException it raises."""
        limiter = RateLimiter(
            max_requests=max_requests, window_seconds=window_seconds
        )
        for _ in range(max_requests):
            limiter.check("user:someone")
        with pytest.raises(HTTPException) as raised:
            limiter.check("user:someone")
        return raised.value

    @pytest.mark.parametrize("window_seconds,expected", CONFIGURED_WINDOWS)
    def test_every_configured_window_reads_in_its_natural_unit(
        self, window_seconds, expected
    ):
        exc = self._refuse(3, window_seconds)
        assert exc.status_code == 429
        assert exc.detail == (
            f"Rate limit exceeded: 3 requests per {expected}. "
            f"Try again in {expected}."
        )

    def test_the_day_long_window_no_longer_reads_as_1440_minutes(self):
        """The message that prompted this change."""
        detail = self._refuse(10, 86400).detail
        assert detail == (
            "Rate limit exceeded: 10 requests per 1 day. Try again in 1 day."
        )
        assert "1440 minutes" not in detail
        assert "86400s" not in detail

    def test_the_retry_after_header_stays_raw_seconds(self):
        """RFC 9110 defines it as seconds; a client parses it, nobody reads it."""
        exc = self._refuse(3, 86400)
        assert exc.headers["Retry-After"].isdigit()
        assert 86000 < int(exc.headers["Retry-After"]) <= 86401

    def test_the_request_count_is_the_configured_one(self):
        assert "7 requests per" in self._refuse(7, 600).detail


class TestTheLimitingItselfIsUnchanged:
    """Formatting was the whole change; the admission decisions were not.

    These are here so a future edit to the message cannot quietly move the
    boundary it is describing.
    """

    def test_requests_up_to_the_limit_are_admitted(self):
        limiter = RateLimiter(max_requests=5, window_seconds=600)
        for _ in range(5):
            limiter.check("user:someone")  # no raise

    def test_the_request_after_the_limit_is_refused(self):
        limiter = RateLimiter(max_requests=5, window_seconds=600)
        for _ in range(5):
            limiter.check("user:someone")
        with pytest.raises(HTTPException) as raised:
            limiter.check("user:someone")
        assert raised.value.status_code == 429

    def test_each_key_has_its_own_window(self):
        limiter = RateLimiter(max_requests=2, window_seconds=600)
        for _ in range(2):
            limiter.check("user:first")
        limiter.check("user:second")  # a different key, still admitted

    def test_a_window_that_has_passed_admits_again(self):
        limiter = RateLimiter(max_requests=1, window_seconds=0.05)
        limiter.check("user:someone")
        with pytest.raises(HTTPException):
            limiter.check("user:someone")
        time.sleep(0.06)
        limiter.check("user:someone")  # the window slid past

    def test_reset_clears_every_window(self):
        limiter = RateLimiter(max_requests=1, window_seconds=600)
        limiter.check("user:someone")
        limiter.reset()
        limiter.check("user:someone")


class TestTheIdentityAKeyIsCountedAgainst:
    def test_user_key_namespaces_the_account_id(self):
        assert user_key({"_id": "507f1f77bcf86cd799439011"}) == (
            "user:507f1f77bcf86cd799439011"
        )

    def test_client_key_reads_the_peer_address(self):
        class Request:
            client = type("Client", (), {"host": "203.0.113.9"})()

        assert client_key(Request()) == "203.0.113.9"

    def test_client_key_survives_a_request_with_no_peer(self):
        class Request:
            client = None

        assert client_key(Request()) == "unknown"

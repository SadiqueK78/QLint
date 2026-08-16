"""The optional scan_type filter on GET /user/scans.

The history list has always returned both kinds of scan, newest first. This
adds one optional query parameter that narrows it to one kind, and the whole
risk of the change is in what happens when the parameter is *absent*: every
caller that existed before it has to get exactly the answer it got before.

Three properties, in the order the classes come:

  * Omitting the parameter returns both kinds, unfiltered, with the same total
    and the same ordering as before.
  * Each value returns only that kind -- and "repository" has a trap in it. A
    document written before scan_type existed has no such field, and in MongoDB
    an equality match on "repository" does not match a missing field. Filtering
    to repositories must not silently hide a user's entire pre-website history,
    which is why the query is spelled "not a website" and why the fixture below
    includes a legacy document.
  * Ownership and soft delete still apply on top of the filter, because a
    filter that widened either would be a much worse bug than a filter that
    did not work at all.

The collection is a fake, but the query it is handed is evaluated rather than
asserted on: a $match that is present and wrong passes a shape assertion.
"""

from datetime import datetime, timedelta, timezone

import pytest
from bson import ObjectId
from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth import get_current_user
from database import SCAN_TYPE_REPOSITORY, SCAN_TYPE_WEBSITE
from routers import user_router as module
from routers.user_router import router as user_router

OWNER = {"_id": "507f1f77bcf86cd799439011", "email": "owner@qlint.dev"}
STRANGER_ID = "507f1f77bcf86cd799439099"

NOW = datetime.now(timezone.utc)


def _resolve(document: dict, key: str):
    """document[key], or None when the field is absent.

    The distinction the legacy documents turn on: an absent scan_type has to
    behave the way Mongo behaves for one, not raise.
    """
    return document.get(key)


def _condition_holds(value, condition) -> bool:
    """The three operators these queries actually use, evaluated honestly."""
    if isinstance(condition, dict):
        if "$ne" in condition:
            return value != condition["$ne"]
        if "$gt" in condition:
            return value is not None and value > condition["$gt"]
        raise AssertionError(f"unsupported condition {condition}")
    return value == condition


class FakeScans:
    """A scans collection that evaluates the query it is given."""

    def __init__(self, documents):
        self.documents = documents
        self.queries: list[dict] = []

    def _matching(self, query):
        self.queries.append(query)
        return [
            document
            for document in self.documents
            if all(
                _condition_holds(_resolve(document, key), condition)
                for key, condition in query.items()
            )
        ]

    async def count_documents(self, query):
        return len(self._matching(query))

    def find(self, query, projection=None):
        return _Cursor(self._matching(query))


class _Cursor:
    def __init__(self, documents):
        self.documents = documents

    def sort(self, key, direction):
        self.documents = sorted(
            self.documents,
            key=lambda document: document.get(key) or NOW,
            reverse=direction == -1,
        )
        return self

    def skip(self, count):
        self.documents = self.documents[count:]
        return self

    def limit(self, count):
        self.documents = self.documents[:count]
        return self

    async def to_list(self, length=None):
        return self.documents[:length]


def _repository(index: int, legacy: bool = False, **extra) -> dict:
    document = {
        "_id": ObjectId(),
        "repo_url": f"https://github.com/acme/repo{index}",
        "user_id": str(OWNER["_id"]),
        "scanned_by": OWNER["email"],
        "created_at": NOW - timedelta(minutes=index),
        "result": {
            "pqc_readiness_score": 40,
            "total_findings": 2,
            "scanned_files": 9,
            "algorithms_found": ["RSA"],
            "findings_by_file": {},
        },
        **extra,
    }
    if not legacy:
        document["scan_type"] = SCAN_TYPE_REPOSITORY
    return document


def _website(index: int, **extra) -> dict:
    return {
        "_id": ObjectId(),
        "scan_type": SCAN_TYPE_WEBSITE,
        "target_url": f"https://site{index}.example.com",
        "user_id": str(OWNER["_id"]),
        "scanned_by": OWNER["email"],
        "created_at": NOW - timedelta(minutes=index),
        "result": {
            "pqc_readiness_score": 70,
            "total_findings": 3,
            "algorithms_found": ["ECC"],
            "findings": [],
        },
        **extra,
    }


# Two modern repository scans, one written before scan_type existed, and two
# website scans. Plus one of each that must never appear: another account's,
# and one this account has deleted.
@pytest.fixture
def scans(monkeypatch):
    collection = FakeScans(
        [
            _repository(1),
            _repository(2),
            _repository(3, legacy=True),
            _website(4),
            _website(5),
            _website(6, user_id=STRANGER_ID),
            _repository(7, user_id=STRANGER_ID),
            _website(8, deleted_at=NOW),
            _repository(9, deleted_at=NOW),
        ]
    )
    monkeypatch.setattr(module, "get_scans", lambda: collection)
    return collection


@pytest.fixture
def client(scans):
    app = FastAPI()
    app.include_router(user_router)
    app.dependency_overrides[get_current_user] = lambda: OWNER
    yield TestClient(app)
    app.dependency_overrides.clear()


def history(client, **params):
    response = client.get("/user/scans", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def kinds(body) -> list[str]:
    return [row["scan_type"] for row in body["scans"]]


# ---------------------------------------------------------------------------
# Omitting the parameter changes nothing
# ---------------------------------------------------------------------------


class TestTheUnfilteredListIsUnchanged:
    def test_both_kinds_come_back(self, client):
        body = history(client)
        assert set(kinds(body)) == {SCAN_TYPE_REPOSITORY, SCAN_TYPE_WEBSITE}

    def test_the_total_counts_every_visible_scan_of_either_kind(self, client):
        # Three repository scans (one legacy) and two website scans; the
        # stranger's two and the two deleted ones are not this user's list.
        assert history(client)["total"] == 5

    def test_the_query_carries_no_scan_type_condition_at_all(self, client, scans):
        """Not "scan_type: None", which would match only documents whose field
        is null -- the absent key is what preserves the old behaviour."""
        history(client)
        assert all("scan_type" not in query for query in scans.queries)

    def test_the_ordering_is_still_newest_first(self, client):
        body = history(client)
        dates = [row["created_at"] for row in body["scans"]]
        assert dates == sorted(dates, reverse=True)

    def test_paging_still_works_the_way_it_did(self, client):
        first = history(client, page=1, limit=2)
        second = history(client, page=2, limit=2)
        assert len(first["scans"]) == 2
        assert first["total"] == 5
        assert first["pages"] == 3
        assert {row["id"] for row in first["scans"]}.isdisjoint(
            {row["id"] for row in second["scans"]}
        )


# ---------------------------------------------------------------------------
# Each value filters to its own kind
# ---------------------------------------------------------------------------


class TestFilteringToWebsites:
    def test_only_website_scans_come_back(self, client):
        body = history(client, scan_type=SCAN_TYPE_WEBSITE)
        assert kinds(body) == [SCAN_TYPE_WEBSITE, SCAN_TYPE_WEBSITE]
        assert all(row["target_url"] for row in body["scans"])

    def test_the_total_counts_the_filtered_list_not_the_whole_history(self, client):
        """`total` drives the page count, so it has to be the size of the list
        actually being paginated."""
        body = history(client, scan_type=SCAN_TYPE_WEBSITE)
        assert body["total"] == 2
        assert body["pages"] == 1

    def test_paging_applies_within_the_filter(self, client):
        body = history(client, scan_type=SCAN_TYPE_WEBSITE, limit=1)
        assert len(body["scans"]) == 1
        assert body["total"] == 2
        assert body["pages"] == 2


class TestFilteringToRepositories:
    def test_only_repository_scans_come_back(self, client):
        body = history(client, scan_type=SCAN_TYPE_REPOSITORY)
        assert set(kinds(body)) == {SCAN_TYPE_REPOSITORY}
        assert all(row["repo_url"] for row in body["scans"])

    def test_a_scan_written_before_scan_type_existed_is_still_a_repository(
        self, client
    ):
        """The trap this filter is spelled around. Three repository scans exist
        and one of them has no scan_type field at all; an equality match on
        "repository" would return two and quietly lose a user's history."""
        body = history(client, scan_type=SCAN_TYPE_REPOSITORY)
        assert body["total"] == 3
        assert len(body["scans"]) == 3

    def test_the_query_is_spelled_as_not_a_website(self, client, scans):
        history(client, scan_type=SCAN_TYPE_REPOSITORY)
        assert scans.queries[-1]["scan_type"] == {"$ne": SCAN_TYPE_WEBSITE}


class TestTheTwoFiltersPartitionTheList:
    def test_the_two_add_up_to_the_unfiltered_total(self, client):
        both = history(client)["total"]
        repositories = history(client, scan_type=SCAN_TYPE_REPOSITORY)["total"]
        websites = history(client, scan_type=SCAN_TYPE_WEBSITE)["total"]
        assert repositories + websites == both

    def test_no_scan_appears_under_both_filters(self, client):
        repositories = {
            row["id"] for row in history(client, scan_type=SCAN_TYPE_REPOSITORY)["scans"]
        }
        websites = {
            row["id"] for row in history(client, scan_type=SCAN_TYPE_WEBSITE)["scans"]
        }
        assert repositories.isdisjoint(websites)


# ---------------------------------------------------------------------------
# The filter narrows; it never widens
# ---------------------------------------------------------------------------


class TestTheFilterIsNarrowingOnly:
    @pytest.mark.parametrize(
        "scan_type", [None, SCAN_TYPE_REPOSITORY, SCAN_TYPE_WEBSITE]
    )
    def test_another_account_s_scans_are_never_returned(self, client, scan_type):
        params = {} if scan_type is None else {"scan_type": scan_type}
        body = history(client, **params)
        assert body["total"] <= 5
        assert len(body["scans"]) <= 5

    @pytest.mark.parametrize(
        "scan_type", [None, SCAN_TYPE_REPOSITORY, SCAN_TYPE_WEBSITE]
    )
    def test_the_ownership_and_soft_delete_conditions_survive(
        self, client, scans, scan_type
    ):
        params = {} if scan_type is None else {"scan_type": scan_type}
        history(client, **params)
        for query in scans.queries:
            assert query["user_id"] == str(OWNER["_id"])
            assert query["deleted_at"] is None


class TestAnUnknownValueIsRefused:
    @pytest.mark.parametrize("value", ["repositories", "site", "", "REPOSITORY", "all"])
    def test_it_is_a_422_rather_than_a_silently_unfiltered_list(self, client, value):
        """Answering an unrecognised filter with the whole list would read as
        "the filter is broken" to a user watching rows appear that should not
        be there. Saying so is better."""
        assert client.get("/user/scans", params={"scan_type": value}).status_code == 422

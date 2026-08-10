"""MongoDB connection and index management for QLint.

A single AsyncIOMotorClient is created on app startup and shared by every
router. Collections are exposed through accessor functions rather than
module-level globals so that importing this module never opens a socket.
"""

import os

from dotenv import load_dotenv
from motor.motor_asyncio import (
    AsyncIOMotorClient,
    AsyncIOMotorCollection,
    AsyncIOMotorDatabase,
)
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import OperationFailure

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = "qlint"

# The filter every user-facing read of the scans collection applies.
#
# A user's delete button hides a scan from their own history; it never removes
# the document. /admin/stats, /admin/users and /admin/scans aggregate this same
# collection, so a hard delete would let any user quietly shrink the operator's
# view of total usage -- which is the whole point of admin oversight. Erasing
# data for real is a separate, deliberate admin action, not a side effect of a
# user tidying up their list.
#
# Matching on null rather than {"$exists": False} is deliberate: in MongoDB a
# null equality match also matches documents where the field is absent, so
# every scan stored before soft delete existed stays visible without a
# migration.
VISIBLE_SCAN: dict = {"deleted_at": None}

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


def connect() -> AsyncIOMotorDatabase:
    """Open the shared client. Safe to call more than once."""
    global _client, _db
    if _client is None:
        _client = AsyncIOMotorClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        _db = _client[DB_NAME]
    return _db


def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        return connect()
    return _db


def get_users() -> AsyncIOMotorCollection:
    return get_db().users


def get_scans() -> AsyncIOMotorCollection:
    return get_db().scans


def get_explanations() -> AsyncIOMotorCollection:
    return get_db().explanations


def get_patches() -> AsyncIOMotorCollection:
    """Cached migration diffs. Separate from explanations rather than sharing
    the collection: the two are keyed the same way but hold different content,
    and one feature's TTL sweep must not evict the other's entries."""
    return get_db().patches


async def create_indexes() -> None:
    """Create every index QLint relies on.

    Index names are left at their MongoDB defaults so re-running against a
    database that already has them is a no-op. A conflict with an index an
    older build created under another name is logged, not fatal.
    """
    db = get_db()
    specs = [
        (db.users, [("email", ASCENDING)], {"unique": True}),
        (db.scans, [("user_id", ASCENDING)], {}),
        # A user's history page: their scans, minus the ones they have hidden,
        # newest first.
        (
            db.scans,
            [
                ("user_id", ASCENDING),
                ("deleted_at", ASCENDING),
                ("created_at", DESCENDING),
            ],
            {},
        ),
        (db.scans, [("repo_url", ASCENDING)], {}),
        (db.scans, [("created_at", DESCENDING)], {}),
        # Cache lookup: newest non-expired scan for a repo.
        (db.scans, [("repo_url", ASCENDING), ("created_at", DESCENDING)], {}),
        # AI explanation cache: one entry per finding signature.
        (db.explanations, [("key", ASCENDING)], {"unique": True}),
        # ...and let Mongo drop each entry once its expires_at passes, rather
        # than filtering expired docs out of every read forever.
        (db.explanations, [("expires_at", ASCENDING)], {"expireAfterSeconds": 0}),
        # AI patch cache: same two indexes, same reasoning, its own collection.
        (db.patches, [("key", ASCENDING)], {"unique": True}),
        (db.patches, [("expires_at", ASCENDING)], {"expireAfterSeconds": 0}),
    ]
    for collection, keys, options in specs:
        try:
            await collection.create_index(keys, **options)
        except OperationFailure as exc:
            print(f"WARNING: could not create index {keys} on {collection.name}: {exc}")


async def ping() -> bool:
    """Return True when the server answers, False otherwise."""
    try:
        await get_db().command("ping")
        return True
    except Exception:
        return False


async def close() -> None:
    global _client, _db
    if _client is not None:
        _client.close()
        _client = None
        _db = None

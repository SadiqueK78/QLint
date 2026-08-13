"""Route-level tests for POST /scan/{scan_id}/create-pr.

Nothing here touches a network, a database or a real repository. Mongo is a
dict, OpenRouter is a stub, and GitHub is a FakeGitHub that records every
write it is asked to make -- which is what lets the batching and orphan-branch
assertions check behaviour rather than mocks having been called.

The test the whole feature exists for is
TestRevalidation::test_a_file_changed_since_the_scan_is_skipped_not_forced.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from github_client import GitHubError
from routers import pr_router as module

# --------------------------------------------------------------- fixtures data

SCAN_ID = "652f1a2b3c4d5e6f70819200"
REPO_URL = "https://github.com/testowner/testrepo"

CRYPTO_PY = (
    "import os\n"
    "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
    "\n"
    "def make_rsa():\n"
    "    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    "    return key\n"
    "\n"
    "def make_ec():\n"
    "    curve = ec.generate_private_key(ec.SECP256R1())\n"
    "    return curve\n"
)

UTIL_PY = "import hashlib\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n"


def finding(file, line, algorithm, snippet, severity="critical"):
    return {
        "file": file,
        "line": line,
        "algorithm": algorithm,
        "severity": severity,
        "attack_vector": "Shor's Algorithm",
        "replacement": "ML-KEM (FIPS 203)",
        "replacement_reason": "Shor's Algorithm factors the modulus.",
        "identifier": algorithm.lower(),
        "match_type": "function_call",
        "language": "python",
        "quantum_vulnerable": True,
        "classical_vulnerable": False,
        "code_snippet": snippet,
        "fix_snippet": "kem = oqs.KeyEncapsulation('ML-KEM-768')",
    }


RSA_FINDING = finding(
    "src/crypto.py",
    5,
    "RSA",
    "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
)
EC_FINDING = finding(
    "src/crypto.py", 9, "ECDSA", "curve = ec.generate_private_key(ec.SECP256R1())"
)
MD5_FINDING = finding(
    "src/util.py", 4, "MD5", "return hashlib.md5(data).hexdigest()", "warning"
)

SCAN_RESULT = {
    "repo": "testowner/testrepo",
    "findings_by_file": {
        "src/crypto.py": [RSA_FINDING, EC_FINDING],
        "src/util.py": [MD5_FINDING],
    },
}

# Diffs whose "-" lines are the real lines of the files above, which is the
# only kind the applier will accept.
RSA_DIFF = (
    "--- a/src/crypto.py\n+++ b/src/crypto.py\n@@ -5 +5 @@\n"
    "-    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    "+    key = oqs.KeyEncapsulation('ML-KEM-768')\n"
)
EC_DIFF = (
    "--- a/src/crypto.py\n+++ b/src/crypto.py\n@@ -9 +9 @@\n"
    "-    curve = ec.generate_private_key(ec.SECP256R1())\n"
    "+    curve = oqs.Signature('ML-DSA-65')\n"
)
MD5_DIFF = (
    "--- a/src/util.py\n+++ b/src/util.py\n@@ -4 +4 @@\n"
    "-    return hashlib.md5(data).hexdigest()\n"
    "+    return hashlib.sha256(data).hexdigest()\n"
)
# Covers line 5 as well as 4-6, so it collides with RSA_DIFF on purpose.
OVERLAPPING_DIFF = (
    "--- a/src/crypto.py\n+++ b/src/crypto.py\n@@ -4,3 +4,3 @@\n"
    " def make_rsa():\n"
    "-    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    "+    key = oqs.KeyEncapsulation('ML-KEM-1024')\n"
    "     return key\n"
)

DIFFS = {
    ("src/crypto.py", 5): RSA_DIFF,
    ("src/crypto.py", 9): EC_DIFF,
    ("src/util.py", 4): MD5_DIFF,
}


# ------------------------------------------------------------------- doubles


class FakeGitHub:
    """Every GitHub call the router makes, over dicts, recording writes."""

    def __init__(self, files=None, can_push=True):
        self.files = dict(files if files is not None else {
            "src/crypto.py": CRYPTO_PY,
            "src/util.py": UTIL_PY,
        })
        self.can_push = can_push
        self.existing_branches: set[str] = set()
        self.blobs: dict[str, str] = {}
        self.trees: list[list[dict]] = []
        self.commits: list[dict] = []
        self.created_branches: list[str] = []
        self.deleted_branches: list[str] = []
        self.pulls: list[dict] = []
        self.fail_pr_with: Exception | None = None
        self.fail_delete = False

    # -- reads
    async def get_repo_metadata(self, owner, repo, token, client):
        return {
            "default_branch": "main",
            "can_push": self.can_push,
            "private": False,
            "full_name": f"{owner}/{repo}",
        }

    async def get_branch_head(self, owner, repo, branch, token, client):
        return "basesha1234"

    async def get_file_content(self, owner, repo, path, token, client=None, ref=None):
        if path not in self.files:
            raise GitHubError(f"File not found: {path}")
        return self.files[path]

    async def ref_exists(self, owner, repo, branch, token, client):
        return branch in self.existing_branches

    # -- writes
    async def create_branch(self, owner, repo, branch, sha, token, client):
        self.created_branches.append(branch)
        self.existing_branches.add(branch)

    async def create_blob(self, owner, repo, content, token, client):
        sha = f"blob{len(self.blobs)}"
        self.blobs[sha] = content
        return sha

    async def create_tree(self, owner, repo, base_tree, entries, token, client):
        self.trees.append(list(entries))
        return f"tree{len(self.trees)}"

    async def create_commit(self, owner, repo, message, tree, parent, token, client):
        self.commits.append({"message": message, "tree": tree, "parent": parent})
        return f"commit{len(self.commits)}"

    async def update_ref(self, owner, repo, branch, sha, token, client):
        return None

    async def create_pull_request(
        self, owner, repo, head, base, title, body, token, client
    ):
        if self.fail_pr_with:
            raise self.fail_pr_with
        self.pulls.append(
            {"head": head, "base": base, "title": title, "body": body}
        )
        number = len(self.pulls)
        return {
            "url": f"https://github.com/{owner}/{repo}/pull/{number}",
            "number": number,
        }

    async def delete_branch(self, owner, repo, branch, token, client):
        if self.fail_delete:
            return False
        self.deleted_branches.append(branch)
        self.existing_branches.discard(branch)
        return True

    # -- what the blob for a path ended up being
    def committed(self, path):
        entry = next(
            item for tree in self.trees for item in tree if item["path"] == path
        )
        return self.blobs[entry["sha"]]


class StubGenerator:
    """generate_patch, answering from DIFFS by the finding's own location."""

    def __init__(self, overrides=None, error=None):
        self.overrides = overrides or {}
        self.error = error
        self.calls = 0
        # What the router handed over as the file to patch against, per call.
        # The F29 false-mismatch was the router passing nothing here, so the
        # model wrote its diff blind; the tests below assert on this directly.
        self.seen_content: list[str | None] = []

    async def __call__(self, finding, client, file_content=None):
        self.calls += 1
        self.seen_content.append(file_content)
        if self.error:
            raise self.error
        key = (finding["file"], finding["line"])
        if key in self.overrides:
            return self.overrides[key], "stub-model"
        return DIFFS[key], "stub-model"


class FakePatchCache:
    def __init__(self, docs=None):
        self.docs = docs or {}
        self.lookups = 0

    async def find_one(self, query):
        self.lookups += 1
        return self.docs.get(query["key"])


USER = {
    "_id": "user-1",
    "email": "dev@example.com",
    "github_connected": True,
    "github_access_token": "read-only-token",
    "github_write_connected": True,
    "github_write_token": "write-token",
}

READ_ONLY_USER = {
    "_id": "user-2",
    "email": "readonly@example.com",
    "github_connected": True,
    "github_access_token": "read-only-token",
}


@pytest.fixture
def github(monkeypatch):
    fake = FakeGitHub()
    for name in (
        "get_repo_metadata",
        "get_branch_head",
        "get_file_content",
        "ref_exists",
        "create_branch",
        "create_blob",
        "create_tree",
        "create_commit",
        "update_ref",
        "create_pull_request",
        "delete_branch",
    ):
        monkeypatch.setattr(module, name, getattr(fake, name))
    return fake


@pytest.fixture
def generator(monkeypatch):
    stub = StubGenerator()
    monkeypatch.setattr(module, "generate_patch", stub)
    return stub


@pytest.fixture
def patch_cache(monkeypatch):
    cache = FakePatchCache()
    monkeypatch.setattr(module, "get_patches", lambda: cache)
    return cache


@pytest.fixture
def scan_owner(monkeypatch):
    """_owned_scan, standing in for the Mongo-backed ownership check."""
    state = {"owner_id": USER["_id"], "result": SCAN_RESULT, "repo_url": REPO_URL}

    async def owned(scan_id, user):
        from fastapi import HTTPException

        if scan_id != SCAN_ID or user["_id"] != state["owner_id"]:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {
            "_id": scan_id,
            "user_id": state["owner_id"],
            "repo_url": state["repo_url"],
            "result": state["result"],
        }

    monkeypatch.setattr(module, "_owned_scan", owned)
    return state


@pytest.fixture
def client(monkeypatch):
    """A bare app carrying just this router, signed in as USER."""
    module._limiter.reset()
    app = FastAPI()
    app.include_router(module.router)
    app.state.github = None  # every GitHub call is stubbed
    app.state.openrouter = None
    app.dependency_overrides[module.get_current_user] = lambda: dict(current["user"])
    current = {"user": USER}

    with TestClient(app) as test_client:
        test_client.sign_in_as = lambda user: current.__setitem__("user", user)
        yield test_client
    module._limiter.reset()


def create(client, findings=None, **extra):
    payload = {
        "findings": findings
        if findings is not None
        else [{"file": "src/crypto.py", "line": 5}],
        **extra,
    }
    return client.post(f"/scan/{SCAN_ID}/create-pr", json=payload)


# ------------------------------------------------------------- write scope


class TestWriteScopeIsRequired:
    def test_read_only_account_gets_403_not_a_silent_failure(
        self, client, github, generator, patch_cache, scan_owner
    ):
        """The whole point of the separate connection: an account that only
        connected GitHub for scanning must not be able to reach this at all."""
        client.sign_in_as({**READ_ONLY_USER, "_id": USER["_id"]})
        response = create(client)
        assert response.status_code == 403
        assert "write access" in response.json()["detail"].lower()

    def test_a_refused_request_touches_nothing_on_github(
        self, client, github, generator, patch_cache, scan_owner
    ):
        client.sign_in_as({**READ_ONLY_USER, "_id": USER["_id"]})
        create(client)
        assert github.created_branches == []
        assert github.pulls == []
        assert generator.calls == 0

    def test_the_read_token_is_never_used_as_a_fallback(
        self, client, github, generator, patch_cache, scan_owner
    ):
        """A connected-but-read-only account is refused rather than tried with
        the token it does have."""
        client.sign_in_as(
            {**USER, "github_write_connected": False, "github_write_token": None}
        )
        assert create(client).status_code == 403

    def test_a_flag_without_a_token_is_still_refused(
        self, client, github, generator, patch_cache, scan_owner
    ):
        client.sign_in_as({**USER, "github_write_token": None})
        assert create(client).status_code == 403

    def test_the_write_token_is_what_reaches_github(
        self, client, github, generator, patch_cache, scan_owner, monkeypatch
    ):
        seen = []

        async def capture(owner, repo, token, client_):
            seen.append(token)
            return {
                "default_branch": "main",
                "can_push": True,
                "private": False,
                "full_name": "x/y",
            }

        monkeypatch.setattr(module, "get_repo_metadata", capture)
        create(client)
        assert seen == ["write-token"]


# --------------------------------------------------------------- ownership


class TestOwnership:
    def test_a_scan_the_caller_does_not_own_is_a_404(
        self, client, github, generator, patch_cache, scan_owner
    ):
        scan_owner["owner_id"] = "somebody-else"
        response = create(client)
        assert response.status_code == 404
        assert github.created_branches == []

    def test_ownership_is_checked_before_anything_is_created(
        self, client, github, generator, patch_cache, scan_owner
    ):
        scan_owner["owner_id"] = "somebody-else"
        create(client)
        assert github.pulls == []
        assert generator.calls == 0


# ------------------------------------------------------------ re-validation


class TestRevalidation:
    def test_a_finding_that_still_matches_is_applied(
        self, client, github, generator, patch_cache, scan_owner
    ):
        response = create(client)
        assert response.status_code == 200
        body = response.json()
        assert body["created"] is True
        assert body["applied_count"] == 1
        assert body["skipped_count"] == 0
        assert "oqs.KeyEncapsulation('ML-KEM-768')" in github.committed(
            "src/crypto.py"
        )

    def test_a_file_changed_since_the_scan_is_skipped_not_forced(
        self, client, github, generator, patch_cache, scan_owner
    ):
        """The test this feature exists to pass. The flagged line has moved on
        since the scan, so the patch is refused and reported -- the file must
        come back untouched, not best-effort patched."""
        github.files["src/crypto.py"] = CRYPTO_PY.replace("key_size=2048", "key_size=4096")

        response = create(client)
        assert response.status_code == 200
        body = response.json()
        assert body["created"] is False
        assert body["applied_count"] == 0
        assert body["skipped_count"] == 1
        assert "file changed since scan" in body["skipped"][0]["reason"]
        assert github.created_branches == []
        assert github.pulls == []

    def test_the_skip_reason_names_the_line(
        self, client, github, generator, patch_cache, scan_owner
    ):
        github.files["src/crypto.py"] = CRYPTO_PY.replace("key_size=2048", "key_size=4096")
        reason = create(client).json()["skipped"][0]["reason"]
        assert "line 5" in reason

    def test_every_finding_is_checked_not_just_the_first(
        self, client, github, generator, patch_cache, scan_owner
    ):
        """One good finding must not carry a stale one into the commit."""
        github.files["src/crypto.py"] = CRYPTO_PY.replace(
            "ec.SECP256R1()", "ec.SECP384R1()"
        )
        body = create(
            client,
            [
                {"file": "src/crypto.py", "line": 5},
                {"file": "src/crypto.py", "line": 9},
            ],
        ).json()

        assert body["applied_count"] == 1
        assert body["skipped_count"] == 1
        assert body["skipped"][0]["finding"]["algorithm"] == "ECDSA"
        committed = github.committed("src/crypto.py")
        assert "ML-KEM-768" in committed
        assert "ec.SECP384R1()" in committed  # the stale line survives untouched

    def test_a_shifted_line_is_skipped_rather_than_guessed_at(
        self, client, github, generator, patch_cache, scan_owner
    ):
        """An edit earlier in the file moves the flagged line. Safe direction
        to be wrong in: a re-scan brings the finding back."""
        github.files["src/crypto.py"] = "# new header comment\n" + CRYPTO_PY
        body = create(client).json()
        assert body["applied_count"] == 0
        assert "file changed since scan" in body["skipped"][0]["reason"]

    def test_content_is_re_read_from_github_not_from_the_scan(
        self, client, github, generator, patch_cache, scan_owner, monkeypatch
    ):
        reads = []

        async def capture(owner, repo, path, token, client=None, ref=None):
            reads.append((path, ref))
            return github.files[path]

        monkeypatch.setattr(module, "get_file_content", capture)
        create(client)
        assert reads == [("src/crypto.py", "main")]

    def test_a_patch_that_cannot_be_placed_is_skipped(
        self, client, github, patch_cache, scan_owner, monkeypatch
    ):
        """The snippet still matches, but the model's diff removes a line that
        is not there. No fuzzy fallback: skipped, with the reason."""
        bad = (
            "--- a/src/crypto.py\n+++ b/src/crypto.py\n@@ -5 +5 @@\n"
            "-    key = rsa.generate_private_key(2048)\n"
            "+    key = oqs.KeyEncapsulation('ML-KEM-768')\n"
        )
        monkeypatch.setattr(
            module,
            "generate_patch",
            StubGenerator(overrides={("src/crypto.py", 5): bad}),
        )
        body = create(client).json()
        assert body["created"] is False
        assert "could not be applied" in body["skipped"][0]["reason"]
        assert github.created_branches == []


# ---------------------------------------------------------------- batching


class TestBatching:
    def test_two_findings_in_one_file_produce_one_commit(
        self, client, github, generator, patch_cache, scan_owner
    ):
        body = create(
            client,
            [
                {"file": "src/crypto.py", "line": 5},
                {"file": "src/crypto.py", "line": 9},
            ],
        ).json()

        assert body["applied_count"] == 2
        assert len(github.commits) == 1
        assert len(github.pulls) == 1
        assert body["files_changed"] == ["src/crypto.py"]

    def test_both_changes_land_in_the_same_blob(
        self, client, github, generator, patch_cache, scan_owner
    ):
        """Not two patches applied to two stale copies of the file: one file,
        one rewritten content, both edits present."""
        create(
            client,
            [
                {"file": "src/crypto.py", "line": 5},
                {"file": "src/crypto.py", "line": 9},
            ],
        )
        committed = github.committed("src/crypto.py")
        assert "ML-KEM-768" in committed
        assert "ML-DSA-65" in committed
        assert len(github.trees) == 1
        assert len(github.trees[0]) == 1

    def test_findings_across_files_are_still_one_commit(
        self, client, github, generator, patch_cache, scan_owner
    ):
        body = create(
            client,
            [
                {"file": "src/crypto.py", "line": 5},
                {"file": "src/util.py", "line": 4},
            ],
        ).json()

        assert body["applied_count"] == 2
        assert body["files_changed"] == ["src/crypto.py", "src/util.py"]
        assert len(github.commits) == 1
        assert len(github.trees[0]) == 2

    def test_overlapping_findings_are_reported_not_merged(
        self, client, github, patch_cache, scan_owner, monkeypatch
    ):
        """Two patches for the same lines. The first stands; the second is
        skipped with the reason, and no invented merge of the two is
        committed."""
        monkeypatch.setattr(
            module,
            "generate_patch",
            StubGenerator(overrides={("src/crypto.py", 9): OVERLAPPING_DIFF}),
        )
        body = create(
            client,
            [
                {"file": "src/crypto.py", "line": 5},
                {"file": "src/crypto.py", "line": 9},
            ],
        ).json()

        assert body["applied_count"] == 1
        assert body["skipped_count"] == 1
        assert "overlapping change" in body["skipped"][0]["reason"]

        committed = github.committed("src/crypto.py")
        assert "ML-KEM-768" in committed
        assert "ML-KEM-1024" not in committed

    def test_the_commit_message_lists_the_changed_files(
        self, client, github, generator, patch_cache, scan_owner
    ):
        create(
            client,
            [
                {"file": "src/crypto.py", "line": 5},
                {"file": "src/util.py", "line": 4},
            ],
        )
        message = github.commits[0]["message"]
        assert "src/crypto.py" in message and "src/util.py" in message


# ------------------------------------------------------- branch and PR shape


class TestBranchAndPullRequest:
    def test_the_branch_is_new_and_the_base_is_the_default_branch(
        self, client, github, generator, patch_cache, scan_owner
    ):
        body = create(client).json()
        assert body["branch"].startswith("qlint-pqc-migration-")
        assert body["base_branch"] == "main"
        assert github.pulls[0]["base"] == "main"
        assert github.pulls[0]["head"] == body["branch"]

    def test_an_existing_branch_name_is_stepped_over(
        self, client, github, generator, patch_cache, scan_owner
    ):
        """Reusing the name would push commits onto a pull request the user
        already opened."""
        github.existing_branches.add(f"qlint-pqc-migration-{SCAN_ID[-8:]}")
        body = create(client).json()
        assert body["branch"] == f"qlint-pqc-migration-{SCAN_ID[-8:]}-2"

    def test_the_pull_request_body_reports_applied_and_skipped(
        self, client, github, generator, patch_cache, scan_owner
    ):
        github.files["src/crypto.py"] = CRYPTO_PY.replace(
            "ec.SECP256R1()", "ec.SECP384R1()"
        )
        create(
            client,
            [
                {"file": "src/crypto.py", "line": 5},
                {"file": "src/crypto.py", "line": 9},
            ],
        )
        body = github.pulls[0]["body"]
        assert "| Severity | File | Line | Algorithm | Replacement |" in body
        assert "Skipped, and why" in body
        assert "file changed since scan" in body

    def test_the_response_carries_the_pr_url(
        self, client, github, generator, patch_cache, scan_owner
    ):
        body = create(client).json()
        assert body["pr_url"] == "https://github.com/testowner/testrepo/pull/1"
        assert body["pr_number"] == 1


# ------------------------------------------------------------- failure paths


class TestFailuresAreReported:
    def test_a_failed_pull_request_removes_the_branch_it_created(
        self, client, github, generator, patch_cache, scan_owner
    ):
        from github_write_client import PullRequestError

        github.fail_pr_with = PullRequestError("GitHub returned 422")
        response = create(client)
        assert response.status_code == 502
        assert github.deleted_branches == github.created_branches
        assert "was removed" in response.json()["detail"]

    def test_a_branch_that_could_not_be_removed_is_named_in_the_error(
        self, client, github, generator, patch_cache, scan_owner
    ):
        """An orphaned branch the user does not know about is the one leftover
        this feature must never create silently."""
        from github_write_client import PullRequestError

        github.fail_pr_with = PullRequestError("GitHub returned 422")
        github.fail_delete = True
        detail = create(client).json()["detail"]
        assert "qlint-pqc-migration-" in detail
        assert "delete it by hand" in detail

    def test_no_push_access_is_a_403_before_any_branch_exists(
        self, client, github, generator, patch_cache, scan_owner
    ):
        github.can_push = False
        response = create(client)
        assert response.status_code == 403
        assert "cannot push" in response.json()["detail"]
        assert github.created_branches == []

    def test_an_unexpected_error_is_a_500_that_says_where_to_look(
        self, client, github, generator, patch_cache, scan_owner, monkeypatch
    ):
        async def boom(*args, **kwargs):
            raise RuntimeError("something nobody predicted")

        monkeypatch.setattr(module, "create_tree", boom)
        response = create(client)
        assert response.status_code in (500, 502)
        assert "qlint-pqc-migration" in response.json()["detail"]

    def test_a_finding_the_scan_does_not_contain_is_a_400(
        self, client, github, generator, patch_cache, scan_owner
    ):
        response = create(client, [{"file": "etc/passwd", "line": 1}])
        assert response.status_code == 400
        assert "No finding at etc/passwd:1" in response.json()["detail"]
        assert github.created_branches == []

    def test_an_empty_selection_is_rejected(
        self, client, github, generator, patch_cache, scan_owner
    ):
        assert create(client, []).status_code == 422

    def test_too_many_findings_is_a_400(
        self, client, github, generator, patch_cache, scan_owner
    ):
        many = [
            {"file": "src/crypto.py", "line": 5}
            for _ in range(module.MAX_FINDINGS_PER_PR + 1)
        ]
        response = create(client, many)
        assert response.status_code == 400
        assert "at most" in response.json()["detail"]


# ------------------------------------------------------------- patch source


class TestPatchSource:
    def test_a_cached_patch_is_used_instead_of_calling_the_model(
        self, client, github, generator, scan_owner, monkeypatch
    ):
        """A patch already generated for this finding against this exact file
        content is reused rather than paid for again."""
        from patch_generator import grounding_excerpt
        from routers.patch_router import FindingPatchRequest, _cache_key

        key = _cache_key(
            FindingPatchRequest.model_validate(RSA_FINDING),
            grounding=grounding_excerpt(CRYPTO_PY, RSA_FINDING["line"]),
        )
        cache = FakePatchCache({key: {"patch": RSA_DIFF}})
        monkeypatch.setattr(module, "get_patches", lambda: cache)

        assert create(client).json()["applied_count"] == 1
        assert generator.calls == 0

    def test_a_finding_without_code_cannot_be_patched_and_is_skipped(
        self, client, github, generator, patch_cache, scan_owner
    ):
        scan_owner["result"] = {
            "findings_by_file": {
                "src/crypto.py": [{**RSA_FINDING, "code_snippet": ""}]
            }
        }
        body = create(client).json()
        assert body["created"] is False
        assert body["skipped_count"] == 1

    def test_a_model_failure_skips_only_that_finding(
        self, client, github, patch_cache, scan_owner, monkeypatch
    ):
        from patch_generator import PatchGeneratorError

        calls = {"n": 0}
        real = StubGenerator()

        async def flaky(finding, http_client, file_content=None):
            calls["n"] += 1
            if finding["line"] == 9:
                raise PatchGeneratorError("OpenRouter returned 502")
            return await real(finding, http_client, file_content)

        monkeypatch.setattr(module, "generate_patch", flaky)
        body = create(
            client,
            [
                {"file": "src/crypto.py", "line": 5},
                {"file": "src/crypto.py", "line": 9},
            ],
        ).json()
        assert body["applied_count"] == 1
        assert "no patch could be generated" in body["skipped"][0]["reason"]


# -------------------------------------------------- F29 false stale mismatch


# The two files below are byte-for-byte what the GitHub contents API returns
# for Abhushan187/qlint-f29-test, the repository the F29 bug was found on.
# Nothing here is tidied up for the test, and that matters: the original
# fixtures in this file were hand-written with single blank lines and a
# hand-written diff that already had the right indentation, so they modelled a
# world where the diff and the file always agreed. These carry the two details
# that actually broke it -- a flagged line indented inside a function, and the
# PEP 8 pair of blank lines before a def that the model kept collapsing into
# one.
REAL_KEYS_PY = (
    '"""Key generation helpers for the demo service."""\n'
    "\n"
    "from Crypto.PublicKey import RSA\n"
    "\n"
    "\n"
    "def make_transport_key():\n"
    "    key = RSA.generate(2048)\n"
    "    return key\n"
)

REAL_SIGNING_PY = (
    '"""Signature helpers for the demo service."""\n'
    "\n"
    "from cryptography.hazmat.primitives.asymmetric import ec\n"
    "\n"
    "\n"
    "def make_signing_key():\n"
    "    key = ec.generate_private_key(ec.SECP256R1())\n"
    "    return key\n"
)

# code_snippet as scanner_common.snippet_at stores it: stripped. The line in
# the file is indented four spaces; this is not, and that gap is what made the
# model emit an unindented "-" line that could never match.
REAL_KEYS_FINDING = finding(
    "crypto/keys.py", 7, "RSA", "key = RSA.generate(2048)"
)
REAL_SIGNING_FINDING = finding(
    "crypto/signing.py",
    7,
    "ECC",
    "key = ec.generate_private_key(ec.SECP256R1())",
)

REAL_SCAN_RESULT = {
    "repo": "Abhushan187/qlint-f29-test",
    "findings_by_file": {
        "crypto/keys.py": [REAL_KEYS_FINDING],
        "crypto/signing.py": [REAL_SIGNING_FINDING],
    },
}

# Real claude-sonnet-4.5 output, captured from a live OpenRouter call made with
# the grounded prompt against the real repository. Whole-file hunks with both
# blank lines present -- the shape a correct patch actually has, rather than
# the minimal one-line hunk the older fixtures use.
REAL_KEYS_DIFF = (
    "--- a/crypto/keys.py\n"
    "+++ b/crypto/keys.py\n"
    "@@ -1,8 +1,8 @@\n"
    ' """Key generation helpers for the demo service."""\n'
    " \n"
    "-from Crypto.PublicKey import RSA\n"
    "+import oqs\n"
    " \n"
    " \n"
    " def make_transport_key():\n"
    "-    key = RSA.generate(2048)\n"
    "-    return key\n"
    "+    with oqs.KeyEncapsulation('ML-KEM-768') as kem:\n"
    "+        public_key = kem.generate_keypair()\n"
    "+    return public_key\n"
)

REAL_SIGNING_DIFF = (
    "--- a/crypto/signing.py\n"
    "+++ b/crypto/signing.py\n"
    "@@ -1,8 +1,8 @@\n"
    ' """Signature helpers for the demo service."""\n'
    " \n"
    "-from cryptography.hazmat.primitives.asymmetric import ec\n"
    "+import oqs\n"
    " \n"
    " \n"
    " def make_signing_key():\n"
    "-    key = ec.generate_private_key(ec.SECP256R1())\n"
    "-    return key\n"
    "+    signer = oqs.Signature('ML-DSA-65')\n"
    "+    return signer\n"
)

REAL_DIFFS = {
    ("crypto/keys.py", 7): REAL_KEYS_DIFF,
    ("crypto/signing.py", 7): REAL_SIGNING_DIFF,
}


@pytest.fixture
def real_repo(monkeypatch, scan_owner):
    """The F29 test repository, its scan, and patches for it."""
    fake = FakeGitHub(
        files={
            "crypto/keys.py": REAL_KEYS_PY,
            "crypto/signing.py": REAL_SIGNING_PY,
        }
    )
    for name in (
        "get_repo_metadata",
        "get_branch_head",
        "get_file_content",
        "ref_exists",
        "create_branch",
        "create_blob",
        "create_tree",
        "create_commit",
        "update_ref",
        "create_pull_request",
        "delete_branch",
    ):
        monkeypatch.setattr(module, name, getattr(fake, name))

    stub = StubGenerator(overrides=REAL_DIFFS)
    monkeypatch.setattr(module, "generate_patch", stub)
    monkeypatch.setattr(module, "get_patches", lambda: FakePatchCache())

    scan_owner["result"] = REAL_SCAN_RESULT
    scan_owner["repo_url"] = "https://github.com/Abhushan187/qlint-f29-test"
    return fake, stub


ALL_REAL = [
    {"file": "crypto/keys.py", "line": 7},
    {"file": "crypto/signing.py", "line": 7},
]


class TestUnmodifiedFilesAlwaysApply:
    """F29 regression: a file nobody has touched since the scan must apply.

    The reported symptom was every finding on a freshly created, never edited
    repository being skipped with "the code the patch expects to change is not
    present in the current file". The re-validation was right and the file was
    unchanged; the patch was the thing that was wrong, because it had been
    generated without the model ever being shown the file.
    """

    def test_every_finding_applies_when_nothing_changed(self, client, real_repo):
        body = create(client, ALL_REAL).json()

        assert body["skipped"] == []
        assert body["skipped_count"] == 0
        assert body["applied_count"] == 2
        assert body["created"] is True
        assert sorted(body["files_changed"]) == [
            "crypto/keys.py",
            "crypto/signing.py",
        ]

    def test_the_model_is_given_the_real_file_to_patch_against(
        self, client, real_repo
    ):
        """The root cause, asserted directly.

        generate_patch used to receive the finding alone, so every context line
        in the returned diff was invented and the indentation of the flagged
        line -- stripped by the scanner before storage -- was gone. A diff
        written against a file the model never saw cannot be located by an
        exact-match applier, and that is the whole bug.
        """
        _, stub = real_repo
        create(client, ALL_REAL)

        assert stub.calls == 2
        assert REAL_KEYS_PY in stub.seen_content
        assert REAL_SIGNING_PY in stub.seen_content
        assert None not in stub.seen_content

    def test_the_indented_flagged_line_reaches_the_prompt_indented(self):
        """The stored snippet lost its indentation; the prompt must not.

        A '-' line has to match the file byte for byte, so a prompt that shows
        the model 'key = RSA.generate(2048)' when the file says
        '    key = RSA.generate(2048)' is asking for an unapplyable diff.
        """
        from patch_generator import _build_prompt

        blind = _build_prompt(REAL_KEYS_FINDING)
        grounded = _build_prompt(REAL_KEYS_FINDING, REAL_KEYS_PY)

        assert "    key = RSA.generate(2048)" not in blind
        assert "    key = RSA.generate(2048)" in grounded
        # The two blank lines before the def are the ones the model kept
        # collapsing, so they have to survive into the prompt as two.
        assert "from Crypto.PublicKey import RSA\n\n\ndef" in REAL_KEYS_PY
        assert "def make_transport_key():" in grounded

    def test_applied_content_is_what_the_diff_describes(self, client, real_repo):
        github, _ = real_repo
        create(client, ALL_REAL)

        assert github.committed("crypto/keys.py") == (
            '"""Key generation helpers for the demo service."""\n'
            "\n"
            "import oqs\n"
            "\n"
            "\n"
            "def make_transport_key():\n"
            "    with oqs.KeyEncapsulation('ML-KEM-768') as kem:\n"
            "        public_key = kem.generate_keypair()\n"
            "    return public_key\n"
        )


class TestRealStalenessStillDetected:
    """The other half: the fix must not blunt real staleness detection.

    Same repository, same scan, but crypto/keys.py has gained a line on GitHub
    since. That file's finding has genuinely moved and must still be refused;
    crypto/signing.py is untouched and must still apply.
    """

    # keys.py with "import logging" inserted, which pushes the flagged line
    # from 7 to 9 -- exactly the edit the manual stale-file test makes.
    STALE_KEYS_PY = (
        '"""Key generation helpers for the demo service."""\n'
        "\n"
        "import logging\n"
        "\n"
        "from Crypto.PublicKey import RSA\n"
        "\n"
        "\n"
        "def make_transport_key():\n"
        "    key = RSA.generate(2048)\n"
        "    return key\n"
    )

    def test_the_edited_file_is_skipped_and_the_untouched_one_applies(
        self, client, real_repo
    ):
        github, _ = real_repo
        github.files["crypto/keys.py"] = self.STALE_KEYS_PY

        body = create(client, ALL_REAL).json()

        assert body["applied_count"] == 1
        assert body["applied"][0]["finding"]["file"] == "crypto/signing.py"
        assert body["skipped_count"] == 1

        skipped = body["skipped"][0]
        assert skipped["finding"]["file"] == "crypto/keys.py"
        assert "file changed since scan" in skipped["reason"]

        # The stale file must not be in the commit at all.
        assert body["files_changed"] == ["crypto/signing.py"]

    def test_the_stale_file_is_never_written(self, client, real_repo):
        github, _ = real_repo
        github.files["crypto/keys.py"] = self.STALE_KEYS_PY

        create(client, ALL_REAL)

        assert [entry["path"] for tree in github.trees for entry in tree] == [
            "crypto/signing.py"
        ]

    def test_the_line_moving_is_what_is_detected_not_the_text_changing(self):
        """The flagged text is still in the stale file -- at a different line.

        Worth pinning: a matcher that searched the whole file would happily
        find 'key = RSA.generate(2048)' in STALE_KEYS_PY and patch it, which is
        the guess this feature refuses to make. Being positional is the point.
        """
        from patch_applier import snippet_matches_at_line

        snippet = REAL_KEYS_FINDING["code_snippet"]
        assert snippet in self.STALE_KEYS_PY
        assert snippet_matches_at_line(REAL_KEYS_PY, snippet, 7) is True
        assert snippet_matches_at_line(self.STALE_KEYS_PY, snippet, 7) is False
        assert snippet_matches_at_line(self.STALE_KEYS_PY, snippet, 9) is True


# ------------------------------------------------------------ rate limiting


class TestRateLimit:
    def test_requests_beyond_the_window_are_rejected_with_429(
        self, client, github, generator, patch_cache, scan_owner
    ):
        for _ in range(module._limiter.max_requests):
            assert create(client).status_code == 200

        blocked = create(client)
        assert blocked.status_code == 429
        assert "Rate limit exceeded" in blocked.json()["detail"]
        assert blocked.headers["Retry-After"]

    def test_the_limit_caps_pull_requests_actually_created(
        self, client, github, generator, patch_cache, scan_owner
    ):
        """The live-count check: every request past the cap must reach neither
        GitHub nor the paid model, not merely return 429."""
        limit = module._limiter.max_requests
        for _ in range(limit + 10):
            create(client)
        assert len(github.pulls) == limit
        assert len(github.created_branches) == limit
        assert generator.calls == limit

    def test_reset_clears_the_window(
        self, client, github, generator, patch_cache, scan_owner
    ):
        for _ in range(module._limiter.max_requests):
            create(client)
        assert create(client).status_code == 429

        module._limiter.reset()
        assert create(client).status_code == 200

    def test_pr_creation_has_the_tightest_bucket_of_any_endpoint(self):
        """A branch and a pull request in someone's repository is not the same
        cost as a completion, so it does not share the completion budget."""
        from routers import explain_router, patch_router

        assert module._limiter is not patch_router._limiter
        assert module._limiter is not explain_router._limiter
        assert module._limiter.max_requests < patch_router._limiter.max_requests

    def test_a_rejected_request_does_not_consume_the_patch_budget(
        self, client, github, generator, patch_cache, scan_owner
    ):
        from routers import patch_router

        patch_router._limiter.reset()
        for _ in range(module._limiter.max_requests + 3):
            create(client)
        assert patch_router._limiter._hits == {}

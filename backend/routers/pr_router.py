"""One-click post-quantum migration pull requests (F29).

The only endpoint in QLint that writes to somebody else's repository, so it is
the only one built defensively from the first line rather than the last.

Four gates stand between a request and a commit, and all four have to open:

1. A JWT, like every other authenticated route.
2. A *write* OAuth token, which is a different field on the user document than
   the one scanning uses. An account that only ever connected GitHub for
   scanning gets a 403 here with the reason, not a silent failure and not an
   attempt with the read token.
3. Ownership of the scan, through user_router's own helper, so this route
   cannot be pointed at a scan id belonging to someone else.
4. Per-finding re-validation against the file as it exists on GitHub *now*.
   A finding's code_snippet was captured whenever the scan ran; the file may
   have changed since. Every selected finding is re-read and re-checked, and
   one that no longer matches is skipped and reported, never force-fitted.

What the endpoint deliberately does not do: touch the default branch, merge
anything, or accept a diff from the client. The findings are looked up in the
stored scan by (file, line) rather than sent in the body, so a caller cannot
name a path the scan never saw, and the diffs come from the patch cache or
are generated server-side. The client chooses *which* findings, never *what*
the change is.
"""

import logging
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from pymongo.errors import PyMongoError

from auth import get_current_user
from database import get_patches
from github_client import (
    GitHubError,
    InvalidRepoURLError,
    InvalidTokenError,
    get_file_content,
    parse_repo_url,
)
from github_write_client import (
    BranchExistsError,
    PullRequestError,
    create_blob,
    create_branch,
    create_commit,
    create_pull_request,
    create_tree,
    delete_branch,
    get_branch_head,
    get_repo_metadata,
    ref_exists,
    update_ref,
)
from patch_applier import (
    PatchApplyError,
    Replacement,
    apply_replacements,
    locate,
    parse_unified_diff,
    snippet_matches_at_line,
)
from patch_generator import PatchGeneratorError, generate_patch, grounding_excerpt
from pr_body_formatter import format_commit_message, format_pr_body
from rate_limit import RateLimiter, rate_limit
from routers.oauth_router import WRITE_CONNECTED_FIELD, WRITE_TOKEN_FIELD
from routers.patch_router import FindingPatchRequest, _cache_key
from routers.user_router import _owned_scan

logger = logging.getLogger(__name__)

router = APIRouter()

# The tightest bucket in the application, and by a wide margin: /scan/explain
# allows 30 per 10 minutes and /scan/patch 15, but both of those spend money
# and nothing else. This one creates branches, commits and pull requests in a
# real repository -- the cost of a runaway loop is not a bill, it is a
# repository full of junk pull requests somebody has to close by hand. Three
# per hour is enough to create a pull request, notice a mistake, and try
# again, and not enough to make a mess with.
_limiter = RateLimiter(max_requests=3, window_seconds=3600)

# Above this the pull request stops being reviewable, and the endpoint would
# sit generating patches for minutes while the browser waits.
MAX_FINDINGS_PER_PR = 25

BRANCH_PREFIX = "qlint-pqc-migration"
# Suffixes tried when the branch name is taken. Bounded rather than unbounded
# so a repository that somehow has them all fails with a message instead of
# looping against GitHub.
MAX_BRANCH_ATTEMPTS = 20

WRITE_ACCESS_REQUIRED = (
    "This account has not connected GitHub write access. Creating a pull "
    "request needs a separate connection from the read-only one used for "
    "scanning: open the account menu and choose Connect write access."
)


class FindingSelection(BaseModel):
    """Which finding, by where it sits in the stored scan.

    A reference, not a payload. The endpoint resolves it against the scan the
    user owns, so a caller cannot smuggle in a file path or a code snippet the
    scan never produced.
    """

    file: str
    line: int


class CreatePRRequest(BaseModel):
    # Required and explicitly listed. There is no "everything" mode: the
    # caller has to name what it wants changed, and the consent screen the
    # user clicked through is what builds this list.
    findings: list[FindingSelection] = Field(min_length=1)
    title: str | None = None


def _require_write_token(user: dict) -> str:
    """The write token, or a 403 that says which connection is missing."""
    if not user.get(WRITE_CONNECTED_FIELD) or not user.get(WRITE_TOKEN_FIELD):
        raise HTTPException(status_code=403, detail=WRITE_ACCESS_REQUIRED)
    return user[WRITE_TOKEN_FIELD]


def _index_findings(result: dict) -> dict[tuple[str, int], dict]:
    """Map (file, line) to the stored finding, for resolving selections."""
    index: dict[tuple[str, int], dict] = {}
    for path, findings in (result.get("findings_by_file") or {}).items():
        for finding in findings or []:
            line = finding.get("line")
            if isinstance(line, int):
                # First finding wins for a duplicated (file, line): two
                # findings on one line would produce two patches for the same
                # code, which the conflict check would reject anyway.
                index.setdefault((path, line), {**finding, "file": path})
    return index


def _resolve(result: dict, selections: list[FindingSelection]) -> list[dict]:
    """Turn the selection list into stored findings, or 400 on an unknown one."""
    index = _index_findings(result)
    resolved: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for selection in selections:
        key = (selection.file, selection.line)
        if key in seen:
            continue  # a double-click on the consent screen is not two patches
        seen.add(key)
        finding = index.get(key)
        if finding is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"No finding at {selection.file}:{selection.line} in this "
                    "scan. Re-scan the repository and try again."
                ),
            )
        resolved.append(finding)
    return resolved


async def _cached_patch(key: str) -> str | None:
    try:
        document = await get_patches().find_one(
            {"key": key, "expires_at": {"$gt": datetime.now(timezone.utc)}}
        )
    except PyMongoError:
        return None  # the cache is an optimization; fall through to the model
    return (document or {}).get("patch")


async def _patch_for(finding: dict, openrouter, file_content: str) -> str:
    """The diff for one finding: the cached one if there is one, else a fresh one.

    The patch is generated against the file content just fetched from GitHub,
    not against the finding's one-line snippet alone. patch_applier places a
    hunk by matching its context and removed lines exactly, so a diff written
    without sight of the file is a diff whose context lines were invented and
    whose indentation was dropped -- it fails to apply against the very file it
    was meant for. That was F29's false "the code the patch expects to change
    is not present in the current file" on repositories nobody had touched.

    Shares /scan/patch's cache, but not its keys: the excerpt goes into the
    hash, so the blind patch shown in the results view is never the one that
    gets committed. The two can therefore differ. That is the right way round
    -- the results-view diff is advisory and the committed one has to actually
    apply -- and the pull request itself is what gets reviewed before merge.
    """
    try:
        request = FindingPatchRequest.model_validate(finding)
    except Exception as exc:
        raise PatchGeneratorError(
            "the finding has no code snippet or no recommended fix, so there "
            "is nothing to build a patch from"
        ) from exc

    excerpt = grounding_excerpt(file_content, finding.get("line"))
    cached = await _cached_patch(_cache_key(request, grounding=excerpt))
    if cached:
        return cached
    patch_text, _ = await generate_patch(finding, openrouter, file_content)
    return patch_text


def _short(scan_id: str) -> str:
    return str(scan_id)[-8:] or "scan"


async def _free_branch_name(
    owner: str, repo: str, scan_id: str, token: str, client: httpx.AsyncClient
) -> str:
    """A branch name nobody is using yet.

    Named after the scan rather than the clock so a second pull request for
    the same scan is visibly the same migration, with a counter making it
    unique. Existence is checked rather than assumed: silently reusing a
    branch would add commits to a pull request the user already opened.
    """
    base = f"{BRANCH_PREFIX}-{_short(scan_id)}"
    for attempt in range(MAX_BRANCH_ATTEMPTS):
        candidate = base if attempt == 0 else f"{base}-{attempt + 1}"
        if not await ref_exists(owner, repo, candidate, token, client):
            return candidate
    raise GitHubError(
        f"Could not find a free branch name: {base} and "
        f"{MAX_BRANCH_ATTEMPTS - 1} numbered variants all exist already."
    )


def _outcome(finding: dict, reason: str) -> dict:
    """One row of the summary: what happened to this finding, and why.

    Applied and skipped findings share a shape so the pull request body, the
    JSON response and the results screen can all render them the same way.
    """
    return {"finding": finding, "reason": reason}


async def _plan_changes(
    owner: str,
    repo: str,
    base_branch: str,
    findings: list[dict],
    token: str,
    client: httpx.AsyncClient,
    openrouter,
) -> tuple[dict[str, str], list[dict], list[dict]]:
    """Work out the new content of every file. No writes happen here.

    Returns (new content by path, applied, skipped). Findings are grouped by
    file first so a file with three findings produces one rewritten blob built
    from one original, rather than three patches racing over stale copies of
    it -- and so overlapping findings within a file can be spotted against
    each other before anything is committed.
    """
    by_file: dict[str, list[dict]] = {}
    for finding in findings:
        by_file.setdefault(finding["file"], []).append(finding)

    new_contents: dict[str, str] = {}
    applied: list[dict] = []
    skipped: list[dict] = []

    for path, file_findings in by_file.items():
        try:
            original = await get_file_content(
                owner, repo, path, token, client=client, ref=base_branch
            )
        except GitHubError as exc:
            for finding in file_findings:
                skipped.append(_outcome(finding, f"could not read the file: {exc}"))
            continue
        if original is None:
            for finding in file_findings:
                skipped.append(
                    _outcome(finding, "the file is larger than 1 MB, so it was not read")
                )
            continue

        # Every replacement resolved against the *same* original content, so
        # the spans are comparable and an overlap is a real overlap.
        claimed: list[Replacement] = []
        file_replacements: list[Replacement] = []
        applied_here: list[dict] = []

        for finding in sorted(file_findings, key=lambda item: item.get("line") or 0):
            if not snippet_matches_at_line(
                original, finding.get("code_snippet") or "", finding.get("line")
            ):
                skipped.append(
                    _outcome(
                        finding,
                        "skipped - file changed since scan: the flagged code is "
                        f"no longer at line {finding.get('line')}",
                    )
                )
                continue

            try:
                patch_text = await _patch_for(finding, openrouter, original)
            except PatchGeneratorError as exc:
                skipped.append(_outcome(finding, f"no patch could be generated: {exc}"))
                continue

            try:
                replacements = locate(original, parse_unified_diff(patch_text))
            except PatchApplyError as exc:
                skipped.append(_outcome(finding, f"the patch could not be applied: {exc}"))
                continue

            conflict = next(
                (
                    existing
                    for existing in claimed
                    for candidate in replacements
                    if existing.overlaps(candidate)
                ),
                None,
            )
            if conflict is not None:
                # Two findings want the same lines. Merging them would mean
                # inventing a combined change neither patch describes, so the
                # earlier one stands and this one is reported.
                skipped.append(
                    _outcome(
                        finding,
                        "overlapping change: another finding in this file "
                        "already patches these lines, so this one was left "
                        "alone rather than merged automatically",
                    )
                )
                continue

            claimed.extend(replacements)
            file_replacements.extend(replacements)
            applied_here.append(finding)

        if not applied_here:
            continue

        try:
            new_contents[path] = apply_replacements(original, file_replacements)
        except PatchApplyError as exc:
            for finding in applied_here:
                skipped.append(_outcome(finding, f"the patch could not be applied: {exc}"))
            continue
        applied.extend(_outcome(finding, "applied") for finding in applied_here)

    return new_contents, applied, skipped


async def _commit_and_open_pr(
    owner: str,
    repo: str,
    base_branch: str,
    base_sha: str,
    branch: str,
    new_contents: dict[str, str],
    title: str,
    body: str,
    message: str,
    token: str,
    client: httpx.AsyncClient,
) -> dict:
    """Create the branch, one commit, and the pull request.

    The branch is created first because a tree needs somewhere to land, which
    means there is a window where a later failure would leave it behind. That
    window is closed explicitly rather than ignored: on any failure after the
    branch exists, it is deleted, and if the deletion also fails the branch
    name goes into the error so the user knows exactly what to look for.
    """
    await create_branch(owner, repo, branch, base_sha, token, client)
    try:
        entries = []
        for path, content in new_contents.items():
            sha = await create_blob(owner, repo, content, token, client)
            entries.append({"path": path, "sha": sha})

        # One tree, one commit, every file. Not one commit per file: the
        # migration is a single change, and a reviewer reading it file by file
        # would be reading fragments of it.
        tree_sha = await create_tree(owner, repo, base_sha, entries, token, client)
        commit_sha = await create_commit(
            owner, repo, message, tree_sha, base_sha, token, client
        )
        await update_ref(owner, repo, branch, commit_sha, token, client)
        pull = await create_pull_request(
            owner, repo, branch, base_branch, title, body, token, client
        )
    except Exception as exc:
        removed = await delete_branch(owner, repo, branch, token, client)
        if removed:
            raise GitHubError(
                f"{exc} The branch {branch} was removed, so nothing was left "
                "behind in the repository."
            ) from exc
        raise GitHubError(
            f"{exc} The branch {branch} was created before this failed and "
            "could not be deleted automatically -- check the repository and "
            "delete it by hand if it is not wanted."
        ) from exc

    pull["commit_sha"] = commit_sha
    return pull


@router.post(
    "/scan/{scan_id}/create-pr", dependencies=[Depends(rate_limit(_limiter))]
)
async def create_pr(
    scan_id: str,
    body: CreatePRRequest,
    request: Request,
    user: dict = Depends(get_current_user),
):
    token = _require_write_token(user)
    entry = await _owned_scan(scan_id, user)

    if len(body.findings) > MAX_FINDINGS_PER_PR:
        raise HTTPException(
            status_code=400,
            detail=(
                f"A pull request can carry at most {MAX_FINDINGS_PER_PR} "
                f"findings; {len(body.findings)} were selected. Split the "
                "migration across several pull requests."
            ),
        )

    result = entry.get("result") or {}
    findings = _resolve(result, body.findings)

    repo_url = entry.get("repo_url") or ""
    try:
        owner, repo = parse_repo_url(repo_url)
    except InvalidRepoURLError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"This scan's repository URL cannot be written to: {exc}",
        ) from exc

    client = request.app.state.github
    try:
        metadata = await get_repo_metadata(owner, repo, token, client)
        if not metadata["can_push"]:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"The connected GitHub account cannot push to "
                    f"{owner}/{repo}. Pull requests can only be created for "
                    "repositories you have write access to."
                ),
            )
        base_branch = metadata["default_branch"]
        base_sha = await get_branch_head(owner, repo, base_branch, token, client)

        new_contents, applied, skipped = await _plan_changes(
            owner,
            repo,
            base_branch,
            findings,
            token,
            client,
            request.app.state.openrouter,
        )

        if not new_contents:
            # Nothing survived re-validation. Reported as a 200 with the
            # reasons rather than an error: the request was well formed and
            # the answer -- "your files moved on, here is which ones" -- is
            # the useful part.
            return {
                "created": False,
                "repo": f"{owner}/{repo}",
                "detail": (
                    "No pull request was created: none of the selected "
                    "findings could be applied to the current files."
                ),
                "applied": [],
                "skipped": skipped,
                "applied_count": 0,
                "skipped_count": len(skipped),
            }

        branch = await _free_branch_name(owner, repo, scan_id, token, client)
        title = (body.title or "").strip() or (
            f"QLint: migrate {len(applied)} quantum-vulnerable finding"
            f"{'' if len(applied) == 1 else 's'} to post-quantum cryptography"
        )
        pull = await _commit_and_open_pr(
            owner,
            repo,
            base_branch,
            base_sha,
            branch,
            new_contents,
            title,
            format_pr_body(f"{owner}/{repo}", applied, skipped, scan_id),
            format_commit_message(f"{owner}/{repo}", applied),
            token,
            client,
        )
    except HTTPException:
        raise
    except InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except BranchExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (PullRequestError, GitHubError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502, detail=f"GitHub API request failed: {exc}"
        ) from exc
    except Exception as exc:
        # The never-raises-unhandled guarantee. A stack trace reaching the
        # browser as a 500 would tell the user nothing about whether a branch
        # was left behind, which is the only thing they need to know here.
        logger.exception("Unexpected failure while creating a pull request")
        raise HTTPException(
            status_code=500,
            detail=(
                f"Pull request creation failed unexpectedly: {exc}. Check "
                f"{owner}/{repo} for a leftover {BRANCH_PREFIX} branch."
            ),
        ) from exc

    return {
        "created": True,
        "repo": f"{owner}/{repo}",
        "pr_url": pull["url"],
        "pr_number": pull["number"],
        "branch": branch,
        "base_branch": base_branch,
        "commit_sha": pull.get("commit_sha"),
        "files_changed": sorted(new_contents),
        "applied": applied,
        "skipped": skipped,
        "applied_count": len(applied),
        "skipped_count": len(skipped),
    }

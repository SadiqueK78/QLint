"""The write half of QLint's GitHub API surface: branches, commits, and PRs.

Kept in its own module rather than added to github_client.py, and that split
is the point rather than tidiness. github_client.py is what a scan imports; it
can only read. Nothing that runs during a scan can reach a function in here,
so there is no path by which an ordinary scan mutates a repository -- the same
reason the write OAuth token is a separate field on the user document instead
of a wider scope on the existing one.

Everything is built on the Git Data API (blobs -> tree -> commit -> ref)
rather than the contents API's one-PUT-per-file, because F29 promises one
commit per pull request across every changed file. The contents API cannot do
that: each PUT is its own commit. Same httpx client, same header helper and
the same error classes as github_client.py -- no new dependency.
"""

import base64

import httpx

from github_client import GitHubError, InvalidTokenError, _headers

GITHUB_API = "https://api.github.com"


class BranchExistsError(GitHubError):
    """The branch name is already taken on the remote."""


class PullRequestError(GitHubError):
    """Creating the pull request itself failed."""


def _raise_for_write_errors(response: httpx.Response, action: str) -> None:
    """Map a failed write to an error whose message names the missing right.

    A 403 here is almost always "the token has no write scope for this repo",
    which is a different fix from "the request was malformed" and has to read
    that way in the summary the user sees.
    """
    if response.status_code == 401:
        raise InvalidTokenError(
            "GitHub rejected the write token; reconnect write access."
        )
    if response.status_code == 403:
        raise GitHubError(
            f"GitHub refused to {action}: the connected write token does not "
            "have push access to this repository."
        )
    if response.status_code == 404:
        raise GitHubError(
            f"GitHub could not {action}: the repository is missing, or the "
            "write token cannot see it."
        )
    if response.status_code >= 400:
        raise GitHubError(
            f"GitHub returned {response.status_code} when asked to {action}: "
            f"{response.text[:300]}"
        )


async def _post(
    client: httpx.AsyncClient, path: str, token: str, payload: dict, action: str
) -> dict:
    try:
        response = await client.post(path, headers=_headers(token), json=payload)
    except httpx.HTTPError as exc:
        raise GitHubError(f"Could not reach GitHub to {action}: {exc}") from exc
    _raise_for_write_errors(response, action)
    return response.json()


async def get_repo_metadata(
    owner: str, repo: str, token: str, client: httpx.AsyncClient
) -> dict:
    """Return {"default_branch": ..., "can_push": bool, "private": bool}.

    can_push is read from the repository's own permissions block, so a token
    that can see a repository but not push to it is caught before a branch is
    created rather than after.
    """
    try:
        response = await client.get(
            f"/repos/{owner}/{repo}", headers=_headers(token)
        )
    except httpx.HTTPError as exc:
        raise GitHubError(f"Could not reach GitHub: {exc}") from exc
    _raise_for_write_errors(response, "read the repository")
    data = response.json()
    return {
        "default_branch": data.get("default_branch") or "main",
        "can_push": bool((data.get("permissions") or {}).get("push", False)),
        "private": bool(data.get("private", False)),
        "full_name": data.get("full_name") or f"{owner}/{repo}",
    }


async def get_branch_head(
    owner: str, repo: str, branch: str, token: str, client: httpx.AsyncClient
) -> str:
    """Commit sha the branch currently points at."""
    try:
        response = await client.get(
            f"/repos/{owner}/{repo}/git/ref/heads/{branch}", headers=_headers(token)
        )
    except httpx.HTTPError as exc:
        raise GitHubError(f"Could not reach GitHub: {exc}") from exc
    _raise_for_write_errors(response, f"read the {branch} branch")
    return response.json()["object"]["sha"]


async def ref_exists(
    owner: str, repo: str, branch: str, token: str, client: httpx.AsyncClient
) -> bool:
    """Does heads/<branch> already exist? Used to pick a free branch name."""
    try:
        response = await client.get(
            f"/repos/{owner}/{repo}/git/ref/heads/{branch}", headers=_headers(token)
        )
    except httpx.HTTPError as exc:
        raise GitHubError(f"Could not reach GitHub: {exc}") from exc
    if response.status_code == 404:
        return False
    _raise_for_write_errors(response, "check for an existing branch")
    return True


async def create_branch(
    owner: str,
    repo: str,
    branch: str,
    sha: str,
    token: str,
    client: httpx.AsyncClient,
) -> None:
    """Point a new heads/<branch> at sha."""
    try:
        response = await client.post(
            f"/repos/{owner}/{repo}/git/refs",
            headers=_headers(token),
            json={"ref": f"refs/heads/{branch}", "sha": sha},
        )
    except httpx.HTTPError as exc:
        raise GitHubError(f"Could not reach GitHub to create a branch: {exc}") from exc
    if response.status_code == 422:
        raise BranchExistsError(f"The branch {branch} already exists.")
    _raise_for_write_errors(response, "create a branch")


async def create_blob(
    owner: str, repo: str, content: str, token: str, client: httpx.AsyncClient
) -> str:
    """Upload one file's new content, base64 so any byte survives the trip."""
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    data = await _post(
        client,
        f"/repos/{owner}/{repo}/git/blobs",
        token,
        {"content": encoded, "encoding": "base64"},
        "upload the patched file",
    )
    return data["sha"]


async def create_tree(
    owner: str,
    repo: str,
    base_tree: str,
    entries: list[dict],
    token: str,
    client: httpx.AsyncClient,
) -> str:
    """Build a tree from base_tree with entries overridden.

    entries are {"path", "sha"} pairs; mode 100644 and type blob are filled in
    here so no caller can accidentally change a file's mode while patching it.
    """
    data = await _post(
        client,
        f"/repos/{owner}/{repo}/git/trees",
        token,
        {
            "base_tree": base_tree,
            "tree": [
                {
                    "path": entry["path"],
                    "mode": entry.get("mode", "100644"),
                    "type": "blob",
                    "sha": entry["sha"],
                }
                for entry in entries
            ],
        },
        "assemble the commit tree",
    )
    return data["sha"]


async def create_commit(
    owner: str,
    repo: str,
    message: str,
    tree_sha: str,
    parent_sha: str,
    token: str,
    client: httpx.AsyncClient,
) -> str:
    """One commit, every changed file, one parent."""
    data = await _post(
        client,
        f"/repos/{owner}/{repo}/git/commits",
        token,
        {"message": message, "tree": tree_sha, "parents": [parent_sha]},
        "create the commit",
    )
    return data["sha"]


async def update_ref(
    owner: str,
    repo: str,
    branch: str,
    sha: str,
    token: str,
    client: httpx.AsyncClient,
) -> None:
    """Move heads/<branch> to sha. force stays off: this branch is brand new,
    so a rejected fast-forward means something else wrote to it and the right
    answer is to fail loudly, not to overwrite whatever that was."""
    try:
        response = await client.patch(
            f"/repos/{owner}/{repo}/git/refs/heads/{branch}",
            headers=_headers(token),
            json={"sha": sha, "force": False},
        )
    except httpx.HTTPError as exc:
        raise GitHubError(f"Could not reach GitHub to update the branch: {exc}") from exc
    _raise_for_write_errors(response, "move the branch to the new commit")


async def create_pull_request(
    owner: str,
    repo: str,
    head: str,
    base: str,
    title: str,
    body: str,
    token: str,
    client: httpx.AsyncClient,
) -> dict:
    """Open the pull request. Returns {"url": html_url, "number": int}."""
    try:
        response = await client.post(
            f"/repos/{owner}/{repo}/pulls",
            headers=_headers(token),
            json={"title": title, "head": head, "base": base, "body": body},
        )
    except httpx.HTTPError as exc:
        raise PullRequestError(
            f"Could not reach GitHub to open the pull request: {exc}"
        ) from exc
    if response.status_code >= 400:
        raise PullRequestError(
            f"GitHub returned {response.status_code} when asked to open the "
            f"pull request: {response.text[:300]}"
        )
    data = response.json()
    return {"url": data.get("html_url"), "number": data.get("number")}


async def delete_branch(
    owner: str, repo: str, branch: str, token: str, client: httpx.AsyncClient
) -> bool:
    """Best-effort cleanup of a branch whose pull request never opened.

    Returns True when the branch is gone. A False here is not swallowed by the
    caller: an orphaned branch the user does not know about is exactly the
    kind of leftover this feature must not create silently, so the failure is
    named in the error the user sees.
    """
    try:
        response = await client.delete(
            f"/repos/{owner}/{repo}/git/refs/heads/{branch}", headers=_headers(token)
        )
    except httpx.HTTPError:
        return False
    return response.status_code in (204, 404)

"""Async GitHub API client helpers for the PQC Migration Scanner."""

import base64
import re
from datetime import datetime, timezone

import httpx

GITHUB_API = "https://api.github.com"
MAX_FILE_SIZE = 1024 * 1024  # 1 MB — the contents API stops inlining base64 above this


class GitHubError(Exception):
    """Base error for GitHub API failures."""


class InvalidRepoURLError(GitHubError):
    """The provided URL is not a valid github.com repository URL."""


class RepoNotFoundError(GitHubError):
    """The repository does not exist or is not accessible."""


class InvalidTokenError(GitHubError):
    """The GitHub token is invalid or expired."""


# Source extensions QLint can scan, mapped to the language whose scanner
# handles them. Order matters: ".tsx" must be tested before ".ts" would be,
# which sorting by length descending guarantees.
EXTENSION_LANGUAGES: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
}


def language_for_path(path: str) -> str | None:
    """Return the scanner language for a file path, or None if unsupported."""
    lowered = path.lower()
    for extension in sorted(EXTENSION_LANGUAGES, key=len, reverse=True):
        if lowered.endswith(extension):
            return EXTENSION_LANGUAGES[extension]
    return None


_REPO_URL_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


def parse_repo_url(repo_url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a full GitHub URL."""
    match = _REPO_URL_RE.match(repo_url.strip())
    if not match:
        raise InvalidRepoURLError(
            f"Invalid GitHub repository URL: {repo_url!r}. "
            "Expected format: https://github.com/owner/repo"
        )
    return match.group(1), match.group(2)


def _headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    }


def _raise_for_common_errors(response: httpx.Response) -> None:
    if response.status_code == 401:
        raise InvalidTokenError("GitHub token is invalid or expired")
    if (
        response.status_code == 403
        and response.headers.get("x-ratelimit-remaining") == "0"
    ):
        raise GitHubError("GitHub API rate limit exceeded")


async def get_repo_files(
    repo_url: str, token: str, client: httpx.AsyncClient | None = None
) -> list[dict[str, str]]:
    """Return every scannable source file in the repo, tagged with its language.

    Each entry is {"path": ..., "language": ...}. Tries the main branch, then
    master. Uses the provided shared client when given; otherwise opens a
    temporary one.
    """
    owner, repo = parse_repo_url(repo_url)
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(base_url=GITHUB_API, timeout=30.0)
    try:
        for branch in ("main", "master"):
            response = await client.get(
                f"/repos/{owner}/{repo}/git/trees/{branch}",
                params={"recursive": "1"},
                headers=_headers(token),
            )
            if response.status_code == 404:
                continue  # branch (or repo) missing — try the next branch
            _raise_for_common_errors(response)
            response.raise_for_status()
            tree = response.json().get("tree", [])
            files: list[dict[str, str]] = []
            for entry in tree:
                if entry.get("type") != "blob":
                    continue
                language = language_for_path(entry["path"])
                if language is not None:
                    files.append({"path": entry["path"], "language": language})
            return files
        raise RepoNotFoundError(
            f"Repository {owner}/{repo} not found, is private, "
            "or has neither a 'main' nor a 'master' branch"
        )
    finally:
        if own_client:
            await client.aclose()


async def get_file_content(
    owner: str,
    repo: str,
    file_path: str,
    token: str,
    client: httpx.AsyncClient | None = None,
) -> str | None:
    """Fetch one file's text content. Returns None for files larger than 1 MB."""
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(base_url=GITHUB_API, timeout=30.0)
    try:
        response = await client.get(
            f"/repos/{owner}/{repo}/contents/{file_path}",
            headers=_headers(token),
        )
        if response.status_code == 404:
            raise RepoNotFoundError(f"File not found: {owner}/{repo}/{file_path}")
        _raise_for_common_errors(response)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            raise GitHubError(f"Path is a directory, not a file: {file_path}")
        if data.get("size", 0) > MAX_FILE_SIZE or data.get("encoding") != "base64":
            return None
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    finally:
        if own_client:
            await client.aclose()


async def check_rate_limit(
    token: str, client: httpx.AsyncClient | None = None
) -> dict[str, int | str]:
    """Return the core API rate limit as {"remaining": int, "reset_at": str}."""
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(base_url=GITHUB_API, timeout=30.0)
    try:
        response = await client.get("/rate_limit", headers=_headers(token))
        _raise_for_common_errors(response)
        response.raise_for_status()
        core = response.json()["resources"]["core"]
        reset_at = datetime.fromtimestamp(core["reset"], tz=timezone.utc)
        return {
            "remaining": core["remaining"],
            "reset_at": reset_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
    finally:
        if own_client:
            await client.aclose()

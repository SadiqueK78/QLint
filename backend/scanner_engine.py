"""Repository scan orchestration for the PQC Migration Scanner.

Ties together github_client (fetch), ast_scanner (detect), and
vulnerability_db (score) into a single repository report.

Two entry points share one aggregation step: scan_repository fetches a GitHub
repo over the API, scan_directory walks a local checkout (what qlint_cli.py
uses in CI). Both feed build_report, so a report means the same thing either
way — only the source of the file contents differs.
"""

import asyncio
import os
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Iterable

import httpx
from fastapi import HTTPException

from ast_scanner import scan_python_source
from github_client import (
    MAX_FILE_SIZE,
    GitHubError,
    check_rate_limit,
    get_file_content,
    get_repo_files,
    language_for_path,
    parse_repo_url,
)
from go_scanner import scan_go_source
from js_scanner import scan_js_source
from vulnerability_db import get_severity_score

MAX_CONCURRENT_FETCHES = 10
MIN_RATE_LIMIT = 100

SCANNERS = {
    "python": scan_python_source,
    "javascript": scan_js_source,
    "typescript": scan_js_source,
    "go": scan_go_source,
}

# Directories with no first-party source in them. Walking a real checkout
# without this reads a vendored dependency tree far larger than the project,
# and reports findings nobody in the repo can fix.
EXCLUDED_DIRS = frozenset(
    {
        "node_modules",
        "venv",
        "env",
        "__pycache__",
        "site-packages",
        "dist",
        "build",
        "out",
        "target",
        "vendor",
        "third_party",
        "coverage",
        "migrations",
    }
)


def _normalize_file(entry: dict | str) -> dict[str, str]:
    """Accept either {"path", "language"} or a bare path string."""
    if isinstance(entry, str):
        return {"path": entry, "language": language_for_path(entry) or "python"}
    return {
        "path": entry["path"],
        "language": entry.get("language")
        or language_for_path(entry["path"])
        or "python",
    }


def scan_source(path: str, language: str, content: str) -> list[dict]:
    """Run the scanner for one file's language, tagging each finding."""
    scanner = SCANNERS.get(language, scan_python_source)
    return [
        {"file": path, "language": language, **finding}
        for finding in scanner(content, filename=path)
    ]


def build_report(scanned: Iterable[tuple[dict[str, str], str | None]]) -> dict:
    """Aggregate (file, content) pairs into the body of a scan report.

    A None content means the file could not be read — too large, or a fetch
    that failed — and is reported as skipped rather than silently dropped.
    The caller adds whatever source-specific fields belong on top ("repo",
    "rate_limit_remaining").
    """
    skipped_files: list[str] = []
    findings_by_file: dict[str, list[dict]] = {}
    all_findings: list[dict] = []
    languages_scanned: list[str] = []
    scanned_files = 0

    for file, content in scanned:
        path, language = file["path"], file["language"]
        if content is None:
            skipped_files.append(path)
            continue
        scanned_files += 1
        if language not in languages_scanned:
            languages_scanned.append(language)
        file_findings = scan_source(path, language, content)
        if file_findings:
            findings_by_file[path] = file_findings
            all_findings.extend(file_findings)

    severity_summary = {"critical": 0, "warning": 0, "safe": 0, "info": 0}
    for finding in all_findings:
        severity = finding["severity"]
        if severity in severity_summary:
            severity_summary[severity] += 1

    # "info" entries (e.g. bare `import hashlib`) are inspection notes,
    # not algorithms — keep them out of the algorithms list.
    algorithms_found = sorted(
        {f["algorithm"] for f in all_findings if f["severity"] != "info"}
    )

    return {
        "scanned_files": scanned_files,
        "skipped_files": skipped_files,
        "total_findings": len(all_findings),
        "pqc_readiness_score": get_severity_score(all_findings),
        "severity_summary": severity_summary,
        "findings_by_file": findings_by_file,
        "algorithms_found": algorithms_found,
        "languages_scanned": sorted(languages_scanned),
    }


def normalize_excludes(patterns: Iterable[str] | None) -> tuple[str, ...]:
    """Clean up user-supplied exclude patterns into POSIX-style globs."""
    if not patterns:
        return ()
    cleaned = []
    for pattern in patterns:
        pattern = (pattern or "").strip().replace("\\", "/").strip("/")
        while pattern.startswith("./"):
            pattern = pattern[2:]
        if pattern:
            cleaned.append(pattern)
    return tuple(cleaned)


def is_excluded(relative_path: str, patterns: Iterable[str]) -> bool:
    """Whether a repo-relative POSIX path matches any exclude pattern.

    A pattern matches the path itself or any of its parent directories, so
    "backend/tests" excludes the whole tree and "backend/tests/*" or
    "*_benchmark.py" work as expected. Matching is case-sensitive on every
    platform: a pattern that excludes a file on a developer's Windows machine
    must exclude the same file on a Linux CI runner.
    """
    patterns = tuple(patterns)
    if not patterns:
        return False
    candidates = [relative_path]
    parent = PurePosixPath(relative_path).parent
    while str(parent) not in (".", "/", ""):
        candidates.append(str(parent))
        parent = parent.parent
    return any(
        fnmatchcase(candidate, pattern)
        for candidate in candidates
        for pattern in patterns
    )


def iter_source_files(
    root: Path, exclude: Iterable[str] = ()
) -> list[dict[str, str]]:
    """Every scannable source file under root, as repo-relative POSIX paths.

    The same extension-to-language mapping github_client uses, so a local scan
    covers exactly the files a GitHub scan of the same tree would. Files
    matching an exclude pattern are dropped here, before anything reads them —
    an excluded file is not scanned, not counted, and not skipped-with-a-note.
    """
    exclude = tuple(exclude)
    files: list[dict[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        relative_dir = Path(dirpath).relative_to(root)
        # Pruning dirnames in place is what stops os.walk descending into them.
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in EXCLUDED_DIRS
            and not name.startswith(".")
            and not is_excluded((relative_dir / name).as_posix(), exclude)
        )
        for filename in sorted(filenames):
            language = language_for_path(filename)
            if language is None:
                continue
            relative_path = (relative_dir / filename).as_posix()
            if is_excluded(relative_path, exclude):
                continue
            files.append(
                {
                    "path": relative_path,
                    "language": language,
                    "absolute_path": str(Path(dirpath) / filename),
                }
            )
    return files


def _read_source(file: dict[str, str]) -> str | None:
    """One file's text, or None if it is too large or unreadable."""
    path = Path(file["absolute_path"])
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def scan_directory(
    directory: str | Path, exclude: Iterable[str] | None = None
) -> dict:
    """Scan a local directory tree and build the same report shape as a repo scan.

    Synchronous and dependency-free at runtime: no network, no database, no
    credentials — this is the path CI runs, where the repo is already checked out.

    exclude takes glob patterns matched against repo-relative paths, on top of
    the built-in EXCLUDED_DIRS and dot-directory pruning.

    Raises NotADirectoryError if the path is not an existing directory.
    """
    root = Path(directory).expanduser()
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")
    root = root.resolve()

    files = iter_source_files(root, normalize_excludes(exclude))
    report = build_report((file, _read_source(file)) for file in files)
    return {"repo": root.name, "path": str(root), **report}


async def scan_repository(
    repo_url: str, token: str, client: httpx.AsyncClient
) -> dict:
    """Scan every .py file in a GitHub repo and build the full PQC report.

    Raises HTTPException 429 when the GitHub rate limit is nearly exhausted;
    propagates github_client errors (RepoNotFoundError, InvalidTokenError, ...)
    for the API layer to map. Individual file failures are skipped, never fatal.
    """
    owner, repo = parse_repo_url(repo_url)

    rate = await check_rate_limit(token, client=client)
    if rate["remaining"] < MIN_RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=(
                f"GitHub rate limit too low: {rate['remaining']} requests "
                f"remaining. Try again after {rate['reset_at']}"
            ),
        )

    repo_files = [
        _normalize_file(entry)
        for entry in await get_repo_files(repo_url, token, client=client)
    ]

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)

    async def fetch(file: dict[str, str]) -> tuple[dict[str, str], str | None]:
        async with semaphore:
            try:
                content = await get_file_content(
                    owner, repo, file["path"], token, client=client
                )
            except (GitHubError, httpx.HTTPError):
                content = None  # skip this file, keep the scan alive
            return file, content

    results = await asyncio.gather(*(fetch(file) for file in repo_files))

    final_rate = await check_rate_limit(token, client=client)

    return {
        "repo": f"{owner}/{repo}",
        **build_report(results),
        "rate_limit_remaining": final_rate["remaining"],
    }

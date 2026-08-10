"""Standalone CLI for QLint — scan a local checkout for quantum-vulnerable crypto.

Built for CI. It scans a directory already on disk, so it needs no FastAPI
server, no MongoDB, no authentication, and no GitHub credentials: nothing here
imports main.py, auth.py, or database.py. The detection logic is exactly what
the web app runs — the same scanners, the same aggregation in scanner_engine,
and the same SARIF and CBOM converters from the /sarif and /cbom endpoints.

Usage:
    python qlint_cli.py --path . --output qlint-results.sarif
    python qlint_cli.py --path . --format cbom --output qlint-cbom.json
    python qlint_cli.py --path ./src --format json --fail-on warning
    python qlint_cli.py --path . --exclude "benchmarks/*,vendor/legacy.py"
    python qlint_cli.py --path . --fail-on none

Exit codes:
    0  scan completed, nothing at or above --fail-on
    1  findings at or above --fail-on, or the scan could not run
"""

import argparse
import json
import sys
from pathlib import Path

from cbom_converter import convert_to_cbom
from sarif_converter import convert_to_sarif
from scanner_engine import scan_directory

DEFAULT_OUTPUT = "qlint-results.sarif"

# Ordered worst-first. --fail-on <level> trips on that level and anything
# above it, so "warning" also fails on critical.
SEVERITY_ORDER = ["critical", "warning", "safe", "info"]
FAIL_ON_CHOICES = ["critical", "warning", "none"]

# How many offending findings to name before truncating the CI log.
MAX_LISTED_FINDINGS = 10


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qlint_cli.py",
        description=(
            "Scan a directory for quantum-vulnerable cryptography and write "
            "SARIF 2.1.0, a CycloneDX CBOM, or the raw JSON report."
        ),
    )
    parser.add_argument(
        "--path",
        default=".",
        help="Directory to scan (default: the current directory)",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Where to write the results (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--format",
        choices=["sarif", "cbom", "json"],
        default="sarif",
        help=(
            "sarif: SARIF 2.1.0 for code scanning tools. cbom: CycloneDX 1.6 "
            "cryptography bill of materials. json: the raw report"
        ),
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "Glob pattern of paths to skip, matched against repo-relative "
            "paths. Repeatable, and each value may be comma-separated. A "
            "pattern matching a directory excludes everything under it"
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="critical",
        help=(
            "Exit 1 when a finding at or above this severity exists "
            "(default: critical). 'none' always exits 0"
        ),
    )
    return parser


def split_excludes(values: list[str] | None) -> list[str]:
    """Flatten repeated --exclude flags and comma-separated values into one list.

    Both spellings are accepted because a workflow file passes one string
    ("a,b") while a shell invocation usually repeats the flag.
    """
    patterns = []
    for value in values or []:
        patterns.extend(part.strip() for part in value.split(",") if part.strip())
    return patterns


def failing_findings(report: dict, fail_on: str) -> list[dict]:
    """Every finding at or above the fail-on threshold, worst first."""
    if fail_on == "none":
        return []
    threshold = SEVERITY_ORDER.index(fail_on)
    failing = [
        finding
        for findings in (report.get("findings_by_file") or {}).values()
        for finding in findings
        if finding.get("severity") in SEVERITY_ORDER
        and SEVERITY_ORDER.index(finding["severity"]) <= threshold
    ]
    return sorted(
        failing,
        key=lambda f: (
            SEVERITY_ORDER.index(f["severity"]),
            f.get("file", ""),
            f.get("line") or 0,
        ),
    )


# --format value -> the converter that renders it. "json" is absent on
# purpose: it is the report itself, with nothing to convert.
CONVERTERS = {"sarif": convert_to_sarif, "cbom": convert_to_cbom}


def render_output(report: dict, output_format: str) -> str:
    convert = CONVERTERS.get(output_format)
    if convert is not None:
        return json.dumps(convert(report), indent=2)
    return json.dumps(report, indent=2)


def print_summary(
    report: dict, output_path: Path, output_format: str, excludes: list[str]
) -> None:
    """The scan at a glance, so a CI log is useful without opening the artifact."""
    summary = report.get("severity_summary") or {}
    counts = ", ".join(f"{level} {summary.get(level, 0)}" for level in SEVERITY_ORDER)

    # ASCII only: this goes to a console whose codepage is not guaranteed to be
    # UTF-8 (a Windows terminal mangles anything outside it).
    print(f"QLint PQC scan: {report.get('path', '')}")
    if excludes:
        # Printed because an exclude that silently matches nothing (or matches
        # too much) is otherwise invisible in a CI log.
        print(f"  Excluding:      {', '.join(excludes)}")
    print(f"  Files scanned:  {report.get('scanned_files', 0)}")
    print(f"  Total findings: {report.get('total_findings', 0)}  ({counts})")
    print(f"  PQC readiness:  {report.get('pqc_readiness_score', 0)} / 100")
    algorithms = report.get("algorithms_found") or []
    if algorithms:
        print(f"  Algorithms:     {', '.join(algorithms)}")
    skipped = report.get("skipped_files") or []
    if skipped:
        print(f"  Skipped:        {len(skipped)} file(s) unreadable or over 1 MB")
    print(f"  Wrote {output_format} to {output_path}")


def print_failures(failing: list[dict], fail_on: str) -> None:
    """Name the findings that failed the build, so the log points at the fix."""
    print()
    print(f"FAIL: {len(failing)} finding(s) at or above '{fail_on}'")
    for finding in failing[:MAX_LISTED_FINDINGS]:
        location = f"{finding.get('file', '?')}:{finding.get('line', '?')}"
        print(
            f"  {finding.get('severity', '?'):>8}  {location}  "
            f"{finding.get('algorithm', '?')}"
        )
    if len(failing) > MAX_LISTED_FINDINGS:
        print(f"  ... and {len(failing) - MAX_LISTED_FINDINGS} more")


def run(argv: list[str] | None = None) -> int:
    """Run one scan and return the process exit code. Never raises."""
    args = build_parser().parse_args(argv)
    excludes = split_excludes(args.exclude)

    try:
        report = scan_directory(args.path, exclude=excludes)
    except NotADirectoryError:
        print(
            f"error: --path is not an existing directory: {args.path}",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(f"error: could not read {args.path}: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # a scan crash must still be a clean CI failure
        print(f"error: scan failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1

    output_path = Path(args.output)
    try:
        if output_path.parent != Path(""):
            output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(render_output(report, args.format), encoding="utf-8")
    except OSError as exc:
        print(f"error: could not write {output_path}: {exc}", file=sys.stderr)
        return 1

    print_summary(report, output_path, args.format, excludes)

    failing = failing_findings(report, args.fail_on)
    if failing:
        print_failures(failing, args.fail_on)
        return 1
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()

"""SARIF 2.1.0 output for QLint scan reports.

Converts a scan report (the shape scanner_engine.scan_repository returns) into
SARIF 2.1.0 so results can be consumed by GitHub Code Scanning, VS Code's SARIF
viewer, and other standard tooling. No scanning logic lives here: this module is
a pure format translation over data that already exists.

Schema: https://json.schemastore.org/sarif-2.1.0.json

Conversion is best-effort by design — convert_to_sarif never raises. A malformed
report yields valid SARIF with whatever could be salvaged rather than a 500 on
the download route.
"""

import re

from vulnerability_db import CRYPTO_DB, find_algorithm

QLINT_VERSION = "1.0.0"
REPO_URL = "https://github.com/Abhushan187/QLint"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

# QLint severity -> SARIF result.level. SARIF has no "safe" notion, so both
# "safe" and "info" land on "note": present in the output, but not a problem.
SARIF_LEVELS = {
    "critical": "error",
    "warning": "warning",
    "safe": "note",
    "info": "note",
}
DEFAULT_LEVEL = "note"

# GitHub's code scanning UI colors findings by this property, read as a
# CVSS-like 0.0-10.0 score. The values are a convention, not a computed CVSS.
SECURITY_SEVERITY = {
    "critical": "9.0",
    "warning": "5.0",
    "safe": "1.0",
    "info": "2.0",
}
DEFAULT_SECURITY_SEVERITY = "1.0"

# nist_standard strings in CRYPTO_DB name a FIPS publication; link the rule at
# the publication itself where one exists. FIPS 206 (FN-DSA) is still a draft
# with no /final URL, so it points at the PQC project page instead.
_FIPS_HELP_URIS = {
    "180-4": "https://csrc.nist.gov/pubs/fips/180-4/upd1/final",
    "197": "https://csrc.nist.gov/pubs/fips/197/final",
    "202": "https://csrc.nist.gov/pubs/fips/202/final",
    "203": "https://csrc.nist.gov/pubs/fips/203/final",
    "204": "https://csrc.nist.gov/pubs/fips/204/final",
    "205": "https://csrc.nist.gov/pubs/fips/205/final",
    "206": "https://csrc.nist.gov/projects/post-quantum-cryptography",
}


def _text(value, fallback: str = "") -> str:
    """A plain string for a SARIF multiformatMessageString, never None."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return fallback


def _help_uri(entry: dict) -> str:
    """The NIST publication behind an algorithm, or the QLint repo."""
    standard = _text(entry.get("nist_standard"))
    # "NIST FIPS 203 / FIPS 204" -> 203: the first named document wins.
    match = re.search(r"FIPS\s*([\d-]+?)\b", standard)
    if match:
        return _FIPS_HELP_URIS.get(match.group(1), REPO_URL)
    return REPO_URL


def _rule(rule_id: str, entry: dict) -> dict:
    """One SARIF reportingDescriptor from a CRYPTO_DB-shaped entry."""
    severity = entry.get("severity")
    tags = ["security"]
    if entry.get("quantum_vulnerable"):
        tags.append("quantum-vulnerable")
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {
            "text": _text(entry.get("attack_vector"), f"{rule_id} usage detected")
        },
        "fullDescription": {
            "text": _text(
                entry.get("replacement_reason"),
                f"{rule_id} was detected by QLint's cryptographic inventory scan.",
            )
        },
        "helpUri": _help_uri(entry),
        "properties": {
            "tags": tags,
            "security-severity": SECURITY_SEVERITY.get(
                severity, DEFAULT_SECURITY_SEVERITY
            ),
        },
    }


def _catalog_rules() -> dict[str, dict]:
    """The full rule catalog, keyed by rule id.

    Every CRYPTO_DB algorithm is emitted, not just the ones this scan hit, so
    tools that cache rule definitions across runs see a stable rule set.
    """
    rules: dict[str, dict] = {}
    for key, entry in CRYPTO_DB.items():
        if not isinstance(entry, dict):
            continue
        rule_id = _text(entry.get("canonical_name"), key)
        rules[rule_id] = _rule(rule_id, entry)
    return rules


def iter_findings(scan_report: dict):
    """Yield finding dicts from either report shape.

    scanner_engine groups findings under findings_by_file; a flat "findings"
    list is also accepted so callers holding a plain list convert cleanly.

    Public because cbom_converter reads the same two report shapes: "the
    findings of a report" has to mean one thing across both output formats,
    and a second copy of this walk is how the two would drift apart.
    """
    if not isinstance(scan_report, dict):
        return

    flat = scan_report.get("findings")
    if isinstance(flat, list):
        for finding in flat:
            if isinstance(finding, dict):
                yield finding

    by_file = scan_report.get("findings_by_file")
    if isinstance(by_file, dict):
        for path, findings in by_file.items():
            if not isinstance(findings, list):
                continue
            for finding in findings:
                if isinstance(finding, dict):
                    # The scanners stamp "file" on each finding already; fall
                    # back to the grouping key if something upstream dropped it.
                    yield finding if finding.get("file") else {**finding, "file": path}


def artifact_uri(value) -> str:
    """A relative, forward-slashed artifact URI.

    SARIF artifact URIs are POSIX-style, so Windows separators are normalized
    and any absolute prefix (drive letter or leading slash) is dropped —
    Code Scanning matches these against repo-relative paths. CBOM occurrence
    locations want exactly the same normalization, and share this.
    """
    if not isinstance(value, str) or not value.strip():
        return "unknown"
    uri = value.strip().replace("\\", "/")
    uri = re.sub(r"^[A-Za-z]:", "", uri)  # C:/src/app.py -> /src/app.py
    uri = uri.lstrip("/")
    while uri.startswith("./"):
        uri = uri[2:]
    return uri or "unknown"


def _start_line(finding: dict) -> int:
    line = finding.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        return 1
    return line


def _start_column(finding: dict) -> int:
    """SARIF columns are 1-based; QLint stores 0-based offsets.

    ast.col_offset and the regex scanners both count from 0, so a finding at the
    start of a line carries col 0 — which SARIF rejects (minimum 1). Shift by
    one, and default to column 1 when col is missing or null.
    """
    col = finding.get("col")
    if isinstance(col, bool) or not isinstance(col, int) or col < 0:
        return 1
    return col + 1


def _resolve_rule(algorithm: str, rules: dict[str, dict], finding: dict) -> str:
    """The rule id for a finding, registering a rule if the catalog lacks one.

    Findings normally carry a canonical CRYPTO_DB name. Anything else — a raw
    identifier, or a synthetic note like "hashlib (requires deeper inspection)"
    that has no catalog entry — is canonicalized where possible and otherwise
    gets a rule built from the finding itself, so no result ever references a
    rule that is missing from the run.
    """
    if algorithm in rules:
        return algorithm

    entry = find_algorithm(algorithm)
    if entry is not None:
        canonical = _text(entry.get("canonical_name"), algorithm)
        if canonical in rules:
            return canonical

    rules[algorithm] = _rule(algorithm, finding)
    return algorithm


def _message(algorithm: str, finding: dict) -> str:
    """A one-line human-readable summary of the finding."""
    entry = find_algorithm(algorithm) or {}
    attack = _text(finding.get("attack_vector")) or _text(entry.get("attack_vector"))
    replacement = _text(finding.get("replacement")) or _text(entry.get("replacement"))

    vulnerable = finding.get("quantum_vulnerable")
    if vulnerable is None:
        vulnerable = entry.get("quantum_vulnerable")

    if vulnerable and attack and attack.lower() != "none":
        message = f"{algorithm} detected — quantum-vulnerable via {attack}."
    elif vulnerable:
        message = f"{algorithm} detected — quantum-vulnerable."
    else:
        message = f"{algorithm} detected."

    if replacement:
        return f"{message} Replace with {replacement}."
    if not vulnerable and entry:
        return f"{message} Quantum-safe, no migration needed."
    return message


def _result(finding: dict, rules: dict[str, dict]) -> dict:
    algorithm = _text(finding.get("algorithm"), "Unknown")
    rule_id = _resolve_rule(algorithm, rules, finding)
    severity = finding.get("severity")
    return {
        "ruleId": rule_id,
        "level": SARIF_LEVELS.get(severity, DEFAULT_LEVEL),
        "message": {"text": _message(algorithm, finding)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri(finding.get("file"))},
                    "region": {
                        "startLine": _start_line(finding),
                        "startColumn": _start_column(finding),
                    },
                }
            }
        ],
    }


def _sarif(rules: list[dict], results: list[dict]) -> dict:
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "QLint",
                        "informationUri": REPO_URL,
                        "version": QLINT_VERSION,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def convert_to_sarif(scan_report: dict) -> dict:
    """Convert a QLint scan report into a SARIF 2.1.0 log.

    Accepts either report shape (findings_by_file or a flat findings list). An
    empty or missing set of findings still produces a valid log: the rule
    catalog is emitted in full and results is an empty list.

    Never raises. A finding that cannot be converted is skipped rather than
    failing the whole report.
    """
    try:
        rules = _catalog_rules()
    except Exception:
        rules = {}

    results: list[dict] = []
    try:
        for finding in iter_findings(scan_report):
            try:
                results.append(_result(finding, rules))
            except Exception:
                continue  # one bad finding must not cost the whole report
    except Exception:
        pass

    return _sarif(list(rules.values()), results)


if __name__ == "__main__":
    fake_report = {
        "findings": [
            {"file": "auth.py", "line": 12, "col": 5, "algorithm": "RSA",
             "severity": "critical"},
            {"file": "utils.py", "line": 3, "col": None, "algorithm": "MD5",
             "severity": "critical"}
        ]
    }
    sarif = convert_to_sarif(fake_report)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 2
    assert sarif["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["region"]["startColumn"] == 1
    print("sarif_converter.py self-test passed")
    import json
    print(json.dumps(sarif, indent=2)[:500])

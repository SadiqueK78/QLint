"""Tests for the SARIF 2.1.0 converter.

These check the structural contract external tooling relies on: GitHub Code
Scanning rejects a log whose results reference unknown rules, and its UI reads
security-severity to color findings.
"""

import json

import pytest

from sarif_converter import (
    SARIF_SCHEMA,
    convert_to_sarif,
)
from vulnerability_db import CRYPTO_DB


def run(sarif: dict) -> dict:
    return sarif["runs"][0]


def rule_ids(sarif: dict) -> set[str]:
    return {rule["id"] for rule in run(sarif)["tool"]["driver"]["rules"]}


def finding(**overrides) -> dict:
    base = {
        "file": "auth.py",
        "line": 12,
        "col": 4,
        "algorithm": "RSA",
        "severity": "critical",
    }
    return {**base, **overrides}


# ------------------------------------------------------------- top-level shape


def test_top_level_structure_is_sarif_2_1_0():
    sarif = convert_to_sarif({"findings": [finding()]})
    assert sarif["$schema"] == SARIF_SCHEMA
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    driver = run(sarif)["tool"]["driver"]
    assert driver["name"] == "QLint"
    assert driver["informationUri"].startswith("https://")
    assert driver["version"]


def test_empty_report_still_produces_the_full_rule_catalog():
    for empty in [{}, {"findings": []}, {"findings_by_file": {}}]:
        sarif = convert_to_sarif(empty)
        assert run(sarif)["results"] == []
        # Rules are the catalog, not the scan: tools caching rule definitions
        # across runs must see the same set every time.
        assert len(run(sarif)["tool"]["driver"]["rules"]) == len(CRYPTO_DB)


def test_output_is_serializable_json():
    sarif = convert_to_sarif({"findings": [finding(), finding(algorithm="MD5")]})
    reparsed = json.loads(json.dumps(sarif))
    assert reparsed == sarif


def test_both_report_shapes_convert():
    """scanner_engine groups by file; a flat list is accepted too."""
    grouped = convert_to_sarif(
        {"findings_by_file": {"auth.py": [finding()], "utils.py": [finding(file="utils.py")]}}
    )
    flat = convert_to_sarif({"findings": [finding(), finding(file="utils.py")]})
    assert len(run(grouped)["results"]) == 2
    assert len(run(flat)["results"]) == 2


def test_grouping_key_fills_in_a_missing_file_field():
    sarif = convert_to_sarif(
        {"findings_by_file": {"src/app.py": [{"algorithm": "RSA", "line": 3}]}}
    )
    location = run(sarif)["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/app.py"


# ------------------------------------------------------------------ severity


@pytest.mark.parametrize(
    "severity,level",
    [
        ("critical", "error"),
        ("warning", "warning"),
        ("safe", "note"),
        ("info", "note"),
    ],
)
def test_each_severity_maps_to_its_sarif_level(severity, level):
    sarif = convert_to_sarif({"findings": [finding(severity=severity)]})
    assert run(sarif)["results"][0]["level"] == level


def test_an_unrecognized_severity_falls_back_to_note():
    sarif = convert_to_sarif({"findings": [finding(severity="bogus")]})
    assert run(sarif)["results"][0]["level"] == "note"


@pytest.mark.parametrize(
    "algorithm,severity,score",
    [
        ("RSA", "critical", "9.0"),
        ("AES-128", "warning", "5.0"),
        ("SHA-512", "safe", "1.0"),
    ],
)
def test_security_severity_is_set_per_tier(algorithm, severity, score):
    """GitHub's UI colors findings by this property, so the mapping is load-bearing."""
    sarif = convert_to_sarif({"findings": [finding(algorithm=algorithm, severity=severity)]})
    rules = {rule["id"]: rule for rule in run(sarif)["tool"]["driver"]["rules"]}
    assert rules[algorithm]["properties"]["security-severity"] == score
    assert CRYPTO_DB[algorithm]["severity"] == severity  # the tier under test is real


def test_info_tier_scores_above_safe():
    sarif = convert_to_sarif({"findings": [finding(algorithm="Whatever", severity="info")]})
    rules = {rule["id"]: rule for rule in run(sarif)["tool"]["driver"]["rules"]}
    assert rules["Whatever"]["properties"]["security-severity"] == "2.0"


def test_every_catalog_rule_carries_a_security_severity_and_tags():
    # Rules are keyed by canonical_name, which is not always the CRYPTO_DB key
    # ("DH" -> "Diffie-Hellman") — findings carry the canonical name.
    by_name = {entry["canonical_name"]: entry for entry in CRYPTO_DB.values()}
    sarif = convert_to_sarif({})
    for rule in run(sarif)["tool"]["driver"]["rules"]:
        properties = rule["properties"]
        assert properties["security-severity"] in {"9.0", "5.0", "2.0", "1.0"}
        assert "security" in properties["tags"]
        quantum_vulnerable = by_name[rule["id"]]["quantum_vulnerable"]
        assert ("quantum-vulnerable" in properties["tags"]) is quantum_vulnerable
        assert rule["shortDescription"]["text"]
        assert rule["fullDescription"]["text"]
        assert rule["helpUri"].startswith("https://")


# ------------------------------------------------------------------- regions


def test_missing_or_null_col_defaults_to_column_one():
    sarif = convert_to_sarif(
        {
            "findings": [
                finding(col=None),
                {"file": "a.py", "line": 3, "algorithm": "MD5", "severity": "critical"},
                finding(col="not a number"),
            ]
        }
    )
    for result in run(sarif)["results"]:
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startColumn"] == 1
        assert "startLine" in region


def test_zero_based_columns_are_shifted_into_sarif_one_based_columns():
    # The scanners report ast.col_offset, which starts at 0; SARIF's minimum
    # startColumn is 1, so a finding at the start of a line must not emit 0.
    sarif = convert_to_sarif({"findings": [finding(col=0), finding(col=4)]})
    columns = [
        result["locations"][0]["physicalLocation"]["region"]["startColumn"]
        for result in run(sarif)["results"]
    ]
    assert columns == [1, 5]


def test_missing_line_defaults_to_line_one():
    sarif = convert_to_sarif({"findings": [{"file": "a.py", "algorithm": "RSA"}]})
    region = run(sarif)["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1


# ----------------------------------------------------------- rule references


def test_no_result_references_a_rule_missing_from_the_run():
    sarif = convert_to_sarif(
        {
            "findings": [
                finding(algorithm="RSA"),
                finding(algorithm="MD5", severity="critical"),
                finding(algorithm="SHA-512", severity="safe"),
                # Neither of these is a CRYPTO_DB key: one is an alias the
                # lookup canonicalizes, the other a synthetic scanner note.
                finding(algorithm="ecdh"),
                finding(algorithm="hashlib (requires deeper inspection)", severity="info"),
            ]
        }
    )
    ids = rule_ids(sarif)
    for result in run(sarif)["results"]:
        assert result["ruleId"] in ids


def test_an_alias_resolves_onto_its_canonical_rule():
    sarif = convert_to_sarif({"findings": [finding(algorithm="ecdh")]})
    assert run(sarif)["results"][0]["ruleId"] == "ECC"
    # and no extra rule was invented for the alias
    assert len(run(sarif)["tool"]["driver"]["rules"]) == len(CRYPTO_DB)


def test_an_unknown_algorithm_gets_its_own_rule_rather_than_an_orphan():
    unknown = "hashlib (requires deeper inspection)"
    sarif = convert_to_sarif({"findings": [finding(algorithm=unknown, severity="info")]})
    assert run(sarif)["results"][0]["ruleId"] == unknown
    assert unknown in rule_ids(sarif)


def test_messages_name_the_algorithm_and_its_replacement():
    sarif = convert_to_sarif({"findings": [finding()]})
    text = run(sarif)["results"][0]["message"]["text"]
    assert text.startswith("RSA detected")
    assert "Shor's Algorithm" in text
    assert "ML-KEM" in text


# ---------------------------------------------------------------------- URIs


@pytest.mark.parametrize(
    "path,uri",
    [
        ("src\\crypto\\auth.py", "src/crypto/auth.py"),
        ("src/crypto/auth.py", "src/crypto/auth.py"),
        ("./src/auth.py", "src/auth.py"),
        ("/src/auth.py", "src/auth.py"),
        ("C:\\Users\\dev\\repo\\auth.py", "Users/dev/repo/auth.py"),
        ("", "unknown"),
        (None, "unknown"),
    ],
)
def test_artifact_uris_are_relative_and_forward_slashed(path, uri):
    sarif = convert_to_sarif({"findings": [finding(file=path)]})
    location = run(sarif)["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == uri
    assert "\\" not in location["artifactLocation"]["uri"]


# ------------------------------------------------------------ malformed input


@pytest.mark.parametrize(
    "report",
    [
        None,
        [],
        "not a report",
        {"findings": None},
        {"findings": ["a string, not a finding", 7]},
        {"findings_by_file": {"a.py": "not a list"}},
        {"findings_by_file": None},
        {"findings": [{}]},
    ],
)
def test_malformed_input_yields_valid_sarif_instead_of_raising(report):
    sarif = convert_to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert isinstance(run(sarif)["results"], list)
    assert run(sarif)["tool"]["driver"]["rules"]
    json.dumps(sarif)  # still serializable


def test_a_single_bad_finding_does_not_drop_the_good_ones():
    sarif = convert_to_sarif({"findings": [finding(), "junk", finding(file="b.py")]})
    assert len(run(sarif)["results"]) == 2

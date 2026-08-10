"""Tests for the CycloneDX 1.6 CBOM converter.

These check the structural contract a CBOM consumer relies on. The two that
matter most are the ones a SARIF-shaped translation would get wrong: an
inventory lists each algorithm once with every place it was seen, not once per
finding, and it lists only what the scan actually found rather than a catalog.

Enum membership is asserted against the constants cbom_converter copies out of
the CycloneDX 1.6 schema, so an invented primitive or crypto function fails
here rather than in whatever tool the file is opened with.
"""

import json
import uuid

import pytest

from cbom_converter import (
    CDX_CRYPTO_FUNCTIONS,
    CDX_PRIMITIVES,
    SPEC_VERSION,
    convert_to_cbom,
)

# Every key the CycloneDX 1.6 schema allows on a component. The schema sets
# additionalProperties:false there, so anything outside this set is a
# validation failure rather than a harmless extra field.
COMPONENT_KEYS = {
    "type", "mime-type", "bom-ref", "supplier", "manufacturer", "authors",
    "author", "publisher", "group", "name", "version", "description", "scope",
    "hashes", "licenses", "copyright", "cpe", "purl", "omniborId", "swhid",
    "swid", "modified", "pedigree", "externalReferences", "components",
    "evidence", "releaseNotes", "modelCard", "data", "cryptoProperties",
    "properties", "tags", "signature",
}

OCCURRENCE_KEYS = {"bom-ref", "location", "line", "offset", "symbol", "additionalContext"}


def finding(**overrides) -> dict:
    base = {
        "file": "auth.py",
        "line": 12,
        "col": 4,
        "algorithm": "RSA",
        "severity": "critical",
        "quantum_vulnerable": True,
    }
    return {**base, **overrides}


def components(cbom: dict) -> dict[str, dict]:
    return {component["name"]: component for component in cbom["components"]}


def properties(cbom: dict, name: str) -> dict:
    return components(cbom)[name]["cryptoProperties"]["algorithmProperties"]


# ------------------------------------------------------------- top-level shape


def test_top_level_structure_is_cyclonedx_1_6():
    cbom = convert_to_cbom({"repo": "acme/demo", "findings": [finding()]})
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == SPEC_VERSION == "1.6"
    assert cbom["version"] == 1


def test_serial_number_is_a_real_uuid4_urn():
    cbom = convert_to_cbom({"findings": [finding()]})
    assert cbom["serialNumber"].startswith("urn:uuid:")
    parsed = uuid.UUID(cbom["serialNumber"].removeprefix("urn:uuid:"))
    assert parsed.version == 4


def test_each_conversion_gets_its_own_serial_number():
    report = {"findings": [finding()]}
    assert (
        convert_to_cbom(report)["serialNumber"]
        != convert_to_cbom(report)["serialNumber"]
    )


def test_metadata_names_the_tool_and_the_scanned_subject():
    cbom = convert_to_cbom({"repo": "acme/demo", "findings": [finding()]})
    metadata = cbom["metadata"]
    assert metadata["tools"][0]["vendor"] == "QLint"
    assert metadata["tools"][0]["name"] == "QLint"
    assert metadata["tools"][0]["version"]
    assert metadata["component"] == {"type": "application", "name": "acme/demo"}
    assert metadata["timestamp"]


def test_a_local_directory_scan_is_named_by_its_path():
    # scan_directory reports carry "path" where a repo scan carries "repo".
    cbom = convert_to_cbom({"path": "/srv/checkout", "findings": [finding()]})
    assert cbom["metadata"]["component"]["name"] == "/srv/checkout"


def test_a_stored_scan_keeps_its_original_timestamp():
    cbom = convert_to_cbom(
        {"created_at": "2026-01-02T03:04:05Z", "findings": [finding()]}
    )
    assert cbom["metadata"]["timestamp"] == "2026-01-02T03:04:05Z"


def test_output_is_serializable_json():
    cbom = convert_to_cbom({"findings": [finding(), finding(algorithm="MD5")]})
    assert json.loads(json.dumps(cbom)) == cbom


# -------------------------------------------------------------------- emptiness


@pytest.mark.parametrize(
    "empty", [{}, {"findings": []}, {"findings_by_file": {}}]
)
def test_empty_report_produces_a_valid_cbom_with_no_components(empty):
    cbom = convert_to_cbom(empty)
    assert cbom["components"] == []
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert cbom["serialNumber"].startswith("urn:uuid:")


def test_the_inventory_is_the_scan_not_the_catalog():
    """The one place a CBOM must not behave like the SARIF converter.

    SARIF emits every CRYPTO_DB rule whether the scan hit it or not. An
    inventory listing algorithms the code does not contain would be false.
    """
    cbom = convert_to_cbom({"findings": [finding(algorithm="MD5")]})
    assert [component["name"] for component in cbom["components"]] == ["MD5"]


# ------------------------------------------------------------------- grouping


def test_the_same_algorithm_in_two_files_is_one_component():
    cbom = convert_to_cbom(
        {
            "findings": [
                finding(file="a.py", line=1),
                finding(file="b.py", line=2),
                finding(file="c/d.py", line=3),
            ]
        }
    )
    assert len(cbom["components"]) == 1
    component = cbom["components"][0]
    assert component["name"] == "RSA"
    assert component["evidence"]["occurrences"] == [
        {"location": "a.py", "line": 1},
        {"location": "b.py", "line": 2},
        {"location": "c/d.py", "line": 3},
    ]


def test_two_occurrences_in_one_file_are_both_recorded():
    cbom = convert_to_cbom(
        {"findings": [finding(line=10), finding(line=40)]}
    )
    assert len(cbom["components"]) == 1
    assert cbom["components"][0]["evidence"]["occurrences"] == [
        {"location": "auth.py", "line": 10},
        {"location": "auth.py", "line": 40},
    ]


def test_an_identical_occurrence_is_not_recorded_twice():
    # The findings_by_file and flat shapes can both be present on one report.
    report = {
        "findings": [finding(file="a.py", line=5)],
        "findings_by_file": {"a.py": [finding(file="a.py", line=5)]},
    }
    cbom = convert_to_cbom(report)
    assert cbom["components"][0]["evidence"]["occurrences"] == [
        {"location": "a.py", "line": 5}
    ]


def test_different_algorithms_get_different_components():
    cbom = convert_to_cbom(
        {
            "findings": [
                finding(algorithm="RSA"),
                finding(algorithm="MD5", file="b.py"),
                finding(algorithm="AES-256", file="c.py", severity="safe",
                        quantum_vulnerable=False),
            ]
        }
    )
    assert [c["name"] for c in cbom["components"]] == ["AES-256", "MD5", "RSA"]


def test_components_are_sorted_by_name_for_a_stable_diff():
    cbom = convert_to_cbom(
        {
            "findings": [
                finding(algorithm="SHA-1"),
                finding(algorithm="MD5"),
                finding(algorithm="ECC"),
            ]
        }
    )
    names = [c["name"] for c in cbom["components"]]
    assert names == sorted(names)


def test_an_alias_groups_onto_its_canonical_component():
    # A finding carrying a raw identifier must not become a second RSA.
    cbom = convert_to_cbom(
        {"findings": [finding(algorithm="RSA"), finding(algorithm="rsa2048",
                                                        file="b.py")]}
    )
    assert [c["name"] for c in cbom["components"]] == ["RSA"]
    assert len(cbom["components"][0]["evidence"]["occurrences"]) == 2


def test_bom_refs_are_unique_across_components():
    cbom = convert_to_cbom(
        {
            "findings": [
                finding(algorithm=name)
                for name in ("RSA", "MD5", "AES-256", "SHA-1", "ECC")
            ]
        }
    )
    refs = [c["bom-ref"] for c in cbom["components"]]
    assert len(refs) == len(set(refs))


def test_the_grouping_key_fills_in_a_missing_file_field():
    cbom = convert_to_cbom(
        {"findings_by_file": {"src/app.py": [{"line": 7, "algorithm": "MD5"}]}}
    )
    assert cbom["components"][0]["evidence"]["occurrences"] == [
        {"location": "src/app.py", "line": 7}
    ]


# ---------------------------------------------------------- crypto properties


def test_every_component_is_a_cryptographic_asset():
    cbom = convert_to_cbom(
        {"findings": [finding(algorithm=name) for name in ("RSA", "MD5", "DES")]}
    )
    for component in cbom["components"]:
        assert component["type"] == "cryptographic-asset"
        assert component["cryptoProperties"]["assetType"] == "algorithm"


@pytest.mark.parametrize(
    "algorithm,primitive",
    [
        ("RSA", "signature"),
        ("DSA", "signature"),
        ("ECC", "signature"),
        ("Ed25519", "signature"),
        ("ML-DSA", "signature"),
        ("Diffie-Hellman", "key-agree"),
        ("ElGamal", "pke"),
        ("ML-KEM", "kem"),
        ("MD5", "hash"),
        ("SHA-1", "hash"),
        ("SHA-256", "hash"),
        ("SHA-512", "hash"),
        ("SHA-3", "hash"),
        ("AES-128", "block-cipher"),
        ("AES-256", "block-cipher"),
        ("DES", "block-cipher"),
        ("3DES", "block-cipher"),
        ("RC4", "stream-cipher"),
        ("HMAC (symmetric)", "mac"),
    ],
)
def test_each_algorithm_maps_to_its_cyclonedx_primitive(algorithm, primitive):
    cbom = convert_to_cbom({"findings": [finding(algorithm=algorithm)]})
    assert properties(cbom, algorithm)["primitive"] == primitive


def test_an_unknown_algorithm_gets_the_unknown_primitive_not_a_guess():
    cbom = convert_to_cbom({"findings": [finding(algorithm="Whirlpool")]})
    assert properties(cbom, "Whirlpool")["primitive"] == "unknown"


def test_every_emitted_primitive_is_in_the_cyclonedx_enum():
    from vulnerability_db import CRYPTO_DB

    names = [entry["canonical_name"] for entry in CRYPTO_DB.values()]
    cbom = convert_to_cbom({"findings": [finding(algorithm=n) for n in names]})
    assert len(cbom["components"]) == len(set(names))
    for component in cbom["components"]:
        assert (
            component["cryptoProperties"]["algorithmProperties"]["primitive"]
            in CDX_PRIMITIVES
        )
        # Nothing in the catalog should fall through to "unknown": that would
        # mean an algorithm was added to the database without being classified.
        assert (
            component["cryptoProperties"]["algorithmProperties"]["primitive"]
            != "unknown"
        )


def test_every_emitted_crypto_function_is_in_the_cyclonedx_enum():
    from vulnerability_db import CRYPTO_DB

    names = [entry["canonical_name"] for entry in CRYPTO_DB.values()]
    cbom = convert_to_cbom({"findings": [finding(algorithm=n) for n in names]})
    for component in cbom["components"]:
        functions = component["cryptoProperties"]["algorithmProperties"].get(
            "cryptoFunctions", []
        )
        assert functions, component["name"]
        assert set(functions) <= CDX_CRYPTO_FUNCTIONS


@pytest.mark.parametrize(
    "algorithm,expected",
    [
        ("MD5", ["digest"]),
        ("SHA-256", ["digest"]),
        ("AES-256", ["encrypt", "decrypt"]),
        ("Ed25519", ["keygen", "sign", "verify"]),
        ("ML-KEM", ["keygen", "encapsulate", "decapsulate"]),
        ("HMAC (symmetric)", ["tag"]),
    ],
)
def test_crypto_functions_follow_the_primitive(algorithm, expected):
    cbom = convert_to_cbom({"findings": [finding(algorithm=algorithm)]})
    assert properties(cbom, algorithm)["cryptoFunctions"] == expected


@pytest.mark.parametrize("algorithm", ["RSA", "ElGamal"])
def test_dual_purpose_algorithms_record_both_jobs(algorithm):
    # CycloneDX allows one primitive, but RSA and ElGamal genuinely do both
    # encryption and signatures — which is why their CRYPTO_DB entries name
    # two different replacements.
    functions = properties(
        convert_to_cbom({"findings": [finding(algorithm=algorithm)]}), algorithm
    )["cryptoFunctions"]
    assert {"encrypt", "sign"} <= set(functions)


@pytest.mark.parametrize(
    "algorithm,parameter_set",
    [("AES-128", "128"), ("AES-192", "192"), ("AES-256", "256"),
     ("SHA-256", "256"), ("SHA-384", "384"), ("SHA-512", "512")],
)
def test_parameter_set_identifier_is_emitted_when_the_name_states_it(
    algorithm, parameter_set
):
    cbom = convert_to_cbom({"findings": [finding(algorithm=algorithm)]})
    assert properties(cbom, algorithm)["parameterSetIdentifier"] == parameter_set


@pytest.mark.parametrize("algorithm", ["RSA", "SHA-1", "MD5", "3DES", "DES", "ECC"])
def test_parameter_set_identifier_is_omitted_when_unknown(algorithm):
    # Deriving it from the digits in the name would make SHA-1 parameter set
    # "1" and 3DES parameter set "3", both of which are wrong.
    cbom = convert_to_cbom({"findings": [finding(algorithm=algorithm)]})
    assert "parameterSetIdentifier" not in properties(cbom, algorithm)


def test_execution_environment_and_platform_are_declared():
    cbom = convert_to_cbom({"findings": [finding()]})
    assert properties(cbom, "RSA")["executionEnvironment"] == "software-plain-ram"
    assert properties(cbom, "RSA")["implementationPlatform"] == "generic"


# --------------------------------------------------- quantum security level


@pytest.mark.parametrize(
    "algorithm", ["RSA", "ECC", "Ed25519", "DSA", "Diffie-Hellman", "ElGamal",
                  "MD5", "SHA-1", "SHA-256", "AES-128", "DES", "3DES"]
)
def test_quantum_vulnerable_algorithms_carry_security_level_zero(algorithm):
    """The field that makes a CBOM useful for PQC migration tracking."""
    cbom = convert_to_cbom(
        {"findings": [finding(algorithm=algorithm, quantum_vulnerable=True)]}
    )
    assert properties(cbom, algorithm)["nistQuantumSecurityLevel"] == 0


@pytest.mark.parametrize(
    "algorithm", ["AES-256", "SHA-384", "SHA-512", "SHA-3", "ML-KEM", "ML-DSA"]
)
def test_quantum_safe_algorithms_omit_the_security_level(algorithm):
    # Absent rather than 0, so "0" keeps meaning "no post-quantum security"
    # instead of being the default every component carries.
    cbom = convert_to_cbom(
        {"findings": [finding(algorithm=algorithm, quantum_vulnerable=False,
                              severity="safe")]}
    )
    assert "nistQuantumSecurityLevel" not in properties(cbom, algorithm)


def test_the_level_falls_back_to_the_database_when_the_finding_omits_the_flag():
    cbom = convert_to_cbom(
        {"findings": [{"file": "a.py", "line": 1, "algorithm": "RSA"}]}
    )
    assert properties(cbom, "RSA")["nistQuantumSecurityLevel"] == 0


def test_one_vulnerable_occurrence_makes_the_asset_vulnerable():
    cbom = convert_to_cbom(
        {
            "findings": [
                finding(file="a.py", quantum_vulnerable=False),
                finding(file="b.py", quantum_vulnerable=True),
            ]
        }
    )
    assert properties(cbom, "RSA")["nistQuantumSecurityLevel"] == 0


# ------------------------------------------------------------ scanner notes


@pytest.mark.parametrize(
    "note",
    [
        "hashlib (requires deeper inspection)",
        "crypto (requires deeper inspection)",
        "crypto/tls (requires deeper inspection)",
        "Bouncy Castle (requires deeper inspection)",
        "openssl crate (requires deeper inspection)",
    ],
)
def test_library_level_notes_are_not_inventoried_as_assets(note):
    # These name a library, not an algorithm. A bill of materials that listed
    # them would be listing parts that do not exist.
    cbom = convert_to_cbom({"findings": [finding(algorithm=note)]})
    assert cbom["components"] == []


def test_an_aes_usage_of_unknown_length_is_still_inventoried():
    # The opposite case: the scanner could not read the key length, but AES is
    # unambiguously present, and parameterSetIdentifier is optional for this.
    cbom = convert_to_cbom(
        {"findings": [finding(algorithm="AES (key length not visible)",
                              severity="info", quantum_vulnerable=False)]}
    )
    assert [c["name"] for c in cbom["components"]] == [
        "AES (key length not visible)"
    ]
    assert properties(cbom, "AES (key length not visible)")[
        "primitive"
    ] == "block-cipher"
    assert "parameterSetIdentifier" not in properties(
        cbom, "AES (key length not visible)"
    )


# ------------------------------------------------------------ schema shape


def test_components_carry_no_field_outside_the_cyclonedx_schema():
    # The 1.6 schema sets additionalProperties:false on component and on each
    # occurrence, so an invented field name fails the whole document.
    cbom = convert_to_cbom(
        {
            "repo": "acme/demo",
            "findings": [finding(), finding(algorithm="MD5", file="b.py")],
        }
    )
    for component in cbom["components"]:
        assert set(component) <= COMPONENT_KEYS, set(component) - COMPONENT_KEYS
        for occurrence in component["evidence"]["occurrences"]:
            assert set(occurrence) <= OCCURRENCE_KEYS
            assert isinstance(occurrence["location"], str)
            assert occurrence["location"]


def test_occurrence_lines_are_non_negative_integers():
    cbom = convert_to_cbom({"findings": [finding(line=1)]})
    line = cbom["components"][0]["evidence"]["occurrences"][0]["line"]
    assert isinstance(line, int) and not isinstance(line, bool)
    assert line >= 0


@pytest.mark.parametrize("line", [None, "twelve", -3, True])
def test_an_unusable_line_omits_the_field_rather_than_inventing_one(line):
    cbom = convert_to_cbom({"findings": [finding(line=line)]})
    occurrence = cbom["components"][0]["evidence"]["occurrences"][0]
    assert "line" not in occurrence
    assert occurrence["location"] == "auth.py"


@pytest.mark.parametrize(
    "path,location",
    [
        ("src\\auth.py", "src/auth.py"),
        ("/abs/path.py", "abs/path.py"),
        ("C:\\src\\app.py", "src/app.py"),
        ("./rel.py", "rel.py"),
        (None, "unknown"),
        ("", "unknown"),
    ],
)
def test_occurrence_locations_are_relative_and_forward_slashed(path, location):
    cbom = convert_to_cbom({"findings": [finding(file=path)]})
    assert cbom["components"][0]["evidence"]["occurrences"][0]["location"] == location


# ------------------------------------------------------------ robustness


@pytest.mark.parametrize(
    "report",
    [
        None,
        "not a dict",
        42,
        [],
        {"findings": "not a list"},
        {"findings": [None, 42, "x"]},
        {"findings_by_file": {"a.py": "not a list"}},
        {"findings_by_file": None},
        {"findings": [{}]},
        {"repo": None, "findings": [finding()]},
        {"created_at": 12345, "findings": [finding()]},
    ],
)
def test_malformed_input_yields_valid_cbom_instead_of_raising(report):
    cbom = convert_to_cbom(report)
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert isinstance(cbom["components"], list)
    assert cbom["metadata"]["timestamp"]
    json.dumps(cbom)


def test_a_single_bad_finding_does_not_drop_the_good_ones():
    cbom = convert_to_cbom(
        {"findings": [finding(), {"algorithm": None}, finding(algorithm="MD5",
                                                             file="b.py")]}
    )
    assert [c["name"] for c in cbom["components"]] == ["MD5", "RSA"]


def test_a_real_report_shape_converts():
    """The shape scanner_engine actually produces, end to end."""
    report = {
        "repo": "acme/demo",
        "scanned_files": 2,
        "findings_by_file": {
            "src/auth.py": [
                {"file": "src/auth.py", "line": 12, "col": 4, "algorithm": "RSA",
                 "severity": "critical", "quantum_vulnerable": True,
                 "language": "python"},
                {"file": "src/auth.py", "line": 30, "col": 0, "algorithm": "MD5",
                 "severity": "critical", "quantum_vulnerable": True,
                 "language": "python"},
            ],
            "src/keys.go": [
                {"file": "src/keys.go", "line": 8, "col": 1, "algorithm": "RSA",
                 "severity": "critical", "quantum_vulnerable": True,
                 "language": "go"},
            ],
        },
    }
    cbom = convert_to_cbom(report)
    assert [c["name"] for c in cbom["components"]] == ["MD5", "RSA"]
    rsa = components(cbom)["RSA"]
    assert rsa["evidence"]["occurrences"] == [
        {"location": "src/auth.py", "line": 12},
        {"location": "src/keys.go", "line": 8},
    ]

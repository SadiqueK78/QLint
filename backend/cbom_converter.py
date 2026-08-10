"""CycloneDX 1.6 CBOM output for QLint scan reports.

A CBOM (Cryptography Bill of Materials) is CycloneDX's standard inventory of
the cryptographic assets a codebase actually contains. The sibling of
sarif_converter.py: same input, same never-raises discipline, different
question. SARIF answers "what is wrong and where"; a CBOM answers "what
cryptography is in here", which is the artifact a PQC migration programme
tracks progress against.

Schema: https://cyclonedx.org/docs/1.6/json/
        https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json

One structural difference from the SARIF converter is deliberate. SARIF emits
the whole CRYPTO_DB as a rule catalog whether or not this scan hit any of it,
because tools cache rule definitions across runs. A CBOM emits only what was
found: an inventory listing algorithms the code does not use would be a false
inventory. For the same reason each algorithm appears exactly once, with every
place it was seen collected under evidence.occurrences, rather than once per
finding.

The enum values below are copied from the 1.6 schema rather than guessed. The
schema sets additionalProperties:false on both the document and each component,
so an invented field name is a validation failure, not a harmless extra.

Conversion is best-effort by design — convert_to_cbom never raises. A malformed
report yields a valid CBOM with whatever could be salvaged rather than a 500 on
the download route.
"""

import uuid
from datetime import datetime, timezone

from sarif_converter import QLINT_VERSION, REPO_URL, artifact_uri, iter_findings
from vulnerability_db import find_algorithm

SPEC_VERSION = "1.6"
BOM_FORMAT = "CycloneDX"

# cryptoProperties.algorithmProperties.primitive — the full 1.6 enum. Anything
# this module emits is checked against it, so a typo cannot reach the output.
CDX_PRIMITIVES = frozenset(
    {
        "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
        "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other",
        "unknown",
    }
)

# cryptoProperties.algorithmProperties.cryptoFunctions — the full 1.6 enum.
CDX_CRYPTO_FUNCTIONS = frozenset(
    {
        "generate", "keygen", "encrypt", "decrypt", "digest", "tag",
        "keyderive", "sign", "verify", "encapsulate", "decapsulate", "other",
        "unknown",
    }
)

# QLint scans source, not a deployment, so it can only ever report on a
# software implementation running on whatever the build targets. Declaring
# anything narrower would be a claim the scanner is not in a position to make.
EXECUTION_ENVIRONMENT = "software-plain-ram"
IMPLEMENTATION_PLATFORM = "generic"

# The NIST PQC security category. Category 0 is the value CycloneDX uses for
# "provides no post-quantum security", which is exactly what a Shor- or
# Grover-exposed algorithm provides. Emitted only for those: leaving the field
# off for the safe entries keeps "0" meaning something rather than being the
# default everything carries.
QUANTUM_VULNERABLE_LEVEL = 0

# Canonical CRYPTO_DB name -> CycloneDX primitive. The asymmetric algorithms
# are classified by the job their CRYPTO_DB entry describes: RSA/DSA/ECC and
# the EdDSA and PQC signature schemes as "signature", Diffie-Hellman as
# "key-agree", ElGamal as "pke" (public-key encryption is its dominant use,
# and its signature mode is the rarer one), ML-KEM as "kem".
_PRIMITIVES: dict[str, str] = {
    "RSA": "signature",
    "ECC": "signature",
    "Ed25519": "signature",
    "DSA": "signature",
    "ML-DSA": "signature",
    "SLH-DSA": "signature",
    "FALCON": "signature",
    "Diffie-Hellman": "key-agree",
    "ElGamal": "pke",
    "ML-KEM": "kem",
    "MD5": "hash",
    "SHA-1": "hash",
    "SHA-256": "hash",
    "SHA-384": "hash",
    "SHA-512": "hash",
    "SHA-3": "hash",
    "AES-128": "block-cipher",
    "AES-192": "block-cipher",
    "AES-256": "block-cipher",
    "DES": "block-cipher",
    "3DES": "block-cipher",
    "RC4": "stream-cipher",
    # Scanner notes that still name a real cryptographic asset. An AES usage
    # whose key length the file never states is still an AES usage, and the
    # inventory is the one place it should not disappear from -- CycloneDX
    # makes parameterSetIdentifier optional for exactly this case.
    "AES (key length not visible)": "block-cipher",
    "HMAC (symmetric)": "mac",
}

# What each primitive is used for. Kept coarse on purpose: the scanner sees an
# import or a constructor, not which half of an API a program goes on to call.
_FUNCTIONS_BY_PRIMITIVE: dict[str, list[str]] = {
    "signature": ["keygen", "sign", "verify"],
    "pke": ["keygen", "encrypt", "decrypt"],
    "key-agree": ["keygen", "keyderive"],
    "kem": ["keygen", "encapsulate", "decapsulate"],
    "hash": ["digest"],
    "block-cipher": ["encrypt", "decrypt"],
    "stream-cipher": ["encrypt", "decrypt"],
    "mac": ["tag"],
    "kdf": ["keyderive"],
}

# The two algorithms whose CRYPTO_DB entry names two different replacements
# because the algorithm genuinely does two different jobs. CycloneDX allows
# only one primitive per component, so the second job is recorded here.
_FUNCTION_OVERRIDES: dict[str, list[str]] = {
    "RSA": ["keygen", "encrypt", "decrypt", "sign", "verify"],
    "ElGamal": ["keygen", "encrypt", "decrypt", "sign", "verify"],
}

# parameterSetIdentifier, only where the canonical name states a real
# parameter size. Derived from a table rather than by pulling the digits out
# of the name: that rule would turn SHA-1 into parameter set "1" and 3DES
# into "3", both of which are wrong.
_PARAMETER_SETS: dict[str, str] = {
    "AES-128": "128",
    "AES-192": "192",
    "AES-256": "256",
    "SHA-256": "256",
    "SHA-384": "384",
    "SHA-512": "512",
}

# The scanners' library-level notes. A note that a file imports openssl, or
# hashlib, or the Bouncy Castle provider is a pointer to look closer -- it
# names no algorithm, so there is no cryptographic asset to inventory. SARIF
# reports these because they are findings; a bill of materials must not, or it
# lists parts that do not exist.
_NOT_AN_ASSET = "requires deeper inspection"


def _text(value, fallback: str = "") -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return fallback


def _canonical_name(algorithm: str) -> str:
    """The CRYPTO_DB name for an algorithm, or the algorithm as reported.

    Findings normally already carry a canonical name. A scanner note or a raw
    identifier is resolved through the alias table so it groups with the real
    entry instead of becoming a second component for the same algorithm.
    """
    if algorithm in _PRIMITIVES:
        return algorithm
    entry = find_algorithm(algorithm)
    if entry is not None:
        return _text(entry.get("canonical_name"), algorithm)
    return algorithm


def _primitive(name: str) -> str:
    return _PRIMITIVES.get(name, "unknown")


def _crypto_functions(name: str, primitive: str) -> list[str]:
    functions = _FUNCTION_OVERRIDES.get(name) or _FUNCTIONS_BY_PRIMITIVE.get(
        primitive, []
    )
    # Filtered against the schema enum rather than trusted: an unlisted value
    # fails validation for the whole document, not just its own field.
    return [function for function in functions if function in CDX_CRYPTO_FUNCTIONS]


def _quantum_vulnerable(name: str, findings: list[dict]) -> bool:
    """Whether this algorithm is quantum-exposed.

    Read from the findings first, because that is what the scanner actually
    reported, and fall back to the database for a finding that carried no
    flag. Any one occurrence being vulnerable makes the asset vulnerable.
    """
    for finding in findings:
        flag = finding.get("quantum_vulnerable")
        if isinstance(flag, bool):
            if flag:
                return True
            continue
        entry = find_algorithm(_text(finding.get("algorithm"), name))
        if entry is not None and entry.get("quantum_vulnerable"):
            return True
    return False


def _line(finding: dict) -> int | None:
    """A CycloneDX occurrence line number, or None to leave the field off.

    Omitted rather than defaulted to 1 when the finding has no usable line: a
    bill of materials that points at line 1 of a file is asserting a location
    nobody measured.
    """
    line = finding.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or line < 0:
        return None
    return line


def _occurrences(findings: list[dict]) -> list[dict]:
    """Every distinct place this algorithm was seen, in file/line order."""
    seen: set[tuple[str, int | None]] = set()
    occurrences: list[dict] = []
    for finding in findings:
        location = artifact_uri(finding.get("file"))
        line = _line(finding)
        if (location, line) in seen:
            continue
        seen.add((location, line))
        occurrence = {"location": location}
        if line is not None:
            occurrence["line"] = line
        occurrences.append(occurrence)
    occurrences.sort(key=lambda item: (item["location"], item.get("line", 0)))
    return occurrences


def _bom_ref(name: str) -> str:
    """A stable, document-unique reference for a component."""
    slug = "".join(
        char if char.isalnum() or char in "-._" else "-" for char in name.lower()
    ).strip("-")
    return f"crypto/{slug or 'unknown'}"


def _component(name: str, findings: list[dict]) -> dict:
    primitive = _primitive(name)
    algorithm_properties: dict = {"primitive": primitive}

    parameter_set = _PARAMETER_SETS.get(name)
    if parameter_set:
        algorithm_properties["parameterSetIdentifier"] = parameter_set

    algorithm_properties["executionEnvironment"] = EXECUTION_ENVIRONMENT
    algorithm_properties["implementationPlatform"] = IMPLEMENTATION_PLATFORM

    functions = _crypto_functions(name, primitive)
    if functions:
        algorithm_properties["cryptoFunctions"] = functions

    if _quantum_vulnerable(name, findings):
        algorithm_properties["nistQuantumSecurityLevel"] = QUANTUM_VULNERABLE_LEVEL

    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref(name),
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": algorithm_properties,
        },
        "evidence": {"occurrences": _occurrences(findings)},
    }


def _group(scan_report: dict) -> dict[str, list[dict]]:
    """Findings bucketed by canonical algorithm name.

    This is what makes one algorithm one component: forty RSA findings across
    twelve files collapse into a single RSA entry carrying forty occurrences.
    """
    grouped: dict[str, list[dict]] = {}
    for finding in iter_findings(scan_report):
        algorithm = _text(finding.get("algorithm"))
        if not algorithm or _NOT_AN_ASSET in algorithm:
            continue
        grouped.setdefault(_canonical_name(algorithm), []).append(finding)
    return grouped


def _timestamp(scan_report: dict) -> str:
    """When the scan happened, as an RFC 3339 / ISO 8601 instant.

    The stored history entries carry created_at; a report handed straight from
    a scan does not, and is being converted now.
    """
    if isinstance(scan_report, dict):
        stored = scan_report.get("created_at")
        if isinstance(stored, str) and stored.strip():
            return stored.strip()
        if isinstance(stored, datetime):
            return stored.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _subject_name(scan_report: dict) -> str:
    """What the BOM is about: the repository, or the directory that was scanned."""
    if isinstance(scan_report, dict):
        for key in ("repo", "path"):
            name = _text(scan_report.get(key))
            if name:
                return name
    return "unknown"


def convert_to_cbom(scan_report: dict) -> dict:
    """Convert a QLint scan report into a CycloneDX 1.6 CBOM.

    Accepts either report shape (findings_by_file or a flat findings list).
    One component per distinct algorithm, each carrying every location it was
    seen at. An empty or missing set of findings still produces a valid
    document, with an empty components array.

    Never raises. A finding that cannot be converted is skipped rather than
    failing the whole document.
    """
    try:
        grouped = _group(scan_report)
    except Exception:
        grouped = {}

    components: list[dict] = []
    for name in sorted(grouped):
        try:
            components.append(_component(name, grouped[name]))
        except Exception:
            continue  # one bad group must not cost the whole inventory

    try:
        timestamp = _timestamp(scan_report)
        subject = _subject_name(scan_report)
    except Exception:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        subject = "unknown"

    return {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "QLint",
                    "name": "QLint",
                    "version": QLINT_VERSION,
                    "externalReferences": [
                        {"type": "website", "url": REPO_URL}
                    ],
                }
            ],
            "component": {"type": "application", "name": subject},
        },
        "components": components,
    }


if __name__ == "__main__":
    import json

    fake_report = {
        "repo": "acme/demo",
        "findings": [
            {"file": "auth.py", "line": 12, "algorithm": "RSA",
             "severity": "critical", "quantum_vulnerable": True},
            {"file": "keys.py", "line": 40, "algorithm": "RSA",
             "severity": "critical", "quantum_vulnerable": True},
            {"file": "utils.py", "line": 3, "algorithm": "MD5",
             "severity": "critical", "quantum_vulnerable": True},
            {"file": "hash.py", "line": 9, "algorithm": "SHA-512",
             "severity": "safe", "quantum_vulnerable": False},
            {"file": "legacy.py", "line": 1,
             "algorithm": "hashlib (requires deeper inspection)",
             "severity": "info", "quantum_vulnerable": False},
        ],
    }
    cbom = convert_to_cbom(fake_report)

    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert cbom["serialNumber"].startswith("urn:uuid:")
    uuid.UUID(cbom["serialNumber"].removeprefix("urn:uuid:"))  # a real UUID
    assert cbom["metadata"]["component"]["name"] == "acme/demo"

    names = [component["name"] for component in cbom["components"]]
    # Three assets, not five findings: the two RSA lines collapse into one
    # component, and the library note is not a cryptographic asset at all.
    assert names == ["MD5", "RSA", "SHA-512"], names

    rsa = next(c for c in cbom["components"] if c["name"] == "RSA")
    properties = rsa["cryptoProperties"]["algorithmProperties"]
    assert rsa["type"] == "cryptographic-asset"
    assert rsa["cryptoProperties"]["assetType"] == "algorithm"
    assert properties["primitive"] == "signature"
    assert properties["nistQuantumSecurityLevel"] == 0
    assert rsa["evidence"]["occurrences"] == [
        {"location": "auth.py", "line": 12},
        {"location": "keys.py", "line": 40},
    ]

    safe = next(c for c in cbom["components"] if c["name"] == "SHA-512")
    # Quantum-safe, so the security-level field is absent rather than 0.
    assert "nistQuantumSecurityLevel" not in (
        safe["cryptoProperties"]["algorithmProperties"]
    )

    # Every emitted enum value is one the CycloneDX 1.6 schema defines.
    for component in cbom["components"]:
        algorithm_properties = component["cryptoProperties"]["algorithmProperties"]
        assert algorithm_properties["primitive"] in CDX_PRIMITIVES
        for function in algorithm_properties.get("cryptoFunctions", []):
            assert function in CDX_CRYPTO_FUNCTIONS

    assert convert_to_cbom({})["components"] == []
    json.dumps(cbom)  # serializable

    print(f"cbom_converter.py self-test passed — {len(cbom['components'])} components")
    print(json.dumps(cbom, indent=2)[:900])

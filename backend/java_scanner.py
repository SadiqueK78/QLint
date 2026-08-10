"""Regex-based crypto detector for Java sources.

Java has no parser reachable from Python the way the stdlib `ast` module backs
ast_scanner, so detection is pattern based — the same methodology js_scanner
and go_scanner use. False positives are kept down by blanking comments with a
small state machine before any pattern runs, and by anchoring patterns on word
boundaries and exact string arguments.

Where Go names its algorithms in import paths, the JCA/JCE names them in the
string argument to a getInstance() factory — Cipher.getInstance("RSA"),
MessageDigest.getInstance("MD5") — so that call shape, not the import block,
is what most rules here read. Requiring the whole call shape is also what keeps
prose out of the report: a bare "RSA" in a Javadoc line or a log message never
looks like Cipher.getInstance("...").

Findings use the same shape as ast_scanner.scan_python_source,
js_scanner.scan_js_source and go_scanner.scan_go_source so the report layer
does not care which language a file was written in.
"""

import re

from scanner_common import (
    attach_snippets,
    line_starts,
    normalize_attack_vector,
    position,
    line_text,
)
from vulnerability_db import find_algorithm

# ----------------------------------------------------------------- helpers


def _strip_comments(source: str) -> str:
    """Blank out comments, preserving every byte offset and line break.

    Walks the source tracking string, text block (\"\"\"...\"\"\", Java 15+),
    char literal and comment state, so that `//` inside a string literal (a URL,
    say) is not mistaken for the start of a comment, and `getInstance("RSA")`
    inside a Javadoc block never reaches a pattern. Comment characters become
    spaces, so line and column numbers computed from the cleaned text still
    point at the original source.

    String literals are left intact on purpose: the JCE names its algorithms in
    string arguments, and they are the primary signal this scanner reads.
    """
    out = list(source)
    i = 0
    length = len(source)
    state = "code"  # code | line_comment | block_comment | string | text | char
    while i < length:
        char = source[i]
        nxt = source[i + 1] if i + 1 < length else ""

        if state == "code":
            if char == "/" and nxt == "/":
                state = "line_comment"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if char == "/" and nxt == "*":
                # Covers Javadoc (/** ... */) as well: same terminator.
                state = "block_comment"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if char == '"' and source[i : i + 3] == '"""':
                state = "text"
                i += 3
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state == "block_comment":
            if char == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "code"
                continue
            if char != "\n":
                out[i] = " "
        elif state == "text":
            # Text blocks process escapes and may span lines.
            if char == "\\":
                i += 2
                continue
            if source[i : i + 3] == '"""':
                state = "code"
                i += 3
                continue
        elif state in ("string", "char"):
            if char == "\\":
                i += 2  # skip the escaped character
                continue
            if (char == '"' and state == "string") or (
                char == "'" and state == "char"
            ):
                state = "code"
            elif char == "\n":
                state = "code"  # unterminated literal; recover
        i += 1

    return "".join(out)


# line_starts, position and line_text live in scanner_common: js_scanner and
# go_scanner need the identical implementation, and so does the code_snippet
# capture.


# ------------------------------------------------------- synthetic findings

# Entries the crypto database does not carry because they are notes rather
# than algorithms, or symmetric constructions with no migration path.
_SYNTHETIC: dict[str, dict] = {
    "bouncycastle_module": {
        "algorithm": "Bouncy Castle (requires deeper inspection)",
        "severity": "info",
        "quantum_vulnerable": False,
        "classical_vulnerable": False,
        "attack_vector": None,
        "replacement": None,
        "replacement_reason": "The Bouncy Castle provider itself is not vulnerable; the specific engines, digests, and key pair generators used through it determine the risk.",
        "fix_snippet": "// Inspect the Bouncy Castle usage: RSA/EC key pair generators and\n// MD5/SHA-1 digests are the classes that carry the risk.",
    },
    "aes_unknown": {
        "algorithm": "AES (key length not visible)",
        "severity": "info",
        "quantum_vulnerable": False,
        "classical_vulnerable": False,
        "attack_vector": None,
        "replacement": None,
        "replacement_reason": "The key length is not declared in this file. AES-128 is weakened by Grover's Algorithm to ~64 bits; AES-256 stays quantum-safe.",
        "fix_snippet": "// Declare the key length explicitly, and prefer 256:\n// KeyGenerator keyGen = KeyGenerator.getInstance(\"AES\");\n// keyGen.init(256);  // AES-256",
    },
    "hmac": {
        "algorithm": "HMAC (symmetric)",
        "severity": "safe",
        "quantum_vulnerable": False,
        "classical_vulnerable": False,
        "attack_vector": None,
        "replacement": None,
        "replacement_reason": "HMAC is a symmetric construction. Grover's Algorithm only halves the effective strength of the shared key, so an adequately sized key stays quantum-safe.",
        "fix_snippet": "// HmacSHA256/384/512 is symmetric and quantum-safe — no migration needed.",
    },
}


def _finding(
    line: int, col: int, identifier: str, match_type: str, entry: dict
) -> dict:
    """Build a finding from a CRYPTO_DB entry, preferring its Java fix snippet."""
    return {
        "line": line,
        "col": col,
        "identifier": identifier,
        "match_type": match_type,
        "algorithm": entry["canonical_name"],
        "severity": entry["severity"],
        "quantum_vulnerable": entry["quantum_vulnerable"],
        "classical_vulnerable": entry["classical_vulnerable"],
        "attack_vector": normalize_attack_vector(entry["attack_vector"]),
        "replacement": entry["replacement"],
        # BEFORE: the flagged source line, filled in by attach_snippets once
        # every rule has run. AFTER: the recommended replacement.
        "code_snippet": "",
        "fix_snippet": entry.get("java_fix_snippet") or entry["fix_snippet"],
        "replacement_reason": entry["replacement_reason"],
    }


def _synthetic_finding(
    line: int, col: int, identifier: str, match_type: str, kind: str
) -> dict:
    note = _SYNTHETIC[kind]
    return {"line": line, "col": col, "identifier": identifier,
            "match_type": match_type, "code_snippet": "", **note}


# -------------------------------------------------------------- AES sizing

_AES_SIZE_ALGORITHMS = {"128": "aes-128", "192": "aes-192", "256": "aes-256"}

# The key length a JCE file declares: `keyGen.init(256)`. KeyGenerator.init is
# the only place AES picks its key size, so it is the only place the algorithm
# is actually named. `initialize(2048)` (KeyPairGenerator) does not match: the
# `(` has to follow `init` directly.
_KEY_SIZE_RE = re.compile(r"\.init\s*\(\s*(128|192|256)\s*[,)]")
# Transformations that carry the size themselves: "AES_256/GCM/NoPadding".
_SIZED_AES_RE = re.compile(r"^aes[_-]?(128|192|256)$")


def _resolve_aes(value: str, cleaned: str) -> tuple[dict | None, str | None]:
    """Resolve AES usage to a sized entry, or the 'unknown length' note.

    Returns (db_entry, synthetic_kind) — exactly one of the two is set. Only an
    unambiguous file (exactly one key length in evidence) resolves to a sized
    entry; anything else is reported for inspection.
    """
    sized = _SIZED_AES_RE.match(value.strip().lower())
    if sized:
        sizes = {sized.group(1)}
    else:
        sizes = {match.group(1) for match in _KEY_SIZE_RE.finditer(cleaned)}
    if len(sizes) == 1:
        entry = find_algorithm(_AES_SIZE_ALGORITHMS[sizes.pop()])
        if entry is not None:
            return entry, None
    return None, "aes_unknown"


# ------------------------------------------------------------- resolvers
#
# Each resolver takes the string argument of a getInstance() call and returns
# (CRYPTO_DB entry, _SYNTHETIC key) with at most one side set.


def _squash(value: str) -> str:
    return re.sub(r"[-_\s]+", "", value.strip().lower())


_PQC_NAMES = ("mlkem", "mldsa", "slhdsa", "kyber", "dilithium", "falcon",
              "sphincs")


def _pqc(squashed: str) -> dict | None:
    """A NIST PQC name, checked before anything else.

    "ML-DSA-65" squashes to "mldsa65", which contains "dsa" — without this the
    replacement algorithm would be reported as the algorithm it replaces.
    """
    if any(name in squashed for name in _PQC_NAMES):
        return find_algorithm(squashed)
    return None


def _resolve_key_algorithm(value: str, cleaned: str) -> tuple[dict | None, str | None]:
    """A KeyPairGenerator / KeyFactory / KeyAgreement algorithm name."""
    squashed = _squash(value)
    pqc = _pqc(squashed)
    if pqc is not None:
        return pqc, None
    if squashed.startswith(("ed25519", "ed448", "eddsa", "x25519", "x448", "xdh")):
        return find_algorithm("ed25519"), None
    # "ec" first: ECDH and ECDSA are elliptic curve, and "ecdsa" would
    # otherwise fall through to the DSA branch below.
    if squashed.startswith("ec"):
        return find_algorithm("ecdsa"), None
    if squashed.startswith("rsa"):
        return find_algorithm("rsa"), None
    if squashed.startswith("dsa"):
        return find_algorithm("dsa"), None
    if squashed.startswith(("diffiehellman", "dh")):
        return find_algorithm("diffie-hellman"), None
    return find_algorithm(value), None


def _resolve_signature(value: str, cleaned: str) -> tuple[dict | None, str | None]:
    """A Signature algorithm name: "SHA256withRSA", "SHA1withECDSA", "Ed25519".

    The asymmetric half is what carries the quantum risk, so it wins over the
    hash half — Signature.getInstance("SHA256withRSA") is an RSA finding, not a
    SHA-256 one.
    """
    squashed = _squash(value)
    pqc = _pqc(squashed)
    if pqc is not None:
        return pqc, None
    if "ed25519" in squashed or "ed448" in squashed or squashed.startswith("eddsa"):
        return find_algorithm("ed25519"), None
    if "ecdsa" in squashed or squashed.startswith("ec"):
        return find_algorithm("ecdsa"), None
    if "rsa" in squashed:
        return find_algorithm("rsa"), None
    if "dsa" in squashed:
        return find_algorithm("dsa"), None
    return find_algorithm(value), None


def _resolve_digest(value: str, cleaned: str) -> tuple[dict | None, str | None]:
    """A MessageDigest algorithm name: "MD5", "SHA-1", "SHA-256", "SHA3-512"."""
    squashed = _squash(value)
    if squashed in ("sha", "sha1"):
        # Bare "SHA" is the JCA's historical name for SHA-1.
        return find_algorithm("sha1"), None
    if squashed.startswith("sha512"):
        # Covers the truncated forms SHA-512/224 and SHA-512/256.
        return find_algorithm("sha512"), None
    if squashed.startswith("sha224"):
        # SHA-224 is SHA-256 truncated — same construction, same Grover exposure.
        return find_algorithm("sha256"), None
    return find_algorithm(value), None


def _resolve_transformation(value: str, cleaned: str) -> tuple[dict | None, str | None]:
    """A Cipher/KeyGenerator transformation: "AES/GCM/NoPadding" -> AES."""
    base = value.split("/")[0].strip()
    squashed = _squash(base)
    pqc = _pqc(squashed)
    if pqc is not None:
        return pqc, None
    if squashed.startswith(("pbkdf2", "pbewith", "pbes")):
        # A password-based KDF carries no Shor exposure, and the hash it names
        # is a KDF parameter rather than a hashing choice — reporting
        # "PBKDF2WithHmacSHA256" as SHA-256 would be a finding about the wrong
        # decision. Only the cipher half of a legacy PBE name is reportable.
        if "desede" in squashed or "tripledes" in squashed:
            return find_algorithm("3des"), None
        if "des" in squashed:
            return find_algorithm("des"), None
        if "rc4" in squashed or "arcfour" in squashed:
            return find_algorithm("rc4"), None
        if "aes" in squashed:
            return _resolve_aes("aes", cleaned)
        return None, None
    if squashed.startswith("hmac"):
        return None, "hmac"
    if squashed.startswith("aes"):
        return _resolve_aes(base, cleaned)
    if squashed.startswith("rsa"):
        return find_algorithm("rsa"), None
    if squashed.startswith("ec"):
        return find_algorithm("ecdsa"), None
    return find_algorithm(base), None


# -------------------------------------------------------------- patterns
#
# Each rule is (compiled pattern, match_type, handler). The handler receives
# the match, the text of the line it landed on, and the cleaned source, and
# returns (CRYPTO_DB entry, _SYNTHETIC key) with at most one side set;
# (None, None) drops the match.

_FIXED = {
    "rsa": lambda: find_algorithm("rsa"),
    "ecc": lambda: find_algorithm("ecdsa"),
    "dsa": lambda: find_algorithm("dsa"),
    # Ed25519 and X25519 are elliptic-curve schemes: Shor's Algorithm breaks
    # both, so they resolve to the Ed25519 entry rather than being waved
    # through as modern-and-therefore-safe.
    "ed25519": lambda: find_algorithm("ed25519"),
    "des": lambda: find_algorithm("des"),
    "3des": lambda: find_algorithm("3des"),
    "rc4": lambda: find_algorithm("rc4"),
    "md5": lambda: find_algorithm("md5"),
    "sha1": lambda: find_algorithm("sha1"),
    "sha256": lambda: find_algorithm("sha256"),
    "sha384": lambda: find_algorithm("sha384"),
    "sha512": lambda: find_algorithm("sha512"),
    "sha3": lambda: find_algorithm("sha3"),
}


def _fixed(name: str):
    return lambda match, line, cleaned: (_FIXED[name](), None)


def _synthetic(kind: str):
    return lambda match, line, cleaned: (None, kind)


def _from_group(resolver):
    return lambda match, line, cleaned: resolver(match.group(1), cleaned)


def _aes(match, line, cleaned):
    return _resolve_aes("aes", cleaned)


def _get_instance_rule(class_name: str, resolver):
    """A rule reading the string argument of `<Class>.getInstance("...")`.

    The class may be written fully qualified (javax.crypto.Cipher.getInstance),
    which the leading word boundary allows. A getInstance() called with a
    constant rather than a literal does not match: there is no algorithm name
    to read, and guessing one would be a finding about code that is not there.
    """
    return (
        re.compile(rf'\b{class_name}\s*\.\s*getInstance\s*\(\s*"([^"\\]*)"'),
        "string_arg",
        _from_group(resolver),
    )


# Bouncy Castle's lightweight API names its algorithms in class names rather
# than in getInstance strings. These are kept in their own list because a file
# that uses any of them has already said what it does, so the generic
# "org.bouncycastle.*" import note is dropped for it.
_BC_CLASS_RULES: list[tuple[re.Pattern, str, object]] = [
    (re.compile(r"\bRSA(?:KeyPairGenerator|Engine|BlindedEngine|DigestSigner"
                r"|KeyParameters|PrivateCrtKeyParameters)\b"), "pattern",
     _fixed("rsa")),
    (re.compile(r"\bEC(?:KeyPairGenerator|DSASigner|DHBasicAgreement"
                r"|DHCBasicAgreement|NamedCurveParameterSpec|KeyParameters)\b"),
     "pattern", _fixed("ecc")),
    (re.compile(r"\bDSA(?:KeyPairGenerator|Signer|ParametersGenerator)\b"),
     "pattern", _fixed("dsa")),
    (re.compile(r"\bEd25519(?:Signer|KeyPairGenerator|PrivateKeyParameters)\b"),
     "pattern", _fixed("ed25519")),
    (re.compile(r"\bX25519(?:Agreement|KeyPairGenerator|PrivateKeyParameters)\b"),
     "pattern", _fixed("ed25519")),
    (re.compile(r"\bMD5Digest\b"), "pattern", _fixed("md5")),
    (re.compile(r"\bSHA1Digest\b"), "pattern", _fixed("sha1")),
    (re.compile(r"\bSHA(?:224|256)Digest\b"), "pattern", _fixed("sha256")),
    (re.compile(r"\bSHA384Digest\b"), "pattern", _fixed("sha384")),
    (re.compile(r"\bSHA512Digest\b"), "pattern", _fixed("sha512")),
    (re.compile(r"\bSHA3Digest\b"), "pattern", _fixed("sha3")),
    (re.compile(r"\bDESedeEngine\b"), "pattern", _fixed("3des")),
    (re.compile(r"\bDESEngine\b"), "pattern", _fixed("des")),
    (re.compile(r"\bRC4Engine\b"), "pattern", _fixed("rc4")),
    (re.compile(r"\bAES(?:Fast|Light)?Engine\b"), "pattern", _aes),
]

_RULES: list[tuple[re.Pattern, str, object]] = [
    # -- JCA/JCE getInstance factories -------------------------------------
    _get_instance_rule("Cipher", _resolve_transformation),
    _get_instance_rule("KeyGenerator", _resolve_transformation),
    _get_instance_rule("SecretKeyFactory", _resolve_transformation),
    _get_instance_rule("KeyPairGenerator", _resolve_key_algorithm),
    _get_instance_rule("KeyFactory", _resolve_key_algorithm),
    _get_instance_rule("KeyAgreement", _resolve_key_algorithm),
    _get_instance_rule("AlgorithmParameterGenerator", _resolve_key_algorithm),
    _get_instance_rule("Signature", _resolve_signature),
    _get_instance_rule("MessageDigest", _resolve_digest),
    _get_instance_rule("Mac", _resolve_transformation),

    # -- key specs and curve names -----------------------------------------
    # An EC parameter spec is elliptic curve by construction, whatever curve
    # it names; the curve names are listed separately because they also turn
    # up as a bare argument to initialize().
    (re.compile(r"\bEC(?:GenParameterSpec|ParameterSpec|NamedCurveSpec)\s*\("),
     "function_call", _fixed("ecc")),
    (re.compile(r'"(?:secp\d{3}[kr]1|prime\d{3}v\d|brainpoolP\d{3}[rt]1)"'),
     "string_arg", _fixed("ecc")),
    # A standard JCA signature name is unambiguous wherever it is written, and
    # libraries routinely declare it as a constant that reaches getInstance
    # somewhere else entirely — jjwt names "SHA256withECDSA" in an enum and
    # calls getInstance(jcaName). Matching the quoted name is what makes those
    # files reportable at all.
    (re.compile(r'"((?:NONE|MD[25]|SHA-?(?:1|224|256|384|512)|SHA3-\d{3})'
                r'[wW]ith[A-Za-z0-9/_-]+)"'), "string_arg",
     _from_group(_resolve_signature)),
    (re.compile(r'"RSASSA-PSS"'), "string_arg", _fixed("rsa")),
    (re.compile(r"\bnew\s+(?:RSAKeyGenParameterSpec|DHParameterSpec"
                r"|RSAPublicKeySpec|RSAPrivateKeySpec)\s*\("), "function_call",
     lambda match, line, cleaned: (
         find_algorithm("rsa") if "RSA" in match.group(0)
         else find_algorithm("diffie-hellman"), None,
     )),
    (re.compile(r'\bnew\s+SecretKeySpec\s*\([^)\n]*,\s*"([^"\\]*)"\s*\)'),
     "string_arg", _from_group(_resolve_transformation)),

    # -- Bouncy Castle ------------------------------------------------------
    # The bare import is a note, not an algorithm: the provider covers
    # everything from RSA to ML-KEM, so what the file actually does is only
    # visible in the classes it goes on to use.
    (re.compile(r"\bimport\s+(?:static\s+)?org\.bouncycastle[\w.]*\*?\s*;"),
     "import", _synthetic("bouncycastle_module")),
    *_BC_CLASS_RULES,
]

_BC_SPECIFIC = {rule[0] for rule in _BC_CLASS_RULES}

# import beats function_call beats string_arg beats pattern when the same
# algorithm is reported more than once on one line.
_PRIORITY = {"import": 0, "function_call": 1, "string_arg": 2, "pattern": 3}


def scan_java_source(source_code: str, filename: str = "") -> list[dict]:
    """Scan Java source for crypto usage. Never raises.

    Returns findings sorted by line number, deduplicated so one algorithm is
    reported at most once per line. Empty or binary input returns [].
    """
    try:
        if not source_code or not source_code.strip():
            return []
        if "\x00" in source_code:
            return []  # binary blob, not source

        cleaned = _strip_comments(source_code)
        # _strip_comments replaces comment characters with spaces one for one,
        # so these offsets address the original source just as well.
        starts = line_starts(cleaned)
        findings: list[dict] = []
        saw_bouncycastle_class = False

        for pattern, match_type, handler in _RULES:
            for match in pattern.finditer(cleaned):
                line, col = position(starts, match.start())
                entry, synthetic = handler(
                    match, line_text(cleaned, starts, line), cleaned
                )
                identifier = match.group(0).strip()
                if entry is not None:
                    findings.append(
                        _finding(line, col, identifier, match_type, entry)
                    )
                elif synthetic is not None:
                    findings.append(
                        _synthetic_finding(line, col, identifier, match_type, synthetic)
                    )
                else:
                    continue
                if pattern in _BC_SPECIFIC:
                    saw_bouncycastle_class = True

        # A file that names a Bouncy Castle class has already answered the
        # question the generic import note asks, so the note is dropped rather
        # than reported alongside the answer. Where it does survive, it
        # survives once: "this file uses Bouncy Castle" is a fact about the
        # file, and a real Bouncy Castle file imports twenty of its packages
        # — one note per import line would bury the findings that matter.
        note = _SYNTHETIC["bouncycastle_module"]["algorithm"]
        first_note = min(
            (f["line"] for f in findings if f["algorithm"] == note), default=None
        )
        if saw_bouncycastle_class or first_note is not None:
            findings = [
                finding
                for finding in findings
                if finding["algorithm"] != note
                or (not saw_bouncycastle_class and finding["line"] == first_note)
            ]

        # Snippets come from the original source, not `cleaned`: the developer
        # should see the line as they wrote it, comments included.
        attach_snippets(findings, source_code, starts)

        best: dict[tuple[int, str], dict] = {}
        for finding in findings:
            key = (finding["line"], finding["algorithm"])
            current = best.get(key)
            if current is None or _PRIORITY.get(
                finding["match_type"], 9
            ) < _PRIORITY.get(current["match_type"], 9):
                best[key] = finding

        return sorted(best.values(), key=lambda f: (f["line"], f["col"]))
    except Exception:
        return []  # a scanner crash must never fail a repository scan


if __name__ == "__main__":
    test_source = """
package com.example.crypto;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.crypto.digests.MD5Digest;

// This is just a comment about Cipher.getInstance("RSA"), not code.

/**
 * Javadoc mentioning MessageDigest.getInstance("MD5") must not be flagged.
 */
public class Keys {
    public void generate() throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));

        Signature signer = Signature.getInstance("SHA256withECDSA");
        MessageDigest md = MessageDigest.getInstance("MD5");
        MessageDigest safe = MessageDigest.getInstance("SHA-512");

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);

        MD5Digest legacy = new MD5Digest();
    }
}
"""
    findings = scan_java_source(test_source, "Keys.java")
    assert len(findings) > 0
    algorithms = [f["algorithm"] for f in findings]
    # One from each pattern category: Cipher, KeyPairGenerator, MessageDigest,
    # Signature, the curve spec, and the Bouncy Castle lightweight API.
    assert "RSA" in algorithms
    assert "ECC" in algorithms
    assert "MD5" in algorithms
    assert "SHA-512" in algorithms
    assert "AES-256" in algorithms
    assert any("MD5Digest" in f["identifier"] for f in findings)
    # Lines 12 to 16 are the line comment and the Javadoc block: both name
    # getInstance calls, and neither is a finding.
    assert not any(12 <= f["line"] <= 16 for f in findings)
    # The specific Bouncy Castle class displaces the generic import note.
    assert not any("deeper inspection" in name for name in algorithms)
    # Every finding carries both halves the AI explain/patch endpoints need.
    for f in findings:
        assert f["code_snippet"], f
        assert f["fix_snippet"], f
    print(f"java_scanner.py self-test passed — {len(findings)} findings")
    for f in findings:
        print(f"  Line {f['line']}: {f['algorithm']} ({f['severity']}) via {f['match_type']}")

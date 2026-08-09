"""Regex-based crypto detector for JavaScript and TypeScript sources.

JS/TS has no stdlib parser to lean on the way Python's `ast` module lets
ast_scanner work, so detection is pattern based. False positives are kept
down by stripping comments and string-embedded noise with a small scanner
pass before any pattern runs, and by anchoring patterns on word boundaries.

Findings use the same shape as ast_scanner.scan_python_source so the report
layer does not care which language a file was written in.
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

    Walks the source tracking string, template-literal, and comment state so
    that `//` inside a string literal (a URL, say) is not mistaken for the
    start of a comment, and `rsa` inside a comment never reaches a pattern.
    Comment characters become spaces, so line and column numbers computed
    from the cleaned text still point at the original source.
    """
    out = list(source)
    i = 0
    length = len(source)
    state = "code"  # code | line_comment | block_comment | string | template
    quote = ""

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
                state = "block_comment"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if char in "'\"":
                state, quote = "string", char
            elif char == "`":
                state, quote = "template", char
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
        elif state in ("string", "template"):
            if char == "\\":
                i += 2  # skip the escaped character
                continue
            if char == quote:
                state, quote = "code", ""
            elif char == "\n" and state == "string":
                state, quote = "code", ""  # unterminated literal; recover
        i += 1

    return "".join(out)


# line_starts, position and line_text live in scanner_common: go_scanner needs
# the identical implementation, and so does the code_snippet capture.


# ------------------------------------------------------- synthetic findings

# Entries the crypto database does not carry because they are notes rather
# than algorithms, or symmetric constructions with no migration path.
_SYNTHETIC: dict[str, dict] = {
    "crypto_module": {
        "algorithm": "crypto (requires deeper inspection)",
        "severity": "info",
        "quantum_vulnerable": False,
        "classical_vulnerable": False,
        "attack_vector": None,
        "replacement": None,
        "replacement_reason": "The Node crypto module itself is not vulnerable; the specific ciphers, hashes, and key types used through it determine the risk.",
        "fix_snippet": "// Inspect crypto usage: createSign/createECDH are quantum-vulnerable, md5/sha1 are broken classically.",
    },
    "hmac": {
        "algorithm": "HMAC (symmetric)",
        "severity": "safe",
        "quantum_vulnerable": False,
        "classical_vulnerable": False,
        "attack_vector": None,
        "replacement": None,
        "replacement_reason": "HMAC is a symmetric construction. Grover's Algorithm only halves the effective strength of the shared key, so an adequately sized key stays quantum-safe.",
        "fix_snippet": "// HMAC (HS256/HS384/HS512) is symmetric and quantum-safe — no migration needed.",
    },
    "aes_unknown": {
        "algorithm": "AES (key length not visible)",
        "severity": "info",
        "quantum_vulnerable": False,
        "classical_vulnerable": False,
        "attack_vector": None,
        "replacement": None,
        "replacement_reason": "The key length is not declared on this line. AES-128 is weakened by Grover's Algorithm to ~64 bits; AES-256 stays quantum-safe.",
        "fix_snippet": "// Declare the key length explicitly, and prefer 256:\n// crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);",
    },
}


def _finding(
    line: int, col: int, identifier: str, match_type: str, entry: dict
) -> dict:
    """Build a finding from a CRYPTO_DB entry, preferring its JS fix snippet."""
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
        "fix_snippet": entry.get("js_fix_snippet") or entry["fix_snippet"],
        "replacement_reason": entry["replacement_reason"],
    }


def _synthetic_finding(
    line: int, col: int, identifier: str, match_type: str, kind: str
) -> dict:
    note = _SYNTHETIC[kind]
    return {"line": line, "col": col, "identifier": identifier,
            "match_type": match_type, "code_snippet": "", **note}


# ------------------------------------------------------------- resolvers

_AES_LENGTH_RE = re.compile(r"length\s*:\s*(\d{2,4})")


def _resolve_signature_alg(value: str) -> dict | None:
    """Map a signature algorithm string ('RSA-SHA256', 'ecdsa-with-SHA256').

    The asymmetric half is what carries the quantum risk, so it wins over the
    hash half — createSign('RSA-SHA256') is an RSA finding, not a SHA-256 one.
    """
    lowered = value.lower()
    if "ed25519" in lowered or "ed448" in lowered:
        return find_algorithm("ed25519")
    if "ecdsa" in lowered or lowered.startswith("ec"):
        return find_algorithm("ecdsa")
    if "rsa" in lowered:
        return find_algorithm("rsa")
    if "dsa" in lowered:
        return find_algorithm("dsa")
    return find_algorithm(value)


def _resolve_webcrypto_name(value: str, line_text: str) -> tuple[dict | None, str | None]:
    """Resolve a Web Crypto `{ name: '...' }` value.

    Returns (db_entry, synthetic_kind) — exactly one of the two is set.
    """
    lowered = value.lower()
    if lowered.startswith("aes"):
        match = _AES_LENGTH_RE.search(line_text)
        if match:
            entry = find_algorithm(f"aes-{match.group(1)}")
            if entry is not None:
                return entry, None
        return None, "aes_unknown"
    if lowered.startswith("hmac"):
        return None, "hmac"
    if "ed25519" in lowered or "ed448" in lowered:
        return find_algorithm("ed25519"), None
    if lowered.startswith("rsa"):
        return find_algorithm("rsa"), None
    if lowered in ("ecdh", "ecdsa") or lowered.startswith("ec"):
        return find_algorithm("ecdsa"), None
    return find_algorithm(value), None


def _resolve_cipher_name(value: str, line_text: str) -> tuple[dict | None, str | None]:
    entry = find_algorithm(value)
    if entry is not None:
        return entry, None
    if value.lower().startswith("aes"):
        return None, "aes_unknown"
    return None, None


# -------------------------------------------------------------- patterns
#
# Each rule is (compiled pattern, match_type, handler). The handler receives
# the match and the text of the line it landed on, and returns either a
# CRYPTO_DB entry, a _SYNTHETIC key, or None to drop the match.

_FIXED = {
    "rsa": lambda: find_algorithm("rsa"),
    "ecc": lambda: find_algorithm("ecdsa"),
    "dh": lambda: find_algorithm("diffie-hellman"),
    "ed25519": lambda: find_algorithm("ed25519"),
}


def _fixed(name: str):
    return lambda match, line_text: (_FIXED[name](), None)


def _from_group(resolver):
    return lambda match, line_text: resolver(match.group(1), line_text)


def _plain_group(match, line_text):
    return find_algorithm(match.group(1)), None


def _synthetic(kind: str):
    return lambda match, line_text: (None, kind)


_RULES: list[tuple[re.Pattern, str, object]] = [
    # -- Node crypto module ------------------------------------------------
    (re.compile(r"""require\(\s*['"]crypto['"]\s*\)"""), "import",
     _synthetic("crypto_module")),
    (re.compile(r"""\bcreate(?:Sign|Verify)\(\s*['"]([^'"]+)['"]"""), "string_arg",
     lambda m, line: (_resolve_signature_alg(m.group(1)), None)),
    (re.compile(r"\bcreateDiffieHellman(?:Group)?\s*\("), "function_call",
     _fixed("dh")),
    (re.compile(r"\bcreateECDH\s*\("), "function_call", _fixed("ecc")),
    (re.compile(r"""\bcreateHash\(\s*['"]([^'"]+)['"]"""), "string_arg",
     _plain_group),
    (re.compile(r"""\bcreateHmac\(\s*['"][^'"]+['"]"""), "function_call",
     _synthetic("hmac")),
    (re.compile(r"""\bcreate(?:Cipher|Decipher)iv?\(\s*['"]([^'"]+)['"]"""),
     "string_arg", _from_group(_resolve_cipher_name)),
    (re.compile(r"""\bgenerateKeyPair(?:Sync)?\(\s*['"]([^'"]+)['"]"""),
     "string_arg", _plain_group),

    # -- node-forge --------------------------------------------------------
    (re.compile(r"\bforge\.pki\.rsa\b"), "pattern", _fixed("rsa")),
    (re.compile(r"\bforge\.pki\.ed25519\b"), "pattern", _fixed("ed25519")),
    (re.compile(r"\bforge\.md\.(md5|sha1|sha256|sha384|sha512)\b"), "pattern",
     _plain_group),

    # -- Web Crypto API ----------------------------------------------------
    (re.compile(r"""\bname\s*:\s*['"]([A-Za-z0-9][A-Za-z0-9_-]*)['"]"""),
     "pattern", _from_group(_resolve_webcrypto_name)),
    (re.compile(r"\b(?:generateKey|importKey|deriveKey|SubtleCrypto)\b"
                r"[^\n]*?\b(RSA-OAEP|RSA-PSS|RSASSA-PKCS1-v1_5|RSA)\b"),
     "function_call", _fixed("rsa")),
    (re.compile(r"\b(?:generateKey|importKey|deriveKey|SubtleCrypto)\b"
                r"[^\n]*?\b(ECDH|ECDSA|EC)\b"),
     "function_call", _fixed("ecc")),

    # -- JOSE / JWT algorithms --------------------------------------------
    (re.compile(r"\b(?:RS|PS)(?:256|384|512)\b"), "pattern", _fixed("rsa")),
    (re.compile(r"\bES(?:256|384|512)\b"), "pattern", _fixed("ecc")),
    (re.compile(r"\bEdDSA\b"), "pattern", _fixed("ed25519")),
    (re.compile(r"\bHS(?:256|384|512)\b"), "pattern", _synthetic("hmac")),

    # -- Common libraries --------------------------------------------------
    (re.compile(r"\bnew\s+NodeRSA\s*\("), "function_call", _fixed("rsa")),
    (re.compile(r"\bRSA\.generate\s*\("), "function_call", _fixed("rsa")),
    (re.compile(r"\bjsrsasign\b"), "import", _fixed("rsa")),
    (re.compile(r"\bnoble-ed25519\b|\bnoble/ed25519\b"), "import",
     _fixed("ed25519")),
    (re.compile(r"\bnoble-secp256k1\b|\bnoble/secp256k1\b|\bsecp256k1\b"),
     "import", _fixed("ecc")),
    (re.compile(r"\belliptic\b"), "import", _fixed("ecc")),
]

# import beats function_call beats string_arg beats pattern when the same
# algorithm is reported more than once on one line.
_PRIORITY = {"import": 0, "function_call": 1, "string_arg": 2, "pattern": 3}


def scan_js_source(source_code: str, filename: str = "") -> list[dict]:
    """Scan JavaScript or TypeScript source for crypto usage. Never raises.

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

        for pattern, match_type, handler in _RULES:
            for match in pattern.finditer(cleaned):
                line, col = position(starts, match.start())
                entry, synthetic = handler(match, line_text(cleaned, starts, line))
                identifier = match.group(0).strip()
                if entry is not None:
                    findings.append(
                        _finding(line, col, identifier, match_type, entry)
                    )
                elif synthetic is not None:
                    findings.append(
                        _synthetic_finding(line, col, identifier, match_type, synthetic)
                    )

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
const crypto = require('crypto');
const { generateKeyPair } = require('crypto');
// This is just a comment about RSA
const sign = crypto.createSign('RSA-SHA256');
const hash = crypto.createHash('sha256');
const md5 = crypto.createHash('md5');
const ecdh = crypto.createECDH('prime256v1');
// jwt signing
const token = jwt.sign(payload, key, { algorithm: 'RS256' });
const safeHash = crypto.createHash('sha512');
"""
    findings = scan_js_source(test_source, "test.js")
    assert len(findings) > 0
    algorithms = [f["algorithm"] for f in findings]
    assert "RSA" in algorithms
    assert "MD5" in algorithms
    assert "ECC" in algorithms
    print(f"js_scanner.py self-test passed — {len(findings)} findings")
    for f in findings:
        print(f"  Line {f['line']}: {f['algorithm']} ({f['severity']}) via {f['match_type']}")

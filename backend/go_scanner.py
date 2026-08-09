"""Regex-based crypto detector for Go sources.

Go has no parser reachable from Python the way the stdlib `ast` module backs
ast_scanner, so detection is pattern based — the same methodology js_scanner
uses. False positives are kept down by blanking comments with a small state
machine before any pattern runs, and by anchoring patterns on word boundaries.

Findings use the same shape as ast_scanner.scan_python_source and
js_scanner.scan_js_source so the report layer does not care which language a
file was written in.
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

    Walks the source tracking interpreted string, raw string (backtick), rune
    literal, and comment state, so that `//` inside a string literal (an
    import path or URL, say) is not mistaken for the start of a comment, and
    `rsa` inside a comment never reaches a pattern. Comment characters become
    spaces, so line and column numbers computed from the cleaned text still
    point at the original source.

    String literals are left intact on purpose: Go import paths are string
    literals, and they are the primary signal this scanner reads.
    """
    out = list(source)
    i = 0
    length = len(source)
    state = "code"  # code | line_comment | block_comment | string | raw | rune
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
            if char == '"':
                state, quote = "string", char
            elif char == "`":
                state, quote = "raw", char
            elif char == "'":
                state, quote = "rune", char
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
        elif state == "raw":
            # Raw string literals process no escapes and may span lines.
            if char == quote:
                state, quote = "code", ""
        elif state in ("string", "rune"):
            if char == "\\":
                i += 2  # skip the escaped character
                continue
            if char == quote:
                state, quote = "code", ""
            elif char == "\n":
                state, quote = "code", ""  # unterminated literal; recover
        i += 1

    return "".join(out)


# line_starts, position and line_text live in scanner_common: js_scanner needs
# the identical implementation, and so does the code_snippet capture.


# ------------------------------------------------------- synthetic findings

# Entries the crypto database does not carry because they are notes rather
# than algorithms.
_SYNTHETIC: dict[str, dict] = {
    "tls_module": {
        "algorithm": "crypto/tls (requires deeper inspection)",
        "severity": "info",
        "quantum_vulnerable": False,
        "classical_vulnerable": False,
        "attack_vector": None,
        "replacement": None,
        "replacement_reason": "The crypto/tls package itself is not vulnerable; the negotiated cipher suites, certificate key types, and curve preferences configured through it determine the risk.",
        "fix_snippet": "// Inspect tls.Config: CipherSuites, CurvePreferences, and the certificate\n// key type decide whether this connection is quantum-vulnerable.",
    },
    "aes_unknown": {
        "algorithm": "AES (key length not visible)",
        "severity": "info",
        "quantum_vulnerable": False,
        "classical_vulnerable": False,
        "attack_vector": None,
        "replacement": None,
        "replacement_reason": "The key length is not declared in this file. AES-128 is weakened by Grover's Algorithm to ~64 bits; AES-256 stays quantum-safe.",
        "fix_snippet": "// Declare the key length explicitly, and prefer 32 bytes:\n// key := make([]byte, 32)  // AES-256\n// block, err := aes.NewCipher(key)",
    },
}


def _finding(
    line: int, col: int, identifier: str, match_type: str, entry: dict
) -> dict:
    """Build a finding from a CRYPTO_DB entry, preferring its Go fix snippet."""
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
        "fix_snippet": entry.get("go_fix_snippet") or entry["fix_snippet"],
        "replacement_reason": entry["replacement_reason"],
    }


def _synthetic_finding(
    line: int, col: int, identifier: str, match_type: str, kind: str
) -> dict:
    note = _SYNTHETIC[kind]
    return {"line": line, "col": col, "identifier": identifier,
            "match_type": match_type, "code_snippet": "", **note}


# -------------------------------------------------------------- AES sizing

_SIZE_ALGORITHMS = {16: "aes-128", 24: "aes-192", 32: "aes-256"}

# Key material whose length is declared in the file: `make([]byte, 32)` or
# `[32]byte`. aes.NewCipher picks AES-128/192/256 from the key length alone,
# so the length is the only thing that names the algorithm.
_KEY_SIZE_RULES = (
    re.compile(r"make\(\s*\[\]byte\s*,\s*(16|24|32)\s*[,)]"),
    re.compile(r"\[(16|24|32)\]byte\b"),
)
_INLINE_KEY_RE = re.compile(r'aes\.NewCipher\(\s*\[\]byte\(\s*"([^"\\]*)"')


def _resolve_aes(cleaned: str) -> tuple[dict | None, str | None]:
    """Resolve AES usage to a sized entry, or the 'unknown length' note.

    Returns (db_entry, synthetic_kind) — exactly one of the two is set. Only
    an unambiguous file (exactly one key length in evidence) resolves to a
    sized entry; anything else is reported for inspection.
    """
    sizes: set[int] = set()
    for pattern in _KEY_SIZE_RULES:
        for match in pattern.finditer(cleaned):
            sizes.add(int(match.group(1)))
    for match in _INLINE_KEY_RE.finditer(cleaned):
        if len(match.group(1)) in _SIZE_ALGORITHMS:
            sizes.add(len(match.group(1)))
    if len(sizes) == 1:
        entry = find_algorithm(_SIZE_ALGORITHMS[sizes.pop()])
        if entry is not None:
            return entry, None
    return None, "aes_unknown"


# -------------------------------------------------------------- patterns
#
# Each rule is (compiled pattern, match_type, handler). The handler receives
# the match, the text of the line it landed on, and the cleaned source, and
# returns (CRYPTO_DB entry, _SYNTHETIC key) with exactly one side set, or
# (None, None) to drop the match.

_FIXED = {
    "rsa": lambda: find_algorithm("rsa"),
    "ecc": lambda: find_algorithm("ecdsa"),
    "dsa": lambda: find_algorithm("dsa"),
    # Ed25519 and X25519 are elliptic-curve schemes: Shor's Algorithm breaks
    # both, so they resolve to the Ed25519 entry rather than being waved
    # through as modern-and-therefore-safe.
    "ed25519": lambda: find_algorithm("ed25519"),
    "des": lambda: find_algorithm("des"),
    "rc4": lambda: find_algorithm("rc4"),
    "md5": lambda: find_algorithm("md5"),
    "sha1": lambda: find_algorithm("sha1"),
    "sha256": lambda: find_algorithm("sha256"),
    "sha384": lambda: find_algorithm("sha384"),
    "sha512": lambda: find_algorithm("sha512"),
    "sha3": lambda: find_algorithm("sha3"),
}


def _fixed(name: str):
    return lambda match, line_text, cleaned: (_FIXED[name](), None)


def _synthetic(kind: str):
    return lambda match, line_text, cleaned: (None, kind)


def _aes(match, line_text, cleaned):
    return _resolve_aes(cleaned)


def _import_rule(path: str, handler, match_type: str = "import"):
    """A rule matching a quoted Go import path exactly."""
    return (re.compile(rf'"{re.escape(path)}"'), match_type, handler)


_RULES: list[tuple[re.Pattern, str, object]] = [
    # -- stdlib crypto imports --------------------------------------------
    _import_rule("crypto/rsa", _fixed("rsa")),
    _import_rule("crypto/dsa", _fixed("dsa")),
    _import_rule("crypto/ecdsa", _fixed("ecc")),
    _import_rule("crypto/elliptic", _fixed("ecc")),
    _import_rule("crypto/ed25519", _fixed("ed25519")),
    _import_rule("crypto/des", _fixed("des")),
    _import_rule("crypto/rc4", _fixed("rc4")),
    _import_rule("crypto/md5", _fixed("md5")),
    _import_rule("crypto/sha1", _fixed("sha1")),
    _import_rule("crypto/sha256", _fixed("sha256")),
    _import_rule("crypto/sha512", _fixed("sha512")),
    _import_rule("crypto/aes", _aes),
    _import_rule("crypto/tls", _synthetic("tls_module")),

    # -- stdlib crypto calls and types ------------------------------------
    # Package-qualified use is the signal: rsa.GenerateKey, rsa.SignPKCS1v15,
    # rsa.EncryptOAEP and *rsa.PrivateKey all commit the file to RSA.
    (re.compile(r"\brsa\.[A-Z]\w*\s*\("), "function_call", _fixed("rsa")),
    (re.compile(r"\becdsa\.[A-Z]\w*\s*\("), "function_call", _fixed("ecc")),
    (re.compile(r"\belliptic\.[A-Z]\w*\s*\("), "function_call", _fixed("ecc")),
    (re.compile(r"\bed25519\.[A-Z]\w*\s*\("), "function_call", _fixed("ed25519")),
    (re.compile(r"\bdsa\.Generate(?:Parameters|Key)\s*\("), "function_call",
     _fixed("dsa")),
    (re.compile(r"\bmd5\.(?:Sum|New)\s*\("), "function_call", _fixed("md5")),
    (re.compile(r"\bsha1\.(?:Sum|New)\s*\("), "function_call", _fixed("sha1")),
    (re.compile(r"\bsha256\.(?:Sum224|Sum256|New224|New)\s*\("), "function_call",
     _fixed("sha256")),
    (re.compile(r"\bsha512\.(?:Sum384|Sum512|New384|New512_256|New)\s*\("),
     "function_call", _fixed("sha512")),
    (re.compile(r"\bdes\.New(?:TripleDES)?Cipher\s*\("), "function_call",
     _fixed("des")),
    (re.compile(r"\brc4\.NewCipher\s*\("), "function_call", _fixed("rc4")),
    (re.compile(r"\baes\.NewCipher\s*\("), "function_call", _aes),
    (re.compile(r"\brsa\.(?:PrivateKey|PublicKey)\b"), "pattern", _fixed("rsa")),
    (re.compile(r"\becdsa\.(?:PrivateKey|PublicKey)\b"), "pattern", _fixed("ecc")),
    (re.compile(r"\bed25519\.(?:PrivateKey|PublicKey)\b"), "pattern",
     _fixed("ed25519")),
    (re.compile(r"\bdsa\.(?:PrivateKey|PublicKey|Parameters)\b"), "pattern",
     _fixed("dsa")),

    # -- crypto.Hash enum constants ---------------------------------------
    # A file can name a hash without importing its package, by using the
    # crypto.Hash enum (crypto.SHA256) and letting a blank import register
    # the implementation. golang-jwt does exactly this, so the enum is the
    # only place its hash choice appears. The bare `import "crypto"` is not
    # flagged on its own: crypto is the parent of the rsa/ecdsa/... packages
    # already covered here, so flagging it would double-report those files.
    (re.compile(r"\bcrypto\.MD5\b"), "pattern", _fixed("md5")),
    (re.compile(r"\bcrypto\.SHA1\b"), "pattern", _fixed("sha1")),
    # SHA-224 is SHA-256 truncated — same construction, same Grover exposure.
    (re.compile(r"\bcrypto\.SHA224\b"), "pattern", _fixed("sha256")),
    (re.compile(r"\bcrypto\.SHA256\b"), "pattern", _fixed("sha256")),
    (re.compile(r"\bcrypto\.SHA384\b"), "pattern", _fixed("sha384")),
    (re.compile(r"\bcrypto\.SHA512\b"), "pattern", _fixed("sha512")),
    (re.compile(r"\bcrypto\.SHA3_(?:256|512)\b"), "pattern", _fixed("sha3")),

    # -- golang.org/x/crypto ----------------------------------------------
    # Only the asymmetric packages are flagged. bcrypt (password hashing),
    # chacha20poly1305 (symmetric AEAD), and pbkdf2 (key derivation) carry no
    # Shor's exposure and are deliberately absent from this table.
    _import_rule("golang.org/x/crypto/curve25519", _fixed("ed25519")),
    _import_rule("golang.org/x/crypto/nacl/box", _fixed("ed25519")),
    (re.compile(r"\bcurve25519\.[A-Z]\w*\s*\("), "function_call",
     _fixed("ed25519")),
    (re.compile(r"\bbox\.GenerateKey\s*\("), "function_call", _fixed("ed25519")),

    # -- TLS cipher suite constants ---------------------------------------
    # ECDHE_RSA names both an ECDHE key exchange and an RSA certificate, so it
    # is listed twice: one rule reports each half.
    (re.compile(r"\b(?:tls\.)?TLS_ECDHE_RSA_WITH_\w+"), "pattern", _fixed("rsa")),
    (re.compile(r"\b(?:tls\.)?TLS_ECDHE_RSA_WITH_\w+"), "pattern", _fixed("ecc")),
    (re.compile(r"\b(?:tls\.)?TLS_ECDHE_ECDSA_WITH_\w+"), "pattern", _fixed("ecc")),
    (re.compile(r"\b(?:tls\.)?TLS_RSA_WITH_\w+"), "pattern", _fixed("rsa")),
]

# import beats function_call beats string_arg beats pattern when the same
# algorithm is reported more than once on one line.
_PRIORITY = {"import": 0, "function_call": 1, "string_arg": 2, "pattern": 3}


def scan_go_source(source_code: str, filename: str = "") -> list[dict]:
    """Scan Go source for crypto usage. Never raises.

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
package main

import (
    "crypto"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/md5"
    "crypto/sha256"
)

// This is just a comment about RSA, should not be flagged

func generateKeys() {
    priv, _ := rsa.GenerateKey(rand.Reader, 2048)
    ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    hash := md5.Sum(data)
    safeHash := sha256.Sum256(data)
    signingHash := crypto.SHA256
}
"""
    findings = scan_go_source(test_source, "test.go")
    assert len(findings) > 0
    algorithms = [f["algorithm"] for f in findings]
    assert "RSA" in algorithms
    assert "MD5" in algorithms
    assert "ECC" in algorithms
    assert "SHA-256" in algorithms
    # The crypto.Hash enum form is detected, and the bare "crypto" import
    # above it is not reported on its own.
    assert any(f["identifier"] == "crypto.SHA256" for f in findings)
    print(f"go_scanner.py self-test passed — {len(findings)} findings")
    for f in findings:
        print(f"  Line {f['line']}: {f['algorithm']} ({f['severity']}) via {f['match_type']}")

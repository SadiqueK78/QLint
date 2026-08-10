"""Regex-based crypto detector for Rust sources.

Rust has no parser reachable from Python the way the stdlib `ast` module backs
ast_scanner, so detection is pattern based — the same methodology js_scanner,
go_scanner and java_scanner use. False positives are kept down by blanking
comments and string literals with a small state machine before any pattern
runs, and by anchoring patterns on word boundaries and exact crate paths.

Where Go names its algorithms in stdlib import paths and Java names them in the
string argument to getInstance(), Rust has no crypto standard library at all:
the ecosystem is spread across crates, and the crate path *is* the algorithm
name. Three families cover almost all of it — RustCrypto (one small crate per
algorithm: rsa, p256, sha2, ...), ring (one crate, algorithms named by
SCREAMING_CASE constants), and the openssl bindings. Each family gets its own
block of rules below.

Unlike Go and Java, string literals are blanked rather than kept: no Rust crate
names its algorithm in a string, so a literal can only contribute false
positives (a doc URL, an error message, a test vector).

Findings use the same shape as ast_scanner.scan_python_source,
js_scanner.scan_js_source, go_scanner.scan_go_source and
java_scanner.scan_java_source so the report layer does not care which language
a file was written in.
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

# A raw string opener: r"..." , r#"..."# , r##"..."## , and the byte-string
# forms br"..." / br#"..."#. The hash count is captured so the matching
# terminator can be built from it.
_RAW_OPEN_RE = re.compile(r'b?r(#*)"')

# A char literal: 'a', '\n', '\x41', '\u{1F600}'. Written out in full because
# the alternative reading of a lone quote in Rust is a lifetime ('static,
# <'a>), and treating one of those as an opening quote would swallow the rest
# of the file up to the next apostrophe.
_CHAR_LIT_RE = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)|[^\\'\n])'")

_IDENT_RE = re.compile(r"\w")


def _blank(out: list[str], start: int, end: int) -> None:
    """Overwrite a span with spaces, leaving newlines where they are."""
    for index in range(start, min(end, len(out))):
        if out[index] != "\n":
            out[index] = " "


def _strip_noise(source: str) -> str:
    """Blank out comments and string literals, preserving every byte offset.

    Walks the source tracking comment, string, raw string and char literal
    state, so that `//` inside a string literal (a URL, say) is not mistaken
    for the start of a comment, and `use rsa::` inside a doc comment or a
    test-vector string never reaches a pattern. Everything blanked becomes a
    space, so line and column numbers computed from the cleaned text still
    point at the original source.

    Rust block comments nest: `/* /* */ */` is one comment, not a comment
    followed by two stray characters. The nesting depth is tracked rather than
    stopping at the first `*/`, because stopping early would hand the tail of a
    commented-out block back to the patterns as if it were live code.
    """
    out = list(source)
    i = 0
    length = len(source)

    while i < length:
        char = source[i]
        nxt = source[i + 1] if i + 1 < length else ""

        # -- line comment (covers /// and //! doc comments: same terminator)
        if char == "/" and nxt == "/":
            end = source.find("\n", i)
            end = length if end == -1 else end
            _blank(out, i, end)
            i = end
            continue

        # -- block comment, nesting-aware
        if char == "/" and nxt == "*":
            depth = 1
            j = i + 2
            while j < length and depth:
                if source[j] == "/" and j + 1 < length and source[j + 1] == "*":
                    depth += 1
                    j += 2
                elif source[j] == "*" and j + 1 < length and source[j + 1] == "/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            _blank(out, i, j)
            i = j
            continue

        # -- raw string: r"...", r#"..."#, br##"..."##
        if char in ("r", "b") and (i == 0 or not _IDENT_RE.match(source[i - 1])):
            raw = _RAW_OPEN_RE.match(source, i)
            if raw is not None:
                terminator = '"' + raw.group(1)
                end = source.find(terminator, raw.end())
                end = length if end == -1 else end + len(terminator)
                _blank(out, i, end)
                i = end
                continue

        # -- ordinary string literal, byte string included
        if char == '"' or (
            char == "b" and nxt == '"' and (i == 0 or not _IDENT_RE.match(source[i - 1]))
        ):
            j = i + (2 if char == "b" else 1)
            while j < length:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == '"':
                    j += 1
                    break
                j += 1
            _blank(out, i, j)
            i = j
            continue

        # -- char literal, or a lifetime that only looks like one
        if char == "'":
            literal = _CHAR_LIT_RE.match(source, i)
            if literal is not None:
                _blank(out, i, literal.end())
                i = literal.end()
                continue
            i += 1  # a lifetime: 'static, <'a> — nothing to blank
            continue

        i += 1

    return "".join(out)


# line_starts, position and line_text live in scanner_common: every other
# scanner needs the identical implementation, and so does the code_snippet
# capture.


# ------------------------------------------------------- synthetic findings

# Entries the crypto database does not carry because they are notes rather
# than algorithms.
_SYNTHETIC: dict[str, dict] = {
    "openssl_module": {
        "algorithm": "openssl crate (requires deeper inspection)",
        "severity": "info",
        "quantum_vulnerable": False,
        "classical_vulnerable": False,
        "attack_vector": None,
        "replacement": None,
        "replacement_reason": "The openssl bindings themselves are not vulnerable; the specific key types, ciphers, and digests reached through them determine the risk.",
        "fix_snippet": "// Inspect the openssl usage: Rsa, EcKey, and MessageDigest::md5()/sha1()\n// are the items that carry the risk.",
    },
}


def _finding(
    line: int, col: int, identifier: str, match_type: str, entry: dict
) -> dict:
    """Build a finding from a CRYPTO_DB entry, preferring its Rust fix snippet."""
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
        "fix_snippet": entry.get("rust_fix_snippet") or entry["fix_snippet"],
        "replacement_reason": entry["replacement_reason"],
    }


def _synthetic_finding(
    line: int, col: int, identifier: str, match_type: str, kind: str
) -> dict:
    note = _SYNTHETIC[kind]
    return {"line": line, "col": col, "identifier": identifier,
            "match_type": match_type, "code_snippet": "", **note}


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
    # Ed25519 is EdDSA over Curve25519: Shor's Algorithm breaks it, so it
    # resolves to the Ed25519 entry rather than being waved through as
    # modern-and-therefore-safe. X25519 is the same curve used for key
    # agreement, and resolves to ECC — the entry whose replacement guidance
    # points at ML-KEM, which is what a key exchange needs.
    "ed25519": lambda: find_algorithm("ed25519"),
    "des": lambda: find_algorithm("des"),
    "3des": lambda: find_algorithm("3des"),
    "md5": lambda: find_algorithm("md5"),
    "sha1": lambda: find_algorithm("sha1"),
    "sha256": lambda: find_algorithm("sha256"),
    "sha384": lambda: find_algorithm("sha384"),
    "sha512": lambda: find_algorithm("sha512"),
    "sha3": lambda: find_algorithm("sha3"),
    "aes-128": lambda: find_algorithm("aes-128"),
    "aes-192": lambda: find_algorithm("aes-192"),
    "aes-256": lambda: find_algorithm("aes-256"),
}

# Constructions that take a hash as a type parameter rather than as a hashing
# decision: Hmac<Sha256>, pbkdf2_hmac::<Sha256>, Hkdf<Sha384>. The hash named
# there is a parameter of a symmetric or key-derivation construction, so
# reporting it would be a finding about the wrong decision — the same reason
# java_scanner refuses to report "PBKDF2WithHmacSHA256" as SHA-256.
#
# `_` counts as a boundary here rather than as a word character, because the
# crates spell these names snake_case: `pbkdf2_hmac` has to match on both
# halves, which \b would refuse at the underscore.
_KEYED_CONSTRUCTION_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:hmac|pbkdf2|hkdf|argon2|scrypt|bcrypt)(?![A-Za-z0-9])",
    re.IGNORECASE,
)


def _fixed(name: str):
    return lambda match, line, cleaned: (_FIXED[name](), None)


def _hash(name: str):
    """A hash rule that stands down inside a keyed or key-derivation construction."""

    def handler(match, line, cleaned):
        if _KEYED_CONSTRUCTION_RE.search(line):
            return None, None
        return _FIXED[name](), None

    return handler


def _synthetic(kind: str):
    return lambda match, line, cleaned: (None, kind)


def _aes_sized(match, line, cleaned):
    """AES named by a self-sizing identifier: Aes128, AES_256_GCM, Aes192Gcm."""
    return _FIXED[f"aes-{match.group(1)}"](), None


def _use_rule(crate: str, handler):
    """A rule matching `use <crate>::` at the head of a use declaration."""
    return (re.compile(rf"\buse\s+{crate}\s*::"), "import", handler)


def _path_rule(pattern: str, handler, match_type: str = "pattern"):
    return (re.compile(pattern), match_type, handler)


# -- RustCrypto ------------------------------------------------------------
#
# One crate per algorithm, so the crate path names the algorithm outright.
# Both halves are matched: the `use` line that pulls the crate in, and the
# qualified paths and type names that commit code to it, because a workspace
# crate re-exported through a facade never writes the `use` line at all.
_RUSTCRYPTO_RULES: list[tuple[re.Pattern, str, object]] = [
    _use_rule("rsa", _fixed("rsa")),
    _path_rule(r"\brsa::\w+", _fixed("rsa")),
    _path_rule(r"\bRsa(?:PrivateKey|PublicKey)\b", _fixed("rsa")),

    _use_rule(r"(?:p256|p384|p521|k256|ecdsa|elliptic_curve)", _fixed("ecc")),
    _path_rule(r"\b(?:p256|p384|p521|k256|ecdsa|elliptic_curve)::\w+", _fixed("ecc")),
    # k256 is secp256k1; the Nist* names are the curve types p256/p384 export.
    _path_rule(r"\b(?:NistP256|NistP384|NistP521|Secp256k1)\b", _fixed("ecc")),
    _path_rule(r"\bP(?:256|384|521)\b", _fixed("ecc")),

    _use_rule("ed25519_dalek", _fixed("ed25519")),
    _path_rule(r"\bed25519(?:_dalek|_consensus)?::\w+", _fixed("ed25519")),
    _path_rule(r"\bEd25519\w*", _fixed("ed25519")),

    # X25519 is Curve25519 used for key agreement — the same discrete log
    # Shor's Algorithm solves, so it is reported, not waved through.
    _use_rule("x25519_dalek", _fixed("ecc")),
    _path_rule(r"\bx25519(?:_dalek)?::\w+", _fixed("ecc")),
    _path_rule(r"\bX25519\w*", _fixed("ecc")),

    _use_rule("dsa", _fixed("dsa")),
    _path_rule(r"\bdsa::\w+", _fixed("dsa")),
    _path_rule(r"\bDsa(?:PrivateKey|PublicKey|SigningKey|VerifyingKey)\b",
               _fixed("dsa")),

    _use_rule("md_5", _fixed("md5")),
    _path_rule(r"\bmd_5::\w+", _fixed("md5")),
    _path_rule(r"\bMd5\b", _hash("md5")),

    _use_rule("sha1", _fixed("sha1")),
    _path_rule(r"\bsha1::\w+", _fixed("sha1")),
    _path_rule(r"\bSha1\b", _hash("sha1")),

    # sha2 exports both the Grover-weakened and the quantum-safe digests, so
    # the crate import says nothing on its own — only the type name does.
    # SHA-224 is SHA-256 truncated: same construction, same Grover exposure.
    _path_rule(r"\bSha(?:224|256)\b", _hash("sha256")),
    _path_rule(r"\bSha384\b", _hash("sha384")),
    _path_rule(r"\bSha512(?:_224|_256)?\b", _hash("sha512")),

    _use_rule("sha3", _fixed("sha3")),
    _path_rule(r"\bsha3::\w+", _fixed("sha3")),
    _path_rule(r"\bSha3_\d{3}\b", _hash("sha3")),
    _path_rule(r"\bKeccak\d{3}\b", _hash("sha3")),

    _use_rule("des", _fixed("des")),
    _path_rule(r"\bdes::\w+", _fixed("des")),
    _path_rule(r"\bTdesEde[23]\b", _fixed("3des")),

    # The aes crate and the aes-gcm/aes-siv wrappers all name the key length
    # in the type: Aes128, Aes256Gcm, Aes192GcmSiv. Nothing to resolve.
    _path_rule(r"\bAes(128|192|256)\w*", _aes_sized),
]

# -- ring ------------------------------------------------------------------
#
# One crate, algorithms named by SCREAMING_CASE constants. The constants are
# matched unqualified as well as through `digest::`/`aead::`, because a `use`
# with a brace group (`use ring::digest::{SHA256, SHA384};`) puts the module
# path on the brace rather than on each name.
_RING_RULES: list[tuple[re.Pattern, str, object]] = [
    _path_rule(r"\bring::rsa::\w+", _fixed("rsa"), "import"),
    _path_rule(r"\bRsaKeyPair\b", _fixed("rsa")),
    _path_rule(r"\bRSA_(?:PKCS1|PSS)_\w+", _fixed("rsa")),

    _path_rule(r"\bECDSA_P(?:256|384|521)_\w+", _fixed("ecc")),
    _path_rule(r"\bED25519\w*", _fixed("ed25519")),

    _path_rule(r"\bSHA1_FOR_LEGACY_USE_ONLY\b", _fixed("sha1")),
    _path_rule(r"\bSHA(?:224|256)\b", _hash("sha256")),
    _path_rule(r"\bSHA384\b", _hash("sha384")),
    _path_rule(r"\bSHA512(?:_256)?\b", _hash("sha512")),

    _path_rule(r"\bAES_(128|192|256)_(?:GCM|GCM_SIV)\b", _aes_sized),
]

# -- openssl bindings ------------------------------------------------------
#
# Everything here except the bare `use openssl...;` note names an algorithm
# outright; the note is what covers a file that only reaches openssl through
# items this table does not list.
_OPENSSL_SPECIFIC_RULES: list[tuple[re.Pattern, str, object]] = [
    _path_rule(r"\bopenssl::rsa\b", _fixed("rsa"), "import"),
    _path_rule(r"\bRsa::\w+", _fixed("rsa"), "function_call"),
    _path_rule(r"\bopenssl::(?:ec|ecdsa)\b", _fixed("ecc"), "import"),
    _path_rule(r"\b(?:EcKey|EcGroup|EcPoint)::\w+", _fixed("ecc"), "function_call"),
    _path_rule(r"\bopenssl::dsa\b", _fixed("dsa"), "import"),
    _path_rule(r"\bDsa::\w+", _fixed("dsa"), "function_call"),
    _path_rule(r"\bMessageDigest::md5\b", _fixed("md5"), "function_call"),
    _path_rule(r"\bMessageDigest::sha1\b", _fixed("sha1"), "function_call"),
    _path_rule(r"\bMessageDigest::sha(?:224|256)\b", _hash("sha256"),
               "function_call"),
    _path_rule(r"\bMessageDigest::sha384\b", _hash("sha384"), "function_call"),
    _path_rule(r"\bMessageDigest::sha512\b", _hash("sha512"), "function_call"),
    _path_rule(r"\bMessageDigest::sha3_\d{3}\b", _hash("sha3"), "function_call"),
]

_RULES: list[tuple[re.Pattern, str, object]] = [
    *_RUSTCRYPTO_RULES,
    *_RING_RULES,
    *_OPENSSL_SPECIFIC_RULES,
    # The bare import is a note, not an algorithm: the openssl crate covers
    # everything from RSA to AES, so what the file actually does is only
    # visible in the items it goes on to use.
    (re.compile(r"\buse\s+openssl\b[^;\n]*;"), "import",
     _synthetic("openssl_module")),
]

_OPENSSL_SPECIFIC = {rule[0] for rule in _OPENSSL_SPECIFIC_RULES}

# import beats function_call beats string_arg beats pattern when the same
# algorithm is reported more than once on one line.
_PRIORITY = {"import": 0, "function_call": 1, "string_arg": 2, "pattern": 3}


def scan_rust_source(source_code: str, filename: str = "") -> list[dict]:
    """Scan Rust source for crypto usage. Never raises.

    Returns findings sorted by line number, deduplicated so one algorithm is
    reported at most once per line. Empty or binary input returns [].
    """
    try:
        if not source_code or not source_code.strip():
            return []
        if "\x00" in source_code:
            return []  # binary blob, not source

        cleaned = _strip_noise(source_code)
        # _strip_noise replaces comment and literal characters with spaces one
        # for one, so these offsets address the original source just as well.
        starts = line_starts(cleaned)
        findings: list[dict] = []
        saw_openssl_item = False

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
                if pattern in _OPENSSL_SPECIFIC:
                    saw_openssl_item = True

        # A file that names a specific openssl item has already answered the
        # question the generic import note asks, so the note is dropped rather
        # than reported alongside the answer. Where it does survive, it
        # survives once: "this file uses openssl" is a fact about the file, and
        # a real openssl file writes a dozen `use openssl::...` lines — one
        # note per line would bury the findings that matter.
        note = _SYNTHETIC["openssl_module"]["algorithm"]
        first_note = min(
            (f["line"] for f in findings if f["algorithm"] == note), default=None
        )
        if saw_openssl_item or first_note is not None:
            findings = [
                finding
                for finding in findings
                if finding["algorithm"] != note
                or (not saw_openssl_item and finding["line"] == first_note)
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
// Comment mentioning use rsa::RsaPrivateKey — not a finding.

/* A block comment that /* nests */ and only ends here,
   naming MessageDigest::md5() the whole way through. */

use rsa::{RsaPrivateKey, RsaPublicKey};
use p256::ecdsa::SigningKey;
use ed25519_dalek::SigningKey as EdSigningKey;
use x25519_dalek::EphemeralSecret;
use md_5::Md5;
use sha2::{Sha256, Sha512};
use sha3::Sha3_512;
use chacha20poly1305::ChaCha20Poly1305;

use ring::signature::{ECDSA_P384_SHA384_ASN1, ED25519};
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, SHA384};
use ring::aead::AES_256_GCM;

use openssl::hash::MessageDigest;
use openssl::symm::Cipher;

fn main() {
    let doc = r#"use rsa::RsaPrivateKey; inside a raw string"#;
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let digest = MessageDigest::sha1();
    let legacy = MessageDigest::md5();
}
"""
    findings = scan_rust_source(test_source, "main.rs")
    assert len(findings) > 0
    algorithms = [f["algorithm"] for f in findings]
    # One from each of the three crate families: RustCrypto, ring, openssl.
    assert "RSA" in algorithms          # RustCrypto rsa crate
    assert "ECC" in algorithms          # RustCrypto p256 / ring ECDSA_P384
    assert "Ed25519" in algorithms      # ed25519_dalek / ring ED25519
    assert "MD5" in algorithms          # openssl MessageDigest::md5()
    assert "SHA-1" in algorithms        # ring SHA1_FOR_LEGACY_USE_ONLY
    assert "SHA-256" in algorithms      # RustCrypto sha2::Sha256
    assert "SHA-384" in algorithms      # ring digest::SHA384 (safe)
    assert "AES-256" in algorithms      # ring aead::AES_256_GCM (safe)
    # Lines 2 to 5 are the line comment and the nested block comment: the
    # nesting must not end the comment early and hand the tail back as code.
    assert not any(2 <= f["line"] <= 5 for f in findings)
    # The raw string on line 24 names RSA and contributes nothing.
    assert not any(f["line"] == 24 for f in findings)
    # A specific openssl item displaces the generic import note.
    assert not any("deeper inspection" in name for name in algorithms)
    # chacha20poly1305 is a symmetric AEAD — deliberately not reported.
    assert "ChaCha20" not in " ".join(algorithms)
    # Every finding carries both halves the AI explain/patch endpoints need.
    for f in findings:
        assert f["code_snippet"], f
        assert f["fix_snippet"], f
    print(f"rust_scanner.py self-test passed — {len(findings)} findings")
    for f in findings:
        print(f"  Line {f['line']}: {f['algorithm']} ({f['severity']}) via {f['match_type']}")

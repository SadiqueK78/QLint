"""Tests for go_scanner.scan_go_source (Go detection)."""

import pytest

from go_scanner import scan_go_source

REQUIRED_FIELDS = {
    "line",
    "col",
    "identifier",
    "match_type",
    "algorithm",
    "severity",
    "quantum_vulnerable",
    "classical_vulnerable",
    "attack_vector",
    "replacement",
    "fix_snippet",
    "replacement_reason",
}


def algorithms(source: str) -> list[str]:
    return [f["algorithm"] for f in scan_go_source(source, "test.go")]


class TestEmptyAndInvalidInput:
    @pytest.mark.parametrize("source", ["", "   ", "\n\n\t\n"])
    def test_empty_input_returns_empty_list(self, source):
        assert scan_go_source(source, "test.go") == []

    def test_binary_input_returns_empty_without_raising(self):
        assert scan_go_source("\x00\x01\x02binary\x00garbage", "blob.go") == []

    def test_unparseable_go_does_not_raise(self):
        # Deliberately broken syntax — a regex scanner still must not crash.
        source = "func ( { ] package := := `unterminated"
        assert isinstance(scan_go_source(source, "broken.go"), list)

    def test_source_with_no_crypto_returns_empty(self):
        source = "package main\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n"
        assert scan_go_source(source, "math.go") == []


class TestCommentHandling:
    def test_comment_only_file_returns_no_findings(self):
        source = '// import "crypto/rsa"\n// md5.Sum(data)\n// ecdsa.GenerateKey()\n'
        assert scan_go_source(source, "notes.go") == []

    def test_block_comments_are_ignored(self):
        source = '/*\n  rsa.GenerateKey(rand.Reader, 2048)\n  md5.Sum(data)\n*/\nvar x = 1'
        assert scan_go_source(source, "notes.go") == []

    def test_trailing_comment_does_not_hide_real_code(self):
        source = "h := md5.Sum(data) // legacy md5 hash\n"
        assert algorithms(source).count("MD5") == 1

    def test_import_path_in_a_string_is_not_treated_as_a_comment(self):
        # The `//` inside a URL must not start a line comment.
        source = 'const doc = "https://example.com/rsa"\nk, _ := rsa.GenerateKey(r, 2048)'
        found = scan_go_source(source, "u.go")
        assert "RSA" in [f["algorithm"] for f in found]
        assert all(f["line"] == 2 for f in found)


class TestStdlibImports:
    @pytest.mark.parametrize(
        "path,algorithm",
        [
            ("crypto/rsa", "RSA"),
            ("crypto/dsa", "DSA"),
            ("crypto/ecdsa", "ECC"),
            ("crypto/elliptic", "ECC"),
            ("crypto/des", "DES"),
            ("crypto/rc4", "RC4"),
            ("crypto/md5", "MD5"),
            ("crypto/sha1", "SHA-1"),
            ("crypto/sha256", "SHA-256"),
            ("crypto/sha512", "SHA-512"),
        ],
    )
    def test_stdlib_crypto_imports(self, path, algorithm):
        found = scan_go_source(f'import (\n\t"{path}"\n)', "a.go")
        assert [f["algorithm"] for f in found] == [algorithm]
        assert found[0]["match_type"] == "import"

    def test_crypto_tls_is_flagged_for_deeper_inspection(self):
        found = scan_go_source('import "crypto/tls"', "a.go")
        assert len(found) == 1
        assert found[0]["severity"] == "info"
        assert found[0]["match_type"] == "import"
        assert "deeper inspection" in found[0]["algorithm"]

    def test_aes_key_length_is_read_from_the_file_when_visible(self):
        source = 'import "crypto/aes"\n\nkey := make([]byte, 32)\nb, _ := aes.NewCipher(key)'
        assert "AES-256" in algorithms(source)
        source_128 = 'import "crypto/aes"\n\nkey := make([]byte, 16)\nb, _ := aes.NewCipher(key)'
        assert "AES-128" in algorithms(source_128)

    def test_aes_without_a_visible_key_length_is_flagged_for_inspection(self):
        found = scan_go_source('import "crypto/aes"', "a.go")
        assert found[0]["severity"] == "info"
        assert "not visible" in found[0]["algorithm"]


class TestStdlibFunctionCalls:
    def test_detects_rsa_generate_key(self):
        assert "RSA" in algorithms("priv, _ := rsa.GenerateKey(rand.Reader, 2048)")

    def test_detects_ecdsa_generate_key(self):
        source = "priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)"
        assert "ECC" in algorithms(source)

    def test_detects_dsa_generate_parameters(self):
        source = "dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256)"
        assert "DSA" in algorithms(source)

    def test_ecdsa_call_is_not_reported_as_dsa(self):
        assert algorithms("ecdsa.GenerateKey(elliptic.P256(), rand.Reader)") == ["ECC"]

    @pytest.mark.parametrize("call", ["md5.Sum(data)", "md5.New()"])
    def test_detects_md5(self, call):
        assert "MD5" in algorithms(f"h := {call}")

    @pytest.mark.parametrize("call", ["sha1.Sum(data)", "sha1.New()"])
    def test_detects_sha1(self, call):
        assert "SHA-1" in algorithms(f"h := {call}")

    def test_detects_rsa_signing_and_encryption_calls(self):
        source = (
            "sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed)\n"
            "ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)\n"
        )
        assert algorithms(source).count("RSA") == 2

    def test_detects_key_types_used_without_a_call(self):
        assert "RSA" in algorithms("func sign(key *rsa.PrivateKey) []byte {")
        assert "ECC" in algorithms("func verify(key *ecdsa.PublicKey) bool {")


class TestCryptoHashEnum:
    """The crypto.Hash constant form: `Hash: crypto.SHA256`, no sha256 import."""

    def test_detects_sha256_constant(self):
        found = scan_go_source("m := &SigningMethodRSA{Hash: crypto.SHA256}", "a.go")
        assert [f["algorithm"] for f in found] == ["SHA-256"]
        assert found[0]["match_type"] == "pattern"
        assert found[0]["severity"] == "warning"

    def test_detects_md5_constant(self):
        assert "MD5" in algorithms("h := crypto.MD5.New()")

    def test_detects_sha1_constant(self):
        assert "SHA-1" in algorithms("if method.Hash == crypto.SHA1 {")

    def test_sha224_is_treated_as_the_sha256_family(self):
        found = scan_go_source("h := crypto.SHA224", "a.go")
        assert [f["algorithm"] for f in found] == ["SHA-256"]
        assert found[0]["severity"] == "warning"

    def test_sha512_constant_is_not_critical(self):
        found = scan_go_source("h := crypto.SHA512", "a.go")
        assert [f["algorithm"] for f in found] == ["SHA-512"]
        assert found[0]["severity"] == "safe"
        assert found[0]["quantum_vulnerable"] is False

    def test_sha384_constant_is_safe(self):
        found = scan_go_source("h := crypto.SHA384", "a.go")
        assert [f["algorithm"] for f in found] == ["SHA-384"]
        assert found[0]["severity"] == "safe"

    @pytest.mark.parametrize("constant", ["crypto.SHA3_256", "crypto.SHA3_512"])
    def test_sha3_constants_are_safe(self, constant):
        found = scan_go_source(f"h := {constant}", "a.go")
        assert [f["algorithm"] for f in found] == ["SHA-3"]
        assert found[0]["severity"] == "safe"

    def test_bare_crypto_import_alone_is_not_flagged(self):
        # "crypto" is the parent of crypto/rsa and friends; flagging the bare
        # import would double-report every file that imports a subpackage.
        assert scan_go_source('import "crypto"', "a.go") == []

    def test_bare_crypto_import_does_not_duplicate_subpackage_findings(self):
        source = 'import (\n\t"crypto"\n\t"crypto/rsa"\n)\n'
        found = scan_go_source(source, "a.go")
        assert [f["algorithm"] for f in found] == ["RSA"]
        assert found[0]["line"] == 3

    def test_word_boundaries_prevent_partial_matches(self):
        assert scan_go_source("h := crypto.SHA256something", "a.go") == []
        assert scan_go_source("h := mycrypto.SHA256", "a.go") == []

    def test_enum_constant_does_not_displace_a_key_finding_on_the_same_line(self):
        source = "SigningMethodRS256 = &SigningMethodRSA{key: *rsa.PublicKey, Hash: crypto.SHA256}"
        assert sorted(algorithms(source)) == ["RSA", "SHA-256"]


class TestEllipticCurveIsNeverTreatedAsSafe:
    def test_ed25519_import_is_critical(self):
        # Ed25519 is EdDSA over Curve25519, so Shor's Algorithm breaks it.
        found = scan_go_source('import "crypto/ed25519"', "a.go")
        assert len(found) == 1
        assert found[0]["severity"] == "critical"
        assert found[0]["quantum_vulnerable"] is True
        assert found[0]["attack_vector"] == "Shor's Algorithm"

    def test_ed25519_generate_key_is_critical(self):
        found = scan_go_source("pub, priv, _ := ed25519.GenerateKey(rand.Reader)", "a.go")
        assert found[0]["severity"] == "critical"
        assert found[0]["quantum_vulnerable"] is True

    def test_curve25519_import_is_critical(self):
        # X25519 is elliptic-curve Diffie-Hellman — Shor's breaks it too.
        found = scan_go_source('import "golang.org/x/crypto/curve25519"', "a.go")
        assert len(found) == 1
        assert found[0]["severity"] == "critical"
        assert found[0]["quantum_vulnerable"] is True

    def test_nacl_box_import_is_critical(self):
        # nacl/box is Curve25519 under the hood.
        found = scan_go_source('import "golang.org/x/crypto/nacl/box"', "a.go")
        assert len(found) == 1
        assert found[0]["severity"] == "critical"


class TestSafePackagesAreNotFlagged:
    def test_bcrypt_import_is_not_flagged(self):
        # Password hashing, not asymmetric crypto — no Shor's exposure.
        assert scan_go_source('import "golang.org/x/crypto/bcrypt"', "a.go") == []

    def test_bcrypt_usage_is_not_flagged(self):
        source = (
            'import "golang.org/x/crypto/bcrypt"\n\n'
            "hash, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)\n"
        )
        assert scan_go_source(source, "a.go") == []

    def test_chacha20poly1305_import_is_not_flagged(self):
        source = 'import "golang.org/x/crypto/chacha20poly1305"'
        assert scan_go_source(source, "a.go") == []

    def test_pbkdf2_import_is_not_flagged(self):
        assert scan_go_source('import "golang.org/x/crypto/pbkdf2"', "a.go") == []

    def test_nacl_secretbox_is_not_confused_with_nacl_box(self):
        # secretbox is symmetric; only nacl/box carries the Curve25519 risk.
        assert scan_go_source('import "golang.org/x/crypto/nacl/secretbox"', "a.go") == []


class TestSeverityClassification:
    def test_sha512_is_not_critical(self):
        found = scan_go_source('import "crypto/sha512"', "a.go")
        assert [f["algorithm"] for f in found] == ["SHA-512"]
        assert found[0]["severity"] == "safe"
        assert found[0]["quantum_vulnerable"] is False

    def test_sha256_is_a_warning_not_critical(self):
        found = scan_go_source('import "crypto/sha256"', "a.go")
        assert found[0]["severity"] == "warning"


class TestTLSCipherSuites:
    def test_rsa_cipher_suite_maps_to_rsa(self):
        assert algorithms("tls.TLS_RSA_WITH_AES_128_CBC_SHA,") == ["RSA"]

    def test_ecdhe_rsa_cipher_suite_reports_both_halves(self):
        found = algorithms("tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,")
        assert sorted(found) == ["ECC", "RSA"]

    def test_ecdhe_ecdsa_cipher_suite_maps_to_ecc(self):
        assert algorithms("tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,") == ["ECC"]


class TestResultShape:
    def test_every_finding_has_the_required_fields(self):
        source = (
            'import (\n'
            '\t"crypto/rsa"\n'
            '\t"crypto/tls"\n'
            ')\n'
            "priv, _ := rsa.GenerateKey(rand.Reader, 2048)\n"
            "h := md5.Sum(data)\n"
        )
        found = scan_go_source(source, "a.go")
        assert found
        for finding in found:
            assert REQUIRED_FIELDS <= set(finding)
            assert isinstance(finding["line"], int)
            assert isinstance(finding["col"], int)
            assert finding["match_type"] in {
                "import",
                "function_call",
                "string_arg",
                "pattern",
            }

    def test_results_are_sorted_by_line_number(self):
        source = (
            "package main\n"
            "h := md5.Sum(data)\n"
            "x := 2\n"
            "priv, _ := rsa.GenerateKey(rand.Reader, 2048)\n"
            "ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)\n"
        )
        lines = [f["line"] for f in scan_go_source(source, "a.go")]
        assert lines == sorted(lines)
        assert lines == [2, 4, 5]

    def test_same_algorithm_is_reported_once_per_line(self):
        source = "a, b := md5.Sum(x), md5.Sum(y)"
        assert algorithms(source).count("MD5") == 1

    def test_go_fix_snippet_is_used_for_go(self):
        found = scan_go_source("priv, _ := rsa.GenerateKey(rand.Reader, 2048)", "a.go")
        assert "mlkem768" in found[0]["fix_snippet"]
        assert "import oqs" not in found[0]["fix_snippet"]


class TestRealisticFile:
    def test_full_file_with_mixed_crypto(self):
        source = """
package signer

import (
\t"crypto/ecdsa"
\t"crypto/elliptic"
\t"crypto/rand"
\t"crypto/rsa"
\t"crypto/sha256"

\t"golang.org/x/crypto/bcrypt"
)

// RSA keys are generated here — this comment must not be flagged.

func NewRSAKey() (*rsa.PrivateKey, error) {
\treturn rsa.GenerateKey(rand.Reader, 4096)
}

func NewECKey() (*ecdsa.PrivateKey, error) {
\treturn ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func HashPassword(pw []byte) ([]byte, error) {
\treturn bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
}

func Digest(data []byte) [32]byte {
\treturn sha256.Sum256(data)
}
"""
        found = scan_go_source(source, "signer.go")
        names = [f["algorithm"] for f in found]
        assert "RSA" in names
        assert "ECC" in names
        assert "SHA-256" in names
        # bcrypt must stay out of the report entirely.
        assert not any("crypt" in name.lower() for name in names)
        assert [f["line"] for f in found] == sorted(f["line"] for f in found)


class TestElGamal:
    """Go's stdlib has no ElGamal; the OpenPGP packages are the real surface.

    golang.org/x/crypto/openpgp is frozen and deprecated but vendored into a
    great many trees, and ProtonMail's fork is what the current PGP tooling
    (go-git among others) depends on.
    """

    def test_detects_the_x_crypto_openpgp_import(self):
        source = 'import "golang.org/x/crypto/openpgp/elgamal"'
        found = scan_go_source(source, "a.go")
        assert [f["algorithm"] for f in found] == ["ElGamal"]
        assert found[0]["severity"] == "critical"
        assert found[0]["match_type"] == "import"
        assert found[0]["attack_vector"] == "Shor's Algorithm"

    def test_detects_the_protonmail_fork_import(self):
        source = 'import "github.com/ProtonMail/go-crypto/openpgp/elgamal"'
        assert [f["algorithm"] for f in scan_go_source(source, "a.go")] == ["ElGamal"]

    def test_detects_package_qualified_calls(self):
        source = "c1, c2, err := elgamal.Encrypt(rand.Reader, pub, message)"
        found = scan_go_source(source, "a.go")
        assert [f["algorithm"] for f in found] == ["ElGamal"]
        assert found[0]["match_type"] == "function_call"

    def test_detects_key_types(self):
        source = "func load() (*elgamal.PrivateKey, error) { return nil, nil }"
        assert [f["algorithm"] for f in scan_go_source(source, "a.go")] == ["ElGamal"]

    def test_elgamal_in_a_comment_is_not_a_finding(self):
        source = "// elgamal.Encrypt was removed here\nx := 1\n"
        assert scan_go_source(source, "a.go") == []

    def test_finding_carries_both_snippets(self):
        source = 'import "golang.org/x/crypto/openpgp/elgamal"'
        found = scan_go_source(source, "a.go")
        assert found[0]["code_snippet"]
        assert "mlkem768" in found[0]["fix_snippet"]

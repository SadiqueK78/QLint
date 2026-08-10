"""Tests for rust_scanner.scan_rust_source (Rust detection)."""

import pytest

from rust_scanner import scan_rust_source

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
    "code_snippet",
    "fix_snippet",
    "replacement_reason",
}


def algorithms(source: str) -> list[str]:
    return [f["algorithm"] for f in scan_rust_source(source, "lib.rs")]


class TestEmptyAndInvalidInput:
    @pytest.mark.parametrize("source", ["", "   ", "\n\n\t\n"])
    def test_empty_input_returns_empty_list(self, source):
        assert scan_rust_source(source, "lib.rs") == []

    def test_binary_input_returns_empty_without_raising(self):
        assert scan_rust_source("\x00\x01\x02binary\x00garbage", "blob.rs") == []

    def test_unparseable_rust_does_not_raise(self):
        # Deliberately broken syntax — a regex scanner still must not crash.
        source = 'fn ( { ] impl for "unterminated /* r#"'
        assert isinstance(scan_rust_source(source, "broken.rs"), list)

    def test_source_with_no_crypto_returns_empty(self):
        source = (
            "pub fn add(a: i32, b: i32) -> i32 {\n"
            "    a + b\n"
            "}\n"
        )
        assert scan_rust_source(source, "math.rs") == []

    def test_lifetimes_do_not_swallow_the_rest_of_the_file(self):
        # A lone `'` opens a lifetime, not a char literal. Treating 'a as an
        # opening quote would blank everything up to the next apostrophe.
        source = (
            "struct Holder<'a> { name: &'a str }\n"
            "fn build<'a>(s: &'static str) -> Holder<'a> { todo!() }\n"
            "use md_5::Md5;\n"
        )
        found = scan_rust_source(source, "lifetime.rs")
        assert [f["algorithm"] for f in found] == ["MD5"]
        assert found[0]["line"] == 3


class TestCommentHandling:
    def test_line_comment_only_file_returns_no_findings(self):
        source = (
            "// use rsa::RsaPrivateKey;\n"
            "/// Doc comment naming ed25519_dalek::SigningKey.\n"
            "//! Module doc naming MessageDigest::md5().\n"
        )
        assert scan_rust_source(source, "notes.rs") == []

    def test_block_comment_only_file_returns_no_findings(self):
        source = (
            "/*\n"
            "  use rsa::RsaPrivateKey;\n"
            "  use md_5::Md5;\n"
            "*/\n"
            "let x = 1;\n"
        )
        assert scan_rust_source(source, "notes.rs") == []

    def test_nested_block_comments_do_not_terminate_early(self):
        # `/* /* */ */` is one comment. Stopping at the first `*/` would hand
        # the tail back to the patterns as if it were live code.
        source = (
            "/* outer /* inner */ use rsa::RsaPrivateKey; */\n"
            "let x = 1;\n"
        )
        assert scan_rust_source(source, "nested.rs") == []

    def test_deeply_nested_block_comment_still_closes_at_the_right_place(self):
        source = (
            "/* a /* b /* c */ d */ use md_5::Md5; */\n"
            "use sha1::Sha1;\n"
        )
        found = scan_rust_source(source, "nested.rs")
        assert [f["algorithm"] for f in found] == ["SHA-1"]
        assert found[0]["line"] == 2

    def test_code_after_a_nested_block_comment_is_still_scanned(self):
        source = (
            "/* /* nested */ */\n"
            "use rsa::RsaPrivateKey;\n"
        )
        found = scan_rust_source(source, "nested.rs")
        assert [f["algorithm"] for f in found] == ["RSA"]
        assert found[0]["line"] == 2

    def test_trailing_comment_does_not_hide_real_code(self):
        source = "use md_5::Md5; // legacy digest\n"
        assert algorithms(source).count("MD5") == 1

    def test_url_in_a_string_is_not_treated_as_a_comment(self):
        source = (
            'let doc = "https://example.com/rsa";\n'
            "use md_5::Md5;\n"
        )
        found = scan_rust_source(source, "url.rs")
        assert [f["algorithm"] for f in found] == ["MD5"]
        assert found[0]["line"] == 2


class TestStringLiterals:
    def test_algorithm_names_inside_a_string_are_not_flagged(self):
        source = 'let note = "use rsa::RsaPrivateKey and md_5::Md5";\n'
        assert scan_rust_source(source, "s.rs") == []

    @pytest.mark.parametrize(
        "literal",
        [
            'r"use rsa::RsaPrivateKey;"',
            'r#"use rsa::RsaPrivateKey;"#',
            'r##"use rsa::RsaPrivateKey; "# still inside"##',
            'br#"use rsa::RsaPrivateKey;"#',
        ],
    )
    def test_raw_strings_are_excluded_from_matching(self, literal):
        assert scan_rust_source(f"let doc = {literal};\n", "raw.rs") == []

    def test_a_raw_string_does_not_swallow_the_code_after_it(self):
        source = (
            'let doc = r#"use rsa::RsaPrivateKey;"#;\n'
            "use md_5::Md5;\n"
        )
        found = scan_rust_source(source, "raw.rs")
        assert [f["algorithm"] for f in found] == ["MD5"]
        assert found[0]["line"] == 2

    def test_a_hash_inside_a_single_hash_raw_string_does_not_end_it_early(self):
        # The terminator for r#"..."# is `"#`, so a bare `#` is just content.
        source = 'let doc = r#"# heading, use rsa::RsaPrivateKey"#;\n'
        assert scan_rust_source(source, "raw.rs") == []


class TestRustCryptoFamily:
    @pytest.mark.parametrize(
        "source",
        [
            "use rsa::{RsaPrivateKey, RsaPublicKey};",
            "use rsa::RsaPrivateKey;",
            "let key = RsaPrivateKey::new(&mut rng, 2048)?;",
            "fn load() -> rsa::RsaPublicKey { todo!() }",
        ],
    )
    def test_detects_rsa(self, source):
        found = scan_rust_source(source, "a.rs")
        assert [f["algorithm"] for f in found] == ["RSA"]
        assert found[0]["severity"] == "critical"
        assert found[0]["attack_vector"] == "Shor's Algorithm"

    @pytest.mark.parametrize(
        "source",
        [
            "use p256::ecdsa::SigningKey;",
            "use p384::SecretKey;",
            "use k256::Secp256k1;",
            "let key = p256::SecretKey::random(&mut rng);",
            "type Curve = NistP384;",
            "fn sign(k: &SigningKey<P256>) {}",
        ],
    )
    def test_detects_ecc(self, source):
        found = scan_rust_source(source, "a.rs")
        assert "ECC" in [f["algorithm"] for f in found]
        assert found[0]["severity"] == "critical"

    def test_k256_is_secp256k1_and_resolves_to_ecc(self):
        assert algorithms("use k256::ecdsa::Signature;") == ["ECC"]

    def test_detects_ed25519_as_critical_not_safe(self):
        # Shor's Algorithm breaks EdDSA over Curve25519 despite it being
        # strong classically — it must not be waved through as modern.
        source = "use ed25519_dalek::{SigningKey, Signer};"
        found = scan_rust_source(source, "a.rs")
        assert [f["algorithm"] for f in found] == ["Ed25519"]
        assert found[0]["severity"] == "critical"
        assert found[0]["quantum_vulnerable"] is True
        assert found[0]["attack_vector"] == "Shor's Algorithm"

    def test_ed25519_type_names_are_detected_without_the_use_line(self):
        assert algorithms("let key: Ed25519KeyPair = load();") == ["Ed25519"]

    def test_detects_x25519_as_critical(self):
        # X25519 is Curve25519 used for key agreement: the same discrete log
        # Shor's Algorithm solves. It resolves to ECC, whose replacement
        # guidance points at ML-KEM — what a key exchange actually needs.
        source = "use x25519_dalek::{EphemeralSecret, PublicKey};"
        found = scan_rust_source(source, "a.rs")
        assert [f["algorithm"] for f in found] == ["ECC"]
        assert found[0]["severity"] == "critical"
        assert found[0]["quantum_vulnerable"] is True

    def test_detects_dsa(self):
        found = scan_rust_source("use dsa::{SigningKey, Components};", "a.rs")
        assert [f["algorithm"] for f in found] == ["DSA"]
        assert found[0]["severity"] == "critical"

    def test_dsa_key_types_are_detected(self):
        assert algorithms("let k: DsaPrivateKey = load();") == ["DSA"]

    def test_ecdsa_crate_is_not_reported_as_dsa(self):
        assert algorithms("use ecdsa::SigningKey;") == ["ECC"]

    def test_detects_des_and_triple_des(self):
        found = scan_rust_source("use des::{Des, TdesEde3};", "a.rs")
        names = {f["algorithm"] for f in found}
        assert names == {"DES", "3DES"}
        assert all(f["severity"] == "critical" for f in found)

    @pytest.mark.parametrize(
        "source,algorithm",
        [
            ("use md_5::{Md5, Digest};", "MD5"),
            ("let d = Md5::digest(data);", "MD5"),
            ("use sha1::{Sha1, Digest};", "SHA-1"),
            ("let d = Sha1::digest(data);", "SHA-1"),
        ],
    )
    def test_detects_broken_hashes(self, source, algorithm):
        found = scan_rust_source(source, "a.rs")
        assert [f["algorithm"] for f in found] == [algorithm]
        assert found[0]["severity"] == "critical"

    def test_sha256_is_a_warning_not_critical(self):
        found = scan_rust_source("use sha2::{Sha256, Digest};", "a.rs")
        assert [f["algorithm"] for f in found] == ["SHA-256"]
        assert found[0]["severity"] == "warning"
        assert found[0]["attack_vector"] == "Grover's Algorithm"

    @pytest.mark.parametrize(
        "source,algorithm",
        [
            ("use sha2::Sha384;", "SHA-384"),
            ("use sha2::{Sha384, Sha512};", "SHA-512"),
            ("use sha3::Sha3_512;", "SHA-3"),
            ("let d = Sha3_256::digest(data);", "SHA-3"),
            ("let d = Keccak256::digest(data);", "SHA-3"),
        ],
    )
    def test_strong_digests_are_safe_not_critical(self, source, algorithm):
        found = scan_rust_source(source, "a.rs")
        names = [f["algorithm"] for f in found]
        assert algorithm in names
        entry = next(f for f in found if f["algorithm"] == algorithm)
        assert entry["severity"] == "safe"
        assert entry["quantum_vulnerable"] is False

    def test_sha2_crate_import_alone_says_nothing(self):
        # sha2 exports both the Grover-weakened and the quantum-safe digests,
        # so the crate name on its own does not name an algorithm.
        assert scan_rust_source("use sha2::Digest;", "a.rs") == []

    def test_detects_aes_key_length_from_the_type_name(self):
        found = scan_rust_source("use aes::Aes128;\nuse aes_gcm::Aes256Gcm;", "a.rs")
        assert [f["algorithm"] for f in found] == ["AES-128", "AES-256"]
        assert found[0]["severity"] == "warning"
        assert found[1]["severity"] == "safe"


class TestRingCrate:
    def test_detects_rsa_via_ring(self):
        found = scan_rust_source("use ring::rsa::KeyPair;", "a.rs")
        assert [f["algorithm"] for f in found] == ["RSA"]
        assert found[0]["severity"] == "critical"

    def test_detects_rsa_key_pair_type(self):
        assert algorithms("use ring::signature::RsaKeyPair;") == ["RSA"]

    @pytest.mark.parametrize(
        "constant", ["ECDSA_P256_SHA256_ASN1", "ECDSA_P384_SHA384_ASN1"]
    )
    def test_detects_ecc_via_ring_signature_constants(self, constant):
        source = f"use ring::signature::{constant};"
        found = scan_rust_source(source, "a.rs")
        assert [f["algorithm"] for f in found] == ["ECC"]
        assert found[0]["severity"] == "critical"

    def test_detects_ed25519_via_ring_constant(self):
        found = scan_rust_source("use ring::signature::ED25519;", "a.rs")
        assert [f["algorithm"] for f in found] == ["Ed25519"]
        assert found[0]["severity"] == "critical"

    def test_detects_sha1_via_ring_digest(self):
        found = scan_rust_source(
            "use ring::digest::SHA1_FOR_LEGACY_USE_ONLY;", "a.rs"
        )
        assert [f["algorithm"] for f in found] == ["SHA-1"]
        assert found[0]["severity"] == "critical"

    def test_detects_sha256_via_ring_digest(self):
        found = scan_rust_source("let alg = &ring::digest::SHA256;", "a.rs")
        assert [f["algorithm"] for f in found] == ["SHA-256"]
        assert found[0]["severity"] == "warning"

    @pytest.mark.parametrize(
        "constant,algorithm", [("SHA384", "SHA-384"), ("SHA512", "SHA-512")]
    )
    def test_ring_strong_digests_are_safe(self, constant, algorithm):
        found = scan_rust_source(f"use ring::digest::{constant};", "a.rs")
        assert [f["algorithm"] for f in found] == [algorithm]
        assert found[0]["severity"] == "safe"

    def test_brace_grouped_digest_imports_are_still_resolved(self):
        # `use ring::digest::{SHA256, SHA384};` puts the module path on the
        # brace, not on each name, so the constants must match unqualified.
        source = "use ring::digest::{SHA256, SHA384};"
        assert sorted(algorithms(source)) == ["SHA-256", "SHA-384"]

    def test_aes_128_gcm_is_a_warning(self):
        found = scan_rust_source("use ring::aead::AES_128_GCM;", "a.rs")
        assert [f["algorithm"] for f in found] == ["AES-128"]
        assert found[0]["severity"] == "warning"
        assert found[0]["attack_vector"] == "Grover's Algorithm"

    def test_aes_256_gcm_is_safe(self):
        found = scan_rust_source("use ring::aead::AES_256_GCM;", "a.rs")
        assert [f["algorithm"] for f in found] == ["AES-256"]
        assert found[0]["severity"] == "safe"
        assert found[0]["quantum_vulnerable"] is False


class TestOpenSSLCrate:
    def test_detects_rsa(self):
        source = "use openssl::rsa::Rsa;\nlet key = Rsa::generate(2048)?;"
        found = scan_rust_source(source, "a.rs")
        assert {f["algorithm"] for f in found} == {"RSA"}
        assert found[0]["severity"] == "critical"

    def test_detects_ecc(self):
        source = "use openssl::ec::EcKey;\nlet key = EcKey::generate(&group)?;"
        found = scan_rust_source(source, "a.rs")
        assert {f["algorithm"] for f in found} == {"ECC"}

    @pytest.mark.parametrize(
        "call,algorithm",
        [
            ("MessageDigest::md5()", "MD5"),
            ("MessageDigest::sha1()", "SHA-1"),
            ("MessageDigest::sha256()", "SHA-256"),
        ],
    )
    def test_detects_message_digest_algorithms(self, call, algorithm):
        found = scan_rust_source(f"let md = {call};", "a.rs")
        assert [f["algorithm"] for f in found] == [algorithm]
        assert found[0]["match_type"] == "function_call"

    def test_message_digest_sha512_is_safe(self):
        found = scan_rust_source("let md = MessageDigest::sha512();", "a.rs")
        assert [f["algorithm"] for f in found] == ["SHA-512"]
        assert found[0]["severity"] == "safe"

    def test_bare_import_alone_is_an_info_note(self):
        found = scan_rust_source("use openssl::symm::Cipher;", "a.rs")
        assert len(found) == 1
        assert found[0]["severity"] == "info"
        assert found[0]["match_type"] == "import"
        assert "deeper inspection" in found[0]["algorithm"]

    def test_the_note_is_reported_once_per_file_not_once_per_line(self):
        # A real openssl file writes a dozen `use openssl::...` lines; a dozen
        # copies of the same note would bury the findings that matter. This is
        # the same per-file dedup the Bouncy Castle note needed in F26.
        source = (
            "use openssl::symm::Cipher;\n"
            "use openssl::pkey::PKey;\n"
            "use openssl::sign::Signer;\n"
            "use openssl::error::ErrorStack;\n"
        )
        found = scan_rust_source(source, "a.rs")
        assert len(found) == 1
        assert found[0]["line"] == 1

    def test_note_is_dropped_when_a_specific_item_is_used(self):
        source = (
            "use openssl::symm::Cipher;\n"
            "use openssl::hash::MessageDigest;\n"
            "\n"
            "fn digest(data: &[u8]) {\n"
            "    let md = MessageDigest::md5();\n"
            "}\n"
        )
        found = scan_rust_source(source, "a.rs")
        assert {f["algorithm"] for f in found} == {"MD5"}
        assert not any(f["severity"] == "info" for f in found)


class TestSafeCratesAreNotFlagged:
    @pytest.mark.parametrize(
        "source",
        [
            "use chacha20poly1305::{ChaCha20Poly1305, KeyInit};",
            "let cipher = ChaCha20Poly1305::new(&key);",
            "use hmac::{Hmac, Mac};",
            "use pbkdf2::pbkdf2_hmac;",
            "use argon2::Argon2;",
            "let hash = Argon2::default().hash_password(pw, &salt)?;",
            "use blake2::{Blake2b512, Digest};",
            "use blake3::Hasher;",
            "let hash = blake3::hash(b\"data\");",
        ],
    )
    def test_symmetric_and_kdf_crates_are_not_flagged(self, source):
        assert scan_rust_source(source, "a.rs") == []

    def test_a_hash_named_as_an_hmac_parameter_is_not_a_hashing_decision(self):
        # The SHA-256 in Hmac<Sha256> parameterises a symmetric MAC; reporting
        # it would be a finding about the wrong decision.
        source = "use hmac::Hmac;\ntype HmacSha256 = Hmac<Sha256>;\n"
        assert scan_rust_source(source, "a.rs") == []

    def test_a_hash_named_as_a_pbkdf2_parameter_is_not_flagged(self):
        source = "pbkdf2_hmac::<Sha256>(password, salt, rounds, &mut key);"
        assert scan_rust_source(source, "a.rs") == []

    def test_a_standalone_sha256_is_still_flagged(self):
        # The guard above must not blanket-suppress the sha2 crate.
        assert algorithms("let d = Sha256::digest(data);") == ["SHA-256"]


class TestResultShape:
    def test_every_finding_has_the_required_fields(self):
        source = (
            "use openssl::symm::Cipher;\n"
            "use rsa::RsaPrivateKey;\n"
            "use md_5::Md5;\n"
            "use ring::aead::AES_128_GCM;\n"
        )
        found = scan_rust_source(source, "a.rs")
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

    def test_every_finding_carries_both_snippets(self):
        """What the /scan/explain and /scan/patch endpoints require (F22/F23)."""
        source = (
            "use rsa::RsaPrivateKey;\n"
            "use p256::ecdsa::SigningKey;\n"
            "use ed25519_dalek::SigningKey as Ed;\n"
            "use x25519_dalek::EphemeralSecret;\n"
            "use dsa::SigningKey as DsaKey;\n"
            "use des::TdesEde3;\n"
            "use md_5::Md5;\n"
            "use sha1::Sha1;\n"
            "use sha2::Sha256;\n"
            "use sha3::Sha3_512;\n"
            "use ring::aead::AES_128_GCM;\n"
            "use openssl::symm::Cipher;\n"
        )
        found = scan_rust_source(source, "a.rs")
        assert found
        for finding in found:
            assert finding["code_snippet"], finding
            assert finding["fix_snippet"], finding
            assert "\n" not in finding["code_snippet"]

    def test_code_snippet_is_the_line_as_written(self):
        source = "    let key = RsaPrivateKey::new(&mut rng, 2048)?; // legacy\n"
        found = scan_rust_source(source, "a.rs")
        assert (
            found[0]["code_snippet"]
            == "let key = RsaPrivateKey::new(&mut rng, 2048)?; // legacy"
        )

    def test_rust_fix_snippet_is_used_for_rust(self):
        found = scan_rust_source("use rsa::RsaPrivateKey;", "a.rs")
        assert "pqcrypto_mlkem" in found[0]["fix_snippet"]
        assert "import oqs" not in found[0]["fix_snippet"]

    def test_rust_fix_snippet_is_used_for_hashes_too(self):
        found = scan_rust_source("use md_5::Md5;", "a.rs")
        assert "sha3::{Sha3_512, Digest}" in found[0]["fix_snippet"]

    def test_results_are_sorted_by_line_number(self):
        source = (
            "use std::io;\n"
            "use md_5::Md5;\n"
            "let x = 2;\n"
            "use rsa::RsaPrivateKey;\n"
            "use p256::ecdsa::SigningKey;\n"
        )
        lines = [f["line"] for f in scan_rust_source(source, "a.rs")]
        assert lines == sorted(lines)
        assert lines == [2, 4, 5]

    def test_same_algorithm_is_reported_once_per_line(self):
        source = "use rsa::{RsaPrivateKey, RsaPublicKey};"
        assert algorithms(source).count("RSA") == 1

    def test_one_line_can_still_report_two_algorithms(self):
        source = "use md_5::Md5; use rsa::RsaPrivateKey;"
        assert sorted(algorithms(source)) == ["MD5", "RSA"]


class TestRealisticFile:
    def test_full_file_with_mixed_crypto(self):
        source = """
//! Legacy signing helpers.
//!
//! This module doc mentions rsa::RsaPrivateKey and Md5 on purpose:
//! neither must reach the report.

use std::io;

use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Sign};
use p256::ecdsa::{SigningKey, VerifyingKey};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use md_5::Md5;
use sha2::{Sha256, Sha512, Digest};
use sha3::Sha3_512;
use hmac::{Hmac, Mac};
use chacha20poly1305::ChaCha20Poly1305;

use ring::signature::{ECDSA_P256_SHA256_ASN1, ED25519};
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, SHA384};
use ring::aead::AES_256_GCM;

/* An older implementation lived here:
   /* it even nested a comment */
   let key = RsaPrivateKey::new(&mut rng, 1024)?;
*/

pub fn describe() -> &'static str {
    r#"This raw string names use rsa::RsaPrivateKey and Md5 too."#
}

pub fn legacy_digest(data: &[u8]) -> Vec<u8> {
    Md5::digest(data).to_vec()
}

pub fn strong_digest(data: &[u8]) -> Vec<u8> {
    Sha3_512::digest(data).to_vec()
}
"""
        found = scan_rust_source(source, "signer.rs")
        names = [f["algorithm"] for f in found]
        assert "RSA" in names
        assert "ECC" in names
        assert "Ed25519" in names
        assert "MD5" in names
        assert "SHA-1" in names
        assert "SHA-256" in names
        assert "SHA-384" in names
        assert "SHA-512" in names
        assert "SHA-3" in names
        assert "AES-256" in names
        # The module doc, the nested block comment, and the raw string all name
        # crypto and contribute nothing.
        assert not any(2 <= f["line"] <= 5 for f in found)
        assert not any(22 <= f["line"] <= 29 for f in found)
        # The Grover-weakened and the quantum-safe halves of sha2 are told apart.
        sha256 = next(f for f in found if f["algorithm"] == "SHA-256")
        assert sha256["severity"] == "warning"
        assert all(
            f["severity"] == "safe"
            for f in found
            if f["algorithm"] in ("SHA-384", "SHA-512", "SHA-3", "AES-256")
        )
        assert [f["line"] for f in found] == sorted(f["line"] for f in found)
        for finding in found:
            assert finding["code_snippet"]
            assert finding["fix_snippet"]


class TestElGamal:
    """Rust has no dominant ElGamal crate, so the whole small field is covered.

    Nearly all of these implement exponential ElGamal over an elliptic-curve
    group for homomorphic or voting schemes. That variant rests on the
    elliptic-curve discrete log, so Shor's Algorithm breaks it exactly as it
    breaks the classic modular construction — it is reported, not excused.
    """

    @pytest.mark.parametrize(
        "source",
        [
            "use elastic_elgamal::{Keypair, group::Ristretto};",
            "use elgamal_ristretto::public::PublicKey;",
            "use rust_elgamal::{DecryptionKey, GENERATOR_TABLE};",
            "use jubjub_elgamal::Ciphertext;",
            "use lnpbp_elgamal::Encrypt;",
            "use elgamal::ElGamal;",
        ],
    )
    def test_detects_the_elgamal_crates(self, source):
        found = scan_rust_source(source, "a.rs")
        assert "ElGamal" in [f["algorithm"] for f in found]
        assert found[0]["severity"] == "critical"
        assert found[0]["quantum_vulnerable"] is True
        assert found[0]["attack_vector"] == "Shor's Algorithm"

    def test_detects_qualified_paths_without_the_use_line(self):
        source = "let keypair = elastic_elgamal::Keypair::generate(&mut rng);"
        assert [f["algorithm"] for f in scan_rust_source(source, "a.rs")] == ["ElGamal"]

    def test_detects_type_names(self):
        assert algorithms("let pk: ElGamalPublicKey = load();") == ["ElGamal"]

    def test_the_longest_crate_name_wins_over_its_prefix(self):
        # `elgamal` is a prefix of `elgamal_ristretto`; the alternation has to
        # reach the longer name rather than stopping at the shorter one.
        found = scan_rust_source("use elgamal_ristretto::ciphertext::Ciphertext;", "a.rs")
        assert [f["algorithm"] for f in found] == ["ElGamal"]

    def test_elgamal_in_a_comment_or_string_is_not_a_finding(self):
        source = (
            "// use elastic_elgamal::Keypair;\n"
            'let note = "elgamal was removed";\n'
        )
        assert scan_rust_source(source, "a.rs") == []

    def test_finding_carries_both_snippets(self):
        found = scan_rust_source("use elastic_elgamal::Keypair;", "a.rs")
        assert found[0]["code_snippet"]
        assert "pqcrypto_mlkem" in found[0]["fix_snippet"]

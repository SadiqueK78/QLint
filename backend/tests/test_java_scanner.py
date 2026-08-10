"""Tests for java_scanner.scan_java_source (Java detection)."""

import pytest

from java_scanner import scan_java_source

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
    return [f["algorithm"] for f in scan_java_source(source, "Test.java")]


class TestEmptyAndInvalidInput:
    @pytest.mark.parametrize("source", ["", "   ", "\n\n\t\n"])
    def test_empty_input_returns_empty_list(self, source):
        assert scan_java_source(source, "Test.java") == []

    def test_binary_input_returns_empty_without_raising(self):
        assert scan_java_source("\x00\x01\x02binary\x00garbage", "Blob.java") == []

    def test_unparseable_java_does_not_raise(self):
        # Deliberately broken syntax — a regex scanner still must not crash.
        source = 'class { ] public static "unterminated /* '
        assert isinstance(scan_java_source(source, "Broken.java"), list)

    def test_source_with_no_crypto_returns_empty(self):
        source = (
            "package com.example;\n\n"
            "public class Math {\n"
            "    int add(int a, int b) { return a + b; }\n"
            "}\n"
        )
        assert scan_java_source(source, "Math.java") == []


class TestCommentHandling:
    def test_line_comment_only_file_returns_no_findings(self):
        source = (
            '// Cipher.getInstance("RSA");\n'
            '// MessageDigest.getInstance("MD5");\n'
            '// KeyPairGenerator.getInstance("EC");\n'
        )
        assert scan_java_source(source, "Notes.java") == []

    def test_block_comment_only_file_returns_no_findings(self):
        source = (
            "/*\n"
            '  Cipher.getInstance("RSA");\n'
            '  MessageDigest.getInstance("MD5");\n'
            "*/\n"
            "int x = 1;\n"
        )
        assert scan_java_source(source, "Notes.java") == []

    def test_javadoc_is_ignored(self):
        source = (
            "/**\n"
            ' * Uses Cipher.getInstance("RSA") under the hood.\n'
            " */\n"
            "public class Doc {}\n"
        )
        assert scan_java_source(source, "Doc.java") == []

    def test_trailing_comment_does_not_hide_real_code(self):
        source = 'MessageDigest md = MessageDigest.getInstance("MD5"); // legacy\n'
        assert algorithms(source).count("MD5") == 1

    def test_url_in_a_string_is_not_treated_as_a_comment(self):
        # The `//` inside a URL must not start a line comment.
        source = (
            'String doc = "https://example.com/rsa";\n'
            'Cipher c = Cipher.getInstance("RSA");\n'
        )
        found = scan_java_source(source, "Url.java")
        assert [f["algorithm"] for f in found] == ["RSA"]
        assert found[0]["line"] == 2

    def test_text_block_does_not_swallow_the_rest_of_the_file(self):
        source = (
            'String help = """\n'
            "    We used to call Cipher.getInstance(RSA) here.\n"
            '    """;\n'
            'MessageDigest md = MessageDigest.getInstance("MD5");\n'
        )
        found = scan_java_source(source, "Block.java")
        assert [f["algorithm"] for f in found] == ["MD5"]
        assert found[0]["line"] == 4


class TestRSA:
    @pytest.mark.parametrize(
        "call",
        [
            'Cipher.getInstance("RSA")',
            'Cipher.getInstance("RSA/ECB/PKCS1Padding")',
            'Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")',
            'javax.crypto.Cipher.getInstance("RSA")',
        ],
    )
    def test_detects_rsa_via_cipher_get_instance(self, call):
        found = scan_java_source(f"Cipher c = {call};", "A.java")
        assert [f["algorithm"] for f in found] == ["RSA"]
        assert found[0]["match_type"] == "string_arg"
        assert found[0]["severity"] == "critical"

    def test_detects_rsa_via_key_pair_generator(self):
        source = 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");'
        assert algorithms(source) == ["RSA"]

    def test_detects_rsa_via_key_factory(self):
        assert "RSA" in algorithms('KeyFactory.getInstance("RSA")')

    @pytest.mark.parametrize(
        "name", ["SHA256withRSA", "SHA1withRSA", "MD5withRSA", "NONEwithRSA"]
    )
    def test_signature_algorithms_resolve_to_rsa_not_the_hash(self, name):
        # The asymmetric half carries the quantum risk, so it wins.
        found = scan_java_source(f'Signature.getInstance("{name}");', "A.java")
        assert [f["algorithm"] for f in found] == ["RSA"]

    def test_signature_name_declared_as_a_constant_is_detected(self):
        # Real libraries name the algorithm once and call getInstance(name)
        # somewhere else; the quoted JCA name is the only place it appears.
        source = 'RS256("RS256", "RSASSA-PKCS-v1_5", "RSA", "SHA256withRSA", 2048),'
        found = scan_java_source(source, "SignatureAlgorithm.java")
        assert [f["algorithm"] for f in found] == ["RSA"]

    def test_rsassa_pss_name_is_detected(self):
        assert algorithms('String PSS_JCA_NAME = "RSASSA-PSS";') == ["RSA"]

    def test_get_instance_with_a_constant_is_not_guessed_at(self):
        # No algorithm name to read: inventing one would be a finding about
        # code that is not there.
        assert scan_java_source("Cipher.getInstance(TRANSFORMATION);", "A.java") == []


class TestEllipticCurve:
    def test_detects_ec_via_key_pair_generator(self):
        found = scan_java_source(
            'KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");', "A.java"
        )
        assert [f["algorithm"] for f in found] == ["ECC"]
        assert found[0]["severity"] == "critical"
        assert found[0]["attack_vector"] == "Shor's Algorithm"

    @pytest.mark.parametrize("name", ["SHA256withECDSA", "SHA1withECDSA"])
    def test_detects_ecdsa_via_signature(self, name):
        found = scan_java_source(f'Signature.getInstance("{name}");', "A.java")
        assert [f["algorithm"] for f in found] == ["ECC"]

    def test_ecdsa_signature_name_constant_is_detected(self):
        source = 'ES256("ES256", "ECDSA using P-256", "SHA256withECDSA", 256),'
        assert algorithms(source) == ["ECC"]

    def test_ecdsa_signature_is_not_reported_as_dsa(self):
        assert algorithms('Signature.getInstance("SHA256withECDSA");') == ["ECC"]

    def test_detects_ecdh_via_key_agreement(self):
        assert algorithms('KeyAgreement.getInstance("ECDH");') == ["ECC"]

    def test_detects_curve_names_in_a_gen_parameter_spec(self):
        source = 'kpg.initialize(new ECGenParameterSpec("secp256r1"));'
        assert algorithms(source) == ["ECC"]

    @pytest.mark.parametrize(
        "curve", ["secp256r1", "secp384r1", "secp256k1", "prime256v1"]
    )
    def test_detects_well_known_curve_name_constants(self, curve):
        source = f'String curve = "{curve}";'
        assert algorithms(source) == ["ECC"]


class TestOtherKeyAlgorithms:
    def test_detects_dsa_via_key_pair_generator(self):
        found = scan_java_source('KeyPairGenerator.getInstance("DSA");', "A.java")
        assert [f["algorithm"] for f in found] == ["DSA"]

    def test_detects_diffie_hellman_via_key_agreement(self):
        # The canonical name the rest of the database uses, not "DH".
        found = scan_java_source('KeyAgreement.getInstance("DH");', "A.java")
        assert [f["algorithm"] for f in found] == ["Diffie-Hellman"]
        assert found[0]["severity"] == "critical"

    def test_detects_ed25519_as_quantum_vulnerable(self):
        found = scan_java_source('Signature.getInstance("Ed25519");', "A.java")
        assert [f["algorithm"] for f in found] == ["Ed25519"]
        assert found[0]["quantum_vulnerable"] is True

    def test_pqc_algorithm_names_are_not_reported_as_what_they_replace(self):
        # "ML-DSA-65" contains "dsa"; it is the replacement, not the problem.
        found = scan_java_source(
            'Signature.getInstance("ML-DSA-65", "BCPQC");', "A.java"
        )
        assert [f["algorithm"] for f in found] == ["ML-DSA"]
        assert found[0]["severity"] == "safe"


class TestMessageDigest:
    def test_detects_md5(self):
        found = scan_java_source('MessageDigest.getInstance("MD5");', "A.java")
        assert [f["algorithm"] for f in found] == ["MD5"]
        assert found[0]["severity"] == "critical"

    @pytest.mark.parametrize("name", ["SHA-1", "SHA1", "SHA"])
    def test_detects_sha1(self, name):
        found = scan_java_source(f'MessageDigest.getInstance("{name}");', "A.java")
        assert [f["algorithm"] for f in found] == ["SHA-1"]
        assert found[0]["severity"] == "critical"

    def test_sha256_is_a_warning_not_critical(self):
        found = scan_java_source('MessageDigest.getInstance("SHA-256");', "A.java")
        assert [f["algorithm"] for f in found] == ["SHA-256"]
        assert found[0]["severity"] == "warning"
        assert found[0]["attack_vector"] == "Grover's Algorithm"

    @pytest.mark.parametrize(
        "name,algorithm",
        [
            ("SHA-384", "SHA-384"),
            ("SHA-512", "SHA-512"),
            ("SHA3-256", "SHA-3"),
            ("SHA3-512", "SHA-3"),
        ],
    )
    def test_strong_digests_are_safe_not_critical(self, name, algorithm):
        found = scan_java_source(f'MessageDigest.getInstance("{name}");', "A.java")
        assert [f["algorithm"] for f in found] == [algorithm]
        assert found[0]["severity"] == "safe"
        assert found[0]["quantum_vulnerable"] is False


class TestSymmetricCiphers:
    def test_detects_des(self):
        found = scan_java_source(
            'Cipher.getInstance("DES/CBC/PKCS5Padding");', "A.java"
        )
        assert [f["algorithm"] for f in found] == ["DES"]
        assert found[0]["severity"] == "critical"

    def test_detects_triple_des(self):
        found = scan_java_source(
            'Cipher.getInstance("DESede/CBC/PKCS5Padding");', "A.java"
        )
        assert [f["algorithm"] for f in found] == ["3DES"]

    def test_hmac_is_reported_as_symmetric_and_safe(self):
        found = scan_java_source('Mac.getInstance("HmacSHA256");', "A.java")
        assert [f["algorithm"] for f in found] == ["HMAC (symmetric)"]
        assert found[0]["severity"] == "safe"

    def test_password_kdf_is_not_reported_as_its_inner_hash(self):
        source = 'SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");'
        assert "SHA-256" not in algorithms(source)


class TestAESKeyLengthResolution:
    def test_key_length_128_is_a_warning(self):
        source = (
            'KeyGenerator keyGen = KeyGenerator.getInstance("AES");\n'
            "keyGen.init(128);\n"
            'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
        )
        found = scan_java_source(source, "A.java")
        assert {f["algorithm"] for f in found} == {"AES-128"}
        assert found[0]["severity"] == "warning"

    def test_key_length_256_is_safe(self):
        source = (
            'KeyGenerator keyGen = KeyGenerator.getInstance("AES");\n'
            "keyGen.init(256);\n"
            'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
        )
        found = scan_java_source(source, "A.java")
        assert {f["algorithm"] for f in found} == {"AES-256"}
        assert found[0]["severity"] == "safe"

    def test_ambiguous_key_length_is_an_info_note(self):
        found = scan_java_source(
            'Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");', "A.java"
        )
        assert len(found) == 1
        assert found[0]["severity"] == "info"
        assert "not visible" in found[0]["algorithm"]

    def test_two_different_key_lengths_stay_ambiguous(self):
        source = (
            "aesKeyGen.init(128);\n"
            "otherKeyGen.init(256);\n"
            'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
        )
        found = scan_java_source(source, "A.java")
        assert found[-1]["severity"] == "info"

    def test_rsa_initialize_is_not_read_as_an_aes_key_length(self):
        # initialize(2048) is a KeyPairGenerator call, not KeyGenerator.init.
        source = (
            'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
            "kpg.initialize(2048);\n"
            'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
        )
        found = scan_java_source(source, "A.java")
        assert [f["algorithm"] for f in found] == [
            "RSA",
            "AES (key length not visible)",
        ]

    def test_sized_transformation_names_itself(self):
        found = scan_java_source(
            'Cipher c = Cipher.getInstance("AES_256/GCM/NoPadding");', "A.java"
        )
        assert [f["algorithm"] for f in found] == ["AES-256"]


class TestBouncyCastle:
    @pytest.mark.parametrize(
        "class_name,algorithm",
        [
            ("RSAKeyPairGenerator", "RSA"),
            ("ECKeyPairGenerator", "ECC"),
            ("DSAKeyPairGenerator", "DSA"),
            ("MD5Digest", "MD5"),
            ("SHA1Digest", "SHA-1"),
        ],
    )
    def test_detects_lightweight_api_classes(self, class_name, algorithm):
        source = f"{class_name} gen = new {class_name}();"
        assert algorithms(source) == [algorithm]

    def test_fully_qualified_generator_import_is_detected(self):
        source = "import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;"
        found = scan_java_source(source, "A.java")
        assert [f["algorithm"] for f in found] == ["RSA"]

    def test_bare_import_alone_is_an_info_note(self):
        source = "import org.bouncycastle.jce.provider.BouncyCastleProvider;"
        found = scan_java_source(source, "A.java")
        assert len(found) == 1
        assert found[0]["severity"] == "info"
        assert found[0]["match_type"] == "import"
        assert "deeper inspection" in found[0]["algorithm"]

    def test_the_note_is_reported_once_per_file_not_once_per_import(self):
        # A real Bouncy Castle file imports twenty of its packages; twenty
        # copies of the same note would bury the findings that matter.
        source = (
            "import org.bouncycastle.asn1.ASN1Encodable;\n"
            "import org.bouncycastle.asn1.ASN1Object;\n"
            "import org.bouncycastle.asn1.ASN1Sequence;\n"
            "import org.bouncycastle.util.Arrays;\n"
        )
        found = scan_java_source(source, "A.java")
        assert len(found) == 1
        assert found[0]["line"] == 1

    def test_wildcard_import_is_an_info_note(self):
        found = scan_java_source("import org.bouncycastle.crypto.*;", "A.java")
        assert [f["severity"] for f in found] == ["info"]

    def test_note_is_dropped_when_a_specific_class_is_used(self):
        source = (
            "import org.bouncycastle.jce.provider.BouncyCastleProvider;\n"
            "import org.bouncycastle.crypto.digests.MD5Digest;\n"
            "\n"
            "public class Legacy {\n"
            "    MD5Digest digest = new MD5Digest();\n"
            "}\n"
        )
        found = scan_java_source(source, "Legacy.java")
        assert {f["algorithm"] for f in found} == {"MD5"}
        assert not any(f["severity"] == "info" for f in found)


class TestResultShape:
    def test_every_finding_has_the_required_fields(self):
        source = (
            "import org.bouncycastle.jce.provider.BouncyCastleProvider;\n"
            'Cipher c = Cipher.getInstance("RSA");\n'
            'MessageDigest md = MessageDigest.getInstance("MD5");\n'
            'Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");\n'
        )
        found = scan_java_source(source, "A.java")
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
            'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
            'KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");\n'
            'MessageDigest md = MessageDigest.getInstance("MD5");\n'
            'MessageDigest sha = MessageDigest.getInstance("SHA-512");\n'
            'Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");\n'
            "MD5Digest bc = new MD5Digest();\n"
        )
        found = scan_java_source(source, "A.java")
        assert found
        for finding in found:
            assert finding["code_snippet"], finding
            assert finding["fix_snippet"], finding
            assert "\n" not in finding["code_snippet"]

    def test_code_snippet_is_the_line_as_written(self):
        source = '    MessageDigest md = MessageDigest.getInstance("MD5"); // legacy\n'
        found = scan_java_source(source, "A.java")
        assert (
            found[0]["code_snippet"]
            == 'MessageDigest md = MessageDigest.getInstance("MD5"); // legacy'
        )

    def test_java_fix_snippet_is_used_for_java(self):
        found = scan_java_source('Cipher.getInstance("RSA");', "A.java")
        assert "BouncyCastlePQCProvider" in found[0]["fix_snippet"]
        assert "import oqs" not in found[0]["fix_snippet"]

    def test_results_are_sorted_by_line_number(self):
        source = (
            "package com.example;\n"
            'MessageDigest md = MessageDigest.getInstance("MD5");\n'
            "int x = 2;\n"
            'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
            'KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");\n'
        )
        lines = [f["line"] for f in scan_java_source(source, "A.java")]
        assert lines == sorted(lines)
        assert lines == [2, 4, 5]

    def test_same_algorithm_is_reported_once_per_line(self):
        source = (
            'MessageDigest a = MessageDigest.getInstance("MD5"), '
            'b = MessageDigest.getInstance("MD5");'
        )
        assert algorithms(source).count("MD5") == 1

    def test_one_line_can_still_report_two_algorithms(self):
        source = 'Cipher.getInstance("RSA"); MessageDigest.getInstance("MD5");'
        assert sorted(algorithms(source)) == ["MD5", "RSA"]


class TestRealisticFile:
    def test_full_file_with_mixed_crypto(self):
        source = """
package com.example.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

/**
 * Legacy signing helpers. This Javadoc mentions RSA and MD5 on purpose:
 * neither must reach the report.
 */
public class Signer {

    // Cipher.getInstance("DES") in a comment is not a finding either.

    public KeyPair rsaKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public KeyPair ecKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    public byte[] sign(byte[] data) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.update(data);
        return signer.sign();
    }

    public byte[] legacyDigest(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }

    public byte[] strongDigest(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-512").digest(data);
    }

    public Cipher symmetric() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    public Mac mac() throws Exception {
        return Mac.getInstance("HmacSHA256");
    }
}
"""
        found = scan_java_source(source, "Signer.java")
        names = [f["algorithm"] for f in found]
        assert "RSA" in names
        assert "ECC" in names
        assert "MD5" in names
        assert "SHA-512" in names
        assert "AES-256" in names
        # The Javadoc and the line comment above rsaKey() contribute nothing.
        assert names.count("MD5") == 1
        assert "DES" not in names
        assert [f["line"] for f in found] == sorted(f["line"] for f in found)
        for finding in found:
            assert finding["code_snippet"]
            assert finding["fix_snippet"]


class TestElGamal:
    """ElGamal reaches Java through Bouncy Castle only.

    The JDK's own providers ship no ElGamal, so getInstance("ElGamal") is a BC
    call too — which is why the JCE spellings resolve through the crypto
    database's alias while the lightweight API needs its own class rules.
    """

    def test_detects_elgamal_via_key_pair_generator(self):
        found = scan_java_source(
            'KeyPairGenerator kpg = KeyPairGenerator.getInstance("ElGamal", "BC");',
            "A.java",
        )
        assert [f["algorithm"] for f in found] == ["ElGamal"]
        assert found[0]["severity"] == "critical"
        assert found[0]["quantum_vulnerable"] is True
        assert found[0]["attack_vector"] == "Shor's Algorithm"

    def test_detects_elgamal_via_a_cipher_transformation(self):
        found = scan_java_source(
            'Cipher c = Cipher.getInstance("ElGamal/None/PKCS1Padding");', "A.java"
        )
        assert [f["algorithm"] for f in found] == ["ElGamal"]

    @pytest.mark.parametrize(
        "class_name",
        [
            "ElGamalKeyPairGenerator",
            "ElGamalEngine",
            "ElGamalParametersGenerator",
            "ElGamalKeyParameters",
        ],
    )
    def test_detects_bouncy_castle_lightweight_classes(self, class_name):
        source = f"{class_name} x = new {class_name}();"
        assert algorithms(source) == ["ElGamal"]

    def test_a_lightweight_class_displaces_the_generic_bc_note(self):
        source = (
            "import org.bouncycastle.jce.provider.BouncyCastleProvider;\n"
            "import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;\n"
            "ElGamalKeyPairGenerator gen = new ElGamalKeyPairGenerator();\n"
        )
        found = scan_java_source(source, "A.java")
        assert {f["algorithm"] for f in found} == {"ElGamal"}
        assert not any(f["severity"] == "info" for f in found)

    def test_elgamal_is_not_reported_as_dsa_or_diffie_hellman(self):
        assert algorithms('KeyPairGenerator.getInstance("ElGamal");') == ["ElGamal"]

    def test_elgamal_in_a_javadoc_is_not_a_finding(self):
        source = '/** Uses Cipher.getInstance("ElGamal") internally. */\nclass A {}\n'
        assert scan_java_source(source, "A.java") == []

    def test_finding_carries_both_snippets(self):
        found = scan_java_source('KeyPairGenerator.getInstance("ElGamal");', "A.java")
        assert found[0]["code_snippet"]
        assert "BouncyCastlePQCProvider" in found[0]["fix_snippet"]

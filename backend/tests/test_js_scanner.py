"""Tests for js_scanner.scan_js_source (JavaScript / TypeScript detection)."""

import pytest

from js_scanner import scan_js_source

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
    return [f["algorithm"] for f in scan_js_source(source, "test.js")]


class TestEmptyAndInvalidInput:
    @pytest.mark.parametrize("source", ["", "   ", "\n\n\t\n"])
    def test_empty_input_returns_empty_list(self, source):
        assert scan_js_source(source, "test.js") == []

    def test_binary_input_returns_empty_without_raising(self):
        assert scan_js_source("\x00\x01\x02binary\x00garbage", "blob.js") == []

    def test_unparseable_javascript_does_not_raise(self):
        # Deliberately broken syntax — a regex scanner still must not crash.
        source = "function ( { ] const = = = 'unterminated"
        assert isinstance(scan_js_source(source, "broken.js"), list)

    def test_source_with_no_crypto_returns_empty(self):
        source = "const sum = (a, b) => a + b;\nexport default sum;\n"
        assert scan_js_source(source, "math.js") == []


class TestCommentHandling:
    def test_comment_only_file_returns_no_findings(self):
        source = "// const rsa = require('rsa')\n// md5 hash"
        assert scan_js_source(source, "notes.js") == []

    def test_block_comments_are_ignored(self):
        source = "/*\n  crypto.createHash('md5')\n  RSA-SHA256\n*/\nconst x = 1;"
        assert scan_js_source(source, "notes.js") == []

    def test_trailing_comment_does_not_hide_real_code(self):
        source = "const h = crypto.createHash('md5'); // legacy md5 hash\n"
        assert algorithms(source).count("MD5") == 1

    def test_url_in_a_string_is_not_treated_as_a_comment(self):
        source = "const doc = 'https://example.com/rsa';\nconst s = crypto.createSign('RSA-SHA256');"
        found = scan_js_source(source, "u.js")
        assert "RSA" in [f["algorithm"] for f in found]
        assert all(f["line"] == 2 for f in found)


class TestNodeCryptoPatterns:
    def test_detects_rsa_from_create_sign(self):
        assert "RSA" in algorithms("const sign = crypto.createSign('RSA-SHA256');")

    def test_detects_rsa_from_create_verify(self):
        assert "RSA" in algorithms("const v = crypto.createVerify('RSA-SHA256');")

    def test_create_sign_reports_the_key_type_not_the_hash(self):
        # RSA-SHA256 is an RSA finding; the hash half must not shadow it.
        assert algorithms("crypto.createSign('RSA-SHA256')") == ["RSA"]

    def test_detects_md5(self):
        assert "MD5" in algorithms("const md5 = crypto.createHash('md5');")

    def test_detects_sha1(self):
        assert "SHA-1" in algorithms("const h = crypto.createHash('sha1');")

    def test_detects_ecc_from_create_ecdh(self):
        assert "ECC" in algorithms("const ecdh = crypto.createECDH('prime256v1');")

    def test_detects_diffie_hellman(self):
        assert "Diffie-Hellman" in algorithms("const dh = crypto.createDiffieHellman(2048);")

    def test_detects_des_and_aes_key_sizes_from_cipher_names(self):
        assert "DES" in algorithms("crypto.createCipheriv('des', key, iv);")
        assert "AES-128" in algorithms("crypto.createCipheriv('aes-128-cbc', key, iv);")
        assert "AES-256" in algorithms("crypto.createCipheriv('aes-256-cbc', key, iv);")

    def test_require_crypto_is_flagged_for_deeper_inspection(self):
        found = scan_js_source("const crypto = require('crypto');", "a.js")
        assert len(found) == 1
        assert found[0]["severity"] == "info"
        assert found[0]["match_type"] == "import"


class TestSeverityClassification:
    def test_sha512_is_not_critical(self):
        found = scan_js_source("const h = crypto.createHash('sha512');", "a.js")
        assert [f["algorithm"] for f in found] == ["SHA-512"]
        assert found[0]["severity"] == "safe"
        assert found[0]["quantum_vulnerable"] is False

    def test_sha256_is_a_warning_not_critical(self):
        found = scan_js_source("crypto.createHash('sha256');", "a.js")
        assert found[0]["severity"] == "warning"

    def test_hmac_jwt_algorithms_are_safe(self):
        found = scan_js_source("jwt.sign(p, k, { algorithm: 'HS256' });", "a.js")
        assert found[0]["severity"] == "safe"
        assert found[0]["quantum_vulnerable"] is False


class TestJoseJwtPatterns:
    @pytest.mark.parametrize("alg", ["RS256", "RS384", "RS512"])
    def test_rs_algorithms_map_to_rsa(self, alg):
        source = f"const token = jwt.sign(payload, key, {{ algorithm: '{alg}' }});"
        assert "RSA" in algorithms(source)

    @pytest.mark.parametrize("alg", ["ES256", "ES384", "ES512"])
    def test_es_algorithms_map_to_ecc(self, alg):
        source = f"const token = jwt.sign(payload, key, {{ algorithm: '{alg}' }});"
        assert "ECC" in algorithms(source)


class TestWebCryptoPatterns:
    @pytest.mark.parametrize("name", ["RSA-OAEP", "RSA-PSS"])
    def test_rsa_algorithm_objects(self, name):
        assert "RSA" in algorithms(f"crypto.subtle.generateKey({{ name: '{name}' }});")

    @pytest.mark.parametrize("name", ["ECDH", "ECDSA"])
    def test_ec_algorithm_objects(self, name):
        assert "ECC" in algorithms(f"crypto.subtle.generateKey({{ name: '{name}' }});")

    def test_aes_key_length_is_read_from_the_line_when_visible(self):
        assert "AES-128" in algorithms(
            "crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, true, []);"
        )
        assert "AES-256" in algorithms(
            "crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, []);"
        )

    def test_aes_without_a_visible_length_is_flagged_for_inspection(self):
        found = scan_js_source("const alg = { name: 'AES-GCM' };", "a.js")
        assert found[0]["severity"] == "info"
        assert "not visible" in found[0]["algorithm"]


class TestLibraryPatterns:
    def test_node_forge_patterns(self):
        source = (
            "const rsa = forge.pki.rsa;\n"
            "const md = forge.md.sha1.create();\n"
            "const md5 = forge.md.md5.create();\n"
        )
        found = algorithms(source)
        assert "RSA" in found and "SHA-1" in found and "MD5" in found

    def test_node_rsa_and_jsrsasign(self):
        assert "RSA" in algorithms("const key = new NodeRSA({b: 512});")
        assert "RSA" in algorithms("const r = require('jsrsasign');")

    def test_elliptic_and_secp256k1_map_to_ecc(self):
        assert "ECC" in algorithms("const EC = require('elliptic').ec;")
        assert "ECC" in algorithms("import * as secp from 'noble-secp256k1';")

    def test_ed25519_is_reported_as_quantum_vulnerable(self):
        # Ed25519 is elliptic-curve based, so Shor's Algorithm breaks it.
        found = scan_js_source("const ed = forge.pki.ed25519;", "a.js")
        assert found[0]["algorithm"] == "Ed25519"
        assert found[0]["quantum_vulnerable"] is True
        assert found[0]["severity"] == "critical"


class TestResultShape:
    def test_every_finding_has_the_required_fields(self):
        source = (
            "const crypto = require('crypto');\n"
            "const s = crypto.createSign('RSA-SHA256');\n"
            "const h = crypto.createHash('md5');\n"
        )
        found = scan_js_source(source, "a.js")
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
            "const a = 1;\n"
            "const h = crypto.createHash('md5');\n"
            "const b = 2;\n"
            "const s = crypto.createSign('RSA-SHA256');\n"
            "const e = crypto.createECDH('prime256v1');\n"
        )
        lines = [f["line"] for f in scan_js_source(source, "a.js")]
        assert lines == sorted(lines)
        assert lines == [2, 4, 5]

    def test_same_algorithm_is_reported_once_per_line(self):
        source = "const a = crypto.createHash('md5'), b = crypto.createHash('md5');"
        assert algorithms(source).count("MD5") == 1

    def test_js_fix_snippet_is_used_for_javascript(self):
        found = scan_js_source("crypto.createSign('RSA-SHA256');", "a.js")
        assert "require(" in found[0]["fix_snippet"]
        assert "import oqs" not in found[0]["fix_snippet"]


class TestTypeScript:
    def test_tsx_file_with_react_and_crypto(self):
        source = """
import React, { useState } from 'react';
import { createHash, createSign } from 'crypto';

interface Props {
  payload: string;
}

// Hash the payload before display
export const Signer: React.FC<Props> = ({ payload }) => {
  const [sig, setSig] = useState<string>('');

  const sign = (key: string): void => {
    const signer = createSign('RSA-SHA256');
    signer.update(payload);
    setSig(signer.sign(key, 'hex'));
  };

  const digest = createHash('sha256').update(payload).digest('hex');
  return <div onClick={() => sign('k')}>{digest}{sig}</div>;
};
"""
        found = scan_js_source(source, "Signer.tsx")
        names = [f["algorithm"] for f in found]
        assert "RSA" in names
        assert "SHA-256" in names
        # The JSX generic <Props> and arrow functions must not break scanning.
        assert all(isinstance(f["line"], int) for f in found)

    def test_typescript_type_annotations_do_not_create_false_positives(self):
        source = "let ec: number = 5;\nconst description: string = 'des';\n"
        assert scan_js_source(source, "types.ts") == []


class TestElGamal:
    """JavaScript has no ElGamal library with meaningful adoption.

    node-forge does not implement it; the npm packages that do are dormant
    (the `elgamal` package was last published in 2016). These rules are exact
    module specifiers and one OpenPGP.js enum path rather than anything
    looser, because a broad /elgamal/i would match prose in a crypto library's
    own source far more often than a real call site.
    """

    def test_detects_the_elgamal_package_via_require(self):
        found = scan_js_source("const ElGamal = require('elgamal');", "a.js")
        assert [f["algorithm"] for f in found] == ["ElGamal"]
        assert found[0]["severity"] == "critical"
        assert found[0]["quantum_vulnerable"] is True

    def test_detects_the_elgamal_package_via_import(self):
        found = scan_js_source("import ElGamal from 'elgamal';", "a.ts")
        assert [f["algorithm"] for f in found] == ["ElGamal"]

    def test_detects_the_basic_simple_elgamal_package(self):
        found = scan_js_source('require("basic_simple_elgamal")', "a.js")
        assert [f["algorithm"] for f in found] == ["ElGamal"]

    def test_detects_the_openpgp_js_public_key_enum(self):
        source = "if (algorithm === enums.publicKey.elgamal) { reject(); }"
        assert [f["algorithm"] for f in scan_js_source(source, "a.js")] == ["ElGamal"]

    def test_the_word_elgamal_in_prose_is_not_a_finding(self):
        # The deliberate limit of the exact-specifier approach: a comment or a
        # variable name mentioning ElGamal is not a use of it.
        source = (
            "// ElGamal support was removed in v3.\n"
            "const elgamalSupported = false;\n"
        )
        assert scan_js_source(source, "a.js") == []

    def test_finding_carries_both_snippets(self):
        found = scan_js_source("const ElGamal = require('elgamal');", "a.js")
        assert found[0]["code_snippet"]
        assert "liboqs-node" in found[0]["fix_snippet"]

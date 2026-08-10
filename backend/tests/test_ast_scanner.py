"""Tests for ast_scanner.scan_python_source."""

from ast_scanner import scan_python_source

REQUIRED_FIELDS = {
    "line",
    "col",
    "identifier",
    "match_type",
    "algorithm",
    "severity",
    "fix_snippet",
}


def algorithms(findings):
    return {f["algorithm"] for f in findings}


class TestEdgeCases:
    def test_empty_string_returns_empty_list(self):
        assert scan_python_source("") == []

    def test_whitespace_only_returns_empty_list(self):
        assert scan_python_source("   \n\n  ") == []

    def test_unparseable_source_returns_empty_without_raising(self):
        assert scan_python_source("def broken(:") == []

    def test_comment_only_file_has_no_crypto_findings(self):
        source = "# rsa is old\n# md5 was used here\nx = 1"
        assert scan_python_source(source) == []


class TestDetection:
    def test_detects_cryptography_rsa_import(self):
        source = "from cryptography.hazmat.primitives.asymmetric import rsa"
        assert "RSA" in algorithms(scan_python_source(source))

    def test_detects_rsa_function_call(self, sample_rsa_source):
        findings = scan_python_source(sample_rsa_source)
        call_findings = [
            f
            for f in findings
            if f["algorithm"] == "RSA" and f["match_type"] == "function_call"
        ]
        assert call_findings, findings

    def test_detects_hashlib_md5_call(self):
        source = "import hashlib\nh = hashlib.md5()"
        assert "MD5" in algorithms(scan_python_source(source))

    def test_detects_hashlib_new_string_arg(self):
        source = 'import hashlib\nh = hashlib.new("sha1")'
        findings = scan_python_source(source)
        sha1 = [f for f in findings if f["algorithm"] == "SHA-1"]
        assert sha1
        assert sha1[0]["match_type"] == "string_arg"

    def test_detects_pycryptodome_rsa_import(self):
        source = "from Crypto.PublicKey import RSA"
        assert "RSA" in algorithms(scan_python_source(source))


class TestOutputShape:
    def test_results_sorted_by_line_number(self):
        source = (
            "from Crypto.Hash import MD5\n"
            "from Crypto.PublicKey import RSA\n"
            "x = 1\n"
            "h = MD5.new()\n"
            "k = RSA.generate(2048)\n"
        )
        findings = scan_python_source(source)
        lines = [f["line"] for f in findings]
        assert lines == sorted(lines)
        assert len(findings) >= 4

    def test_findings_have_required_fields(self, sample_rsa_source):
        findings = scan_python_source(sample_rsa_source)
        assert findings
        for finding in findings:
            missing = REQUIRED_FIELDS - finding.keys()
            assert not missing, f"finding missing fields: {missing}"


class TestElGamal:
    """pycryptodome is the one Python library with a first-class ElGamal API.

    The `cryptography` package has no ElGamal at all, so Crypto.PublicKey /
    Cryptodome.PublicKey is the whole realistic surface. No ast_scanner change
    was needed for any of this: the scanner is database-driven, so the
    CRYPTO_DB entry is what makes these resolve.
    """

    def test_detects_pycryptodome_elgamal_import(self):
        source = "from Crypto.PublicKey import ElGamal"
        findings = scan_python_source(source)
        assert "ElGamal" in algorithms(findings)
        assert findings[0]["severity"] == "critical"
        assert findings[0]["quantum_vulnerable"] is True
        assert findings[0]["attack_vector"] == "Shor's Algorithm"

    def test_detects_the_cryptodome_fork_too(self):
        source = "from Cryptodome.PublicKey import ElGamal"
        assert "ElGamal" in algorithms(scan_python_source(source))

    def test_detects_a_fully_qualified_module_import(self):
        source = "import Crypto.PublicKey.ElGamal"
        assert "ElGamal" in algorithms(scan_python_source(source))

    def test_detects_key_generation(self):
        source = (
            "from Crypto.PublicKey import ElGamal\n"
            "key = ElGamal.generate(2048, get_random_bytes)\n"
        )
        findings = scan_python_source(source)
        assert [f["algorithm"] for f in findings] == ["ElGamal", "ElGamal"]
        assert [f["line"] for f in findings] == [1, 2]

    def test_elgamal_is_not_reported_as_diffie_hellman(self):
        # Both rest on the discrete log, but they are separate entries with
        # separate replacement guidance.
        source = "from Crypto.PublicKey import ElGamal"
        assert algorithms(scan_python_source(source)) == {"ElGamal"}

    def test_findings_carry_both_snippets(self):
        source = "from Crypto.PublicKey import ElGamal"
        for finding in scan_python_source(source):
            assert finding["code_snippet"]
            assert finding["fix_snippet"]
            assert "ML-KEM" in finding["fix_snippet"]

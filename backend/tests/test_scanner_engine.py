"""Tests for scanner_engine's two entry points.

scan_repository's github_client layer is replaced with fakes via monkeypatch —
no real API calls are made. scan_directory runs against real temp directories.
"""

import asyncio

import pytest

import scanner_engine
from scanner_engine import scan_directory

REPORT_KEYS = {
    "repo",
    "scanned_files",
    "skipped_files",
    "total_findings",
    "pqc_readiness_score",
    "severity_summary",
    "findings_by_file",
    "algorithms_found",
    "languages_scanned",
    "rate_limit_remaining",
}


def run_scan(monkeypatch, contents, rate_limit_response):
    """Run scan_repository against a fake repo defined by {path: source}."""

    async def fake_check_rate_limit(token, client=None):
        return rate_limit_response

    async def fake_get_repo_files(repo_url, token, client=None):
        return list(contents)

    async def fake_get_file_content(owner, repo, path, token, client=None):
        return contents[path]

    monkeypatch.setattr(scanner_engine, "check_rate_limit", fake_check_rate_limit)
    monkeypatch.setattr(scanner_engine, "get_repo_files", fake_get_repo_files)
    monkeypatch.setattr(scanner_engine, "get_file_content", fake_get_file_content)

    return asyncio.run(
        scanner_engine.scan_repository(
            "https://github.com/acme/demo", "token", None
        )
    )


class TestScanRepository:
    def test_empty_repo(self, monkeypatch, mock_rate_limit_response):
        report = run_scan(monkeypatch, {}, mock_rate_limit_response)
        assert report["scanned_files"] == 0
        assert report["total_findings"] == 0
        assert report["pqc_readiness_score"] == 100
        assert report["findings_by_file"] == {}

    def test_repo_with_rsa_file(
        self, monkeypatch, sample_rsa_source, mock_rate_limit_response
    ):
        report = run_scan(
            monkeypatch, {"src/crypto.py": sample_rsa_source}, mock_rate_limit_response
        )
        assert report["total_findings"] > 0
        assert "RSA" in report["algorithms_found"]
        assert report["pqc_readiness_score"] < 100
        assert "src/crypto.py" in report["findings_by_file"]
        for finding in report["findings_by_file"]["src/crypto.py"]:
            assert finding["file"] == "src/crypto.py"

    def test_skipped_files_are_reported(
        self, monkeypatch, sample_safe_source, mock_rate_limit_response
    ):
        contents = {"src/ok.py": sample_safe_source, "src/huge.py": None}
        report = run_scan(monkeypatch, contents, mock_rate_limit_response)
        assert report["skipped_files"] == ["src/huge.py"]
        assert report["scanned_files"] == 1

    def test_report_structure(
        self, monkeypatch, sample_rsa_source, mock_rate_limit_response
    ):
        report = run_scan(
            monkeypatch, {"a.py": sample_rsa_source}, mock_rate_limit_response
        )
        assert set(report) == REPORT_KEYS
        assert report["repo"] == "acme/demo"
        assert (
            report["rate_limit_remaining"] == mock_rate_limit_response["remaining"]
        )

    def test_javascript_file_is_scanned_with_the_js_scanner(
        self, monkeypatch, mock_rate_limit_response
    ):
        contents = {"src/auth.js": "const s = crypto.createSign('RSA-SHA256');\n"}
        report = run_scan(monkeypatch, contents, mock_rate_limit_response)
        assert "RSA" in report["algorithms_found"]
        assert report["languages_scanned"] == ["javascript"]
        finding = report["findings_by_file"]["src/auth.js"][0]
        assert finding["language"] == "javascript"

    def test_typescript_file_is_scanned_with_the_js_scanner(
        self, monkeypatch, mock_rate_limit_response
    ):
        contents = {"src/hash.ts": "const h = crypto.createHash('md5');\n"}
        report = run_scan(monkeypatch, contents, mock_rate_limit_response)
        assert "MD5" in report["algorithms_found"]
        assert report["languages_scanned"] == ["typescript"]

    def test_go_file_is_scanned_with_the_go_scanner(
        self, monkeypatch, mock_rate_limit_response
    ):
        contents = {"cmd/keys.go": "priv, _ := rsa.GenerateKey(rand.Reader, 2048)\n"}
        report = run_scan(monkeypatch, contents, mock_rate_limit_response)
        assert "RSA" in report["algorithms_found"]
        assert report["languages_scanned"] == ["go"]
        finding = report["findings_by_file"]["cmd/keys.go"][0]
        assert finding["language"] == "go"
        # The Go fix snippet, not the Python one, reaches the report.
        assert "mlkem768" in finding["fix_snippet"]

    def test_java_file_is_scanned_with_the_java_scanner(
        self, monkeypatch, mock_rate_limit_response
    ):
        contents = {
            "src/main/java/Keys.java": (
                'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
            )
        }
        report = run_scan(monkeypatch, contents, mock_rate_limit_response)
        assert "RSA" in report["algorithms_found"]
        assert report["languages_scanned"] == ["java"]
        finding = report["findings_by_file"]["src/main/java/Keys.java"][0]
        assert finding["language"] == "java"
        # The Java fix snippet, not the Python one, reaches the report.
        assert "BouncyCastlePQCProvider" in finding["fix_snippet"]
        # Both halves the AI explain and patch endpoints require.
        assert finding["code_snippet"]

    def test_rust_file_is_scanned_with_the_rust_scanner(
        self, monkeypatch, mock_rate_limit_response
    ):
        contents = {"src/keys.rs": "use rsa::{RsaPrivateKey, RsaPublicKey};\n"}
        report = run_scan(monkeypatch, contents, mock_rate_limit_response)
        assert "RSA" in report["algorithms_found"]
        assert report["languages_scanned"] == ["rust"]
        finding = report["findings_by_file"]["src/keys.rs"][0]
        assert finding["language"] == "rust"
        # The Rust fix snippet, not the Python one, reaches the report.
        assert "pqcrypto_mlkem" in finding["fix_snippet"]
        # Both halves the AI explain and patch endpoints require.
        assert finding["code_snippet"]

    def test_mixed_language_repo_reports_every_language(
        self, monkeypatch, sample_rsa_source, mock_rate_limit_response
    ):
        contents = {
            "server.py": sample_rsa_source,
            "src/hash.js": "const h = crypto.createHash('md5');\n",
            "src/sign.tsx": "const s = crypto.createSign('RSA-SHA256');\n",
        }
        report = run_scan(monkeypatch, contents, mock_rate_limit_response)
        assert report["scanned_files"] == 3
        assert report["languages_scanned"] == ["javascript", "python", "typescript"]
        assert "RSA" in report["algorithms_found"]
        assert "MD5" in report["algorithms_found"]
        languages = {
            finding["language"]
            for findings in report["findings_by_file"].values()
            for finding in findings
        }
        assert languages == {"python", "javascript", "typescript"}

    def test_file_entries_may_be_dicts_with_a_language(
        self, monkeypatch, mock_rate_limit_response
    ):
        """get_repo_files returns {"path", "language"} dicts since F13."""

        async def fake_check_rate_limit(token, client=None):
            return mock_rate_limit_response

        async def fake_get_repo_files(repo_url, token, client=None):
            return [{"path": "a.js", "language": "javascript"}]

        async def fake_get_file_content(owner, repo, path, token, client=None):
            return "const h = crypto.createHash('md5');\n"

        monkeypatch.setattr(scanner_engine, "check_rate_limit", fake_check_rate_limit)
        monkeypatch.setattr(scanner_engine, "get_repo_files", fake_get_repo_files)
        monkeypatch.setattr(scanner_engine, "get_file_content", fake_get_file_content)

        report = asyncio.run(
            scanner_engine.scan_repository("https://github.com/acme/demo", "t", None)
        )
        assert report["languages_scanned"] == ["javascript"]
        assert "MD5" in report["algorithms_found"]

    def test_severity_summary_keys(
        self, monkeypatch, sample_rsa_source, mock_rate_limit_response
    ):
        report = run_scan(
            monkeypatch, {"a.py": sample_rsa_source}, mock_rate_limit_response
        )
        assert set(report["severity_summary"]) == {
            "critical",
            "warning",
            "safe",
            "info",
        }


class TestScanDirectory:
    """The local path qlint_cli uses in CI. No network, no credentials."""

    def test_report_matches_the_repo_scan_shape(self, tmp_path, sample_rsa_source):
        (tmp_path / "a.py").write_text(sample_rsa_source, encoding="utf-8")
        report = scan_directory(tmp_path)
        # Same keys as a GitHub scan, minus the two that only a GitHub scan can
        # know, plus the local path that replaces them.
        assert set(report) == (REPORT_KEYS - {"rate_limit_remaining"}) | {"path"}
        assert report["repo"] == tmp_path.name
        assert "RSA" in report["algorithms_found"]

    def test_findings_use_relative_posix_paths(self, tmp_path, sample_rsa_source):
        nested = tmp_path / "src" / "crypto"
        nested.mkdir(parents=True)
        (nested / "keys.py").write_text(sample_rsa_source, encoding="utf-8")
        report = scan_directory(tmp_path)
        assert "src/crypto/keys.py" in report["findings_by_file"]
        for finding in report["findings_by_file"]["src/crypto/keys.py"]:
            assert finding["file"] == "src/crypto/keys.py"

    def test_every_supported_language_is_picked_up(self, tmp_path):
        (tmp_path / "a.py").write_text("import hashlib", encoding="utf-8")
        (tmp_path / "b.js").write_text(
            "crypto.createHash('md5');", encoding="utf-8"
        )
        (tmp_path / "c.ts").write_text(
            "crypto.createSign('RSA-SHA256');", encoding="utf-8"
        )
        (tmp_path / "d.go").write_text(
            "priv, _ := rsa.GenerateKey(rand.Reader, 2048)", encoding="utf-8"
        )
        (tmp_path / "E.java").write_text(
            'Cipher c = Cipher.getInstance("RSA");', encoding="utf-8"
        )
        (tmp_path / "f.rs").write_text(
            "use rsa::RsaPrivateKey;", encoding="utf-8"
        )
        report = scan_directory(tmp_path)
        assert report["scanned_files"] == 6
        assert report["languages_scanned"] == [
            "go",
            "java",
            "javascript",
            "python",
            "rust",
            "typescript",
        ]

    def test_java_file_is_scanned_with_the_java_scanner(self, tmp_path):
        """The CLI path routes Java too, not just the GitHub path."""
        source = tmp_path / "src" / "main" / "java"
        source.mkdir(parents=True)
        (source / "Keys.java").write_text(
            'MessageDigest md = MessageDigest.getInstance("MD5");\n',
            encoding="utf-8",
        )
        report = scan_directory(tmp_path)
        assert report["languages_scanned"] == ["java"]
        assert "MD5" in report["algorithms_found"]
        finding = report["findings_by_file"]["src/main/java/Keys.java"][0]
        assert finding["language"] == "java"
        assert finding["code_snippet"]
        assert "SHA3-512" in finding["fix_snippet"]

    def test_rust_file_is_scanned_with_the_rust_scanner(self, tmp_path):
        """The CLI path routes Rust too, not just the GitHub path."""
        source = tmp_path / "src"
        source.mkdir(parents=True)
        (source / "digest.rs").write_text(
            "use md_5::{Md5, Digest};\n", encoding="utf-8"
        )
        report = scan_directory(tmp_path)
        assert report["languages_scanned"] == ["rust"]
        assert "MD5" in report["algorithms_found"]
        finding = report["findings_by_file"]["src/digest.rs"][0]
        assert finding["language"] == "rust"
        assert finding["code_snippet"]
        assert "sha3::{Sha3_512, Digest}" in finding["fix_snippet"]

    def test_unsupported_extensions_are_ignored(self, tmp_path):
        (tmp_path / "notes.md").write_text("rsa.generate_private_key()", encoding="utf-8")
        (tmp_path / "config.yml").write_text("key: rsa", encoding="utf-8")
        report = scan_directory(tmp_path)
        assert report["scanned_files"] == 0
        assert report["total_findings"] == 0

    @pytest.mark.parametrize("excluded", ["node_modules", "__pycache__", ".git", ".venv"])
    def test_vendored_and_hidden_trees_are_pruned(
        self, tmp_path, sample_rsa_source, excluded
    ):
        skipped = tmp_path / excluded
        skipped.mkdir()
        (skipped / "dep.py").write_text(sample_rsa_source, encoding="utf-8")
        (tmp_path / "app.py").write_text("x = 1", encoding="utf-8")
        report = scan_directory(tmp_path)
        assert report["scanned_files"] == 1
        assert report["findings_by_file"] == {}

    def test_an_empty_directory_scores_a_perfect_report(self, tmp_path):
        report = scan_directory(tmp_path)
        assert report["scanned_files"] == 0
        assert report["total_findings"] == 0
        assert report["pqc_readiness_score"] == 100

    def test_oversized_files_are_skipped_not_scanned(
        self, tmp_path, sample_rsa_source, monkeypatch
    ):
        monkeypatch.setattr(scanner_engine, "MAX_FILE_SIZE", 10)
        (tmp_path / "big.py").write_text(sample_rsa_source, encoding="utf-8")
        report = scan_directory(tmp_path)
        assert report["skipped_files"] == ["big.py"]
        assert report["scanned_files"] == 0

    def test_exclude_patterns_drop_files_before_they_are_read(
        self, tmp_path, sample_rsa_source
    ):
        (tmp_path / "keep.py").write_text(sample_rsa_source, encoding="utf-8")
        (tmp_path / "drop.py").write_text(sample_rsa_source, encoding="utf-8")
        report = scan_directory(tmp_path, exclude=["drop.py"])
        assert report["scanned_files"] == 1
        assert set(report["findings_by_file"]) == {"keep.py"}
        assert report["skipped_files"] == []

    def test_exclude_prunes_whole_subtrees(self, tmp_path, sample_rsa_source):
        nested = tmp_path / "bench" / "deep"
        nested.mkdir(parents=True)
        (nested / "baseline.py").write_text(sample_rsa_source, encoding="utf-8")
        (tmp_path / "app.py").write_text(sample_rsa_source, encoding="utf-8")
        report = scan_directory(tmp_path, exclude=["bench"])
        assert report["scanned_files"] == 1
        assert set(report["findings_by_file"]) == {"app.py"}

    @pytest.mark.parametrize(
        "pattern", ["bench/baseline.py", "bench/*", "*/baseline.py", "bench"]
    )
    def test_pattern_spellings_that_must_all_match(
        self, tmp_path, sample_rsa_source, pattern
    ):
        (tmp_path / "bench").mkdir()
        (tmp_path / "bench" / "baseline.py").write_text(
            sample_rsa_source, encoding="utf-8"
        )
        report = scan_directory(tmp_path, exclude=[pattern])
        assert report["scanned_files"] == 0

    @pytest.mark.parametrize(
        "pattern", ["bench\\baseline.py", "./bench/baseline.py", "/bench/baseline.py"]
    )
    def test_separator_and_prefix_noise_in_patterns_is_normalized(
        self, tmp_path, sample_rsa_source, pattern
    ):
        (tmp_path / "bench").mkdir()
        (tmp_path / "bench" / "baseline.py").write_text(
            sample_rsa_source, encoding="utf-8"
        )
        assert scan_directory(tmp_path, exclude=[pattern])["scanned_files"] == 0

    def test_a_non_matching_pattern_excludes_nothing(self, tmp_path, sample_rsa_source):
        (tmp_path / "app.py").write_text(sample_rsa_source, encoding="utf-8")
        report = scan_directory(tmp_path, exclude=["nothing/here.py", "*.rs"])
        assert report["scanned_files"] == 1

    def test_pattern_matching_is_case_sensitive_on_every_platform(
        self, tmp_path, sample_rsa_source
    ):
        # A Windows dev and a Linux runner must agree on what got excluded.
        (tmp_path / "Bench").mkdir()
        (tmp_path / "Bench" / "baseline.py").write_text(
            sample_rsa_source, encoding="utf-8"
        )
        assert scan_directory(tmp_path, exclude=["bench"])["scanned_files"] == 1
        assert scan_directory(tmp_path, exclude=["Bench"])["scanned_files"] == 0

    def test_no_excludes_is_the_default(self, tmp_path, sample_rsa_source):
        (tmp_path / "app.py").write_text(sample_rsa_source, encoding="utf-8")
        assert scan_directory(tmp_path)["scanned_files"] == 1
        assert scan_directory(tmp_path, exclude=None)["scanned_files"] == 1
        assert scan_directory(tmp_path, exclude=[])["scanned_files"] == 1

    def test_a_missing_directory_raises_not_a_directory(self, tmp_path):
        with pytest.raises(NotADirectoryError):
            scan_directory(tmp_path / "nope")

    def test_a_file_path_raises_not_a_directory(self, tmp_path):
        target = tmp_path / "a.py"
        target.write_text("x = 1", encoding="utf-8")
        with pytest.raises(NotADirectoryError):
            scan_directory(target)

"""Tests for the standalone CI scanner (qlint_cli.py).

run() returns the process exit code instead of calling sys.exit, so every case
here is an ordinary function call against a real temporary directory tree.
"""

import json

import pytest

import qlint_cli
from qlint_cli import failing_findings, run, split_excludes

RSA_SOURCE = """
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""

# AES-128 is "warning", not "critical": Grover halves its strength but does not
# break it. It is the only tier that separates --fail-on critical from warning.
AES128_SOURCE = """
from cryptography.hazmat.primitives.ciphers import algorithms

cipher = algorithms.AES128(key)
"""

CLEAN_SOURCE = """
def add(a, b):
    return a + b
"""


@pytest.fixture
def vulnerable_repo(tmp_path):
    """A checkout with a critical (RSA) finding, plus noise that must be skipped."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "auth.py").write_text(RSA_SOURCE, encoding="utf-8")
    (tmp_path / "src" / "helpers.py").write_text(CLEAN_SOURCE, encoding="utf-8")
    (tmp_path / "README.md").write_text("not source", encoding="utf-8")
    return tmp_path


@pytest.fixture
def clean_repo(tmp_path):
    (tmp_path / "ok.py").write_text(CLEAN_SOURCE, encoding="utf-8")
    return tmp_path


def sarif_of(path):
    return json.loads(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ scanning


def test_a_vulnerable_directory_produces_findings(vulnerable_repo, tmp_path, capsys):
    output = tmp_path / "out.sarif"
    code = run(["--path", str(vulnerable_repo), "--output", str(output)])

    assert code == 1  # RSA is critical, and critical is the default fail-on
    results = sarif_of(output)["runs"][0]["results"]
    assert results
    assert "RSA" in {result["ruleId"] for result in results}
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ].endswith("src/auth.py")


def test_the_summary_reports_files_and_severities(vulnerable_repo, tmp_path, capsys):
    run(["--path", str(vulnerable_repo), "--output", str(tmp_path / "out.sarif")])
    out = capsys.readouterr().out
    assert "Files scanned:  2" in out  # the two .py files, not README.md
    assert "critical" in out
    assert "RSA" in out


def test_vendored_and_hidden_directories_are_not_scanned(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text(
        "crypto.createHash('md5');", encoding="utf-8"
    )
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hook.py").write_text(RSA_SOURCE, encoding="utf-8")
    (tmp_path / "app.py").write_text(CLEAN_SOURCE, encoding="utf-8")

    output = tmp_path / "out.json"
    code = run(["--path", str(tmp_path), "--output", str(output), "--format", "json"])
    report = json.loads(output.read_text(encoding="utf-8"))

    assert code == 0
    assert report["scanned_files"] == 1
    assert report["total_findings"] == 0


def test_an_empty_directory_scans_cleanly(tmp_path):
    (tmp_path / "empty").mkdir()
    output = tmp_path / "out.sarif"
    code = run(["--path", str(tmp_path / "empty"), "--output", str(output)])
    assert code == 0
    assert sarif_of(output)["runs"][0]["results"] == []


def test_a_clean_directory_produces_zero_findings_and_exits_zero(clean_repo, tmp_path):
    output = tmp_path / "out.sarif"
    assert run(["--path", str(clean_repo), "--output", str(output)]) == 0
    assert sarif_of(output)["runs"][0]["results"] == []


# -------------------------------------------------------------------- output


def test_output_is_written_to_the_requested_path(vulnerable_repo, tmp_path):
    output = tmp_path / "nested" / "dir" / "results.sarif"
    run(["--path", str(vulnerable_repo), "--output", str(output)])
    assert output.is_file()
    assert sarif_of(output)["version"] == "2.1.0"


def test_the_default_output_path_is_used_when_none_is_given(
    vulnerable_repo, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    run(["--path", str(vulnerable_repo)])
    assert (tmp_path / qlint_cli.DEFAULT_OUTPUT).is_file()


def test_sarif_and_json_formats_produce_different_shapes(vulnerable_repo, tmp_path):
    sarif_path = tmp_path / "out.sarif"
    json_path = tmp_path / "out.json"
    run(["--path", str(vulnerable_repo), "--output", str(sarif_path)])
    run(
        [
            "--path",
            str(vulnerable_repo),
            "--output",
            str(json_path),
            "--format",
            "json",
        ]
    )

    sarif = sarif_of(sarif_path)
    report = json.loads(json_path.read_text(encoding="utf-8"))

    # SARIF is the tool-facing log...
    assert sarif["version"] == "2.1.0"
    assert set(sarif) == {"$schema", "version", "runs"}
    # ...the JSON format is the raw report the API serves.
    assert "runs" not in report
    assert report["findings_by_file"]
    assert set(report) >= {
        "scanned_files",
        "total_findings",
        "pqc_readiness_score",
        "severity_summary",
        "findings_by_file",
        "algorithms_found",
    }
    # Same underlying scan either way.
    assert len(sarif["runs"][0]["results"]) == report["total_findings"]


def test_sarif_output_matches_the_converter_used_by_the_api(vulnerable_repo, tmp_path):
    """The CLI must not be a divergent code path — same converter, same output."""
    from sarif_converter import convert_to_sarif
    from scanner_engine import scan_directory

    output = tmp_path / "out.sarif"
    run(["--path", str(vulnerable_repo), "--output", str(output)])
    assert sarif_of(output) == convert_to_sarif(scan_directory(vulnerable_repo))


# ------------------------------------------------------------------- fail-on


def test_fail_on_critical_exits_one_when_a_critical_finding_exists(
    vulnerable_repo, tmp_path
):
    code = run(
        [
            "--path",
            str(vulnerable_repo),
            "--output",
            str(tmp_path / "out.sarif"),
            "--fail-on",
            "critical",
        ]
    )
    assert code == 1


def test_fail_on_critical_exits_zero_without_critical_findings(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "cipher.py").write_text(AES128_SOURCE, encoding="utf-8")

    output = tmp_path / "out.json"
    code = run(
        [
            "--path",
            str(source),
            "--output",
            str(output),
            "--format",
            "json",
            "--fail-on",
            "critical",
        ]
    )
    report = json.loads(output.read_text(encoding="utf-8"))

    assert report["severity_summary"]["critical"] == 0
    assert report["severity_summary"]["warning"] > 0  # AES-128 is a warning
    assert code == 0  # ...which does not trip a critical-only gate


def test_fail_on_warning_also_trips_on_warnings(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "cipher.py").write_text(AES128_SOURCE, encoding="utf-8")
    code = run(
        [
            "--path",
            str(source),
            "--output",
            str(tmp_path / "out.sarif"),
            "--fail-on",
            "warning",
        ]
    )
    assert code == 1


def test_fail_on_none_always_exits_zero(vulnerable_repo, tmp_path):
    code = run(
        [
            "--path",
            str(vulnerable_repo),
            "--output",
            str(tmp_path / "out.sarif"),
            "--fail-on",
            "none",
        ]
    )
    assert code == 0


def test_fail_on_none_still_writes_the_findings(vulnerable_repo, tmp_path):
    """Exit 0 must not mean an empty report — upload-sarif still needs the results."""
    output = tmp_path / "out.sarif"
    run(
        [
            "--path",
            str(vulnerable_repo),
            "--output",
            str(output),
            "--fail-on",
            "none",
        ]
    )
    assert sarif_of(output)["runs"][0]["results"]


@pytest.mark.parametrize(
    "fail_on,expected",
    [("critical", 1), ("warning", 2), ("none", 0)],
)
def test_failing_findings_respects_the_threshold(fail_on, expected):
    report = {
        "findings_by_file": {
            "a.py": [
                {"algorithm": "RSA", "severity": "critical", "file": "a.py", "line": 1},
                {"algorithm": "AES-128", "severity": "warning", "file": "a.py", "line": 2},
                {"algorithm": "SHA-512", "severity": "safe", "file": "a.py", "line": 3},
                {"algorithm": "hashlib", "severity": "info", "file": "a.py", "line": 4},
            ]
        }
    }
    assert len(failing_findings(report, fail_on)) == expected


def test_failing_findings_lists_the_worst_severity_first():
    report = {
        "findings_by_file": {
            "a.py": [
                {"algorithm": "AES-128", "severity": "warning", "file": "a.py", "line": 9},
                {"algorithm": "RSA", "severity": "critical", "file": "a.py", "line": 1},
            ]
        }
    }
    assert [f["severity"] for f in failing_findings(report, "warning")] == [
        "critical",
        "warning",
    ]


def test_failing_findings_tolerates_a_report_without_findings():
    assert failing_findings({}, "critical") == []
    assert failing_findings({"findings_by_file": None}, "critical") == []


# ------------------------------------------------------------------- exclude


@pytest.fixture
def benchmark_repo(tmp_path):
    """The shape that motivated --exclude: one real file, one deliberate baseline."""
    (tmp_path / "app.py").write_text(RSA_SOURCE, encoding="utf-8")
    (tmp_path / "benchmarks").mkdir()
    (tmp_path / "benchmarks" / "baseline.py").write_text(RSA_SOURCE, encoding="utf-8")
    (tmp_path / "benchmarks" / "helper.py").write_text(RSA_SOURCE, encoding="utf-8")
    return tmp_path


def report_from(argv, output):
    run(argv)
    return json.loads(output.read_text(encoding="utf-8"))


def test_excluded_files_are_not_scanned_at_all(benchmark_repo, tmp_path):
    """The point of --exclude: excluded files leave the report entirely.

    Not merely filtered out of the findings afterwards — they must not be
    counted in scanned_files either, or the summary misreports the scan.
    """
    output = tmp_path / "out.json"
    baseline = report_from(
        ["--path", str(benchmark_repo), "--output", str(output), "--format", "json",
         "--fail-on", "none"],
        output,
    )
    assert baseline["scanned_files"] == 3
    assert set(baseline["findings_by_file"]) == {
        "app.py",
        "benchmarks/baseline.py",
        "benchmarks/helper.py",
    }

    excluded = report_from(
        ["--path", str(benchmark_repo), "--output", str(output), "--format", "json",
         "--fail-on", "none", "--exclude", "benchmarks/baseline.py"],
        output,
    )
    assert excluded["scanned_files"] == 2  # not 3 with one filtered out
    assert "benchmarks/baseline.py" not in excluded["findings_by_file"]
    assert "benchmarks/baseline.py" not in excluded["skipped_files"]
    assert excluded["total_findings"] < baseline["total_findings"]


def test_excluding_a_directory_excludes_everything_under_it(benchmark_repo, tmp_path):
    output = tmp_path / "out.json"
    report = report_from(
        ["--path", str(benchmark_repo), "--output", str(output), "--format", "json",
         "--fail-on", "none", "--exclude", "benchmarks"],
        output,
    )
    assert report["scanned_files"] == 1
    assert set(report["findings_by_file"]) == {"app.py"}


def test_exclude_removes_the_findings_from_the_sarif_too(benchmark_repo, tmp_path):
    output = tmp_path / "out.sarif"
    run(
        ["--path", str(benchmark_repo), "--output", str(output), "--fail-on", "none",
         "--exclude", "benchmarks/*"]
    )
    uris = {
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for result in sarif_of(output)["runs"][0]["results"]
    }
    assert uris == {"app.py"}


def test_exclude_can_turn_a_failing_scan_green(benchmark_repo, tmp_path):
    """The self-scan case: exclude the deliberate baselines, gate on the rest."""
    output = tmp_path / "out.sarif"
    assert run(["--path", str(benchmark_repo), "--output", str(output)]) == 1
    assert (
        run(
            ["--path", str(benchmark_repo), "--output", str(output),
             "--exclude", "app.py,benchmarks"]
        )
        == 0
    )


def test_exclude_accepts_repeated_flags_and_comma_separated_values(
    benchmark_repo, tmp_path
):
    output = tmp_path / "out.json"
    repeated = report_from(
        ["--path", str(benchmark_repo), "--output", str(output), "--format", "json",
         "--fail-on", "none",
         "--exclude", "benchmarks/baseline.py",
         "--exclude", "benchmarks/helper.py"],
        output,
    )
    comma = report_from(
        ["--path", str(benchmark_repo), "--output", str(output), "--format", "json",
         "--fail-on", "none",
         "--exclude", "benchmarks/baseline.py,benchmarks/helper.py"],
        output,
    )
    assert repeated["scanned_files"] == comma["scanned_files"] == 1
    assert repeated["findings_by_file"] == comma["findings_by_file"]


def test_a_glob_pattern_matches_by_filename(benchmark_repo, tmp_path):
    output = tmp_path / "out.json"
    report = report_from(
        ["--path", str(benchmark_repo), "--output", str(output), "--format", "json",
         "--fail-on", "none", "--exclude", "*/baseline.py"],
        output,
    )
    assert set(report["findings_by_file"]) == {"app.py", "benchmarks/helper.py"}


def test_the_summary_names_the_active_excludes(benchmark_repo, tmp_path, capsys):
    run(
        ["--path", str(benchmark_repo), "--output", str(tmp_path / "o.sarif"),
         "--fail-on", "none", "--exclude", "benchmarks"]
    )
    assert "Excluding:      benchmarks" in capsys.readouterr().out


def test_no_exclude_flag_leaves_the_scan_untouched(benchmark_repo, tmp_path, capsys):
    output = tmp_path / "out.json"
    report = report_from(
        ["--path", str(benchmark_repo), "--output", str(output), "--format", "json",
         "--fail-on", "none"],
        output,
    )
    assert report["scanned_files"] == 3
    assert "Excluding:" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "values,expected",
    [
        (None, []),
        ([], []),
        (["a.py"], ["a.py"]),
        (["a.py,b.py"], ["a.py", "b.py"]),
        (["a.py", "b.py,c.py"], ["a.py", "b.py", "c.py"]),
        ([" a.py , b.py "], ["a.py", "b.py"]),
        (["", ",", " "], []),  # an empty value must not become a match-everything
    ],
)
def test_split_excludes_flattens_both_spellings(values, expected):
    assert split_excludes(values) == expected


def test_an_empty_exclude_value_does_not_exclude_anything(benchmark_repo, tmp_path):
    output = tmp_path / "out.json"
    report = report_from(
        ["--path", str(benchmark_repo), "--output", str(output), "--format", "json",
         "--fail-on", "none", "--exclude", ""],
        output,
    )
    assert report["scanned_files"] == 3


# --------------------------------------------------------------- error paths


def test_a_missing_path_is_a_clear_error_not_a_crash(tmp_path, capsys):
    code = run(["--path", str(tmp_path / "nope"), "--output", str(tmp_path / "o.sarif")])
    assert code == 1
    error = capsys.readouterr().err
    assert "not an existing directory" in error
    assert "nope" in error


def test_pointing_path_at_a_file_is_a_clear_error(tmp_path, capsys):
    target = tmp_path / "a.py"
    target.write_text(CLEAN_SOURCE, encoding="utf-8")
    code = run(["--path", str(target), "--output", str(tmp_path / "o.sarif")])
    assert code == 1
    assert "not an existing directory" in capsys.readouterr().err


def test_an_unwritable_output_path_is_reported_not_raised(
    vulnerable_repo, tmp_path, monkeypatch, capsys
):
    def refuse(*args, **kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr(qlint_cli.Path, "write_text", refuse)
    code = run(["--path", str(vulnerable_repo), "--output", str(tmp_path / "o.sarif")])
    assert code == 1
    assert "could not write" in capsys.readouterr().err


def test_an_unexpected_scan_failure_still_exits_cleanly(
    vulnerable_repo, tmp_path, monkeypatch, capsys
):
    def explode(_directory, exclude=None):
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(qlint_cli, "scan_directory", explode)
    code = run(["--path", str(vulnerable_repo), "--output", str(tmp_path / "o.sarif")])
    assert code == 1
    assert "scan failed: RuntimeError: scanner exploded" in capsys.readouterr().err


def test_an_invalid_fail_on_is_rejected_by_the_parser(tmp_path):
    # argparse exits 2 for a bad flag value; that is the standard CLI contract
    # and distinguishes "you invoked me wrong" from "the scan found something".
    with pytest.raises(SystemExit) as exc:
        run(["--path", str(tmp_path), "--fail-on", "whenever"])
    assert exc.value.code == 2

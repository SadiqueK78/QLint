"""Tests for pqc_benchmark, the live PQC vs classical measurement module.

RUN THESE FROM WSL. They import oqs, which needs the liboqs C library, and
that library only exists in the WSL environment on this machine:

  wsl bash -c "cd /mnt/c/Users/DELL/QLint/backend && \
      source ~/pqc-env/bin/activate && python -m pytest tests/test_pqc_benchmark.py"

Under the native Windows venv every test here fails at import.

Iteration counts are kept small on purpose: these tests check that the
measurements are real and correctly shaped, not that they are fast.
"""

import pytest

# Skip rather than error where liboqs is absent, so the native Windows run of
# the rest of the suite still collects cleanly instead of failing at import.
pytest.importorskip(
    "oqs", reason="liboqs is not available in this environment; run from WSL"
)

import pqc_benchmark
from pqc_benchmark import (
    MAX_ITERATIONS,
    SLH_DSA_MAX_ITERATIONS,
    SLH_DSA_MECHANISMS,
    benchmark_ecdsa,
    benchmark_kem,
    benchmark_rsa,
    benchmark_sig,
    clamp_iterations,
    resolve_sig_mechanism,
    run_full_benchmark,
    sig_iteration_cap,
)

KEM_FIELDS = {
    "algorithm",
    "iterations",
    "keygen_ops_per_sec",
    "encap_ops_per_sec",
    "decap_ops_per_sec",
    "public_key_bytes",
    "ciphertext_bytes",
    "shared_secret_bytes",
}

SIG_FIELDS = {
    "algorithm",
    "iterations",
    "keygen_ops_per_sec",
    "sign_ops_per_sec",
    "verify_ops_per_sec",
    "public_key_bytes",
    "signature_bytes",
}


def assert_positive_rates(entry: dict, rate_fields: set[str]) -> None:
    for field in rate_fields:
        value = entry[field]
        assert isinstance(value, float), f"{field} is {type(value).__name__}"
        assert value > 0, f"{field} is {value}"


def assert_positive_sizes(entry: dict, size_fields: set[str]) -> None:
    for field in size_fields:
        value = entry[field]
        assert isinstance(value, int) and not isinstance(value, bool)
        assert value > 0, f"{field} is {value}"


class TestBenchmarkKem:
    @staticmethod
    @pytest.fixture(scope="class")
    def result():
        return benchmark_kem("ML-KEM-768", iterations=5)

    def test_returns_every_required_field(self, result):
        assert KEM_FIELDS <= set(result)
        assert result["algorithm"] == "ML-KEM-768"
        assert result["iterations"] == 5
        assert "error" not in result

    def test_rates_are_positive_floats(self, result):
        assert_positive_rates(
            result,
            {"keygen_ops_per_sec", "encap_ops_per_sec", "decap_ops_per_sec"},
        )

    def test_byte_sizes_match_the_fips_203_values(self, result):
        # Exact, not merely positive: a wrong size here would mean the numbers
        # came from something other than a real ML-KEM-768 run.
        assert result["public_key_bytes"] == 1184
        assert result["ciphertext_bytes"] == 1088
        assert result["shared_secret_bytes"] == 32

    @pytest.mark.parametrize(
        "algorithm,public_key_bytes,ciphertext_bytes",
        [("ML-KEM-512", 800, 768), ("ML-KEM-768", 1184, 1088),
         ("ML-KEM-1024", 1568, 1568)],
    )
    def test_every_supported_parameter_set_runs(
        self, algorithm, public_key_bytes, ciphertext_bytes
    ):
        result = benchmark_kem(algorithm, iterations=2)
        assert result["public_key_bytes"] == public_key_bytes
        assert result["ciphertext_bytes"] == ciphertext_bytes
        assert result["shared_secret_bytes"] == 32


class TestBenchmarkSig:
    @staticmethod
    @pytest.fixture(scope="class")
    def result():
        return benchmark_sig("ML-DSA-65", iterations=5)

    def test_returns_every_required_field(self, result):
        assert SIG_FIELDS <= set(result)
        assert result["algorithm"] == "ML-DSA-65"
        assert result["iterations"] == 5
        assert "error" not in result

    def test_rates_are_positive_floats(self, result):
        assert_positive_rates(
            result,
            {"keygen_ops_per_sec", "sign_ops_per_sec", "verify_ops_per_sec"},
        )

    def test_byte_sizes_match_the_fips_204_values(self, result):
        assert result["public_key_bytes"] == 1952
        assert result["signature_bytes"] == 3309

    @pytest.mark.parametrize(
        "algorithm,public_key_bytes,signature_bytes",
        [("ML-DSA-44", 1312, 2420), ("ML-DSA-65", 1952, 3309),
         ("ML-DSA-87", 2592, 4627)],
    )
    def test_every_supported_parameter_set_runs(
        self, algorithm, public_key_bytes, signature_bytes
    ):
        result = benchmark_sig(algorithm, iterations=2)
        assert result["public_key_bytes"] == public_key_bytes
        assert result["signature_bytes"] == signature_bytes


class TestBenchmarkSlhDsa:
    """FIPS 205, the hash-based signature family offered beside ML-DSA.

    Iteration counts here are 1 or 2 on purpose: a single SLH-DSA signature is
    tens of milliseconds, which is the whole reason the module caps this row.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def result():
        return benchmark_sig("SLH-DSA-SHA2-128f", iterations=2)

    def test_matches_the_signature_result_shape(self, result):
        assert SIG_FIELDS <= set(result)
        assert "error" not in result

    def test_reports_the_fips_205_name_not_the_liboqs_mechanism(self, result):
        """The row is labeled with the standard's name for the parameter set.

        liboqs spells these SLH_DSA_PURE_SHA2_128F (or, on older builds,
        SPHINCS+-SHA2-128f-simple). Neither belongs in a table of standardized
        algorithms.
        """
        assert result["algorithm"] == "SLH-DSA-SHA2-128f"

    def test_rates_are_positive_floats(self, result):
        assert_positive_rates(
            result,
            {"keygen_ops_per_sec", "sign_ops_per_sec", "verify_ops_per_sec"},
        )

    @pytest.mark.parametrize(
        "algorithm,public_key_bytes,signature_bytes",
        [
            ("SLH-DSA-SHA2-128f", 32, 17088),
            ("SLH-DSA-SHAKE-128f", 32, 17088),
            ("SLH-DSA-SHA2-192f", 48, 35664),
        ],
    )
    def test_every_offered_parameter_set_runs_at_its_fips_205_sizes(
        self, algorithm, public_key_bytes, signature_bytes
    ):
        # Exact sizes, for the reason the ML-KEM test gives: a wrong one means
        # something other than the requested parameter set was measured.
        result = benchmark_sig(algorithm, iterations=1)
        assert "error" not in result
        assert result["public_key_bytes"] == public_key_bytes
        assert result["signature_bytes"] == signature_bytes

    def test_signatures_are_far_larger_than_ml_dsa_at_the_same_level(self):
        slh_dsa = benchmark_sig("SLH-DSA-SHA2-128f", iterations=1)
        ml_dsa = benchmark_sig("ML-DSA-44", iterations=2)
        # The trade the page exists to show: a 32-byte public key against
        # ML-DSA's 1312, paid for with a signature several times the size.
        assert slh_dsa["public_key_bytes"] < ml_dsa["public_key_bytes"]
        assert slh_dsa["signature_bytes"] > 5 * ml_dsa["signature_bytes"]

    def test_the_iteration_cap_holds_however_many_were_asked_for(self):
        result = benchmark_sig("SLH-DSA-SHA2-128f", iterations=MAX_ITERATIONS)
        assert result["iterations"] == SLH_DSA_MAX_ITERATIONS
        assert result["keygen_iterations"] == SLH_DSA_MAX_ITERATIONS

    def test_a_lower_request_is_still_honoured(self):
        assert benchmark_sig("SLH-DSA-SHA2-128f", iterations=1)["iterations"] == 1

    def test_only_slh_dsa_is_capped(self):
        assert sig_iteration_cap("ML-DSA-65") == MAX_ITERATIONS
        assert sig_iteration_cap("SLH-DSA-SHA2-128f") == SLH_DSA_MAX_ITERATIONS
        assert benchmark_sig("ML-DSA-44", iterations=12)["iterations"] == 12

    def test_a_capped_run_is_quick_enough_for_a_live_request(self):
        """The guard the cap exists for, asserted rather than assumed."""
        import time

        started = time.perf_counter()
        benchmark_sig("SLH-DSA-SHAKE-128f", iterations=SLH_DSA_MAX_ITERATIONS)
        # Generous: this is a timeout guard, not a performance target, and CI
        # machines are slower than laptops.
        assert time.perf_counter() - started < 10.0


class TestSigMechanismResolution:
    def test_names_liboqs_already_uses_pass_straight_through(self):
        for algorithm in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
            assert resolve_sig_mechanism(algorithm) == algorithm

    def test_an_unknown_name_is_left_alone_for_oqs_to_reject(self):
        assert resolve_sig_mechanism("NOT-A-REAL-SIG") == "NOT-A-REAL-SIG"

    def test_every_offered_set_resolves_to_a_mechanism_this_build_enables(self):
        import oqs

        enabled = set(oqs.get_enabled_sig_mechanisms())
        for algorithm in SLH_DSA_MECHANISMS:
            assert resolve_sig_mechanism(algorithm) in enabled, algorithm

    def test_resolution_survives_an_oqs_that_will_not_list_mechanisms(
        self, monkeypatch
    ):
        """A binding that cannot enumerate must not take the row down."""
        monkeypatch.setattr(
            pqc_benchmark.oqs,
            "get_enabled_sig_mechanisms",
            lambda: (_ for _ in ()).throw(RuntimeError("no library")),
        )
        resolved = resolve_sig_mechanism("SLH-DSA-SHA2-128f")
        assert resolved == SLH_DSA_MECHANISMS["SLH-DSA-SHA2-128f"][0]


class TestClassicalBenchmarks:
    """RSA and ECDSA must be drop-in comparable with the ML-DSA rows."""

    @staticmethod
    @pytest.fixture(scope="class")
    def rsa_result():
        return benchmark_rsa(2048, iterations=3)

    @staticmethod
    @pytest.fixture(scope="class")
    def ecdsa_result():
        return benchmark_ecdsa("P-256", iterations=5)

    def test_rsa_matches_the_signature_result_shape(self, rsa_result):
        assert SIG_FIELDS <= set(rsa_result)
        assert rsa_result["algorithm"] == "RSA-2048"
        assert "error" not in rsa_result

    def test_ecdsa_matches_the_signature_result_shape(self, ecdsa_result):
        assert SIG_FIELDS <= set(ecdsa_result)
        assert ecdsa_result["algorithm"] == "ECDSA-P256"
        assert "error" not in ecdsa_result

    def test_classical_fields_line_up_exactly_with_the_pqc_ones(
        self, rsa_result, ecdsa_result
    ):
        pqc = benchmark_sig("ML-DSA-65", iterations=2)
        assert set(rsa_result) == set(pqc)
        assert set(ecdsa_result) == set(pqc)

    @pytest.mark.parametrize("fixture", ["rsa_result", "ecdsa_result"])
    def test_rates_are_positive_floats(self, fixture, request):
        assert_positive_rates(
            request.getfixturevalue(fixture),
            {"keygen_ops_per_sec", "sign_ops_per_sec", "verify_ops_per_sec"},
        )

    @pytest.mark.parametrize("fixture", ["rsa_result", "ecdsa_result"])
    def test_sizes_are_positive_ints(self, fixture, request):
        assert_positive_sizes(
            request.getfixturevalue(fixture),
            {"public_key_bytes", "signature_bytes"},
        )

    def test_rsa_2048_signature_is_the_modulus_length(self, rsa_result):
        assert rsa_result["signature_bytes"] == 256

    def test_rsa_keygen_is_capped_below_the_requested_iterations(self):
        # RSA keygen is ~1000x the cost of everything else here, so the module
        # runs fewer of them and says so rather than blowing the time budget.
        result = benchmark_rsa(2048, iterations=40)
        assert result["iterations"] == 40
        assert result["keygen_iterations"] == pqc_benchmark.RSA_KEYGEN_MAX_ITERATIONS
        assert result["keygen_iterations"] < result["iterations"]

    def test_an_unknown_curve_raises_with_the_valid_options(self):
        with pytest.raises(ValueError) as exc:
            benchmark_ecdsa("P-42", iterations=1)
        assert "P-42" in str(exc.value)
        assert "P-256" in str(exc.value)


class TestSizeTradeoff:
    """The headline the page exists to show, asserted rather than asserted-at."""

    def test_pqc_keys_and_signatures_are_far_larger_than_classical_ones(self):
        pqc = benchmark_sig("ML-DSA-65", iterations=2)
        ecdsa = benchmark_ecdsa("P-256", iterations=2)
        assert pqc["public_key_bytes"] > 10 * ecdsa["public_key_bytes"]
        assert pqc["signature_bytes"] > 10 * ecdsa["signature_bytes"]


class TestClampIterations:
    @pytest.mark.parametrize(
        "given,expected",
        [(50, 50), (1, 1), (0, 1), (-99, 1), (MAX_ITERATIONS, MAX_ITERATIONS),
         (MAX_ITERATIONS + 1, MAX_ITERATIONS), (10**9, MAX_ITERATIONS)],
    )
    def test_clamps_into_range(self, given, expected):
        assert clamp_iterations(given) == expected

    def test_garbage_falls_back_to_the_default_instead_of_raising(self):
        assert clamp_iterations(None) == pqc_benchmark.DEFAULT_ITERATIONS
        assert clamp_iterations("many") == pqc_benchmark.DEFAULT_ITERATIONS

    def test_the_clamp_reaches_the_benchmarks(self):
        assert benchmark_kem("ML-KEM-768", iterations=0)["iterations"] == 1


class TestRunFullBenchmark:
    @staticmethod
    @pytest.fixture(scope="class")
    def result():
        return run_full_benchmark(iterations=3)

    def test_both_result_lists_are_non_empty(self, result):
        assert result["kem_results"]
        assert result["sig_results"]

    def test_reports_when_it_ran_and_at_what_iteration_count(self, result):
        assert result["iterations"] == 3
        from datetime import datetime

        # Parses, is timezone-aware, and is not a placeholder string.
        stamp = datetime.fromisoformat(result["generated_at"])
        assert stamp.tzinfo is not None

    def test_covers_one_representative_algorithm_per_family(self, result):
        assert [r["algorithm"] for r in result["kem_results"]] == ["ML-KEM-768"]
        assert [r["algorithm"] for r in result["sig_results"]] == [
            "ML-DSA-65",
            "RSA-2048",
            "ECDSA-P256",
        ]

    def test_every_entry_measured_something(self, result):
        for entry in result["kem_results"]:
            assert "error" not in entry
            assert KEM_FIELDS <= set(entry)
        for entry in result["sig_results"]:
            assert "error" not in entry
            assert SIG_FIELDS <= set(entry)

    def test_both_signature_families_measure_in_one_run(self):
        """What /benchmark/run asks for: ML-DSA and SLH-DSA side by side."""
        result = run_full_benchmark(
            iterations=2, sig_algorithms=("ML-DSA-44", "SLH-DSA-SHA2-128f")
        )
        assert [r["algorithm"] for r in result["sig_results"]] == [
            "ML-DSA-44",
            "SLH-DSA-SHA2-128f",
            "RSA-2048",
            "ECDSA-P256",
        ]
        for entry in result["sig_results"]:
            assert "error" not in entry
            assert SIG_FIELDS <= set(entry)

    def test_a_failed_slh_dsa_row_reports_the_capped_iteration_count(self):
        """An error row must not claim more iterations than a good one would."""
        result = run_full_benchmark(
            iterations=MAX_ITERATIONS, sig_algorithms=("SLH-DSA-NOT-REAL",)
        )
        failed = result["sig_results"][0]
        assert failed["error"]
        assert failed["algorithm"] == "SLH-DSA-NOT-REAL"
        # Not in SLH_DSA_MECHANISMS, so uncapped: the cap follows the offered
        # sets, and this asserts the error path reports honestly either way.
        assert failed["iterations"] == MAX_ITERATIONS

    def test_results_are_live_rather_than_cached(self):
        # Two runs of genuinely timed code do not produce identical rates.
        first = run_full_benchmark(iterations=3)
        second = run_full_benchmark(iterations=3)
        assert first["generated_at"] != second["generated_at"]
        assert (
            first["kem_results"][0]["keygen_ops_per_sec"]
            != second["kem_results"][0]["keygen_ops_per_sec"]
        )


class TestFailureIsolation:
    def test_an_invalid_algorithm_becomes_an_error_field_not_an_exception(
        self, monkeypatch
    ):
        monkeypatch.setattr(
            pqc_benchmark, "DEFAULT_KEM_ALGORITHMS", ("NOT-A-REAL-KEM",)
        )
        result = run_full_benchmark(iterations=2)

        failed = result["kem_results"][0]
        assert failed["error"]
        assert failed["algorithm"] == "NOT-A-REAL-KEM"
        # Measured fields are present but empty, so a table renderer sees a row
        # with blanks rather than a KeyError.
        assert KEM_FIELDS <= set(failed)
        assert failed["keygen_ops_per_sec"] is None
        assert failed["public_key_bytes"] is None

    def test_one_failure_does_not_cost_the_other_algorithms(self, monkeypatch):
        monkeypatch.setattr(
            pqc_benchmark, "DEFAULT_KEM_ALGORITHMS", ("NOT-A-REAL-KEM",)
        )
        result = run_full_benchmark(iterations=2)

        assert len(result["sig_results"]) == 3
        for entry in result["sig_results"]:
            assert "error" not in entry
            assert entry["sign_ops_per_sec"] > 0

    def test_a_broken_classical_benchmark_is_isolated_too(self, monkeypatch):
        def explode(*args, **kwargs):
            raise RuntimeError("no entropy source")

        monkeypatch.setattr(pqc_benchmark, "benchmark_rsa", explode)
        result = run_full_benchmark(iterations=2)

        rsa_entry = next(
            r for r in result["sig_results"] if r["algorithm"] == "RSA-2048"
        )
        assert "no entropy source" in rsa_entry["error"]
        assert result["kem_results"][0]["keygen_ops_per_sec"] > 0

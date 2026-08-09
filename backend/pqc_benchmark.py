"""Live benchmarks of NIST post-quantum algorithms against classical ones.

Everything this module reports is measured on the machine that runs it, in
the moment it is asked. Nothing is looked up from a table: each figure comes
from actually generating keys, encapsulating secrets, signing, and verifying,
timed with time.perf_counter().

The post-quantum side runs through liboqs (via the oqs Python binding), which
needs the liboqs C library present in the process. That is the one hard
environment requirement here: importing this module fails outright without it.
The classical side runs through `cryptography`, which the project already
depends on via python-jose[cryptography].

Two measurement choices worth stating plainly, because they affect how the
numbers compare:

  * Key and signature sizes are read with len() off the real objects each run
    produces, not from a specification table. ML-KEM and ML-DSA hand back raw
    byte strings, so those sizes are the raw ones. RSA and ECDSA public keys
    have no canonical raw form, so they are measured as DER SubjectPublicKeyInfo
    -- a few bytes of structure larger than the bare key material. ECDSA
    signatures are DER-encoded and vary by a byte or two between runs.
  * RSA key generation is a rejection-sampling search for primes, so it costs
    roughly a thousand times what every other operation here costs and varies
    wildly run to run. Running it the full iteration count would dominate the
    wall clock of an interactive benchmark, so it is capped separately at
    RSA_KEYGEN_MAX_ITERATIONS. Every result reports the keygen_iterations it
    actually used, so the cap is visible rather than hidden.

Pure functions and no framework imports: this module is runnable and testable
on its own, and benchmark_router.py is the only thing that knows about HTTP.
"""

import time
from datetime import datetime, timezone

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Signed by every signature benchmark, so RSA, ECDSA and ML-DSA are all timed
# over identical input and the comparison is not skewed by message length.
TEST_MESSAGE = b"QLint PQC benchmark: the quick brown fox jumps over the lazy dog"

DEFAULT_ITERATIONS = 50
MIN_ITERATIONS = 1
# Ceiling on what any caller can ask for. The router imports this rather than
# defining its own, so the HTTP cap and the module cap cannot drift apart.
MAX_ITERATIONS = 200

# See the module docstring: RSA keygen is the one operation slow enough to
# blow the time budget of a live button click.
RSA_KEYGEN_MAX_ITERATIONS = 10

# The default run covers one representative security level per family rather
# than every variant, so a click returns in a couple of seconds.
DEFAULT_KEM_ALGORITHMS: tuple[str, ...] = ("ML-KEM-768",)
DEFAULT_SIG_ALGORITHMS: tuple[str, ...] = ("ML-DSA-65",)
DEFAULT_RSA_KEY_SIZE = 2048
DEFAULT_ECDSA_CURVE = "P-256"

_ECDSA_CURVES: dict[str, type] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}

_PQC_SIZE_NOTE = (
    "Sizes are the raw byte strings liboqs returns, measured with len()."
)
_RSA_NOTE = (
    "RSASSA-PSS with MGF1-SHA256 and a salt the length of the digest. Public "
    "key size is DER SubjectPublicKeyInfo, which carries a little structural "
    "overhead over the bare modulus."
)
_ECDSA_NOTE = (
    "ECDSA over SHA-256. Public key size is DER SubjectPublicKeyInfo; the "
    "signature is DER-encoded, so its length moves by a byte or two per run."
)


def clamp_iterations(iterations: int) -> int:
    """Force an iteration count into [MIN_ITERATIONS, MAX_ITERATIONS].

    Silently, and without raising on garbage: a caller asking for a million
    iterations, or for "50", gets a sane run rather than an error page. The
    router relies on this to keep a hostile query string from pinning a CPU.
    """
    try:
        value = int(iterations)
    except (TypeError, ValueError):
        return DEFAULT_ITERATIONS
    return max(MIN_ITERATIONS, min(value, MAX_ITERATIONS))


def _ops_per_sec(iterations: int, elapsed_seconds: float) -> float:
    # perf_counter is nanosecond-resolution and real crypto is never free, so
    # the floor here is belt-and-braces against a division by zero rather than
    # a case that is expected to fire.
    return float(iterations) / max(elapsed_seconds, 1e-9)


def benchmark_kem(algorithm: str, iterations: int = DEFAULT_ITERATIONS) -> dict:
    """Time keygen, encapsulation and decapsulation for an ML-KEM parameter set.

    Handles "ML-KEM-512", "ML-KEM-768" and "ML-KEM-1024", plus anything else
    the installed liboqs enables. Each iteration checks that the encapsulated
    and decapsulated shared secrets actually match, so a run that reports
    numbers is a run where the KEM demonstrably worked; the check sits outside
    every timed region.

    Raises whatever oqs raises for an unsupported algorithm. run_full_benchmark
    is the caller that turns that into an error entry.
    """
    iterations = clamp_iterations(iterations)
    keygen_seconds = 0.0
    encap_seconds = 0.0
    decap_seconds = 0.0

    with oqs.KeyEncapsulation(algorithm) as kem:
        for _ in range(iterations):
            start = time.perf_counter()
            public_key = kem.generate_keypair()
            keygen_seconds += time.perf_counter() - start

            start = time.perf_counter()
            ciphertext, secret_sent = kem.encap_secret(public_key)
            encap_seconds += time.perf_counter() - start

            start = time.perf_counter()
            secret_received = kem.decap_secret(ciphertext)
            decap_seconds += time.perf_counter() - start

            if secret_sent != secret_received:
                raise RuntimeError(
                    f"{algorithm} shared secrets did not match: the KEM is "
                    f"not working correctly in this environment"
                )

    return {
        "algorithm": algorithm,
        "family": "post-quantum",
        "iterations": iterations,
        "keygen_iterations": iterations,
        "keygen_ops_per_sec": _ops_per_sec(iterations, keygen_seconds),
        "encap_ops_per_sec": _ops_per_sec(iterations, encap_seconds),
        "decap_ops_per_sec": _ops_per_sec(iterations, decap_seconds),
        "public_key_bytes": len(public_key),
        "ciphertext_bytes": len(ciphertext),
        "shared_secret_bytes": len(secret_sent),
        "notes": _PQC_SIZE_NOTE,
    }


def benchmark_sig(algorithm: str, iterations: int = DEFAULT_ITERATIONS) -> dict:
    """Time keygen, signing and verification for an ML-DSA parameter set.

    Handles "ML-DSA-44", "ML-DSA-65" and "ML-DSA-87", plus anything else the
    installed liboqs enables. A failed verification aborts the run rather than
    being reported as throughput, for the same reason the KEM checks its
    shared secrets.
    """
    iterations = clamp_iterations(iterations)
    keygen_seconds = 0.0
    sign_seconds = 0.0
    verify_seconds = 0.0

    with oqs.Signature(algorithm) as signer:
        for _ in range(iterations):
            start = time.perf_counter()
            public_key = signer.generate_keypair()
            keygen_seconds += time.perf_counter() - start

            start = time.perf_counter()
            signature = signer.sign(TEST_MESSAGE)
            sign_seconds += time.perf_counter() - start

            start = time.perf_counter()
            verified = signer.verify(TEST_MESSAGE, signature, public_key)
            verify_seconds += time.perf_counter() - start

            if not verified:
                raise RuntimeError(
                    f"{algorithm} failed to verify its own signature: the "
                    f"algorithm is not working correctly in this environment"
                )

    return {
        "algorithm": algorithm,
        "family": "post-quantum",
        "iterations": iterations,
        "keygen_iterations": iterations,
        "keygen_ops_per_sec": _ops_per_sec(iterations, keygen_seconds),
        "sign_ops_per_sec": _ops_per_sec(iterations, sign_seconds),
        "verify_ops_per_sec": _ops_per_sec(iterations, verify_seconds),
        "public_key_bytes": len(public_key),
        "signature_bytes": len(signature),
        "notes": _PQC_SIZE_NOTE,
    }


def benchmark_rsa(
    key_size: int = DEFAULT_RSA_KEY_SIZE, iterations: int = DEFAULT_ITERATIONS
) -> dict:
    """Time RSA keygen, signing and verification, shaped like benchmark_sig.

    Signing uses RSASSA-PSS (MGF1-SHA256, salt length equal to the digest),
    the padding current guidance prefers over PKCS#1 v1.5 for new signatures.

    Key generation runs at most RSA_KEYGEN_MAX_ITERATIONS times regardless of
    `iterations`; signing and verification run the full count. The returned
    keygen_iterations says which count produced keygen_ops_per_sec.
    """
    iterations = clamp_iterations(iterations)
    keygen_iterations = min(iterations, RSA_KEYGEN_MAX_ITERATIONS)
    pss = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH
    )

    keygen_seconds = 0.0
    private_key = None
    for _ in range(keygen_iterations):
        start = time.perf_counter()
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size
        )
        keygen_seconds += time.perf_counter() - start

    public_key = private_key.public_key()
    public_key_der = public_key.public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )

    sign_seconds = 0.0
    verify_seconds = 0.0
    for _ in range(iterations):
        start = time.perf_counter()
        signature = private_key.sign(TEST_MESSAGE, pss, hashes.SHA256())
        sign_seconds += time.perf_counter() - start

        start = time.perf_counter()
        # verify() raises InvalidSignature rather than returning False, so a
        # signature that did not check out aborts the run the same way a bad
        # ML-DSA verification does.
        public_key.verify(signature, TEST_MESSAGE, pss, hashes.SHA256())
        verify_seconds += time.perf_counter() - start

    return {
        "algorithm": f"RSA-{key_size}",
        "family": "classical",
        "iterations": iterations,
        "keygen_iterations": keygen_iterations,
        "keygen_ops_per_sec": _ops_per_sec(keygen_iterations, keygen_seconds),
        "sign_ops_per_sec": _ops_per_sec(iterations, sign_seconds),
        "verify_ops_per_sec": _ops_per_sec(iterations, verify_seconds),
        "public_key_bytes": len(public_key_der),
        "signature_bytes": len(signature),
        "notes": _RSA_NOTE,
    }


def benchmark_ecdsa(
    curve: str = DEFAULT_ECDSA_CURVE, iterations: int = DEFAULT_ITERATIONS
) -> dict:
    """Time ECDSA keygen, signing and verification, shaped like benchmark_sig.

    Accepts "P-256", "P-384" and "P-521"; anything else raises ValueError
    listing the options, which run_full_benchmark turns into an error entry.
    """
    if curve not in _ECDSA_CURVES:
        raise ValueError(
            f"Unknown curve: {curve!r}. Valid options: "
            f"{', '.join(sorted(_ECDSA_CURVES))}"
        )
    iterations = clamp_iterations(iterations)
    curve_factory = _ECDSA_CURVES[curve]
    algorithm = ec.ECDSA(hashes.SHA256())

    keygen_seconds = 0.0
    sign_seconds = 0.0
    verify_seconds = 0.0
    for _ in range(iterations):
        start = time.perf_counter()
        private_key = ec.generate_private_key(curve_factory())
        keygen_seconds += time.perf_counter() - start

        public_key = private_key.public_key()

        start = time.perf_counter()
        signature = private_key.sign(TEST_MESSAGE, algorithm)
        sign_seconds += time.perf_counter() - start

        start = time.perf_counter()
        # Raises InvalidSignature on failure; see the note in benchmark_rsa.
        public_key.verify(signature, TEST_MESSAGE, algorithm)
        verify_seconds += time.perf_counter() - start

    public_key_der = public_key.public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "algorithm": f"ECDSA-{curve.replace('-', '')}",
        "family": "classical",
        "iterations": iterations,
        "keygen_iterations": iterations,
        "keygen_ops_per_sec": _ops_per_sec(iterations, keygen_seconds),
        "sign_ops_per_sec": _ops_per_sec(iterations, sign_seconds),
        "verify_ops_per_sec": _ops_per_sec(iterations, verify_seconds),
        "public_key_bytes": len(public_key_der),
        "signature_bytes": len(signature),
        "notes": _ECDSA_NOTE,
    }


def _error_entry(algorithm: str, family: str, iterations: int, kind: str,
                 exc: Exception) -> dict:
    """A result row for a benchmark that failed, shaped like a successful one.

    Every measured field is None rather than absent, so a caller rendering a
    table gets a row with blanks instead of a crash, and `error` is the only
    thing it has to check.
    """
    entry = {
        "algorithm": algorithm,
        "family": family,
        "iterations": iterations,
        "keygen_iterations": 0,
        "keygen_ops_per_sec": None,
        "public_key_bytes": None,
        "error": f"{type(exc).__name__}: {exc}",
    }
    if kind == "kem":
        entry.update(
            encap_ops_per_sec=None,
            decap_ops_per_sec=None,
            ciphertext_bytes=None,
            shared_secret_bytes=None,
        )
    else:
        entry.update(
            sign_ops_per_sec=None, verify_ops_per_sec=None, signature_bytes=None
        )
    return entry


def _safe(algorithm: str, family: str, iterations: int, kind: str,
          run) -> dict:
    """Run one benchmark, converting any failure into an error entry.

    Catching bare Exception is deliberate: liboqs surfaces missing algorithms,
    build mismatches and native-layer problems through several unrelated
    exception types, and one broken algorithm must not cost the caller every
    other measurement in the run.
    """
    try:
        return run()
    except Exception as exc:
        return _error_entry(algorithm, family, iterations, kind, exc)


def run_full_benchmark(
    iterations: int = DEFAULT_ITERATIONS,
    kem_algorithms: tuple[str, ...] | None = None,
    sig_algorithms: tuple[str, ...] | None = None,
) -> dict:
    """Measure one representative algorithm from each family, live.

    Defaults to ML-KEM-768, ML-DSA-65, RSA-2048 and ECDSA P-256 -- enough to
    show the post-quantum/classical trade-off without the wait of a full
    sweep. At the default iteration count the whole run is a couple of
    seconds, nearly all of it RSA key generation.

    `kem_algorithms` and `sig_algorithms` let a caller pick which post-quantum
    parameter sets to measure; the classical RSA and ECDSA rows are fixed,
    because they are the baseline the post-quantum numbers are read against
    rather than a variable of the experiment. Both default to None rather than
    to the module constants directly, so the constants stay late-bound and a
    test that patches them still steers the run.

    Never raises. An algorithm that fails contributes an entry carrying an
    `error` field and None measurements, and the rest of the run continues.
    """
    if kem_algorithms is None:
        kem_algorithms = DEFAULT_KEM_ALGORITHMS
    if sig_algorithms is None:
        sig_algorithms = DEFAULT_SIG_ALGORITHMS
    iterations = clamp_iterations(iterations)
    started = time.perf_counter()

    kem_results = [
        _safe(
            algorithm,
            "post-quantum",
            iterations,
            "kem",
            lambda algorithm=algorithm: benchmark_kem(algorithm, iterations),
        )
        for algorithm in kem_algorithms
    ]

    sig_results = [
        _safe(
            algorithm,
            "post-quantum",
            iterations,
            "sig",
            lambda algorithm=algorithm: benchmark_sig(algorithm, iterations),
        )
        for algorithm in sig_algorithms
    ]
    sig_results.append(
        _safe(
            f"RSA-{DEFAULT_RSA_KEY_SIZE}",
            "classical",
            iterations,
            "sig",
            lambda: benchmark_rsa(DEFAULT_RSA_KEY_SIZE, iterations),
        )
    )
    sig_results.append(
        _safe(
            f"ECDSA-{DEFAULT_ECDSA_CURVE.replace('-', '')}",
            "classical",
            iterations,
            "sig",
            lambda: benchmark_ecdsa(DEFAULT_ECDSA_CURVE, iterations),
        )
    )

    return {
        "kem_results": kem_results,
        "sig_results": sig_results,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "iterations": iterations,
        "total_seconds": round(time.perf_counter() - started, 3),
        "liboqs_version": oqs.oqs_version(),
    }


if __name__ == "__main__":
    result = run_full_benchmark(iterations=10)
    print(f"pqc_benchmark.py self-test passed")
    for r in result["kem_results"]:
        print(f"  {r['algorithm']}: keygen {r['keygen_ops_per_sec']:.1f} ops/sec, pubkey {r['public_key_bytes']} bytes")
    for r in result["sig_results"]:
        print(f"  {r['algorithm']}: sign {r['sign_ops_per_sec']:.1f} ops/sec, sig {r['signature_bytes']} bytes")

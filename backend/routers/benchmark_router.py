"""Live PQC vs classical benchmark endpoint.

This module imports pqc_benchmark, which imports oqs, which needs the liboqs C
library present in the process:

  * Locally, right now, that means the backend has to be launched from WSL
    (source ~/pqc-env/bin/activate) whenever this endpoint is exercised. The
    native Windows venv cannot import oqs.
  * In production it is handled at deploy time in F25, where the container
    image builds liboqs alongside the app.

The import is therefore guarded. A hard import would mean a backend started
without liboqs -- which is every native Windows dev run today -- fails at
startup and takes scanning, auth and history down with it. Instead the route
stays mounted and answers 503 with an explanation, matching how main.py already
degrades when MongoDB is absent rather than refusing to boot.

No rate limiting is applied. The project has no rate-limit middleware or
decorator to reuse (scan_router only checks GitHub's own API quota, which is a
different thing), and adding a dependency for one public endpoint is not worth
it. The abuse ceiling comes instead from clamp_iterations, which bounds the
work any single request can ask for.
"""

from fastapi import APIRouter, HTTPException

try:
    from pqc_benchmark import (
        DEFAULT_ITERATIONS,
        MAX_ITERATIONS,
        SLH_DSA_MAX_ITERATIONS,
        run_full_benchmark,
    )

    BENCHMARK_AVAILABLE = True
    IMPORT_ERROR = ""
except ImportError as exc:  # liboqs (or the oqs binding) is not in this process
    BENCHMARK_AVAILABLE = False
    IMPORT_ERROR = str(exc)
    DEFAULT_ITERATIONS = 50
    MAX_ITERATIONS = 200
    SLH_DSA_MAX_ITERATIONS = 10
    run_full_benchmark = None

UNAVAILABLE = (
    "The PQC benchmark needs the liboqs native library, which this backend "
    "process does not have. Start the backend from an environment where "
    "liboqs is built (locally: WSL with the pqc-env virtualenv activated)."
)

router = APIRouter(prefix="/benchmark")

# The NIST security levels the caller may choose between. Allow-lists rather
# than "whatever liboqs enables": these three parameter sets per family are the
# standardized ones, they are what the UI offers, and pinning the list here
# means an unsupported name is answered with a 400 naming the options instead
# of a per-algorithm error entry buried in an otherwise-successful 200.
KEM_ALGORITHMS: tuple[str, ...] = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
SIG_ALGORITHMS: tuple[str, ...] = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")

# FIPS 205's hash-based signatures, the second standardized signature family
# and the conservative alternative to ML-DSA: its security rests on hash
# functions alone rather than on a lattice problem. Same allow-list discipline
# as the two above, and the same names pqc_benchmark.SLH_DSA_MECHANISMS knows
# how to resolve against whatever liboqs the process loaded.
#
# Only fast-signing ("f") sets are offered, and only the 128- and 192-bit
# levels: the "s" sets sign roughly fifteen times slower for a smaller
# signature, which is the wrong end of the trade for a live request.
#
# Unlike the two families above, this one has no default and is measured only
# when a caller names a set. The two deploys are independent, so a backend
# carrying this feature will serve the previous frontend for a while, and that
# frontend must keep getting exactly the response it got before: three
# sig_results entries, ML-DSA and the two classical rows. An opt-in parameter
# is the only version of that with no window where the answer changes under a
# caller that did not ask for it.
SLH_DSA_ALGORITHMS: tuple[str, ...] = (
    "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHA2-192f",
)

DEFAULT_KEM_ALGORITHM = "ML-KEM-768"
DEFAULT_SIG_ALGORITHM = "ML-DSA-65"


def _validate(value: str, allowed: tuple[str, ...], parameter: str) -> str:
    """Return `value` if it is in `allowed`, else raise 400 listing the options.

    A silent fallback to the default would be worse than an error here: the
    whole point of the page is that the numbers belong to the algorithm named
    beside them, so quietly measuring something else would make the tool lie.
    """
    if value not in allowed:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown {parameter}: {value!r}. Valid options: "
                f"{', '.join(allowed)}"
            ),
        )
    return value


@router.get("/run")
def run(
    iterations: int = DEFAULT_ITERATIONS,
    kem_algorithm: str = DEFAULT_KEM_ALGORITHM,
    sig_algorithm: str = DEFAULT_SIG_ALGORITHM,
    slh_dsa_algorithm: str | None = None,
):
    """Measure chosen ML-KEM and ML-DSA sets against RSA and ECDSA.

    Public on purpose: this is a showcase of real post-quantum cryptography
    running server-side, not something tied to a user's scans, so it takes no
    auth and touches no scan data.

    The post-quantum parameter sets are selectable so a caller can watch key
    and signature sizes move across NIST security levels. The classical pair is
    deliberately fixed: it is the baseline the post-quantum numbers are read
    against, and a moving baseline would make two runs incomparable.

    `slh_dsa_algorithm` is the one parameter with no default. Naming a FIPS 205
    set adds a fourth signature row, between ML-DSA and the classical pair, and
    omitting it returns exactly the three-entry sig_results this endpoint
    returned before SLH-DSA existed. See SLH_DSA_ALGORITHMS for why that is
    opt-in rather than defaulted.

    `iterations` is clamped into [1, MAX_ITERATIONS] silently rather than
    rejected, so a caller passing 100000 gets a real answer for a bounded
    amount of work instead of a 422 or a pinned CPU. An SLH-DSA row is capped
    further, at SLH_DSA_MAX_ITERATIONS, because its signing costs tens of
    milliseconds where ML-DSA's costs one or two; the row reports the count it
    actually ran. Algorithm names are validated strictly instead, for the
    reason given in _validate.

    Declared `def`, not `async def`, deliberately: the benchmark is seconds of
    blocking CPU work, and FastAPI runs sync endpoints in a threadpool, so one
    person clicking Run Benchmark does not stall every other request.
    """
    if not BENCHMARK_AVAILABLE:
        raise HTTPException(status_code=503, detail=f"{UNAVAILABLE} ({IMPORT_ERROR})")

    kem_algorithm = _validate(kem_algorithm, KEM_ALGORITHMS, "kem_algorithm")
    sig_algorithm = _validate(sig_algorithm, SIG_ALGORITHMS, "sig_algorithm")

    # Order matters to the reader more than to the code: the post-quantum
    # signature rows first, then the classical baseline run_full_benchmark
    # appends. An omitted slh_dsa_algorithm measures nothing extra -- not an
    # empty row, no row at all.
    sig_algorithms = (sig_algorithm,)
    if slh_dsa_algorithm is not None:
        sig_algorithms += (
            _validate(slh_dsa_algorithm, SLH_DSA_ALGORITHMS, "slh_dsa_algorithm"),
        )

    return run_full_benchmark(
        iterations=iterations,
        kem_algorithms=(kem_algorithm,),
        sig_algorithms=sig_algorithms,
    )

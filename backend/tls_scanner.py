"""Level 1 scanning: what a website's TLS actually negotiates, over the wire.

Every other scanner in QLint reads source code. This one opens a socket to a
host somebody typed into a form. Deciding whether that host may be connected to
at all is not this module's job -- it is ssrf_guard's, which is where the URL
parsing, DNS resolution and address blocklist now live, because a second
feature (HTTP security headers) needs exactly the same decision and a validator
named for TLS is the wrong thing for it to import.

What stays here is everything TLS-specific: the handshake, the certificate, and
the classification of both against CRYPTO_DB.

One rule from the guard reaches into this file and has to be honoured here:
`_handshake` takes an IP address, never a hostname. The guard resolved the name
once and judged the answer; handing the *name* to ssl/socket would resolve it a
second time, and nothing says the second answer matches the first -- a DNS
server the attacker controls can return a public address to the check and
127.0.0.1 to the connection a moment later. The hostname travels only as the
SNI/verification name. There is exactly one resolution.

Scope is deliberately small: https only, port 443 only, no redirects, no
following anything the target says. The endpoint reports on the exact host it
was given or it fails.
"""

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from scanner_common import normalize_attack_vector
from ssrf_guard import (
    HTTPS_PORT,
    BlockedTargetError,
    InvalidTargetURLError,
    SSRFGuardError,
    TargetResolutionError,
    parse_target,
    validate_target,
)
from vulnerability_db import find_algorithm, get_severity_score

# Re-exported under this module's own name because the port is part of the TLS
# story here (443 is where TLS lives), and because `raw.connect((ip_address,
# TLS_PORT))` reads better in _handshake than a generic constant would.
TLS_PORT = HTTPS_PORT

# Names kept importable from this module so nothing that already depends on
# tls_scanner for them has to learn about ssrf_guard. They are the guard's
# types, not this module's -- the aliases exist for compatibility, not to
# suggest a TLS scan owns them.
__all__ = [
    "BlockedTargetError",
    "InvalidTargetURLError",
    "SSRFGuardError",
    "TLSConnectionError",
    "TLSScanError",
    "TargetResolutionError",
    "scan_url",
]

# Two bounds, because they fail differently. The handshake timeout is what the
# socket itself enforces, so a host that accepts the connection and then says
# nothing is dropped by the OS rather than by us. The overall timeout is the
# promise made to the request: resolution plus handshake plus parsing returns
# within it or the request is over, whatever the socket is doing.
HANDSHAKE_TIMEOUT_SECONDS = 5.0
OVERALL_TIMEOUT_SECONDS = 10.0


class TLSScanError(Exception):
    """Base for every failure this module reports."""


class TLSConnectionError(TLSScanError):
    """The target was allowed, and talking to it failed."""


# ---------------------------------------------------------------------------
# The handshake
# ---------------------------------------------------------------------------

# ssl's spelling of a protocol version, mapped to the one people write.
_PROTOCOL_NAMES = {
    "SSLv2": "SSL 2.0",
    "SSLv3": "SSL 3.0",
    "TLSv1": "TLS 1.0",
    "TLSv1.1": "TLS 1.1",
    "TLSv1.2": "TLS 1.2",
    "TLSv1.3": "TLS 1.3",
}


def _handshake(ip_address: str, hostname: str, verify: bool = True) -> dict:
    """Connect to one already-validated address and complete a TLS handshake.

    Takes an address, not a name. That is the point: the name was resolved and
    judged once by the caller, and re-resolving it here -- which is what
    passing `hostname` to create_connection would do -- would hand the target's
    DNS a second chance to answer differently.

    `verify=False` is the inspection mode, used only after a verified
    handshake has already failed on the certificate. It turns off trust
    checking so the certificate can be read and reported on; it does not make
    the certificate acceptable, and every caller that uses it records why it
    had to. Nothing in the returned report is trusted differently -- the
    verification failure becomes a High-severity finding of its own.

    Blocking on purpose; the caller runs it off the event loop.
    """
    family = (
        socket.AF_INET6 if ":" in ip_address else socket.AF_INET
    )
    context = ssl.create_default_context()
    if verify:
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        # Order matters: verify_mode cannot be set to CERT_NONE while
        # check_hostname is still True, so hostname checking goes first.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(HANDSHAKE_TIMEOUT_SECONDS)
    try:
        raw.connect((ip_address, TLS_PORT))
        with context.wrap_socket(raw, server_hostname=hostname) as tls:
            tls.settimeout(HANDSHAKE_TIMEOUT_SECONDS)
            cipher = tls.cipher() or (None, None, None)
            # binary_form, not the dict form: getpeercert() returns {} for an
            # unverified peer, but the DER is always there to be parsed.
            der = tls.getpeercert(binary_form=True)
            return {
                "protocol_raw": tls.version(),
                "cipher_name": cipher[0],
                "cipher_bits": cipher[2],
                "key_exchange_group": _negotiated_group(tls),
                "certificate_der": der,
                "peer_ip": ip_address,
            }
    finally:
        # wrap_socket owns `raw` on success and closes it with the `with`
        # block; closing twice is harmless and closing once is required on
        # every path that failed before the wrap.
        try:
            raw.close()
        except OSError:
            pass


def _negotiated_group(tls) -> str | None:
    """The key agreement group, when the runtime can report it.

    SSLSocket.group() needs Python 3.13 and OpenSSL 3.2, so it is asked for
    rather than assumed. It is worth asking: the group is the one field in the
    whole handshake that says whether this connection is already using a
    hybrid post-quantum key exchange, which is exactly what QLint is for.
    """
    getter = getattr(tls, "group", None)
    if getter is None:
        return None
    try:
        return getter()
    except (ssl.SSLError, OSError, NotImplementedError, ValueError):
        return None


def _verification_reason(exc: ssl.SSLCertVerificationError) -> str:
    """Why the certificate was rejected, in OpenSSL's words.

    getattr throughout: `verify_message` and `reason` are populated by the ssl
    module's own error path and are simply absent on an SSLError built any
    other way. Reading them directly is what turned a bad certificate into a
    500 once already.
    """
    return str(
        getattr(exc, "verify_message", None)
        or getattr(exc, "reason", None)
        or exc
    )


def _safe_describe(exc: Exception, hostname: str) -> str:
    """_describe_failure, guaranteed not to raise.

    Describing a failure means reading attributes off an exception object, and
    those attributes are not always present. An AttributeError raised inside an
    `except` block is not caught by that same block, so it would escape as a
    500 carrying the stack trace this whole layer exists to suppress -- which
    is exactly the bug this wrapper was written for.
    """
    try:
        return _describe_failure(exc, hostname)
    except Exception:  # pragma: no cover - the belt for the braces
        return f"The TLS scan of {hostname} failed."


def _describe_failure(exc: Exception, hostname: str) -> str:
    """One sentence saying what went wrong, with nothing internal in it.

    Every branch names the host and the failure mode. The exception text is
    included only where it comes from ssl/socket and describes the remote end;
    no traceback and no local detail reaches the caller.
    """
    if isinstance(exc, ssl.SSLCertVerificationError):
        # Only reached when the unverified retry *also* failed. An untrusted
        # certificate on its own is no longer an error at all -- it is read
        # from the untrusted chain and reported as a Certificate Validity
        # finding. So this describes a host that rejected the second
        # connection, not merely a host with a bad certificate.
        return (
            f"The certificate presented by {hostname} could not be verified "
            f"({_verification_reason(exc)}), and the host did not complete a "
            "second handshake for the certificate to be read and reported on."
        )
    if isinstance(exc, ssl.SSLError):
        why = getattr(exc, "reason", None) or exc
        return (
            f"The TLS handshake with {hostname} failed: {why}. "
            "The host accepted the connection but no shared TLS version and "
            "cipher suite could be agreed."
        )
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return (
            f"{hostname} did not complete a TLS handshake within "
            f"{HANDSHAKE_TIMEOUT_SECONDS:.0f} seconds, so the scan was "
            "abandoned."
        )
    if isinstance(exc, ConnectionRefusedError):
        return f"{hostname} refused the connection on port {TLS_PORT}."
    if isinstance(exc, ConnectionResetError):
        return f"{hostname} reset the connection before the handshake finished."
    if isinstance(exc, OSError):
        return (
            f"Could not reach {hostname} on port {TLS_PORT}: "
            f"{exc.strerror or exc}."
        )
    return f"The TLS scan of {hostname} failed: {exc}"


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------


def _common_name(name: x509.Name) -> str | None:
    values = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    if values:
        return str(values[0].value)
    # Modern certificates increasingly leave the subject CN out entirely and
    # carry the identity in the SAN, so fall back rather than reporting None
    # for a certificate that plainly names an organisation.
    values = name.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
    return str(values[0].value) if values else None


def _public_key_details(certificate: x509.Certificate) -> tuple[str, int | None, str]:
    """(algorithm, size in bits, the CRYPTO_DB identifier to look it up by)."""
    key = certificate.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, "RSA"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ECDSA", key.curve.key_size, "ECDSA"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 448, "Ed25519"
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size, "DSA"
    return type(key).__name__.replace("PublicKey", ""), None, ""


def _curve_name(certificate: x509.Certificate) -> str | None:
    key = certificate.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        return key.curve.name
    return None


def _signature_algorithm(certificate: x509.Certificate, key_algorithm: str) -> str:
    """"SHA256withRSA" and friends, built from the hash and the key type.

    Composed rather than read from a lookup of OID names so that a signature
    algorithm this code has never seen still comes back readable instead of
    coming back as a dotted OID.
    """
    try:
        hash_algorithm = certificate.signature_hash_algorithm
    except Exception:  # unsupported/unknown signature algorithm
        hash_algorithm = None
    if hash_algorithm is None:
        # Ed25519/Ed448 sign the message directly; there is no separate hash.
        return key_algorithm or _oid_name(certificate)
    return f"{hash_algorithm.name.upper()}with{key_algorithm}"


def _oid_name(certificate: x509.Certificate) -> str:
    oid = certificate.signature_algorithm_oid
    return getattr(oid, "_name", None) or oid.dotted_string


def _validity(certificate: x509.Certificate) -> tuple[datetime, datetime]:
    """not-before / not-after as aware UTC datetimes.

    The `_utc` properties are the non-deprecated spelling in cryptography 42+;
    the fallback keeps this working against an older pin without warning noise.
    """
    before = getattr(certificate, "not_valid_before_utc", None)
    after = getattr(certificate, "not_valid_after_utc", None)
    if before is None or after is None:  # pragma: no cover - older cryptography
        before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
        after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    return before, after


def parse_certificate(der: bytes) -> dict:
    """The certificate fields this report is built from."""
    if not der:
        raise TLSConnectionError(
            "The handshake completed but the server sent no certificate to "
            "inspect."
        )
    try:
        certificate = x509.load_der_x509_certificate(der)
    except Exception as exc:
        raise TLSConnectionError(
            f"The server's certificate could not be parsed: {exc}"
        ) from exc

    algorithm, key_size, db_key = _public_key_details(certificate)
    not_before, not_after = _validity(certificate)
    return {
        "subject_common_name": _common_name(certificate.subject),
        "issuer_common_name": _common_name(certificate.issuer),
        "public_key_algorithm": algorithm,
        "public_key_size_bits": key_size,
        "public_key_curve": _curve_name(certificate),
        "signature_algorithm": _signature_algorithm(certificate, algorithm),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": (not_after - datetime.now(timezone.utc)).days,
        "serial_number": format(certificate.serial_number, "x"),
        "_db_key": db_key,
    }


# ---------------------------------------------------------------------------
# Classification -- CRYPTO_DB, applied to a live handshake
# ---------------------------------------------------------------------------

# The display severity of a live TLS finding, which is not the same axis as
# CRYPTO_DB's. CRYPTO_DB answers "how urgent is migrating off this primitive",
# and RSA is "critical" there whatever the key size, because Shor breaks all of
# it. A TLS report also has to answer "how broken is this site right now", and
# an RSA-2048 certificate is not broken right now -- it is a perfectly ordinary
# certificate with a post-quantum problem ahead of it.
#
# So each finding carries both. `severity` is this axis, the one a reader of
# the report acts on today. `db_severity` is CRYPTO_DB's own verdict, passed
# through untouched, which is what feeds the readiness score below and what
# keeps a TLS finding comparable to a code finding for the same algorithm.
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"

STATUS_WEAK = "Weak"
STATUS_DEPRECATED = "Deprecated"
STATUS_ACCEPTABLE = "Acceptable"

# Protocol version -> (status, severity, recommendation). SSL 2.0/3.0 and
# TLS 1.0/1.1 are deprecated by RFC 8996 and rejected by every current browser.
_PROTOCOL_VERDICTS = {
    "SSL 2.0": (STATUS_WEAK, SEVERITY_CRITICAL, "Disable SSL 2.0"),
    "SSL 3.0": (STATUS_WEAK, SEVERITY_CRITICAL, "Disable SSL 3.0"),
    "TLS 1.0": (STATUS_DEPRECATED, SEVERITY_HIGH, "Disable TLS 1.0"),
    "TLS 1.1": (STATUS_DEPRECATED, SEVERITY_HIGH, "Disable TLS 1.1"),
    "TLS 1.2": (
        STATUS_ACCEPTABLE,
        SEVERITY_LOW,
        "Enable TLS 1.3 alongside TLS 1.2 for forward secrecy by default and a "
        "faster handshake",
    ),
    "TLS 1.3": (
        STATUS_ACCEPTABLE,
        SEVERITY_LOW,
        "No action needed. TLS 1.3 is the current standard and is the version "
        "hybrid post-quantum key exchange is being deployed on",
    ),
}

# Symmetric primitives, longest name first so AES-256 is matched before AES.
_CIPHER_PRIMITIVES = (
    ("CHACHA20", "ChaCha20", 256),
    ("AES_256", "AES-256", 256),
    ("AES256", "AES-256", 256),
    ("AES_128", "AES-128", 128),
    ("AES128", "AES-128", 128),
    ("3DES", "3DES", 112),
    ("DES_CBC3", "3DES", 112),
    ("RC4", "RC4", 128),
    ("DES", "DES", 56),
)

# Substrings that make a cipher suite unacceptable regardless of anything else.
_BROKEN_CIPHER_MARKERS = ("NULL", "EXPORT", "ANON", "_MD5", "-MD5", "RC4", "DES")

# ChaCha20 is negotiated by a large share of real sites but has no CRYPTO_DB
# entry, because no code scanner has ever had to name it: it is a TLS cipher,
# not something the language scanners find in source. Rather than widen
# CRYPTO_DB -- which every SARIF rule list and fix-snippet test enumerates --
# the one missing primitive is described here in CRYPTO_DB's own field names,
# so _quantum_risk and _finding read it exactly like a real entry.
_SYMMETRIC_FALLBACKS: dict[str, dict] = {
    # Shaped like AES-256's entry, which is the primitive it is equivalent to:
    # a 256-bit key, so Grover leaves ~128 bits and there is nothing to migrate.
    "ChaCha20": {
        "canonical_name": "ChaCha20",
        "severity": "safe",
        "quantum_vulnerable": False,
        "classical_vulnerable": False,
        "attack_vector": "None",
        "replacement": None,
    },
}


def _symmetric_entry(algorithm: str | None) -> dict | None:
    """The CRYPTO_DB entry for a cipher, or the local stand-in for ChaCha20."""
    if not algorithm:
        return None
    return find_algorithm(algorithm) or _SYMMETRIC_FALLBACKS.get(algorithm)


def _quantum_risk(entry: dict | None) -> str:
    """The quantum story for an algorithm, in CRYPTO_DB's own words.

    Not re-derived here. The attack vector and the vulnerable flag come
    straight out of the same table the code scanners read, so "Vulnerable to
    Shor's algorithm" means the same thing on a TLS certificate as it does on
    a line of Python.
    """
    if entry is None:
        return "Not assessed: this algorithm is not in QLint's database"
    if not entry.get("quantum_vulnerable"):
        return "No known quantum attack -- considered post-quantum safe"
    vector = normalize_attack_vector(entry.get("attack_vector")) or ""
    if vector.lower().startswith("shor"):
        return "Vulnerable to Shor's algorithm"
    if vector.lower().startswith("grover"):
        return "Weakened by Grover's algorithm (effective security halved)"
    return f"Vulnerable to {vector}" if vector else "Quantum-vulnerable"


def _finding(
    asset: str,
    kind: str,
    purpose: str,
    status: str,
    severity: str,
    recommendation: str,
    algorithm: str | None = None,
    key_size: str | None = None,
    entry: dict | None = None,
    db_severity: str | None = None,
) -> dict:
    """One row of the report.

    The first block is this domain's shape -- what the asset is, how it rates.
    The second block is carried over from a code-scan finding unchanged, so a
    consumer that already renders `quantum_vulnerable` / `attack_vector` /
    `replacement` for a line of source renders a TLS row with no new cases.
    """
    return {
        "asset": asset,
        "type": kind,
        "purpose": purpose,
        "algorithm": algorithm,
        "key_size": key_size,
        "status": status,
        "quantum_risk": _quantum_risk(entry),
        "severity": severity,
        "recommendation": recommendation,
        # CRYPTO_DB's own fields, passed through rather than restated.
        "db_severity": db_severity or (entry or {}).get("severity") or "info",
        "quantum_vulnerable": bool((entry or {}).get("quantum_vulnerable", False)),
        "classical_vulnerable": bool((entry or {}).get("classical_vulnerable", False)),
        # normalize_attack_vector, not the raw field: safe entries carry the
        # literal string "None", which is truthy and renders as "Attack vector:
        # None". The code scanners hit this first and this is their fix.
        "attack_vector": normalize_attack_vector((entry or {}).get("attack_vector")),
        "replacement": (entry or {}).get("replacement"),
    }


def _protocol_finding(protocol: str) -> dict:
    status, severity, recommendation = _PROTOCOL_VERDICTS.get(
        protocol, (STATUS_ACCEPTABLE, SEVERITY_LOW, "No action needed")
    )
    # A protocol version is not an algorithm, so there is no CRYPTO_DB entry to
    # read: the quantum risk of a TLS version lives in its key exchange and its
    # cipher, which get findings of their own below.
    db_severity = "critical" if severity in (SEVERITY_CRITICAL, SEVERITY_HIGH) else "safe"
    return _finding(
        asset=protocol,
        kind="Protocol",
        purpose="TLS Connection",
        status=status,
        severity=severity,
        recommendation=recommendation,
        algorithm=protocol,
        db_severity=db_severity,
    )


def _symmetric_primitive(cipher_name: str) -> tuple[str, int] | None:
    upper = (cipher_name or "").upper()
    for marker, name, bits in _CIPHER_PRIMITIVES:
        if marker in upper:
            return name, bits
    return None


def _cipher_finding(cipher_name: str, cipher_bits: int | None) -> dict:
    upper = (cipher_name or "").upper()
    primitive = _symmetric_primitive(cipher_name)
    algorithm = primitive[0] if primitive else None
    entry = _symmetric_entry(algorithm)

    broken = next((m for m in _BROKEN_CIPHER_MARKERS if m in upper), None)
    # "DES" also matches inside "3DES" and "AES"; only treat it as the standalone
    # cipher when the primitive lookup agrees.
    if broken in ("DES", "RC4") and algorithm not in ("DES", "3DES", "RC4"):
        broken = None

    if broken:
        status, severity = STATUS_WEAK, SEVERITY_CRITICAL
        recommendation = (
            f"Remove {cipher_name} from the enabled cipher suites. It is "
            "classically broken, not merely quantum-vulnerable. Prefer "
            "AES-256-GCM or ChaCha20-Poly1305 with an ECDHE key exchange."
        )
    elif primitive and primitive[1] < 128:
        status, severity = STATUS_WEAK, SEVERITY_HIGH
        recommendation = f"Replace {algorithm} with AES-256-GCM or ChaCha20-Poly1305"
    elif "CBC" in upper:
        status, severity = STATUS_DEPRECATED, SEVERITY_MEDIUM
        recommendation = (
            "Prefer an AEAD cipher suite (AES-GCM or ChaCha20-Poly1305) over "
            "CBC mode, which has a long history of padding-oracle attacks."
        )
    elif primitive and primitive[1] >= 256:
        status, severity = STATUS_ACCEPTABLE, SEVERITY_LOW
        recommendation = (
            "No action needed. A 256-bit symmetric cipher retains 128-bit "
            "security against Grover's algorithm."
        )
    else:
        status, severity = STATUS_ACCEPTABLE, SEVERITY_MEDIUM
        recommendation = (
            "Acceptable today. Prefer AES-256-GCM or ChaCha20-Poly1305: "
            "Grover's algorithm halves the effective key length, leaving a "
            "128-bit cipher with 64-bit security against a quantum attacker."
        )

    bits = cipher_bits or (primitive[1] if primitive else None)
    return _finding(
        asset=cipher_name or "unknown",
        kind="Cipher Suite",
        purpose="TLS Connection",
        status=status,
        severity=severity,
        recommendation=recommendation,
        algorithm=algorithm or cipher_name,
        key_size=f"{bits} bits" if bits else None,
        entry=entry,
    )


def _key_exchange_finding(
    cipher_name: str, protocol: str, group: str | None
) -> dict | None:
    """The handshake's key agreement, which is the harvest-now target.

    Worth its own row rather than being folded into the cipher suite: this is
    the one part of a TLS session that an attacker can record today and break
    later. The cipher protects the traffic, but the key exchange is what
    protects the key, and a recorded ECDHE handshake is decryptable the day
    Shor's algorithm runs at scale.
    """
    upper = (cipher_name or "").upper()

    # A negotiated group naming ML-KEM means this connection is already using
    # hybrid post-quantum key agreement -- the good news case, and the reason
    # _negotiated_group is asked for at all.
    if group and ("MLKEM" in group.upper().replace("-", "").replace("_", "")):
        return _finding(
            asset=group,
            kind="Key Exchange",
            purpose="TLS Connection",
            status=STATUS_ACCEPTABLE,
            severity=SEVERITY_LOW,
            recommendation=(
                "No action needed. This connection negotiated hybrid "
                "post-quantum key agreement, so the session key is not "
                "recoverable from a recorded handshake by Shor's algorithm."
            ),
            algorithm="ML-KEM (hybrid)",
            entry=find_algorithm("ML-KEM"),
        )

    if "ECDHE" in upper or "EECDH" in upper or protocol == "TLS 1.3":
        # Every TLS 1.3 suite uses ephemeral (EC)DHE; the suite name no longer
        # spells it out, so the version is what identifies it.
        asset = group or "ECDHE"
        entry = find_algorithm("ECDH")
        recommendation = (
            "Forward secrecy is in place, which is correct today, but the "
            "handshake is still classically-only. Plan to enable a hybrid "
            "post-quantum group such as X25519MLKEM768: traffic recorded now "
            "is decryptable once a cryptographically relevant quantum computer "
            "exists (harvest-now, decrypt-later)."
        )
        return _finding(
            asset=asset,
            kind="Key Exchange",
            purpose="TLS Connection",
            status=STATUS_ACCEPTABLE,
            severity=SEVERITY_MEDIUM,
            recommendation=recommendation,
            algorithm="ECDH",
            entry=entry,
        )

    if "DHE" in upper:
        return _finding(
            asset=group or "DHE",
            kind="Key Exchange",
            purpose="TLS Connection",
            status=STATUS_ACCEPTABLE,
            severity=SEVERITY_MEDIUM,
            recommendation=(
                "Finite-field Diffie-Hellman provides forward secrecy but is "
                "slower than ECDHE and equally broken by Shor's algorithm. "
                "Prefer ECDHE now and a hybrid post-quantum group next."
            ),
            algorithm="Diffie-Hellman",
            entry=find_algorithm("DH"),
        )

    if upper.startswith("AES") or upper.startswith("RSA") or "STATIC" in upper:
        # No (EC)DHE in the suite name means the premaster secret is encrypted
        # to the certificate's RSA key: no forward secrecy at all, so one
        # recorded session plus one stolen private key decrypts everything.
        return _finding(
            asset="RSA key transport",
            kind="Key Exchange",
            purpose="TLS Connection",
            status=STATUS_WEAK,
            severity=SEVERITY_HIGH,
            recommendation=(
                "Disable static RSA key exchange and require ECDHE. Without "
                "forward secrecy, every past session becomes readable the "
                "moment the certificate's private key is compromised -- or "
                "factored by Shor's algorithm."
            ),
            algorithm="RSA",
            entry=find_algorithm("RSA"),
        )
    return None


def _public_key_finding(certificate: dict) -> dict:
    algorithm = certificate["public_key_algorithm"]
    bits = certificate["public_key_size_bits"]
    curve = certificate.get("public_key_curve")
    entry = find_algorithm(certificate.get("_db_key") or algorithm)

    if algorithm == "RSA":
        if bits and bits < 2048:
            status, severity = STATUS_WEAK, SEVERITY_CRITICAL
            recommendation = (
                f"Reissue this certificate with at least a 2048-bit key. "
                f"RSA-{bits} is below the CA/Browser Forum minimum and is "
                "considered breakable classically."
            )
        else:
            status, severity = STATUS_ACCEPTABLE, SEVERITY_MEDIUM
            recommendation = (
                "Acceptable today. Plan migration to ML-DSA (FIPS 204) for "
                "certificate signatures: Shor's algorithm factors an RSA "
                "modulus of any size in polynomial time."
            )
    elif algorithm in ("ECDSA", "Ed25519", "Ed448"):
        if bits and bits < 256:
            status, severity = STATUS_WEAK, SEVERITY_HIGH
            recommendation = (
                f"Reissue this certificate on P-256 or stronger. A {bits}-bit "
                "curve is below current classical guidance."
            )
        else:
            status, severity = STATUS_ACCEPTABLE, SEVERITY_MEDIUM
            recommendation = (
                "Acceptable today. Plan migration to ML-DSA (FIPS 204): "
                "elliptic-curve signatures fall to Shor's algorithm, and a "
                "smaller curve is not a smaller problem than RSA, it is a "
                "faster one to break."
            )
    elif algorithm == "DSA":
        status, severity = STATUS_WEAK, SEVERITY_HIGH
        recommendation = (
            "Reissue this certificate with ECDSA (P-256) or RSA-2048 now, and "
            "with ML-DSA when your CA supports it. DSA is not accepted by "
            "current browsers."
        )
    else:
        status, severity = STATUS_ACCEPTABLE, SEVERITY_LOW
        recommendation = f"{algorithm} is not in QLint's database; review it by hand."

    asset = f"{algorithm}-{bits}" if bits else algorithm
    if curve:
        asset = f"{algorithm}-{curve}"
    return _finding(
        asset=asset,
        kind="Public Key",
        purpose="TLS Certificate",
        status=status,
        severity=severity,
        recommendation=recommendation,
        algorithm=algorithm,
        key_size=f"{bits} bits" if bits else None,
        entry=entry,
    )


def _signature_finding(certificate: dict) -> dict:
    name = certificate["signature_algorithm"]
    upper = name.upper()
    # The hash half is what decides classical safety here: a SHA-1 signature is
    # forgeable today, whatever key signed it.
    hash_entry = None
    for candidate in ("SHA512", "SHA384", "SHA256", "SHA1", "MD5"):
        if upper.startswith(candidate):
            hash_entry = find_algorithm(candidate)
            break

    if upper.startswith(("MD5", "SHA1")):
        status, severity = STATUS_WEAK, SEVERITY_CRITICAL
        recommendation = (
            f"Reissue this certificate with a SHA-256 signature. {name} relies "
            "on a hash with practical collision attacks, so the signature can "
            "be forged classically."
        )
    else:
        status, severity = STATUS_ACCEPTABLE, SEVERITY_MEDIUM
        recommendation = (
            "The hash is sound. The signing key is the quantum exposure: plan "
            "migration to ML-DSA (FIPS 204)."
        )
    return _finding(
        asset=name,
        kind="Signature Algorithm",
        purpose="TLS Certificate",
        status=status,
        severity=severity,
        recommendation=recommendation,
        algorithm=name,
        entry=hash_entry,
    )


STATUS_EXPIRED = "Expired"
STATUS_INVALID = "Invalid"

# Fragments OpenSSL puts in a verification message, mapped to the status and
# the sentence a site owner can act on. Ordered: the first match wins, and
# "expired" is checked before the generic self-signed/untrusted cases because
# an expired self-signed certificate is more usefully described as expired.
_VERIFY_FAILURES: tuple[tuple[str, str, str], ...] = (
    (
        "certificate has expired",
        STATUS_EXPIRED,
        "Certificate expired on {not_after}; renew immediately. Browsers are "
        "refusing this site now.",
    ),
    (
        "certificate is not yet valid",
        STATUS_INVALID,
        "This certificate is not valid until {not_before}. Check the issuing "
        "date and the server's clock.",
    ),
    # Before the plain self-signed cases: OpenSSL says "self-signed certificate
    # in certificate chain" when the *root* is untrusted rather than the leaf,
    # and calling that a self-signed certificate misdescribes what to fix.
    (
        "self-signed certificate in certificate chain",
        STATUS_INVALID,
        "Certificate is not trusted by standard certificate authorities: the "
        "chain terminates in a self-signed root that is not in the public "
        "trust store. Reissue the certificate under a publicly trusted CA.",
    ),
    (
        "self signed certificate in certificate chain",
        STATUS_INVALID,
        "Certificate is not trusted by standard certificate authorities: the "
        "chain terminates in a self-signed root that is not in the public "
        "trust store. Reissue the certificate under a publicly trusted CA.",
    ),
    (
        "self-signed certificate",
        STATUS_INVALID,
        "Certificate is self-signed, so it is not trusted by standard "
        "certificate authorities. Replace it with one issued by a public CA.",
    ),
    (
        "self signed certificate",
        STATUS_INVALID,
        "Certificate is self-signed, so it is not trusted by standard "
        "certificate authorities. Replace it with one issued by a public CA.",
    ),
    (
        "unable to get local issuer",
        STATUS_INVALID,
        "Certificate is not trusted by standard certificate authorities: the "
        "issuing chain is incomplete. Serve the full intermediate chain "
        "alongside the leaf certificate.",
    ),
    (
        "hostname mismatch",
        STATUS_INVALID,
        "Certificate is not valid for {host}: the name is not listed in its "
        "subject alternative names. Reissue it covering this hostname.",
    ),
)


def _verification_finding(certificate: dict, verification_error: str, host: str) -> dict:
    """The certificate failed verification, reported rather than raised.

    This used to be a 502 with no report at all, which threw away the useful
    half of the answer: a site with an expired certificate still has a
    protocol, a cipher suite and a key worth rating, and "expired" is itself
    the single most actionable finding a TLS scan can produce. The certificate
    is read from the untrusted chain and every other finding is produced as
    normal -- the trust failure is carried here, and in `certificate_trusted`
    on the response, so nothing reads as reassurance about a site that is
    broken today.
    """
    message = (verification_error or "").lower()
    status, template = STATUS_INVALID, (
        "Certificate is not trusted by standard certificate authorities "
        "({reason}). Replace it with one issued by a public CA."
    )
    for fragment, matched_status, matched_template in _VERIFY_FAILURES:
        if fragment in message:
            status, template = matched_status, matched_template
            break

    return _finding(
        asset=status,
        kind="Certificate Validity",
        purpose="TLS Certificate",
        status=status,
        severity=SEVERITY_HIGH,
        recommendation=template.format(
            not_after=certificate.get("not_after") or "an unknown date",
            not_before=certificate.get("not_before") or "an unknown date",
            reason=verification_error or "verification failed",
            host=host,
        ),
        # Live breakage, not a migration item: scored like a critical code
        # finding rather than like the expiring-soon warning below.
        db_severity="critical",
    )


def _validity_finding(certificate: dict) -> dict | None:
    """The certificate verifies, but not for much longer.

    Only reached when verification succeeded -- an expired or untrusted
    certificate gets _verification_finding instead, so there is never more
    than one Certificate Validity finding in a report.
    """
    days = certificate.get("days_until_expiry")
    if days is None or days > 30:
        return None
    if days <= 7:
        status, severity = STATUS_WEAK, SEVERITY_HIGH
    else:
        status, severity = STATUS_DEPRECATED, SEVERITY_MEDIUM
    return _finding(
        asset=f"Expires in {days} day{'' if days == 1 else 's'}",
        kind="Certificate Validity",
        purpose="TLS Certificate",
        status=status,
        severity=severity,
        recommendation=(
            f"Renew this certificate: it expires on {certificate['not_after']}."
        ),
        db_severity="warning",
    )


def classify(
    handshake: dict,
    certificate: dict,
    verification_error: str | None = None,
    host: str = "",
) -> list[dict]:
    """Every finding for one scanned host, most severe first.

    `verification_error` is the reason the certificate failed trust checking,
    or None when it verified. Exactly one of the two Certificate Validity
    findings can result: the trust failure if there was one, otherwise the
    expiring-soon warning.
    """
    protocol = _PROTOCOL_NAMES.get(
        handshake.get("protocol_raw") or "", handshake.get("protocol_raw") or "unknown"
    )
    cipher_name = handshake.get("cipher_name") or ""

    if verification_error:
        validity = _verification_finding(certificate, verification_error, host)
    else:
        validity = _validity_finding(certificate)

    findings = [
        _protocol_finding(protocol),
        _key_exchange_finding(cipher_name, protocol, handshake.get("key_exchange_group")),
        _cipher_finding(cipher_name, handshake.get("cipher_bits")),
        _public_key_finding(certificate),
        _signature_finding(certificate),
        validity,
    ]
    order = {
        SEVERITY_CRITICAL: 0,
        SEVERITY_HIGH: 1,
        SEVERITY_MEDIUM: 2,
        SEVERITY_LOW: 3,
    }
    return sorted(
        (finding for finding in findings if finding is not None),
        key=lambda finding: order.get(finding["severity"], 4),
    )


def summarize(findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {
        "total_findings": len(findings),
        "by_severity": counts,
        "quantum_vulnerable": sum(1 for f in findings if f["quantum_vulnerable"]),
        "classically_vulnerable": sum(
            1 for f in findings if f["classical_vulnerable"]
        ),
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def scan_url(raw_url: str) -> dict:
    """Validate, resolve, guard, handshake, parse, classify.

    The whole thing is bounded by OVERALL_TIMEOUT_SECONDS, DNS included: the
    guard's lookup runs inside the timed section, so a resolver that hangs
    cannot hold a worker past the budget. The blocking work runs in worker
    threads so a slow target stalls a thread rather than the event loop, and
    the socket's own 5-second timeouts mean such a thread cannot outlive the
    request by more than one handshake attempt even though asyncio.wait_for
    cannot interrupt it.
    """
    try:
        return await asyncio.wait_for(
            _resolve_and_inspect(raw_url), timeout=OVERALL_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError as exc:
        raise TLSConnectionError(
            f"The scan of {_name_for_message(raw_url)} did not finish within "
            f"{OVERALL_TIMEOUT_SECONDS:.0f} seconds and was abandoned."
        ) from exc


def _name_for_message(raw_url: str) -> str:
    """The host to name in a timeout message, without trusting the parse.

    Only ever called on the timeout path, where the URL already parsed once --
    but a message-formatting helper that can raise is how the certificate
    handling sprouted a 500 in Phase 1, so this one cannot.
    """
    try:
        return parse_target(raw_url).hostname
    except Exception:  # pragma: no cover - the URL parsed to get this far
        return "the target"


async def _resolve_and_inspect(raw_url: str) -> dict:
    # The shared guard: parses, resolves once, and judges every address it got
    # back. Identical call to the one header_scanner makes.
    target = await validate_target(raw_url)
    addresses = target.addresses
    # Connect to the address that was just judged, not to the name.
    address = target.address

    verification_error: str | None = None
    try:
        handshake = await asyncio.to_thread(_handshake, address, target.hostname)
    except ssl.SSLCertVerificationError as exc:
        # The certificate is untrusted, not absent. A host that presents an
        # expired or self-signed certificate is still a host with a protocol, a
        # cipher suite and a key worth reporting on, and the trust failure is
        # the most actionable thing the scan can say -- so it becomes a finding
        # rather than the end of the scan.
        #
        # It costs a second connection, because the first one was torn down at
        # the point verification failed. Back to the same address that was
        # validated, never a re-resolved name: the guard's decision still has
        # to be the one governing where this socket goes.
        verification_error = _verification_reason(exc)
        try:
            handshake = await asyncio.to_thread(
                _handshake, address, target.hostname, False
            )
        except Exception as retry_exc:
            # The retry failed too, so there is no certificate to report on
            # after all. Report the original trust failure, which describes the
            # target better than "the second connection also failed" does.
            raise TLSConnectionError(
                _safe_describe(exc, target.hostname)
            ) from retry_exc
    except TLSScanError:
        raise
    except Exception as exc:
        # Everything ssl and socket can raise is turned into one sentence here.
        # Nothing else in this module lets an exception through to FastAPI, so
        # a caller can never receive a traceback for a target that misbehaved.
        #
        # This is the genuine-connection-failure path and it is unchanged by
        # certificate reporting: an unreachable host, a refused connection or a
        # handshake that never completed presented no certificate, so there is
        # nothing to build a report from and the caller gets an error.
        raise TLSConnectionError(_safe_describe(exc, target.hostname)) from exc

    certificate = parse_certificate(handshake["certificate_der"])
    findings = classify(handshake, certificate, verification_error, target.hostname)
    protocol = _PROTOCOL_NAMES.get(
        handshake["protocol_raw"] or "", handshake["protocol_raw"] or "unknown"
    )
    certificate.pop("_db_key", None)

    return {
        "host": target.hostname,
        "port": target.port,
        "resolved_ips": addresses,
        "scanned_ip": handshake["peer_ip"],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "tls": {
            "protocol": protocol,
            "cipher_suite": handshake["cipher_name"],
            "cipher_bits": handshake["cipher_bits"],
            "key_exchange_group": handshake["key_exchange_group"],
        },
        "certificate": certificate,
        # Stated at the top level as well as in the findings, so a consumer
        # cannot render a report of key sizes and cipher suites for an
        # untrusted certificate without having been told it is untrusted.
        # None here means the certificate verified.
        "certificate_trusted": verification_error is None,
        "verification_error": verification_error,
        "findings": findings,
        "summary": summarize(findings),
        # The same 0-100 readiness score a code scan reports, computed by the
        # same function from the same severity vocabulary -- so a site and a
        # repository are scored on one scale rather than two.
        "pqc_readiness_score": get_severity_score(
            [{"severity": finding["db_severity"]} for finding in findings]
        ),
    }

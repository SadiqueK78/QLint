"""Level 1 TLS scanning, and above all the guard that decides where it connects.

This is the first endpoint in QLint that opens a socket to a host a user names,
so most of what is checked here is not "does the report come out right" but
"did the connection happen at all". Every rejection test therefore asserts on
`network.connections` -- proving the refusal landed *before* a socket was
opened, not after. A guard that blocks the response but still made the request
has already done the damage SSRF is about.

Nothing here touches the network. `FakeNetwork` replaces the two seams in
tls_scanner -- name resolution and the handshake -- the same way
test_scan_cancellation.py replaces github_client's calls in scanner_engine.
The certificates are real X.509 built with `cryptography` at module import, so
the parsing path is genuinely exercised against DER bytes rather than a dict
pretending to be a certificate.
"""

import socket
import ssl
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient

import tls_scanner
from auth import get_current_user
from routers import web_scan_router as web_scan_module
from routers.web_scan_router import router as web_scan_router

SCAN_USER = {"_id": "507f1f77bcf86cd799439011", "email": "owner@qlint.dev"}

# A stable, well-known https host. example.com is reserved by IANA (RFC 2606),
# so it is the one name guaranteed not to change hands or configuration -- but
# nothing in this file resolves or contacts it. It is a label.
TARGET = "https://example.com"
TARGET_HOST = "example.com"
PUBLIC_IP = "93.184.216.34"

CLOUD_METADATA_IP = "169.254.169.254"


# ---------------------------------------------------------------------------
# Real certificates, built once
# ---------------------------------------------------------------------------


def _certificate(
    key, hash_algorithm, common_name=TARGET_HOST, days_valid=90, issued_days_ago=1
):
    """A self-signed DER certificate. Real enough for x509 to parse in earnest.

    `days_valid` is measured from issue, so a negative total puts not_after in
    the past and produces a genuinely expired certificate rather than one that
    merely claims to be.
    """
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QLint Test"),
        ]
    )
    issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "QLint Test Issuing CA")]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=issued_days_ago))
        .not_valid_after(now + timedelta(days=days_valid))
    )
    return builder.sign(key, hash_algorithm).public_bytes(Encoding.DER)


# Generated once at import: RSA-2048 keygen is the slowest thing in this file.
_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_EC_KEY = ec.generate_private_key(ec.SECP256R1())

RSA_CERT_DER = _certificate(_RSA_KEY, hashes.SHA256())
EC_CERT_DER = _certificate(_EC_KEY, hashes.SHA256())
EXPIRING_CERT_DER = _certificate(_EC_KEY, hashes.SHA256(), days_valid=3)
# Genuinely past not_after: issued 400 days ago, valid for 365 of them.
EXPIRED_CERT_DER = _certificate(
    _RSA_KEY, hashes.SHA256(), days_valid=-35, issued_days_ago=400
)


def _verification_error(message):
    """An SSLCertVerificationError shaped like the one ssl actually raises."""
    error = ssl.SSLCertVerificationError(1, message)
    error.verify_message = message
    return error


EXPIRED_ERROR = _verification_error("certificate has expired")
SELF_SIGNED_ERROR = _verification_error("self-signed certificate")
UNTRUSTED_ERROR = _verification_error("unable to get local issuer certificate")
# What OpenSSL actually says for an untrusted root, as observed against
# untrusted-root.badssl.com -- the leaf is not self-signed, the root is.
UNTRUSTED_ROOT_ERROR = _verification_error(
    "self-signed certificate in certificate chain"
)
HOSTNAME_MISMATCH_ERROR = _verification_error("Hostname mismatch")


# ---------------------------------------------------------------------------
# The fake network
# ---------------------------------------------------------------------------


class FakeNetwork:
    """Stands in for DNS and the TLS handshake, and records what was attempted.

    `connections` is the important attribute. Every test that expects a target
    to be refused asserts it stayed empty, which is what distinguishes a guard
    that runs before the socket from one that runs after it.
    """

    def __init__(
        self,
        addresses=(PUBLIC_IP,),
        protocol="TLSv1.3",
        cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        certificate_der=RSA_CERT_DER,
        group=None,
        resolve_error=None,
        handshake_error=None,
        verify_error=None,
    ):
        self.addresses = list(addresses)
        self.protocol = protocol
        self.cipher = cipher
        self.certificate_der = certificate_der
        self.group = group
        self.resolve_error = resolve_error
        # Raised on every handshake attempt, verified or not: the host is
        # unreachable or the handshake never completes, so no certificate is
        # ever presented and there is nothing to report on.
        self.handshake_error = handshake_error
        # Raised on the *verified* attempt only. The unverified retry succeeds
        # and hands back the certificate, which is what a real host with an
        # expired or self-signed certificate does.
        self.verify_error = verify_error
        self.resolutions: list[str] = []
        self.connections: list[tuple[str, str]] = []
        # The port each handshake was actually asked to connect to.
        self.ports: list[int] = []
        self.verify_flags: list[bool] = []

    def install(self, monkeypatch):
        def _getaddrinfo(host, port, *args, **kwargs):
            """Stand in for the resolver itself, not for tls_scanner's wrapper.

            Patched this low deliberately: tls_scanner._resolve is where a
            gaierror becomes a reportable error and where the answer is
            flattened to a list of addresses, and mocking _resolve away would
            leave both untested.
            """
            self.resolutions.append(host)
            if self.resolve_error is not None:
                raise self.resolve_error
            answers = []
            for address in self.addresses:
                if ":" in address:
                    answers.append(
                        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, port, 0, 0))
                    )
                else:
                    answers.append(
                        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))
                    )
            return answers

        def _handshake(ip_address, hostname, verify=True, port=443):
            self.connections.append((ip_address, hostname))
            self.ports.append(port)
            self.verify_flags.append(verify)
            if self.handshake_error is not None:
                raise self.handshake_error
            if verify and self.verify_error is not None:
                raise self.verify_error
            return {
                "protocol_raw": self.protocol,
                "cipher_name": self.cipher[0],
                "cipher_bits": self.cipher[2],
                "key_exchange_group": self.group,
                "certificate_der": self.certificate_der,
                "peer_ip": ip_address,
            }

        monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)
        monkeypatch.setattr(tls_scanner, "_handshake", _handshake)
        return self


@pytest.fixture
def network(monkeypatch):
    return FakeNetwork().install(monkeypatch)


@pytest.fixture(autouse=True)
def reset_limiter():
    """A fresh window per test: the limiter is module state shared between them."""
    web_scan_module._limiter.reset()
    yield
    web_scan_module._limiter.reset()


@pytest.fixture
def app():
    application = FastAPI()
    application.include_router(web_scan_router)
    return application


@pytest.fixture
def client(app):
    """A client whose every request is authenticated."""
    app.dependency_overrides[get_current_user] = lambda: SCAN_USER
    yield TestClient(app)
    app.dependency_overrides.clear()


def scan(client, url=TARGET):
    return client.post("/web-scan/tls", json={"url": url})


def findings_of(body, kind):
    return [finding for finding in body["findings"] if finding["type"] == kind]


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


class TestASuccessfulScan:
    def test_a_well_known_https_site_is_scanned_and_reported(self, client, network):
        response = scan(client)
        assert response.status_code == 200
        body = response.json()

        assert body["host"] == TARGET_HOST
        assert body["port"] == 443
        assert body["scanned_ip"] == PUBLIC_IP
        # The connection went to the address that was validated, not to the name.
        assert network.connections == [(PUBLIC_IP, TARGET_HOST)]

    def test_the_negotiated_protocol_and_cipher_are_reported(self, client, network):
        body = scan(client).json()
        assert body["tls"]["protocol"] == "TLS 1.3"
        assert body["tls"]["cipher_suite"] == "TLS_AES_256_GCM_SHA384"

    def test_ssl_protocol_spellings_are_translated(self, client, monkeypatch):
        FakeNetwork(
            protocol="TLSv1.2",
            cipher=("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128),
        ).install(monkeypatch)
        body = scan(client).json()
        assert body["tls"]["protocol"] == "TLS 1.2"

    def test_the_certificate_fields_are_parsed_from_the_der(self, client, network):
        certificate = scan(client).json()["certificate"]
        assert certificate["subject_common_name"] == TARGET_HOST
        assert certificate["issuer_common_name"] == "QLint Test Issuing CA"
        assert certificate["public_key_algorithm"] == "RSA"
        assert certificate["public_key_size_bits"] == 2048
        assert certificate["signature_algorithm"] == "SHA256withRSA"
        assert certificate["not_before"] < certificate["not_after"]

    def test_an_ecdsa_certificate_reports_its_curve_and_size(self, client, monkeypatch):
        FakeNetwork(certificate_der=EC_CERT_DER).install(monkeypatch)
        certificate = scan(client).json()["certificate"]
        assert certificate["public_key_algorithm"] == "ECDSA"
        assert certificate["public_key_size_bits"] == 256
        assert certificate["signature_algorithm"] == "SHA256withECDSA"
        assert certificate["public_key_curve"] == "secp256r1"

    def test_the_internal_db_key_does_not_leak_into_the_response(
        self, client, network
    ):
        assert "_db_key" not in scan(client).json()["certificate"]


class TestFindingsUseTheCodeScanFramework:
    """The classification is CRYPTO_DB's, not a second one invented here."""

    def test_an_rsa_2048_certificate_matches_the_documented_shape(
        self, client, network
    ):
        finding = findings_of(scan(client).json(), "Public Key")[0]
        assert finding["asset"] == "RSA-2048"
        assert finding["type"] == "Public Key"
        assert finding["purpose"] == "TLS Certificate"
        assert finding["algorithm"] == "RSA"
        assert finding["key_size"] == "2048 bits"
        assert finding["status"] == "Acceptable"
        assert finding["quantum_risk"] == "Vulnerable to Shor's algorithm"
        assert finding["severity"] == "Medium"
        assert finding["recommendation"]

    def test_an_rsa_key_carries_crypto_dbs_own_verdict_unchanged(
        self, client, network
    ):
        from vulnerability_db import CRYPTO_DB

        finding = findings_of(scan(client).json(), "Public Key")[0]
        assert finding["db_severity"] == CRYPTO_DB["RSA"]["severity"]
        assert finding["attack_vector"] == CRYPTO_DB["RSA"]["attack_vector"]
        assert finding["replacement"] == CRYPTO_DB["RSA"]["replacement"]
        assert finding["quantum_vulnerable"] is True

    def test_an_ecdsa_certificate_carries_the_same_shor_reasoning_as_a_code_scan(
        self, client, monkeypatch
    ):
        from vulnerability_db import CRYPTO_DB

        FakeNetwork(certificate_der=EC_CERT_DER).install(monkeypatch)
        finding = findings_of(scan(client).json(), "Public Key")[0]
        assert finding["quantum_risk"] == "Vulnerable to Shor's algorithm"
        assert finding["attack_vector"] == CRYPTO_DB["ECC"]["attack_vector"]
        assert finding["db_severity"] == CRYPTO_DB["ECC"]["severity"]
        assert finding["severity"] == "Medium"

    @pytest.mark.parametrize(
        "protocol,expected",
        [("TLSv1", "TLS 1.0"), ("TLSv1.1", "TLS 1.1")],
    )
    def test_a_deprecated_protocol_matches_the_documented_shape(
        self, client, monkeypatch, protocol, expected
    ):
        FakeNetwork(
            protocol=protocol, cipher=("ECDHE-RSA-AES128-SHA", protocol, 128)
        ).install(monkeypatch)
        finding = findings_of(scan(client).json(), "Protocol")[0]
        assert finding["asset"] == expected
        assert finding["type"] == "Protocol"
        assert finding["status"] == "Deprecated"
        assert finding["severity"] == "High"
        assert finding["recommendation"] == f"Disable {expected}"

    def test_tls_13_is_acceptable_rather_than_flagged(self, client, network):
        finding = findings_of(scan(client).json(), "Protocol")[0]
        assert finding["asset"] == "TLS 1.3"
        assert finding["status"] == "Acceptable"
        assert finding["severity"] == "Low"

    def test_a_broken_cipher_suite_is_critical(self, client, monkeypatch):
        FakeNetwork(
            protocol="TLSv1.2", cipher=("ECDHE-RSA-RC4-SHA", "TLSv1.2", 128)
        ).install(monkeypatch)
        finding = findings_of(scan(client).json(), "Cipher Suite")[0]
        assert finding["status"] == "Weak"
        assert finding["severity"] == "Critical"
        assert finding["classical_vulnerable"] is True

    def test_aes_128_is_acceptable_but_carries_grovers_reasoning(
        self, client, monkeypatch
    ):
        FakeNetwork(
            protocol="TLSv1.2",
            cipher=("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128),
        ).install(monkeypatch)
        finding = findings_of(scan(client).json(), "Cipher Suite")[0]
        assert finding["algorithm"] == "AES-128"
        assert finding["status"] == "Acceptable"
        assert "Grover" in finding["quantum_risk"]

    def test_the_key_exchange_is_reported_as_the_harvest_now_target(
        self, client, network
    ):
        finding = findings_of(scan(client).json(), "Key Exchange")[0]
        assert finding["algorithm"] == "ECDH"
        assert finding["quantum_risk"] == "Vulnerable to Shor's algorithm"
        assert "harvest-now" in finding["recommendation"]

    def test_a_hybrid_post_quantum_group_is_recognised_as_safe(
        self, client, monkeypatch
    ):
        FakeNetwork(group="X25519MLKEM768").install(monkeypatch)
        finding = findings_of(scan(client).json(), "Key Exchange")[0]
        assert finding["asset"] == "X25519MLKEM768"
        assert finding["quantum_vulnerable"] is False
        assert finding["severity"] == "Low"

    def test_static_rsa_key_exchange_is_flagged_for_having_no_forward_secrecy(
        self, client, monkeypatch
    ):
        FakeNetwork(
            protocol="TLSv1.2", cipher=("AES256-GCM-SHA384", "TLSv1.2", 256)
        ).install(monkeypatch)
        finding = findings_of(scan(client).json(), "Key Exchange")[0]
        assert finding["status"] == "Weak"
        assert finding["severity"] == "High"

    def test_a_certificate_expiring_soon_is_reported(self, client, monkeypatch):
        FakeNetwork(certificate_der=EXPIRING_CERT_DER).install(monkeypatch)
        findings = findings_of(scan(client).json(), "Certificate Validity")
        assert len(findings) == 1
        assert "Expires in" in findings[0]["asset"]

    def test_a_healthy_certificate_reports_no_validity_finding(self, client, network):
        assert findings_of(scan(client).json(), "Certificate Validity") == []


class TestAnUntrustedCertificateIsAFindingNotAFailure:
    """A bad certificate is the most actionable thing a TLS scan can find.

    It used to end the scan with a 502 and no findings, which threw away the
    useful half of the answer: a site with an expired certificate still has a
    protocol, a cipher suite and a key worth rating -- and "expired" is itself
    the headline. Now the certificate is read from the untrusted chain and the
    trust failure becomes a High-severity Certificate Validity finding.
    """

    def _scan_untrusted(self, client, monkeypatch, error, der=EXPIRED_CERT_DER):
        net = FakeNetwork(verify_error=error, certificate_der=der).install(monkeypatch)
        response = scan(client)
        assert response.status_code == 200, response.json()
        return response.json(), net

    def test_an_expired_certificate_returns_200_with_a_finding_not_502(
        self, client, monkeypatch
    ):
        body, _ = self._scan_untrusted(client, monkeypatch, EXPIRED_ERROR)
        findings = findings_of(body, "Certificate Validity")
        assert len(findings) == 1
        finding = findings[0]
        assert finding["status"] == "Expired"
        assert finding["severity"] == "High"
        assert "renew immediately" in finding["recommendation"].lower()

    def test_the_expiry_recommendation_names_the_actual_date(
        self, client, monkeypatch
    ):
        body, _ = self._scan_untrusted(client, monkeypatch, EXPIRED_ERROR)
        finding = findings_of(body, "Certificate Validity")[0]
        assert body["certificate"]["not_after"] in finding["recommendation"]

    def test_a_self_signed_certificate_behaves_the_same_way(
        self, client, monkeypatch
    ):
        body, _ = self._scan_untrusted(
            client, monkeypatch, SELF_SIGNED_ERROR, RSA_CERT_DER
        )
        finding = findings_of(body, "Certificate Validity")[0]
        assert finding["status"] == "Invalid"
        assert finding["severity"] == "High"
        assert "self-signed" in finding["recommendation"]
        assert "certificate authorities" in finding["recommendation"]

    def test_an_untrusted_chain_behaves_the_same_way(self, client, monkeypatch):
        body, _ = self._scan_untrusted(
            client, monkeypatch, UNTRUSTED_ERROR, RSA_CERT_DER
        )
        finding = findings_of(body, "Certificate Validity")[0]
        assert finding["status"] == "Invalid"
        assert finding["severity"] == "High"
        assert "not trusted by standard certificate authorities" in (
            finding["recommendation"]
        )

    def test_an_untrusted_root_is_described_as_a_chain_problem_not_a_self_signed_leaf(
        self, client, monkeypatch
    ):
        """The more specific OpenSSL message must win over the generic one."""
        body, _ = self._scan_untrusted(
            client, monkeypatch, UNTRUSTED_ROOT_ERROR, RSA_CERT_DER
        )
        recommendation = findings_of(body, "Certificate Validity")[0]["recommendation"]
        assert "chain terminates in a self-signed root" in recommendation
        assert "Certificate is self-signed, so" not in recommendation

    def test_a_hostname_mismatch_names_the_host(self, client, monkeypatch):
        body, _ = self._scan_untrusted(
            client, monkeypatch, HOSTNAME_MISMATCH_ERROR, RSA_CERT_DER
        )
        finding = findings_of(body, "Certificate Validity")[0]
        assert finding["status"] == "Invalid"
        assert TARGET_HOST in finding["recommendation"]

    def test_the_certificate_details_are_still_extracted_from_the_untrusted_cert(
        self, client, monkeypatch
    ):
        """The whole point: the report is complete, not empty."""
        body, _ = self._scan_untrusted(client, monkeypatch, EXPIRED_ERROR)
        certificate = body["certificate"]
        assert certificate["public_key_algorithm"] == "RSA"
        assert certificate["public_key_size_bits"] == 2048
        assert certificate["signature_algorithm"] == "SHA256withRSA"
        assert certificate["subject_common_name"] == TARGET_HOST
        assert certificate["issuer_common_name"] == "QLint Test Issuing CA"
        assert certificate["not_before"] and certificate["not_after"]
        # Genuinely in the past, not merely labelled expired.
        assert certificate["days_until_expiry"] < 0

    def test_the_other_findings_are_still_produced(self, client, monkeypatch):
        body, _ = self._scan_untrusted(client, monkeypatch, EXPIRED_ERROR)
        kinds = {finding["type"] for finding in body["findings"]}
        assert {
            "Protocol",
            "Key Exchange",
            "Cipher Suite",
            "Public Key",
            "Signature Algorithm",
            "Certificate Validity",
        } <= kinds

    def test_the_response_says_the_certificate_is_untrusted_at_the_top_level(
        self, client, monkeypatch
    ):
        """A consumer must not be able to render the report without being told."""
        body, _ = self._scan_untrusted(client, monkeypatch, EXPIRED_ERROR)
        assert body["certificate_trusted"] is False
        assert "expired" in body["verification_error"].lower()

    def test_a_trusted_certificate_says_so(self, client, network):
        body = scan(client).json()
        assert body["certificate_trusted"] is True
        assert body["verification_error"] is None

    def test_the_retry_goes_to_the_same_validated_address(self, client, monkeypatch):
        """The guard's decision still governs where the second socket goes."""
        _, net = self._scan_untrusted(client, monkeypatch, EXPIRED_ERROR)
        assert net.connections == [
            (PUBLIC_IP, TARGET_HOST),
            (PUBLIC_IP, TARGET_HOST),
        ]
        # Verified first, unverified only as a fallback -- never the other way.
        assert net.verify_flags == [True, False]
        # And the name was resolved once, not once per connection attempt.
        assert net.resolutions == [TARGET_HOST]

    def test_a_healthy_scan_never_makes_a_second_unverified_connection(
        self, client, network
    ):
        assert scan(client).status_code == 200
        assert network.verify_flags == [True]

    def test_an_untrusted_certificate_still_scores_as_broken(
        self, client, monkeypatch
    ):
        """The finding is scored, not merely displayed."""
        from vulnerability_db import get_severity_score

        body, _ = self._scan_untrusted(client, monkeypatch, EXPIRED_ERROR)
        finding = findings_of(body, "Certificate Validity")[0]
        assert finding["db_severity"] == "critical"

        # The same report with the trust failure taken out scores higher, which
        # is what "the finding counts" means. Computed from this response
        # rather than from a second scan, because a second scan through the
        # same fixture would be the same untrusted target again.
        without_validity = get_severity_score(
            [
                {"severity": item["db_severity"]}
                for item in body["findings"]
                if item["type"] != "Certificate Validity"
            ]
        )
        assert body["pqc_readiness_score"] < without_validity

    def test_only_one_certificate_validity_finding_is_ever_produced(
        self, client, monkeypatch
    ):
        """An expiring-soon cert that also fails verification is not two rows."""
        body, _ = self._scan_untrusted(
            client, monkeypatch, EXPIRED_ERROR, EXPIRING_CERT_DER
        )
        assert len(findings_of(body, "Certificate Validity")) == 1

    def test_safe_findings_never_carry_the_literal_string_none(self, client, network):
        for finding in scan(client).json()["findings"]:
            assert finding["attack_vector"] != "None"

    def test_findings_are_ordered_most_severe_first(self, client, monkeypatch):
        FakeNetwork(
            protocol="TLSv1", cipher=("ECDHE-RSA-RC4-SHA", "TLSv1", 128)
        ).install(monkeypatch)
        order = ["Critical", "High", "Medium", "Low"]
        severities = [f["severity"] for f in scan(client).json()["findings"]]
        assert severities == sorted(severities, key=order.index)

    def test_the_readiness_score_uses_the_shared_scoring_function(
        self, client, network
    ):
        from vulnerability_db import get_severity_score

        body = scan(client).json()
        expected = get_severity_score(
            [{"severity": f["db_severity"]} for f in body["findings"]]
        )
        assert body["pqc_readiness_score"] == expected
        assert 0 <= body["pqc_readiness_score"] <= 100


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------


class TestTheUrlMustBeHttps:
    def test_an_http_url_is_rejected_with_a_reason(self, client, network):
        response = scan(client, "http://example.com")
        assert response.status_code == 400
        detail = response.json()["detail"]
        assert "https" in detail.lower()
        assert "TLS" in detail
        # Nothing was resolved and nothing was contacted.
        assert network.resolutions == []
        assert network.connections == []

    def test_a_url_with_no_scheme_is_rejected_rather_than_assumed_https(
        self, client, network
    ):
        response = scan(client, "example.com")
        assert response.status_code == 400
        assert "scheme" in response.json()["detail"].lower()
        assert network.connections == []

    @pytest.mark.parametrize(
        "url",
        [
            "ftp://example.com",
            "file:///etc/passwd",
            "gopher://example.com",
            "ws://example.com",
        ],
    )
    def test_other_schemes_are_rejected(self, client, network, url):
        assert scan(client, url).status_code == 400
        assert network.connections == []

    def test_a_port_outside_the_allowlist_is_rejected(self, client, network):
        """8443 used to fail here and now succeeds: it is one of the five ports
        ssrf_guard.ALLOWED_PORTS holds. A port outside that set still fails,
        and the refusal still lands before any socket is opened."""
        response = scan(client, "https://example.com:8080")
        assert response.status_code == 400
        assert "443" in response.json()["detail"]
        assert network.connections == []

    def test_an_explicit_443_is_accepted(self, client, network):
        assert scan(client, "https://example.com:443").status_code == 200

    def test_credentials_in_the_url_are_rejected(self, client, network):
        response = scan(client, "https://user:pass@example.com")
        assert response.status_code == 400
        assert network.connections == []

    @pytest.mark.parametrize("url", ["", "   ", "https://", "not a url"])
    def test_junk_input_is_a_400_not_a_500(self, client, network, url):
        assert scan(client, url).status_code == 400
        assert network.connections == []

    def test_a_path_and_query_are_ignored_rather_than_fetched(self, client, network):
        """Only the host is inspected; nothing is requested over the connection."""
        response = scan(client, "https://example.com/admin?token=secret")
        assert response.status_code == 200
        assert response.json()["host"] == TARGET_HOST


# ---------------------------------------------------------------------------
# SSRF: the address guard
# ---------------------------------------------------------------------------


class TestPrivateAndInternalTargetsAreRefused:
    """The control this feature lives or dies by.

    Every test asserts `network.connections == []`. A 400 that arrives after
    the socket was opened is not a rejection -- the request has already been
    made, and for the metadata endpoint that is the entire attack.
    """

    @pytest.mark.parametrize(
        "ip,label",
        [
            ("10.0.0.1", "RFC 1918 10/8"),
            ("10.255.255.254", "RFC 1918 10/8 upper"),
            ("172.16.0.1", "RFC 1918 172.16/12"),
            ("172.31.255.254", "RFC 1918 172.16/12 upper"),
            ("192.168.1.1", "RFC 1918 192.168/16"),
            ("127.0.0.1", "loopback"),
            ("127.1.2.3", "loopback, non-obvious"),
            ("169.254.1.1", "link-local"),
            ("0.0.0.0", "unspecified"),
            ("224.0.0.1", "multicast"),
            ("240.0.0.1", "reserved"),
            ("100.64.0.1", "carrier-grade NAT"),
        ],
    )
    def test_a_name_resolving_to_a_blocked_ipv4_is_refused_before_connecting(
        self, client, monkeypatch, ip, label
    ):
        net = FakeNetwork(addresses=(ip,)).install(monkeypatch)
        response = scan(client)
        assert response.status_code == 400, f"{label} ({ip}) was not blocked"
        assert net.connections == [], f"{label} ({ip}) was contacted anyway"

    @pytest.mark.parametrize(
        "ip,label",
        [
            ("::1", "IPv6 loopback"),
            ("fe80::1", "IPv6 link-local"),
            ("fc00::1", "IPv6 unique-local"),
            ("::ffff:127.0.0.1", "IPv4-mapped loopback"),
            ("::ffff:169.254.169.254", "IPv4-mapped metadata"),
            ("::ffff:10.0.0.1", "IPv4-mapped RFC 1918"),
            ("2002:7f00:1::", "6to4-wrapped loopback"),
        ],
    )
    def test_a_name_resolving_to_a_blocked_ipv6_is_refused_before_connecting(
        self, client, monkeypatch, ip, label
    ):
        net = FakeNetwork(addresses=(ip,)).install(monkeypatch)
        response = scan(client)
        assert response.status_code == 400, f"{label} ({ip}) was not blocked"
        assert net.connections == [], f"{label} ({ip}) was contacted anyway"

    def test_the_cloud_metadata_address_is_refused_and_named(
        self, client, monkeypatch
    ):
        """169.254.169.254 is the address that makes SSRF worth exploiting."""
        net = FakeNetwork(addresses=(CLOUD_METADATA_IP,)).install(monkeypatch)
        response = scan(client)
        assert response.status_code == 400
        detail = response.json()["detail"]
        assert CLOUD_METADATA_IP in detail
        assert "metadata" in detail.lower()
        assert net.connections == []

    def test_the_metadata_address_is_refused_as_a_bare_url_too(
        self, client, monkeypatch
    ):
        net = FakeNetwork(addresses=(CLOUD_METADATA_IP,)).install(monkeypatch)
        response = scan(client, f"https://{CLOUD_METADATA_IP}/latest/meta-data/")
        assert response.status_code == 400
        assert net.connections == []

    def test_every_resolved_address_is_checked_not_only_the_first(
        self, client, monkeypatch
    ):
        """A public first record must not launder a private second one.

        This is the multi-record case: a name with one routable answer and one
        pointing inside. Checking `addresses[0]` and connecting would pass here
        and then connect to whichever the OS happened to prefer.
        """
        net = FakeNetwork(addresses=(PUBLIC_IP, "127.0.0.1")).install(monkeypatch)
        response = scan(client)
        assert response.status_code == 400
        assert "127.0.0.1" in response.json()["detail"]
        assert net.connections == []

    def test_a_private_address_hidden_in_the_middle_of_the_list_is_caught(
        self, client, monkeypatch
    ):
        net = FakeNetwork(
            addresses=(PUBLIC_IP, "8.8.8.8", "169.254.169.254", "1.1.1.1")
        ).install(monkeypatch)
        assert scan(client).status_code == 400
        assert net.connections == []

    def test_an_all_public_answer_still_scans(self, client, monkeypatch):
        """The guard rejects blocked addresses, not multi-homed hosts."""
        net = FakeNetwork(addresses=(PUBLIC_IP, "8.8.8.8")).install(monkeypatch)
        assert scan(client).status_code == 200
        assert net.connections == [(PUBLIC_IP, TARGET_HOST)]

    def test_the_error_does_not_distinguish_blocked_from_malformed(
        self, client, monkeypatch
    ):
        """Both are 400, so the endpoint is not a network-mapping oracle."""
        FakeNetwork(addresses=("10.0.0.1",)).install(monkeypatch)
        blocked = scan(client).status_code
        malformed = scan(client, "http://example.com").status_code
        assert blocked == malformed == 400


class TestInternalHostnamesAreRefusedAsWell:
    """The advisory layer. Bypassable by DNS, which is why the IP check exists."""

    @pytest.mark.parametrize(
        "host",
        [
            "localhost",
            "metadata.google.internal",
            "instance-data",
            "foo.internal",
            "db.cluster.local",
            "printer.local",
            "server.lan",
            "backend",
        ],
    )
    def test_an_internal_name_is_refused_without_resolving_it(
        self, client, network, host
    ):
        response = scan(client, f"https://{host}")
        assert response.status_code == 400
        assert network.resolutions == []
        assert network.connections == []

    def test_a_public_name_that_merely_contains_localhost_is_not_blocked(
        self, client, monkeypatch
    ):
        """Pattern matching must not eat legitimate names."""
        FakeNetwork().install(monkeypatch)
        assert scan(client, "https://localhost-tools.example.com").status_code == 200


class TestTheGuardUnitLevel:
    """What this file still owns of the guard: how *TLS scanning* uses it.

    The validator itself moved to ssrf_guard.py when the HTTP header check
    needed the same decision, and its unit tests moved with it to
    test_ssrf_guard.py. The endpoint-level SSRF tests above stayed here, because
    they are testing that this endpoint is wired to the guard rather than
    testing the guard.
    """

    def test_the_tls_scanner_uses_the_shared_guard_rather_than_its_own_copy(self):
        """The point of the extraction: one validator, not two.

        A second copy of this logic is the one that would be subtly wrong, so
        the import is asserted rather than assumed.
        """
        import inspect

        import ssrf_guard

        assert tls_scanner.validate_target is ssrf_guard.validate_target
        source = inspect.getsource(tls_scanner)
        assert "from ssrf_guard import" in source
        # None of the guard's internals were left behind as a private copy.
        for leftover in ("_blocked_reason", "_reject_blocked_address", "_resolve("):
            assert f"def {leftover}" not in source

    def test_the_handshake_is_never_given_a_hostname_to_resolve(self):
        """DNS rebinding defence: _handshake connects to an address, not a name.

        If this signature ever changes to take a hostname and hand it to
        socket.create_connection, the name would be resolved a second time and
        the address the guard approved would stop being the address contacted.
        """
        import ast
        import inspect
        import textwrap

        parameters = list(inspect.signature(tls_scanner._handshake).parameters)
        assert parameters[0] == "ip_address"

        # The docstring and comments name create_connection to explain why it
        # is *not* used, so the check has to read the code and nothing else.
        # ast.unparse drops both.
        function = ast.parse(
            textwrap.dedent(inspect.getsource(tls_scanner._handshake))
        ).body[0]
        if ast.get_docstring(function):
            function.body = function.body[1:]
        code = ast.unparse(function)

        # The socket goes to the validated address...
        assert "raw.connect((ip_address, port))" in code
        assert "create_connection" not in code
        # ...and the hostname is carried only as the SNI/verification name, so
        # the certificate is still checked against the name the user asked for.
        assert "server_hostname=hostname" in code
        assert "context.check_hostname = True" in code


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class TestTheRouteRequiresASession:
    def test_a_request_with_no_token_is_401_and_does_nothing(self, app, network):
        response = TestClient(app).post("/web-scan/tls", json={"url": TARGET})
        assert response.status_code == 401
        assert response.json()["detail"] == "Not authenticated"
        assert network.resolutions == []
        assert network.connections == []

    def test_a_request_with_a_junk_token_is_401(self, app, network):
        response = TestClient(app).post(
            "/web-scan/tls",
            json={"url": TARGET},
            headers={"Authorization": "Bearer not-a-real-jwt"},
        )
        assert response.status_code == 401
        assert network.connections == []

    def test_an_unauthenticated_request_does_not_spend_the_rate_limit(
        self, app, network
    ):
        """rate_limit_by_user resolves the session before touching the window."""
        unauthenticated = TestClient(app)
        for _ in range(web_scan_module._limiter.max_requests + 5):
            assert unauthenticated.post(
                "/web-scan/tls", json={"url": TARGET}
            ).status_code == 401

        app.dependency_overrides[get_current_user] = lambda: SCAN_USER
        try:
            assert scan(TestClient(app)).status_code == 200
        finally:
            app.dependency_overrides.clear()


class TestTheRouteIsRateLimitedPerAccount:
    def test_the_window_is_ten_scans_per_twenty_four_hours(self):
        assert web_scan_module._limiter.max_requests == 10
        assert web_scan_module._limiter.window_seconds == 86400

    def test_the_window_closes_after_the_configured_number_of_scans(
        self, client, network
    ):
        limit = web_scan_module._limiter.max_requests
        for _ in range(limit):
            assert scan(client).status_code == 200
        response = scan(client)
        assert response.status_code == 429
        assert "Retry-After" in response.headers

    def test_the_day_long_window_reads_as_a_day_not_as_1440_minutes(
        self, client, network
    ):
        """The message this endpoint's window prompted the formatting fix for.

        A day-long window rendered in minutes produced "10 requests per 1440
        minutes. Try again in 86400s.", which is accurate and unreadable.
        """
        for _ in range(web_scan_module._limiter.max_requests):
            scan(client)
        response = scan(client)
        assert response.status_code == 429
        detail = response.json()["detail"]
        assert detail.startswith("Rate limit exceeded: 10 requests per 1 day.")
        assert "1440 minutes" not in detail
        assert "86400s" not in detail
        # Loose on the remaining wait: it is the window minus however long the
        # ten requests took, so it renders as "1 day" or "24 hours" depending
        # on machine speed. Pinning one makes this fail on a slow day rather
        # than on a real regression.
        assert "Try again in 1 day." in detail or "Try again in 24 hours." in detail

    def test_the_retry_after_header_is_still_raw_seconds(self, client, network):
        """The header is machine-read, so the friendlier units must not reach it."""
        for _ in range(web_scan_module._limiter.max_requests):
            scan(client)
        response = scan(client)
        assert response.status_code == 429
        retry_after = int(response.headers["Retry-After"])
        # The whole window is still ahead of them: the first hit was moments ago.
        assert retry_after > 86000

    def test_the_limiter_is_keyed_on_the_account_not_the_address(self):
        """The create-pr fix, applied here.

        Render terminates TLS and forwards over its own network, so every
        visitor shares one peer address: an address-keyed limit here would be
        ten scans a day for the entire site.
        """
        import inspect

        from rate_limit import rate_limit, rate_limit_by_user, user_key

        source = inspect.getsource(web_scan_module)
        assert "rate_limit_by_user(_limiter)" in source
        assert "rate_limit(_limiter)" not in source
        assert user_key(SCAN_USER) == f"user:{SCAN_USER['_id']}"
        # The by-user dependency takes a user; the by-address one takes a request.
        assert "user" in inspect.signature(
            rate_limit_by_user(web_scan_module._limiter)
        ).parameters
        assert "request" in inspect.signature(
            rate_limit(web_scan_module._limiter)
        ).parameters

    @staticmethod
    def _client_from(app, host: str) -> TestClient:
        """Another client onto the same app, arriving from a different address.

        Written the same way test_pr_router.py writes it: the address is
        rewritten in the ASGI scope, which is where uvicorn puts it from the
        socket, so this exercises exactly what an address-keyed limit would
        read. Dependency overrides live on the wrapped app, so the same account
        stays signed in across all of them.
        """

        class FromAddress:
            def __init__(self, inner):
                self.app = inner

            async def __call__(self, scope, receive, send):
                if scope["type"] == "http":
                    scope = {**scope, "client": (host, 41234)}
                await self.app(scope, receive, send)

        return TestClient(FromAddress(app))

    def test_a_new_address_does_not_buy_the_same_account_a_fresh_allowance(
        self, app, network
    ):
        """The behavioural half, matching test_pr_router's.

        Every request is the same account from a different IP. Under address
        keying each one is a new bucket; under account keying they are one.
        """
        app.dependency_overrides[get_current_user] = lambda: SCAN_USER
        try:
            limit = web_scan_module._limiter.max_requests
            addresses = [f"203.0.113.{index + 1}" for index in range(limit + 1)]
            clients = [self._client_from(app, host) for host in addresses]

            for index in range(limit):
                assert scan(clients[index]).status_code == 200, (
                    f"request {index + 1} from a new IP"
                )
            assert scan(clients[limit]).status_code == 429
        finally:
            app.dependency_overrides.clear()

    def test_the_window_is_keyed_on_the_account_id(self, app, network):
        """Asserted on the key itself, so the intent cannot drift silently."""
        app.dependency_overrides[get_current_user] = lambda: SCAN_USER
        try:
            scan(self._client_from(app, "203.0.113.7"))
            assert list(web_scan_module._limiter._hits) == [
                f"user:{SCAN_USER['_id']}"
            ]
        finally:
            app.dependency_overrides.clear()

    def test_two_accounts_each_get_their_own_allowance(self, app, network):
        limit = web_scan_module._limiter.max_requests
        second = {**SCAN_USER, "_id": "507f1f77bcf86cd799439099"}

        app.dependency_overrides[get_current_user] = lambda: SCAN_USER
        try:
            for _ in range(limit):
                assert scan(TestClient(app)).status_code == 200
            assert scan(TestClient(app)).status_code == 429

            # A different account, same address, still has its full allowance.
            app.dependency_overrides[get_current_user] = lambda: second
            assert scan(TestClient(app)).status_code == 200
        finally:
            app.dependency_overrides.clear()

    def test_this_endpoint_has_its_own_bucket(self, client, network):
        """Scanning websites must not spend the explain or patch allowance."""
        from routers import explain_router, patch_router

        assert web_scan_module._limiter is not explain_router._limiter
        assert web_scan_module._limiter is not patch_router._limiter
        # And a longer window than either of them.
        assert (
            web_scan_module._limiter.window_seconds
            > patch_router._limiter.window_seconds
        )

        patch_router._limiter.reset()
        explain_router._limiter.reset()
        for _ in range(web_scan_module._limiter.max_requests):
            scan(client)
        assert patch_router._limiter._hits == {}
        assert explain_router._limiter._hits == {}


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


class TestConnectionFailuresAreReportedCleanly:
    """No traceback, no raw exception, and always a sentence naming the host."""

    def _assert_clean(self, response, expect_in_detail=None):
        assert response.status_code == 502
        detail = response.json()["detail"]
        assert isinstance(detail, str) and detail
        assert TARGET_HOST in detail
        # Nothing internal leaked.
        assert "Traceback" not in detail
        assert "tls_scanner" not in detail
        assert "backend" not in detail.lower()
        if expect_in_detail:
            assert expect_in_detail.lower() in detail.lower()
        return detail

    def test_a_handshake_timeout_is_a_clean_error(self, client, monkeypatch):
        FakeNetwork(handshake_error=socket.timeout("timed out")).install(monkeypatch)
        self._assert_clean(scan(client), "handshake")

    def test_a_generic_timeout_error_is_a_clean_error(self, client, monkeypatch):
        FakeNetwork(handshake_error=TimeoutError()).install(monkeypatch)
        self._assert_clean(scan(client), "seconds")

    def test_a_handshake_failure_is_a_clean_error(self, client, monkeypatch):
        FakeNetwork(
            handshake_error=ssl.SSLError(1, "SSLV3_ALERT_HANDSHAKE_FAILURE")
        ).install(monkeypatch)
        self._assert_clean(scan(client), "handshake")

    def test_a_certificate_failure_on_both_attempts_is_a_clean_error(
        self, client, monkeypatch
    ):
        """The one case where a bad certificate is still an error.

        The verified handshake failed on trust and the unverified retry did not
        complete either, so no certificate was ever read and there is nothing
        to report on.
        """
        FakeNetwork(handshake_error=EXPIRED_ERROR).install(monkeypatch)
        detail = self._assert_clean(scan(client), "certificate")
        assert "second handshake" in detail

    def test_a_refused_connection_is_a_clean_error(self, client, monkeypatch):
        FakeNetwork(
            handshake_error=ConnectionRefusedError(111, "Connection refused")
        ).install(monkeypatch)
        self._assert_clean(scan(client), "refused")

    def test_a_reset_connection_is_a_clean_error(self, client, monkeypatch):
        FakeNetwork(
            handshake_error=ConnectionResetError(104, "Connection reset by peer")
        ).install(monkeypatch)
        self._assert_clean(scan(client), "reset")

    def test_an_unreachable_host_is_a_clean_error(self, client, monkeypatch):
        FakeNetwork(
            handshake_error=OSError(113, "No route to host")
        ).install(monkeypatch)
        self._assert_clean(scan(client))

    def test_a_name_that_does_not_resolve_is_a_clean_error(self, client, monkeypatch):
        net = FakeNetwork(
            resolve_error=socket.gaierror(-2, "Name or service not known")
        ).install(monkeypatch)
        detail = self._assert_clean(scan(client), "does not resolve")
        assert "DNS" in detail
        assert net.connections == []

    def test_a_certificate_that_will_not_parse_is_a_clean_error(
        self, client, monkeypatch
    ):
        FakeNetwork(certificate_der=b"not a certificate").install(monkeypatch)
        response = scan(client)
        assert response.status_code == 502
        assert "certificate could not be parsed" in response.json()["detail"]

    def test_a_missing_certificate_is_a_clean_error(self, client, monkeypatch):
        FakeNetwork(certificate_der=b"").install(monkeypatch)
        response = scan(client)
        assert response.status_code == 502
        assert "no certificate" in response.json()["detail"]

    def test_an_unexpected_exception_becomes_a_500_with_no_detail_leaked(
        self, client, monkeypatch
    ):
        """The never-raises-unhandled guarantee, matching pr_router's."""

        def explode(url):
            raise RuntimeError("secret internal detail: /srv/qlint/config")

        monkeypatch.setattr(web_scan_module, "scan_url", explode)
        response = scan(client)
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert "secret internal detail" not in detail
        assert "/srv/qlint" not in detail

    def test_the_overall_timeout_bounds_the_whole_operation(
        self, client, monkeypatch
    ):
        """A target that hangs past the overall budget ends the request anyway."""
        import asyncio

        monkeypatch.setattr(tls_scanner, "OVERALL_TIMEOUT_SECONDS", 0.05)

        async def never_finishes(target):
            await asyncio.sleep(5)

        monkeypatch.setattr(tls_scanner, "_resolve_and_inspect", never_finishes)
        response = scan(client)
        assert response.status_code == 502
        assert "did not finish" in response.json()["detail"]


class TestTheTimeoutsAreConfiguredAsSpecified:
    def test_the_handshake_timeout_is_five_seconds(self):
        assert tls_scanner.HANDSHAKE_TIMEOUT_SECONDS == 5.0

    def test_the_overall_timeout_is_ten_seconds(self):
        assert tls_scanner.OVERALL_TIMEOUT_SECONDS == 10.0

    def test_only_port_443_is_ever_used(self):
        assert tls_scanner.TLS_PORT == 443


class TestTheRouterIsRegistered:
    """Checked by reading main.py rather than importing it.

    Importing main pulls in benchmark_router -> pqc_benchmark -> oqs, which
    calls SystemExit(1) at import time wherever liboqs is not built. That is
    why test_routers.py cannot run on every machine, and there is no reason to
    give this file the same problem to assert one include_router line.
    """

    @staticmethod
    def _main_source() -> str:
        from pathlib import Path

        return (Path(__file__).resolve().parent.parent / "main.py").read_text(
            encoding="utf-8"
        )

    def test_main_mounts_the_web_scan_router(self):
        source = self._main_source()
        assert "from routers.web_scan_router import router as web_scan_router" in source
        assert "app.include_router(web_scan_router" in source

    def test_the_existing_routers_are_all_still_mounted(self):
        """This feature is additive; nothing else may have been displaced."""
        source = self._main_source()
        for name in (
            "auth_router",
            "oauth_router",
            "scan_router",
            "explain_router",
            "patch_router",
            "pr_router",
            "user_router",
            "admin_router",
            "hndl_router",
            "benchmark_router",
        ):
            assert f"app.include_router({name}" in source

    def test_the_route_is_declared_at_the_specified_path(self):
        """This file asserts its own route is there, not the router's whole set.

        It used to assert the set was exactly {"/web-scan/tls"}, which was true
        while this was the only endpoint on the router and became wrong the
        moment /web-scan/headers was added alongside it. Owning the full set
        from here would mean every future Level 1 endpoint has to edit the TLS
        test file to be allowed to exist; test_web_scan_headers.py asserts the
        complete set in one place instead.
        """
        paths = {
            route.path for route in web_scan_router.routes if hasattr(route, "path")
        }
        assert "/web-scan/tls" in paths

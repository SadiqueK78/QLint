"""Tests for ai_explainer. All HTTP is served by httpx.MockTransport — no
real OpenRouter calls.
"""

import asyncio

import httpx
import pytest

import ai_explainer
from ai_explainer import AIExplainerError, explain_finding
from ast_scanner import scan_python_source
from js_scanner import scan_js_source
from scanner_engine import scan_source


def make_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


SAMPLE_FINDING = {
    "file": "src/crypto.py",
    "line": 12,
    "language": "python",
    "algorithm": "RSA",
    "severity": "critical",
    "quantum_vulnerable": True,
    "classical_vulnerable": False,
    "attack_vector": "Shor's Algorithm",
    "replacement": "ML-KEM (FIPS 203)",
    "replacement_reason": "Shor's Algorithm factors RSA in polynomial time.",
    "identifier": "rsa.generate_private_key",
    "match_type": "call",
    "code_snippet": "private_key = rsa.generate_private_key(",
    "fix_snippet": "kem = oqs.KeyEncapsulation('ML-KEM-768')",
}


def openrouter_success_handler(request: httpx.Request) -> httpx.Response:
    assert request.url.path == "/api/v1/chat/completions"
    assert request.headers["Authorization"] == "Bearer test-key"
    return httpx.Response(
        200,
        json={
            "model": "openai/gpt-4o-mini",
            "choices": [
                {"message": {"content": "RSA breaks under Shor's Algorithm."}}
            ],
        },
    )


def run_explain(monkeypatch, handler, finding=None, api_key="test-key"):
    monkeypatch.setattr(ai_explainer, "OPENROUTER_API_KEY", api_key)

    async def run():
        async with make_client(handler) as client:
            return await explain_finding(finding or SAMPLE_FINDING, client)

    return asyncio.run(run())


class TestExplainFinding:
    def test_missing_api_key_raises(self, monkeypatch):
        with pytest.raises(AIExplainerError, match="OPENROUTER_API_KEY"):
            run_explain(monkeypatch, openrouter_success_handler, api_key=None)

    def test_missing_algorithm_raises(self, monkeypatch):
        with pytest.raises(AIExplainerError, match="algorithm"):
            run_explain(
                monkeypatch,
                openrouter_success_handler,
                finding={**SAMPLE_FINDING, "algorithm": ""},
            )

    def test_success_returns_content_and_model(self, monkeypatch):
        text, model = run_explain(monkeypatch, openrouter_success_handler)
        assert text == "RSA breaks under Shor's Algorithm."
        assert model == "openai/gpt-4o-mini"

    def test_non_200_raises(self, monkeypatch):
        def handler(request):
            return httpx.Response(401, text="invalid api key")

        with pytest.raises(AIExplainerError, match="401"):
            run_explain(monkeypatch, handler)

    def test_malformed_response_raises(self, monkeypatch):
        def handler(request):
            return httpx.Response(200, json={"unexpected": "shape"})

        with pytest.raises(AIExplainerError, match="missing content"):
            run_explain(monkeypatch, handler)

    def test_empty_content_raises(self, monkeypatch):
        def handler(request):
            return httpx.Response(
                200,
                json={
                    "model": "openai/gpt-4o-mini",
                    "choices": [{"message": {"content": "   "}}],
                },
            )

        with pytest.raises(AIExplainerError, match="empty"):
            run_explain(monkeypatch, handler)

    def test_network_error_raises(self, monkeypatch):
        def handler(request):
            raise httpx.ConnectError("connection refused")

        with pytest.raises(AIExplainerError, match="Could not reach OpenRouter"):
            run_explain(monkeypatch, handler)

    def test_null_content_raises_cleanly(self, monkeypatch):
        """content: null on a content-filter stop or a tool-call-only reply.

        Used to hit .strip() on None and raise AttributeError, which is not in
        explain_finding's except tuple -- it escaped the function and the
        router's 502 mapping, and surfaced as a 500.
        """

        def handler(request):
            return httpx.Response(
                200,
                json={
                    "model": "openai/gpt-4o-mini",
                    "choices": [{"message": {"content": None}}],
                },
            )

        with pytest.raises(AIExplainerError, match="empty"):
            run_explain(monkeypatch, handler)

    def test_null_content_does_not_raise_attribute_error(self, monkeypatch):
        def handler(request):
            return httpx.Response(
                200, json={"choices": [{"message": {"content": None}}]}
            )

        with pytest.raises(AIExplainerError) as caught:
            run_explain(monkeypatch, handler)
        assert not isinstance(caught.value, AttributeError)
        assert caught.value.__cause__ is None

    def test_truncated_response_raises(self, monkeypatch):
        """finish_reason "length" means the model was cut off mid-sentence."""

        def handler(request):
            return httpx.Response(
                200,
                json={
                    "model": "openai/gpt-4o-mini",
                    "choices": [
                        {
                            "message": {"content": "RSA is broken by Shor's and"},
                            "finish_reason": "length",
                        }
                    ],
                },
            )

        with pytest.raises(AIExplainerError, match="truncated"):
            run_explain(monkeypatch, handler)

    def test_complete_response_with_stop_reason_succeeds(self, monkeypatch):
        def handler(request):
            return httpx.Response(
                200,
                json={
                    "model": "openai/gpt-4o-mini",
                    "choices": [
                        {
                            "message": {"content": "A complete explanation."},
                            "finish_reason": "stop",
                        }
                    ],
                },
            )

        text, _ = run_explain(monkeypatch, handler)
        assert text == "A complete explanation."


class TestBuildPrompt:
    def test_includes_core_fields(self):
        prompt = ai_explainer._build_prompt(SAMPLE_FINDING)
        assert "RSA" in prompt
        assert "critical" in prompt
        assert "Shor's Algorithm" in prompt
        assert "src/crypto.py:12" in prompt

    def test_omits_missing_optional_fields(self):
        prompt = ai_explainer._build_prompt({"algorithm": "RSA"})
        assert "Algorithm: RSA" in prompt
        assert "Location" not in prompt

    def test_attack_vector_none_string_is_not_presented_as_an_answer(self):
        """Safe/info findings used to carry the literal string "None", which is
        truthy -- the prompt read "Attack vector: None" as though that were a
        real vector. Scanners send real None now; a client can still post the
        string, and it must be dropped either way."""
        for value in ("None", "none", "  None  ", "", None):
            prompt = ai_explainer._build_prompt(
                {"algorithm": "HMAC (symmetric)", "attack_vector": value}
            )
            assert "Attack vector" not in prompt

    def test_real_attack_vector_still_appears(self):
        prompt = ai_explainer._build_prompt(
            {"algorithm": "RSA", "attack_vector": "Shor's Algorithm"}
        )
        assert "Attack vector: Shor's Algorithm" in prompt


# Python source carrying one unambiguous RSA finding. Written out here rather
# than fixtured so the exact text the assertions look for is visible.
VULNERABLE_PYTHON = """\
from cryptography.hazmat.primitives.asymmetric import rsa


def issue_session_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key
"""

VULNERABLE_JS = """\
const crypto = require('crypto');

function signSession(payload) {
  const signer = crypto.createSign('RSA-SHA256');
  return signer.sign(privateKey);
}
"""


def _rsa_finding(findings: list[dict]) -> dict:
    for finding in findings:
        if finding["algorithm"] == "RSA" and finding["match_type"] != "import":
            return finding
    raise AssertionError(f"no RSA usage finding in {findings}")


class TestPromptIsGroundedInRealScannerOutput:
    """The regression this whole fix exists for.

    _build_prompt used to read before_code/code_before/after_code/code_after --
    four keys no scanner has ever produced -- so the model received the
    algorithm and nothing else and could only answer in the abstract. Nothing
    failed; the explanations were just ungrounded. These tests run the real
    scanners and assert the developer's own code reaches the prompt.
    """

    def test_python_scanner_finding_carries_its_source_line(self):
        finding = _rsa_finding(scan_python_source(VULNERABLE_PYTHON, "crypto.py"))
        assert finding["code_snippet"] == (
            "private_key = rsa.generate_private_key("
            "public_exponent=65537, key_size=2048)"
        )

    def test_python_finding_reaches_the_prompt_as_before_and_after_code(self):
        finding = _rsa_finding(
            scan_source("src/auth.py", "python", VULNERABLE_PYTHON)
        )
        prompt = ai_explainer._build_prompt(finding)

        # The BEFORE half: the developer's actual line, verbatim.
        assert "BEFORE code (vulnerable):" in prompt
        assert "rsa.generate_private_key(public_exponent=65537" in prompt
        # The AFTER half: the replacement CRYPTO_DB recommends.
        assert "AFTER code (quantum-safe fix):" in prompt
        assert finding["fix_snippet"] in prompt
        # And the instruction that only fires when code is present.
        assert "Reference the BEFORE and AFTER code directly" in prompt

    def test_js_scanner_finding_reaches_the_prompt(self):
        finding = _rsa_finding(scan_source("src/sign.js", "javascript", VULNERABLE_JS))
        prompt = ai_explainer._build_prompt(finding)
        assert "const signer = crypto.createSign('RSA-SHA256');" in prompt
        assert "BEFORE code (vulnerable):" in prompt
        assert "AFTER code (quantum-safe fix):" in prompt

    def test_snippet_is_one_line_not_a_context_window(self):
        for finding in scan_python_source(VULNERABLE_PYTHON, "crypto.py"):
            assert "\n" not in finding["code_snippet"]

    def test_two_files_with_the_same_algorithm_carry_different_snippets(self):
        """What makes the widened cache key in explain_router necessary."""
        other = VULNERABLE_PYTHON.replace(
            "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
            "signing_key = rsa.generate_private_key(public_exponent=3, key_size=1024)",
        )
        first = _rsa_finding(scan_python_source(VULNERABLE_PYTHON, "a.py"))
        second = _rsa_finding(scan_python_source(other, "b.py"))
        assert first["algorithm"] == second["algorithm"]
        assert first["code_snippet"] != second["code_snippet"]

    def test_findings_from_every_scanner_have_the_field(self):
        from go_scanner import scan_go_source
        from java_scanner import scan_java_source

        go_source = 'package main\n\nimport "crypto/rsa"\n'
        java_source = 'Cipher c = Cipher.getInstance("RSA");\n'
        for findings in (
            scan_python_source(VULNERABLE_PYTHON, "a.py"),
            scan_js_source(VULNERABLE_JS, "a.js"),
            scan_go_source(go_source, "a.go"),
            scan_java_source(java_source, "A.java"),
        ):
            assert findings
            for finding in findings:
                assert "code_snippet" in finding
                assert finding["code_snippet"]

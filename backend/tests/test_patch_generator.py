"""Tests for patch_generator. All HTTP is served by httpx.MockTransport — no
real OpenRouter calls.
"""

import asyncio

import httpx
import pytest

import patch_generator
from ast_scanner import scan_python_source
from js_scanner import scan_js_source
from patch_generator import PatchGeneratorError, generate_patch
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
    "code_snippet": "private_key = rsa.generate_private_key(key_size=2048)",
    "fix_snippet": "kem = oqs.KeyEncapsulation('ML-KEM-768')",
}

SAMPLE_DIFF = (
    "--- a/src/crypto.py\n"
    "+++ b/src/crypto.py\n"
    "@@ -12,1 +12,2 @@\n"
    "-private_key = rsa.generate_private_key(key_size=2048)\n"
    "+kem = oqs.KeyEncapsulation('ML-KEM-768')\n"
    "+public_key = kem.generate_keypair()\n"
)


def openrouter_success_handler(request: httpx.Request) -> httpx.Response:
    assert request.url.path == "/api/v1/chat/completions"
    assert request.headers["Authorization"] == "Bearer test-key"
    return httpx.Response(
        200,
        json={
            "model": "openai/gpt-4o-mini",
            "choices": [{"message": {"content": SAMPLE_DIFF}}],
        },
    )


def run_patch(monkeypatch, handler, finding=None, api_key="test-key"):
    monkeypatch.setattr(patch_generator, "OPENROUTER_API_KEY", api_key)

    async def run():
        async with make_client(handler) as client:
            return await generate_patch(finding or SAMPLE_FINDING, client)

    return asyncio.run(run())


class TestGeneratePatch:
    def test_missing_api_key_raises(self, monkeypatch):
        with pytest.raises(PatchGeneratorError, match="OPENROUTER_API_KEY"):
            run_patch(monkeypatch, openrouter_success_handler, api_key=None)

    def test_missing_algorithm_raises(self, monkeypatch):
        with pytest.raises(PatchGeneratorError, match="algorithm"):
            run_patch(
                monkeypatch,
                openrouter_success_handler,
                finding={**SAMPLE_FINDING, "algorithm": ""},
            )

    def test_missing_code_snippet_raises_before_any_http_call(self, monkeypatch):
        """Stricter than the explainer. Without the real code there is nothing
        to patch, and a diff invented from the algorithm name would look
        applicable while pointing at lines that do not exist."""
        calls = []

        def handler(request):
            calls.append(request)
            return openrouter_success_handler(request)

        with pytest.raises(PatchGeneratorError, match="code_snippet"):
            run_patch(
                monkeypatch, handler, finding={**SAMPLE_FINDING, "code_snippet": ""}
            )
        assert calls == []

    def test_absent_code_snippet_key_raises(self, monkeypatch):
        finding = {k: v for k, v in SAMPLE_FINDING.items() if k != "code_snippet"}
        with pytest.raises(PatchGeneratorError, match="code_snippet"):
            run_patch(monkeypatch, openrouter_success_handler, finding=finding)

    def test_missing_fix_snippet_raises(self, monkeypatch):
        with pytest.raises(PatchGeneratorError, match="fix_snippet"):
            run_patch(
                monkeypatch,
                openrouter_success_handler,
                finding={**SAMPLE_FINDING, "fix_snippet": ""},
            )

    def test_success_returns_diff_and_model(self, monkeypatch):
        patch, model = run_patch(monkeypatch, openrouter_success_handler)
        assert patch == SAMPLE_DIFF.strip()
        assert model == "openai/gpt-4o-mini"
        assert patch.startswith("--- a/src/crypto.py")
        assert "@@" in patch

    def test_non_200_raises(self, monkeypatch):
        def handler(request):
            return httpx.Response(401, text="invalid api key")

        with pytest.raises(PatchGeneratorError, match="401"):
            run_patch(monkeypatch, handler)

    def test_malformed_response_raises(self, monkeypatch):
        def handler(request):
            return httpx.Response(200, json={"unexpected": "shape"})

        with pytest.raises(PatchGeneratorError, match="missing content"):
            run_patch(monkeypatch, handler)

    def test_empty_content_raises(self, monkeypatch):
        def handler(request):
            return httpx.Response(
                200,
                json={
                    "model": "openai/gpt-4o-mini",
                    "choices": [{"message": {"content": "   "}}],
                },
            )

        with pytest.raises(PatchGeneratorError, match="empty"):
            run_patch(monkeypatch, handler)

    def test_network_error_raises(self, monkeypatch):
        def handler(request):
            raise httpx.ConnectError("connection refused")

        with pytest.raises(PatchGeneratorError, match="Could not reach OpenRouter"):
            run_patch(monkeypatch, handler)

    def test_null_content_raises_cleanly(self, monkeypatch):
        """content: null on a content-filter stop or a tool-call-only reply.

        F22's bug: .strip() on None raises AttributeError, which is not in
        the except tuple -- it escapes the function and the router's 502
        mapping, and surfaces as a 500. Checked for type before use here.
        """

        def handler(request):
            return httpx.Response(
                200,
                json={
                    "model": "openai/gpt-4o-mini",
                    "choices": [{"message": {"content": None}}],
                },
            )

        with pytest.raises(PatchGeneratorError, match="empty"):
            run_patch(monkeypatch, handler)

    def test_null_content_does_not_raise_attribute_error(self, monkeypatch):
        def handler(request):
            return httpx.Response(
                200, json={"choices": [{"message": {"content": None}}]}
            )

        with pytest.raises(PatchGeneratorError) as caught:
            run_patch(monkeypatch, handler)
        assert not isinstance(caught.value, AttributeError)
        assert caught.value.__cause__ is None

    def test_truncated_diff_raises(self, monkeypatch):
        """finish_reason "length" means the hunk was cut off mid-diff, which
        is not a short patch but an unapplyable one."""

        def handler(request):
            return httpx.Response(
                200,
                json={
                    "model": "openai/gpt-4o-mini",
                    "choices": [
                        {
                            "message": {"content": "--- a/x.py\n+++ b/x.py\n@@ -1,1"},
                            "finish_reason": "length",
                        }
                    ],
                },
            )

        with pytest.raises(PatchGeneratorError, match="truncated"):
            run_patch(monkeypatch, handler)

    def test_complete_diff_with_stop_reason_succeeds(self, monkeypatch):
        def handler(request):
            return httpx.Response(
                200,
                json={
                    "model": "openai/gpt-4o-mini",
                    "choices": [
                        {"message": {"content": SAMPLE_DIFF}, "finish_reason": "stop"}
                    ],
                },
            )

        patch, _ = run_patch(monkeypatch, handler)
        assert patch == SAMPLE_DIFF.strip()

    def test_max_tokens_is_larger_than_the_explainers(self, monkeypatch):
        """A diff carries context lines and often a second import hunk, so it
        runs longer than a 180-word explanation."""
        import ai_explainer

        assert patch_generator.MAX_TOKENS > ai_explainer.MAX_TOKENS

        sent = {}

        def handler(request):
            import json as json_module

            sent.update(json_module.loads(request.content))
            return openrouter_success_handler(request)

        run_patch(monkeypatch, handler)
        assert sent["max_tokens"] == patch_generator.MAX_TOKENS


class TestCodeFences:
    def test_wrapping_diff_fence_is_stripped(self, monkeypatch):
        def handler(request):
            return httpx.Response(
                200,
                json={
                    "model": "openai/gpt-4o-mini",
                    "choices": [
                        {"message": {"content": f"```diff\n{SAMPLE_DIFF}```"}}
                    ],
                },
            )

        patch, _ = run_patch(monkeypatch, handler)
        assert "```" not in patch
        assert patch.startswith("--- a/src/crypto.py")

    def test_unfenced_diff_is_untouched(self):
        assert patch_generator._strip_code_fences(SAMPLE_DIFF) == SAMPLE_DIFF.strip()

    def test_fence_only_content_is_rejected(self, monkeypatch):
        def handler(request):
            return httpx.Response(
                200,
                json={
                    "model": "openai/gpt-4o-mini",
                    "choices": [{"message": {"content": "```diff\n```"}}],
                },
            )

        with pytest.raises(PatchGeneratorError, match="empty"):
            run_patch(monkeypatch, handler)


class TestBuildPrompt:
    def test_includes_core_fields(self):
        prompt = patch_generator._build_prompt(SAMPLE_FINDING)
        assert "RSA" in prompt
        assert "critical" in prompt
        assert "Shor's Algorithm" in prompt
        assert "src/crypto.py" in prompt
        assert "Line number of the flagged code: 12" in prompt

    def test_includes_both_snippets(self):
        prompt = patch_generator._build_prompt(SAMPLE_FINDING)
        assert SAMPLE_FINDING["code_snippet"] in prompt
        assert SAMPLE_FINDING["fix_snippet"] in prompt
        assert "BEFORE code" in prompt
        assert "FIX REFERENCE" in prompt

    def test_asks_for_a_diff_and_nothing_else(self):
        prompt = patch_generator._build_prompt(SAMPLE_FINDING)
        assert "unified diff" in prompt
        assert "Output the diff and nothing else." in prompt

    def test_falls_back_to_a_placeholder_path(self):
        finding = {k: v for k, v in SAMPLE_FINDING.items() if k != "file"}
        prompt = patch_generator._build_prompt(finding)
        assert "path/to/file" in prompt

    def test_attack_vector_none_string_is_not_presented_as_an_answer(self):
        for value in ("None", "none", "  None  ", "", None):
            prompt = patch_generator._build_prompt(
                {
                    "algorithm": "HMAC (symmetric)",
                    "attack_vector": value,
                    "code_snippet": "mac = hmac.new(key, msg)",
                    "fix_snippet": "# no migration needed",
                }
            )
            assert "Attack vector" not in prompt


class TestSystemPrompt:
    def test_forbids_prose_and_fences(self):
        assert "no markdown code fences" in patch_generator.SYSTEM_PROMPT
        assert "ONLY the diff" in patch_generator.SYSTEM_PROMPT

    def test_demands_the_real_code_on_the_minus_lines(self):
        assert "character for character" in patch_generator.SYSTEM_PROMPT

    def test_covers_indentation_scope_and_imports(self):
        text = patch_generator.SYSTEM_PROMPT
        assert "indentation style" in text
        assert "Change only what the migration requires" in text
        assert "include " in text and "imports" in text


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
    """The test category whose absence let F22 ship broken.

    Every assertion here starts from output a real scanner produced, not from
    a hand-written fixture finding: a fixture can be written to match whatever
    keys the prompt builder happens to read, which is exactly how F22's
    prompt came to read four keys no scanner has ever emitted. Running the
    scanner is what makes the assertion mean anything.
    """

    def test_python_scanner_finding_reaches_the_patch_prompt_verbatim(self):
        finding = _rsa_finding(
            scan_source("src/auth.py", "python", VULNERABLE_PYTHON)
        )
        prompt = patch_generator._build_prompt(finding)

        # The scanner's own captured line, character for character.
        assert finding["code_snippet"] in prompt
        assert (
            "private_key = rsa.generate_private_key("
            "public_exponent=65537, key_size=2048)"
        ) in prompt
        # ...and the recommended fix it is to be migrated toward.
        assert finding["fix_snippet"] in prompt
        assert "BEFORE code (the exact flagged line(s), patch this):" in prompt
        assert "FIX REFERENCE" in prompt
        # The real path and line, which the diff header is built from.
        assert "src/auth.py" in prompt
        assert f"Line number of the flagged code: {finding['line']}" in prompt

    def test_js_scanner_finding_reaches_the_patch_prompt_verbatim(self):
        finding = _rsa_finding(
            scan_source("src/sign.js", "javascript", VULNERABLE_JS)
        )
        prompt = patch_generator._build_prompt(finding)
        assert finding["code_snippet"] in prompt
        assert "const signer = crypto.createSign('RSA-SHA256');" in prompt
        assert finding["fix_snippet"] in prompt

    def test_real_finding_reaches_the_model_over_the_wire(self, monkeypatch):
        """End to end: scanner -> generate_patch -> the HTTP body OpenRouter
        would receive. Asserting on _build_prompt alone would not catch a
        payload that dropped the user message."""
        finding = _rsa_finding(
            scan_source("src/auth.py", "python", VULNERABLE_PYTHON)
        )
        captured = {}

        def handler(request):
            import json as json_module

            captured.update(json_module.loads(request.content))
            return openrouter_success_handler(request)

        run_patch(monkeypatch, handler, finding=finding)

        user_message = captured["messages"][1]["content"]
        assert finding["code_snippet"] in user_message
        assert finding["fix_snippet"] in user_message
        assert captured["messages"][0]["content"] == patch_generator.SYSTEM_PROMPT

    def test_two_files_with_the_same_algorithm_produce_different_prompts(self):
        """What makes the wide cache key in patch_router necessary: the same
        algorithm on different code must not share one patch."""
        other = VULNERABLE_PYTHON.replace(
            "private_key = rsa.generate_private_key("
            "public_exponent=65537, key_size=2048)",
            "signing_key = rsa.generate_private_key("
            "public_exponent=3, key_size=1024)",
        )
        first = _rsa_finding(scan_python_source(VULNERABLE_PYTHON, "a.py"))
        second = _rsa_finding(scan_python_source(other, "b.py"))
        assert first["algorithm"] == second["algorithm"]
        assert patch_generator._build_prompt(first) != patch_generator._build_prompt(
            second
        )

    def test_every_scanner_emits_the_two_fields_a_patch_needs(self):
        from go_scanner import scan_go_source

        go_source = 'package main\n\nimport "crypto/rsa"\n'
        for findings in (
            scan_python_source(VULNERABLE_PYTHON, "a.py"),
            scan_js_source(VULNERABLE_JS, "a.js"),
            scan_go_source(go_source, "a.go"),
        ):
            assert findings
            for finding in findings:
                assert finding.get("code_snippet")
                assert finding.get("fix_snippet")

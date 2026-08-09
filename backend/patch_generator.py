"""OpenRouter-backed migration patches for PQC scan findings.

The sibling of ai_explainer.py: same OpenRouter client shape, same failure
modes, different product. Where the explainer answers "why is this a problem",
this answers "what exactly do I change", as a unified diff the developer can
read and copy.

Same deliberate limits as the explainer: one HTTP call, no framework imports,
no caching (that lives in routers/patch_router.py). The one hard rule this
module adds is that a patch is refused outright without the finding's real
code -- a diff invented from an algorithm name would be a plausible-looking
patch against code that does not exist, which is worse than no patch at all.
"""

import os

import httpx
from dotenv import load_dotenv

from scanner_common import normalize_attack_vector

load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
# OpenRouter asks callers to identify themselves with these two headers.
# Neither is secret; both just show up in OpenRouter's own dashboard.
OPENROUTER_SITE_URL = os.getenv("OPENROUTER_SITE_URL", "http://localhost:5174")
OPENROUTER_SITE_NAME = os.getenv("OPENROUTER_SITE_NAME", "QLint")

REQUEST_TIMEOUT = 30.0
# 600 rather than the explainer's 400. An explanation is capped at 180 words;
# a diff has no comparable ceiling -- it carries the hunk header, every context
# line, both sides of each changed line, and often an added import at the top
# of the file as a second hunk. At 400 the common "add an import plus rewrite
# the call" patch lands right at the cap, and truncation here is not a slightly
# short answer, it is a diff that cannot apply. Raising the cap is cheaper than
# the retries that cap would cause: unused tokens are not billed.
MAX_TOKENS = 600

SYSTEM_PROMPT = (
    "You are a security engineer writing a migration patch for ONE specific "
    "finding in a developer's real codebase. You will be given the exact "
    "vulnerable code that was flagged (BEFORE) and the direction of the "
    "recommended post-quantum-safe fix (FIX REFERENCE). Your entire output "
    "is a unified diff.\n\n"
    "Output format, strictly:\n"
    "(1) Output ONLY the diff. No prose before it, no summary after it, no "
    "markdown code fences, no ```diff marker, no commentary of any kind.\n"
    "(2) Standard unified diff: a '--- a/<path>' line, a '+++ b/<path>' "
    "line, then one or more '@@ -old,count +new,count @@' hunk headers, with "
    "each following line prefixed by ' ' (context), '-' (removed) or '+' "
    "(added). Use the real file path you were given.\n\n"
    "Content rules:\n"
    "(a) Patch THIS code. The '-' lines must be the actual code you were "
    "shown, character for character, not a paraphrase and not a generic "
    "example of the algorithm. If you cannot produce a hunk that removes the "
    "real flagged line, you have the wrong answer.\n"
    "(b) Preserve the surrounding structure and the indentation style the "
    "BEFORE code implies -- same indent width, same quoting style, same "
    "naming conventions. The '+' lines should look like they were written by "
    "whoever wrote the '-' lines.\n"
    "(c) Change only what the migration requires. Do not rename unrelated "
    "variables, do not reformat untouched lines, do not refactor nearby code, "
    "do not add logging or comments that were not needed for the fix.\n"
    "(d) If the replacement needs imports the file does not have, include "
    "them as part of the diff -- as a separate earlier hunk at the import "
    "block, which is where they actually belong.\n"
    "(e) Treat FIX REFERENCE as the direction, not as text to paste. Adapt "
    "it to the real variable names, call shape and surrounding lines shown in "
    "BEFORE, so the result is syntactically plausible in this file.\n"
    "(f) Line numbers in the hunk header should be consistent with the line "
    "the finding was reported at; approximate context is acceptable, an "
    "inconsistent or malformed header is not."
)


class PatchGeneratorError(Exception):
    """Raised when OpenRouter cannot produce a patch."""


def _build_prompt(finding: dict) -> str:
    lines = [f"Algorithm: {finding.get('algorithm')}"]
    if finding.get("severity"):
        lines.append(f"Severity: {finding['severity']}")
    # Same guard the explainer needs: safe/info findings can carry the literal
    # string "None", which is truthy and would read as a real attack vector.
    attack_vector = normalize_attack_vector(finding.get("attack_vector"))
    if attack_vector:
        lines.append(f"Attack vector: {attack_vector}")
    if finding.get("replacement"):
        lines.append(f"Recommended replacement: {finding['replacement']}")
    if finding.get("replacement_reason"):
        lines.append(
            f"Why the replacement is needed: {finding['replacement_reason']}"
        )
    if finding.get("language"):
        lines.append(f"Language: {finding['language']}")
    if finding.get("identifier"):
        lines.append(f"Code identifier matched: {finding['identifier']}")

    # The diff's own header needs a path, so the file is part of the prompt
    # here rather than optional context the way it is for an explanation.
    path = finding.get("file") or "path/to/file"
    lines.append(f"File path (use this in the diff header): {path}")
    if finding.get("line"):
        lines.append(f"Line number of the flagged code: {finding['line']}")

    lines.append(
        "\nBEFORE code (the exact flagged line(s), patch this):\n"
        f"{finding['code_snippet']}"
    )
    lines.append(
        "\nFIX REFERENCE (the recommended direction, adapt it -- do not "
        f"paste it verbatim):\n{finding['fix_snippet']}"
    )

    return (
        "Write a unified diff migrating this finding to a quantum-safe "
        "implementation:\n" + "\n".join(lines) + "\n\nRemove the BEFORE line "
        "shown above verbatim as a '-' line and add the migrated replacement "
        "as '+' lines. Output the diff and nothing else."
    )


async def generate_patch(
    finding: dict, client: httpx.AsyncClient
) -> tuple[str, str]:
    """Return (patch_text, model_used).

    Raises PatchGeneratorError for a missing key, a finding with no code to
    patch, an unreachable OpenRouter, a non-200 response, or a response with
    no usable content -- callers map this to a single HTTP error rather than
    inspecting exception subtypes.
    """
    if not OPENROUTER_API_KEY:
        raise PatchGeneratorError(
            "OPENROUTER_API_KEY is not configured. Add it to backend/.env"
        )
    if not finding.get("algorithm"):
        raise PatchGeneratorError("Finding is missing an algorithm to patch.")
    # Stricter than the explainer on purpose. An explanation with no code is
    # merely generic; a patch with no code is a fabricated diff against lines
    # that may not exist, which a developer could try to apply.
    if not finding.get("code_snippet"):
        raise PatchGeneratorError(
            "Finding is missing code_snippet, so there is no real code to "
            "patch. A patch cannot be grounded without it."
        )
    if not finding.get("fix_snippet"):
        raise PatchGeneratorError(
            "Finding is missing fix_snippet, so there is no recommended fix "
            "to build the patch from."
        )

    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _build_prompt(finding)},
        ],
        "max_tokens": MAX_TOKENS,
        # Lower than the explainer's 0.3: a diff has a rigid format and one
        # mostly-correct answer, so there is nothing for sampling variety to
        # improve and a malformed hunk header for it to cost.
        "temperature": 0.1,
    }
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": OPENROUTER_SITE_URL,
        "X-Title": OPENROUTER_SITE_NAME,
    }

    try:
        response = await client.post(
            f"{OPENROUTER_BASE_URL}/chat/completions",
            json=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        raise PatchGeneratorError(f"Could not reach OpenRouter: {exc}") from exc

    if response.status_code != 200:
        raise PatchGeneratorError(
            f"OpenRouter returned {response.status_code}: {response.text[:300]}"
        )

    try:
        data = response.json()
        choice = data["choices"][0]
        content = choice["message"]["content"]
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise PatchGeneratorError("OpenRouter response was missing content.") from exc

    # content comes back null on a content-filter stop and on a response that
    # carried only tool calls. This is F22's bug: .strip() on None raises
    # AttributeError, which is not in the tuple above, so it escapes the
    # function entirely and the caller's 502 mapping never sees it. Check the
    # type before touching the value.
    if not isinstance(content, str) or not content.strip():
        raise PatchGeneratorError("OpenRouter returned an empty patch.")
    content = _strip_code_fences(content)
    if not content:
        raise PatchGeneratorError("OpenRouter returned an empty patch.")

    # A diff cut off by the token cap is not a short patch, it is an
    # unapplyable one -- and caching it would serve that broken hunk for 30
    # days. Fail instead.
    if choice.get("finish_reason") == "length":
        raise PatchGeneratorError(
            f"OpenRouter truncated the patch at the {MAX_TOKENS}-token limit, "
            "so it was not cached. Retry, or raise MAX_TOKENS."
        )

    return content, data.get("model", OPENROUTER_MODEL)


def _strip_code_fences(text: str) -> str:
    """Drop a wrapping ```diff fence if the model added one anyway.

    The prompt forbids fences, but models add them to anything that looks like
    code often enough that leaving the backticks in the cached patch -- and in
    whatever the developer copies -- is not worth the purity.
    """
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    lines = lines[1:]  # the opening ``` plus any language tag on that line
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


if __name__ == "__main__":
    fake_finding = {
        "file": "src/auth.py",
        "line": 12,
        "language": "python",
        "algorithm": "RSA",
        "severity": "critical",
        "attack_vector": "Shor's Algorithm",
        "replacement": "ML-KEM (FIPS 203)",
        "replacement_reason": "Shor's Algorithm factors the RSA modulus.",
        "identifier": "rsa.generate_private_key",
        "code_snippet": "private_key = rsa.generate_private_key(key_size=2048)",
        "fix_snippet": "import oqs\nkem = oqs.KeyEncapsulation('ML-KEM-768')",
    }
    prompt = _build_prompt(fake_finding)
    # The whole point of the module: the developer's real line reaches the model.
    assert fake_finding["code_snippet"] in prompt
    assert fake_finding["fix_snippet"] in prompt
    assert "src/auth.py" in prompt
    assert "Line number of the flagged code: 12" in prompt

    # A safe finding's literal "None" attack vector must not read as an answer.
    safe_prompt = _build_prompt(
        {
            "algorithm": "HMAC (symmetric)",
            "attack_vector": "None",
            "code_snippet": "mac = hmac.new(key, msg, hashlib.sha256)",
            "fix_snippet": "# HMAC is quantum-safe; no migration needed.",
        }
    )
    assert "Attack vector" not in safe_prompt

    # Fences the prompt forbids but models emit anyway.
    fenced = "```diff\n--- a/src/auth.py\n+++ b/src/auth.py\n```"
    assert _strip_code_fences(fenced) == "--- a/src/auth.py\n+++ b/src/auth.py"
    assert _strip_code_fences("--- a/x.py\n+++ b/x.py") == "--- a/x.py\n+++ b/x.py"

    print("patch_generator.py self-test passed")
    print(f"  MAX_TOKENS: {MAX_TOKENS} (explainer uses 400)")
    print(f"  Prompt length: {len(prompt)} chars")
    print("  --- grounded prompt ---")
    print(prompt)

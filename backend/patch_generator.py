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
# Patches get their own model, and a more capable one than the rest of QLint.
# Every other OpenRouter call here produces prose, where a weaker model is
# merely blander. This one produces a unified diff that patch_applier matches
# against the real file character for character, and a model that miscounts two
# consecutive blank lines as one emits a hunk that cannot be placed. Measured
# on the F29 test repository: with the same grounded prompt, gpt-4o-mini landed
# 1-2 of 4 findings and claude-sonnet-4.5 landed 4 of 4, the failures every time
# being dropped or merged blank lines rather than wrong code.
#
# Deliberately its own setting rather than a share of OPENROUTER_MODEL: pointing
# the whole application at a cheap model is a reasonable thing for an operator
# to do, and it should not silently turn every pull request into a list of
# skipped findings.
OPENROUTER_MODEL = os.getenv(
    "OPENROUTER_PATCH_MODEL", "anthropic/claude-sonnet-4.5"
)
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
# OpenRouter asks callers to identify themselves with these two headers.
# Neither is secret; both just show up in OpenRouter's own dashboard.
OPENROUTER_SITE_URL = os.getenv("OPENROUTER_SITE_URL", "http://localhost:5174")
OPENROUTER_SITE_NAME = os.getenv("OPENROUTER_SITE_NAME", "QLint")

REQUEST_TIMEOUT = 30.0

# How much of the real file to show the model. A diff whose context lines were
# invented cannot be applied by patch_applier, which matches before-blocks
# exactly, so the model has to be shown the actual lines it is writing context
# for. Small files go in whole; larger ones go in as two excerpts, because the
# two places a migration patch touches are the import block at the top and the
# flagged line itself.
WHOLE_FILE_MAX_LINES = 200
GROUNDING_HEAD_LINES = 40
GROUNDING_CONTEXT_LINES = 20
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
    "(added). Use the real file path you were given.\n"
    "(3) Exactly ONE prefix character per line, with no extra space after it. "
    "A removed line reading 'key = f()' is '-key = f()', never '- key = f()' "
    "-- the character straight after the prefix is already the first character "
    "of the code.\n"
    "(4) Every '@@' hunk header is mandatory. A diff without one cannot be "
    "applied at all.\n"
    "(5) Blank lines count. FILE CONTENT is numbered so you can count them: if "
    "lines 4 and 5 are both empty, your hunk covering that range has two empty "
    "lines, each written as the ' ' context prefix and nothing else. Dropping "
    "one, or merging two into one, puts every following line out of step and "
    "the patch is rejected.\n\n"
    "Content rules:\n"
    "(a) Patch THIS code. The '-' lines must be the actual code you were "
    "shown, character for character, not a paraphrase and not a generic "
    "example of the algorithm. If you cannot produce a hunk that removes the "
    "real flagged line, you have the wrong answer.\n"
    "(b) Copy every '-' and ' ' line verbatim out of the FILE CONTENT you "
    "were given, including its exact leading indentation. These lines are "
    "matched against the real file character for character: a context line "
    "you invented, a line you re-indented, or a line you guessed at because "
    "it seemed likely to be there will cause the whole patch to be rejected. "
    "If FILE CONTENT does not show you a line, do not write it as context. "
    "Never write a context line for a part of the file you were not shown.\n"
    "(c) Preserve the surrounding structure and the indentation style the "
    "file implies -- same indent width, same quoting style, same naming "
    "conventions. A '+' line replacing an indented '-' line carries the same "
    "indentation as the line it replaces, so the result is still valid code. "
    "The '+' lines should look like they were written by whoever wrote the "
    "'-' lines.\n"
    "(d) Change only what the migration requires. Do not rename unrelated "
    "variables, do not reformat untouched lines, do not refactor nearby code, "
    "do not add logging or comments that were not needed for the fix.\n"
    "(e) If the replacement needs imports the file does not have, include "
    "them as part of the diff -- as a separate earlier hunk at the import "
    "block, which is where they actually belong, anchored on an import line "
    "you can see in FILE CONTENT.\n"
    "(f) Treat FIX REFERENCE as the direction, not as text to paste. Adapt "
    "it to the real variable names, call shape and surrounding lines shown in "
    "BEFORE, so the result is syntactically plausible in this file.\n"
    "(g) Line numbers in the hunk header should be consistent with the line "
    "the finding was reported at; approximate context is acceptable, an "
    "inconsistent or malformed header is not."
)


class PatchGeneratorError(Exception):
    """Raised when OpenRouter cannot produce a patch."""


def grounding_excerpt(file_content: str, line: int | None) -> str | None:
    """The real lines of the file the model must write its diff against.

    Without this the model is asked to produce a unified diff for a file it has
    never seen, so every context line in the hunk is necessarily a guess -- and
    patch_applier matches before-blocks exactly, so a guessed context line means
    the patch is refused even when nothing about the file has changed. That was
    F29's false "the code the patch expects to change is not present in the
    current file" on freshly scanned, never-edited repositories.

    Whole file when it is short enough to be cheap. Otherwise the two regions a
    migration patch actually touches: the head, where the import hunk lands, and
    a window around the flagged line. The gap between them is marked so the
    model cannot read the two excerpts as one contiguous run and write a context
    line spanning the join.
    """
    if not file_content:
        return None

    lines = file_content.splitlines()
    if not lines:
        return None

    def numbered(start: int, end: int) -> list[str]:
        # Numbered because the failure that survives grounding is miscounting
        # consecutive blank lines: a run of empty lines is impossible to count
        # by eye but trivial to count when each one carries its number. The
        # numbers are stripped back off before anything is matched -- they are
        # a reading aid in the prompt only, and the prompt says so.
        return [f"{index + 1:>4} | {lines[index]}" for index in range(start, end)]

    if len(lines) <= WHOLE_FILE_MAX_LINES:
        return "\n".join(numbered(0, len(lines)))

    if line is None or line < 1:
        return "\n".join(numbered(0, GROUNDING_HEAD_LINES))

    start = max(0, line - 1 - GROUNDING_CONTEXT_LINES)
    end = min(len(lines), line + GROUNDING_CONTEXT_LINES)
    if start <= GROUNDING_HEAD_LINES:
        # The window already reaches the head; one excerpt, no join to mark.
        return "\n".join(numbered(0, end))
    return "\n".join(
        numbered(0, GROUNDING_HEAD_LINES)
        + [f"... (lines {GROUNDING_HEAD_LINES + 1}-{start} not shown) ..."]
        + numbered(start, end)
    )


def _build_prompt(finding: dict, file_content: str | None = None) -> str:
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

    excerpt = grounding_excerpt(file_content or "", finding.get("line"))
    if excerpt:
        lines.append(
            "\nFILE CONTENT (the real file, exactly as it is on disk right "
            "now). Each line is shown as 'NUMBER | TEXT': the number and the "
            "'|' are a reading aid and are NOT part of the file -- everything "
            "after '| ' is. Every '-' line and every ' ' context line in your "
            "diff must be copied character for character from the TEXT side, "
            "leading indentation included:\n"
            f"{excerpt}"
        )

    # The scanner strips the flagged line before storing it, so code_snippet has
    # lost its indentation. Sending only that teaches the model to emit an
    # unindented '-' line, which then does not match the indented line in the
    # real file. When the file is available the raw line is authoritative.
    before = finding["code_snippet"]
    raw_line = _raw_line(file_content, finding.get("line"))
    if raw_line is not None and raw_line.strip() == before.strip():
        before = raw_line
        lines.append(
            "\nBEFORE code (the flagged line exactly as it appears in FILE "
            "CONTENT, with its real indentation -- reproduce this byte for "
            f"byte after the '-' prefix):\n{before}"
        )
    else:
        lines.append(
            "\nBEFORE code (the exact flagged line(s), patch this):\n"
            f"{before}"
        )

    lines.append(
        "\nFIX REFERENCE (the recommended direction, adapt it -- do not "
        f"paste it verbatim):\n{finding['fix_snippet']}"
    )

    closing = (
        "\n\nRemove the BEFORE line shown above verbatim as a '-' line and add "
        "the migrated replacement as '+' lines. Output the diff and nothing "
        "else."
    )
    if excerpt:
        closing = (
            "\n\nRemove the BEFORE line shown above verbatim as a '-' line, "
            "with its exact leading indentation, and add the migrated "
            "replacement as '+' lines indented to match. Use only context "
            "lines that appear verbatim in FILE CONTENT. Output the diff and "
            "nothing else."
        )

    return (
        "Write a unified diff migrating this finding to a quantum-safe "
        "implementation:\n" + "\n".join(lines) + closing
    )


def _raw_line(file_content: str | None, line: int | None) -> str | None:
    """The untrimmed text of a 1-based line, or None if it is not there."""
    if not file_content or line is None or line < 1:
        return None
    lines = file_content.splitlines()
    if line > len(lines):
        return None
    return lines[line - 1]


async def generate_patch(
    finding: dict, client: httpx.AsyncClient, file_content: str | None = None
) -> tuple[str, str]:
    """Return (patch_text, model_used).

    file_content is the real current text of the file the finding sits in. Pass
    it whenever the caller has it: a diff written against the actual file has
    real context lines and real indentation, which is what patch_applier
    requires to place a hunk. Without it the model can only guess at everything
    around the flagged line, and those guesses are what patch_applier refuses.
    /scan/patch has no file to pass and gets a display-only patch; the pull
    request path always passes the content it just fetched.

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
            {"role": "user", "content": _build_prompt(finding, file_content)},
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

    # Grounding: the file the diff will be matched against has to be in the
    # prompt, and the flagged line has to arrive with the indentation the
    # scanner stripped off it. Without both, the model writes a diff whose
    # context and indentation are guesses and patch_applier refuses it.
    indented_file = (
        '"""Keys."""\n\nfrom Crypto.PublicKey import RSA\n\n\n'
        "def make_key():\n    private_key = rsa.generate_private_key(key_size=2048)\n"
    )
    indented_finding = {**fake_finding, "line": 7}
    blind = _build_prompt(indented_finding)
    grounded = _build_prompt(indented_finding, indented_file)
    assert "    private_key = rsa.generate_private_key(key_size=2048)" not in blind
    assert "    private_key = rsa.generate_private_key(key_size=2048)" in grounded
    assert "FILE CONTENT" in grounded and "FILE CONTENT" not in blind
    # Both blank lines before the def survive into the excerpt: collapsing them
    # is exactly what makes a hunk unplaceable.
    assert "   4 | \n   5 | \n" in grounded

    # Fences the prompt forbids but models emit anyway.
    fenced = "```diff\n--- a/src/auth.py\n+++ b/src/auth.py\n```"
    assert _strip_code_fences(fenced) == "--- a/src/auth.py\n+++ b/src/auth.py"
    assert _strip_code_fences("--- a/x.py\n+++ b/x.py") == "--- a/x.py\n+++ b/x.py"

    print("patch_generator.py self-test passed")
    print(f"  MAX_TOKENS: {MAX_TOKENS} (explainer uses 400)")
    print(f"  Prompt length: {len(prompt)} chars")
    print("  --- grounded prompt ---")
    print(prompt)

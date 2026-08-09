"""OpenRouter-backed plain-English explanations for PQC scan findings.

Calls OpenRouter's OpenAI-compatible /chat/completions endpoint, so any model
OpenRouter hosts (GPT, Claude, Llama, ...) can be swapped in via
OPENROUTER_MODEL without touching this module. Pure function + one HTTP call:
no framework imports, no caching (that lives in routers/explain_router.py).
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
MAX_TOKENS = 400

SYSTEM_PROMPT = (
    "You are a security engineer reviewing a SPECIFIC finding in a "
    "developer's code, not writing a general encyclopedia entry about a "
    "cryptographic algorithm. You will be given the vulnerable code that "
    "was flagged and the suggested fix code. Write a short, plain-English "
    "explanation (120-180 words) that a developer who is not a "
    "cryptography expert can act on.\n\n"
    "Ground every sentence in the specific finding you were given: "
    "\n(1) Point at what the BEFORE code is actually doing -- name the "
    "real function/class/import used (e.g. 'this RSA-2048 key generated "
    "via rsa.generate_private_key'), not just the algorithm in the "
    "abstract, and say concretely why that exact usage is quantum-"
    "vulnerable or quantum-weakened.\n"
    "(2) Describe the realistic real-world consequence for THIS usage if "
    "a future quantum computer breaks it -- or, for 'harvest now, decrypt "
    "later' cases, if an attacker is recording this traffic today to "
    "decrypt later. Tie it to what the code appears to protect (e.g. a "
    "key exchange, a signature, a session), not a generic 'data breaches "
    "could occur' statement.\n"
    "(3) Point at what the AFTER code changes -- name the specific "
    "replacement (e.g. 'ML-KEM-768 via liboqs's oqs.KeyEncapsulation') "
    "and say in one sentence what the developer has to actually change to "
    "adopt it (new import, new call shape, key/ciphertext size "
    "differences, etc.), then state urgency given the severity.\n\n"
    "Never repeat the raw input fields back verbatim as a list. Never "
    "write a paragraph that would be equally true for every RSA finding "
    "in existence -- if you could paste this explanation onto a different "
    "finding of the same algorithm unchanged, rewrite it to be more "
    "specific to the code shown. Plain prose only, no headings, no bullet "
    "points, no markdown, no code fences."
)


class AIExplainerError(Exception):
    """Raised when OpenRouter cannot produce an explanation."""


def _build_prompt(finding: dict) -> str:
    lines = [f"Algorithm: {finding.get('algorithm')}"]
    if finding.get("severity"):
        lines.append(f"Severity: {finding['severity']}")
    # Scanners now send real None for safe/info findings, but a client can
    # still post the literal string "None"; either way it must not reach the
    # model as though it were an attack vector.
    attack_vector = normalize_attack_vector(finding.get("attack_vector"))
    if attack_vector:
        lines.append(f"Attack vector: {attack_vector}")
    if finding.get("quantum_vulnerable") is not None:
        lines.append(f"Quantum-vulnerable: {finding['quantum_vulnerable']}")
    if finding.get("classical_vulnerable") is not None:
        lines.append(f"Classically weakened: {finding['classical_vulnerable']}")
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
    if finding.get("file"):
        location = finding["file"]
        if finding.get("line"):
            location += f":{finding['line']}"
        lines.append(f"Location: {location}")

    # The two fields that actually let the model ground its answer in the real
    # code instead of talking about the algorithm in the abstract. These are
    # the names the scanners produce: code_snippet is the flagged source line
    # captured at scan time, fix_snippet the replacement CRYPTO_DB recommends.
    before_code = finding.get("code_snippet")
    after_code = finding.get("fix_snippet")
    if before_code:
        lines.append(f"\nBEFORE code (vulnerable):\n{before_code}")
    if after_code:
        lines.append(f"\nAFTER code (quantum-safe fix):\n{after_code}")

    prompt = "Explain this PQC scan finding:\n" + "\n".join(lines)
    if before_code or after_code:
        prompt += (
            "\n\nReference the BEFORE and AFTER code directly in your "
            "explanation -- name the actual functions/calls shown rather "
            "than describing the algorithm generically."
        )
    return prompt


async def explain_finding(
    finding: dict, client: httpx.AsyncClient
) -> tuple[str, str]:
    """Return (explanation_text, model_used).

    Raises AIExplainerError for a missing key, an unreachable OpenRouter, a
    non-200 response, or a response with no usable content -- callers map
    this to a single HTTP error rather than inspecting exception subtypes.
    """
    if not OPENROUTER_API_KEY:
        raise AIExplainerError(
            "OPENROUTER_API_KEY is not configured. Add it to backend/.env"
        )
    if not finding.get("algorithm"):
        raise AIExplainerError("Finding is missing an algorithm to explain.")

    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _build_prompt(finding)},
        ],
        "max_tokens": MAX_TOKENS,
        "temperature": 0.3,
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
        raise AIExplainerError(f"Could not reach OpenRouter: {exc}") from exc

    if response.status_code != 200:
        raise AIExplainerError(
            f"OpenRouter returned {response.status_code}: {response.text[:300]}"
        )

    try:
        data = response.json()
        choice = data["choices"][0]
        content = choice["message"]["content"]
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise AIExplainerError("OpenRouter response was missing content.") from exc

    # content comes back null on a content-filter stop and on a response that
    # carried only tool calls. Calling .strip() on it raises AttributeError,
    # which is not in the tuple above and so escaped this function entirely --
    # the caller's 502 mapping never saw it and the request 500'd.
    if not isinstance(content, str) or not content.strip():
        raise AIExplainerError("OpenRouter returned an empty explanation.")
    content = content.strip()

    # A completion stopped by the token cap ends mid-sentence. Failing here is
    # what keeps a truncated explanation out of the 30-day cache.
    if choice.get("finish_reason") == "length":
        raise AIExplainerError(
            f"OpenRouter truncated the explanation at the {MAX_TOKENS}-token "
            "limit, so it was not cached. Retry, or raise MAX_TOKENS."
        )

    return content, data.get("model", OPENROUTER_MODEL)
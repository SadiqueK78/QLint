"""OpenRouter-backed plain-English explanations for website-scan findings.

The sibling of ai_explainer, and a separate module rather than a branch inside
it. The two explain different things to different readers:

  * ai_explainer explains a finding in a developer's code. Its whole prompt is
    built around the BEFORE/AFTER pair the scanners capture -- the flagged
    source line and the replacement -- and it refuses a finding with no
    algorithm, because there is nothing to talk about without one.
  * This one explains what a live site is serving. A TLS cipher suite, a
    certificate, a missing HTTP header: none of them has a file, a line, or a
    snippet of code, and the reader is as likely to be the person who owns the
    site as the person who wrote it. Passing these through the other module's
    prompt would mean either sending it empty code fields or inventing values
    for them, and the model's instructions there tell it to name the functions
    in code it would never have been given.

What is shared is deliberately shared: the OpenRouter configuration, the
timeout, the error type. Those are properties of the account and the provider,
not of one feature, and duplicating them is how the two would drift apart the
next time a model or a base URL changes.
"""

import httpx

from ai_explainer import (
    MAX_TOKENS,
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OPENROUTER_MODEL,
    OPENROUTER_SITE_NAME,
    OPENROUTER_SITE_URL,
    REQUEST_TIMEOUT,
    AIExplainerError,
)

SYSTEM_PROMPT = (
    "You are a security engineer explaining ONE specific finding from a scan "
    "of a live website to the person responsible for that site. They may not "
    "know what a cipher suite, a certificate signature algorithm or an HTTP "
    "security header actually is, and your job is to make this one finding "
    "make sense to them. Write 100-160 words of plain English.\n\n"
    "Cover three things, in this order, grounded in the finding you were "
    "given rather than in the topic in general:\n"
    "(1) What this finding is actually saying about the site -- explain the "
    "thing being reported (the header, the cipher, the certificate field) in "
    "ordinary words, and say what the reported status means for it.\n"
    "(2) Why it matters, or why it does not. Be honest about a passing or "
    "acceptable finding: say plainly that this one is fine and what it is "
    "already protecting against, rather than manufacturing a risk. For a "
    "finding that does matter, describe the realistic consequence -- who could "
    "do what to whom -- and, where quantum risk is the reason, explain that an "
    "attacker can record this traffic today and decrypt it once a quantum "
    "computer exists.\n"
    "(3) What it implies for the reader: the concrete action, whose job it "
    "usually is (a server or CDN configuration change, a certificate reissue "
    "from the certificate authority, a change to the site's code), and how "
    "urgent it is given the severity. If no action is needed, say so.\n\n"
    "Never repeat the input fields back as a list. Never write a paragraph "
    "that would be equally true of every site with this header or cipher -- "
    "use the actual values you were given. Do not invent details about the "
    "site that you were not told, and do not mention source code, files or "
    "line numbers: this is a scan of a running site, not of a repository. "
    "Plain prose only, no headings, no bullet points, no markdown."
)


def _build_prompt(finding: dict) -> str:
    """The user message, from whichever fields this finding actually carries.

    Every field is optional except in combination, because the four domains
    fill in different ones: a TLS finding has an algorithm and a key size, a
    header finding has a header name and what the site sent, a JavaScript
    finding has an algorithm and no status at all. Absent fields are omitted
    rather than sent as "None" -- a model told the status is None will write a
    sentence about it.
    """
    labels = (
        ("category", "Part of the site this concerns"),
        ("asset", "What was checked"),
        ("type", "Kind of thing it is"),
        ("status", "What the scan found"),
        ("severity", "Severity"),
        ("algorithm", "Cryptographic algorithm involved"),
        ("key_size", "Key size"),
        ("observed_value", "Value the site actually sent"),
        ("quantum_risk", "Quantum risk"),
        ("recommendation", "Recommended action"),
    )
    lines = [
        f"{label}: {finding[key]}"
        for key, label in labels
        if finding.get(key) not in (None, "")
    ]
    return "Explain this finding from a website security scan:\n" + "\n".join(lines)


async def explain_web_finding(
    finding: dict, client: httpx.AsyncClient
) -> tuple[str, str]:
    """Return (explanation_text, model_used).

    Mirrors ai_explainer.explain_finding's contract exactly -- one exception
    type for every failure, so the router maps it to a single HTTP error
    instead of inspecting subtypes -- while asking a different question.
    """
    if not OPENROUTER_API_KEY:
        raise AIExplainerError(
            "OPENROUTER_API_KEY is not configured. Add it to backend/.env"
        )
    # The website equivalent of the other module's missing-algorithm guard. A
    # header finding legitimately has no algorithm and a JavaScript finding
    # legitimately has no asset, so either alone is enough -- but a finding
    # with neither names nothing, and there is no explanation to write.
    if not finding.get("asset") and not finding.get("algorithm"):
        raise AIExplainerError(
            "Finding names neither an asset nor an algorithm to explain."
        )

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

    # Null content on a content-filter stop or a tool-call-only response, and
    # the same AttributeError trap ai_explainer documents: .strip() on None is
    # not in the tuple above and would escape as a 500.
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

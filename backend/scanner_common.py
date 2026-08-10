"""Helpers shared by every language scanner.

ast_scanner, js_scanner, go_scanner, java_scanner and rust_scanner all need the
same two things: a way to turn a character offset into a line/column pair, and
a way to pull the text of a line back out of the source. js_scanner and
go_scanner each carried their own copy; this module holds the one
implementation all of them use, so that "the line at N" means the same thing in
every language and the code_snippet attached to a finding is produced in
exactly one place.
"""


def line_starts(source: str) -> list[int]:
    """Character offset of the first character of each line."""
    starts = [0]
    for index, char in enumerate(source):
        if char == "\n":
            starts.append(index + 1)
    return starts


def position(starts: list[int], offset: int) -> tuple[int, int]:
    """Translate a character offset into 1-based line and 0-based column."""
    low, high = 0, len(starts) - 1
    while low < high:
        mid = (low + high + 1) // 2
        if starts[mid] <= offset:
            low = mid
        else:
            high = mid - 1
    return low + 1, offset - starts[low]


def line_text(source: str, starts: list[int], line: int) -> str:
    """The raw text of a 1-based line, trailing newline included."""
    if line < 1 or line > len(starts):
        return ""
    start = starts[line - 1]
    end = starts[line] if line < len(starts) else len(source)
    return source[start:end]


def snippet_at(source: str, starts: list[int], line: int) -> str:
    """The flagged line, whitespace-trimmed — the BEFORE code of a finding.

    One line and one line only: this is the text the scanner already read to
    decide there was a finding here, not a surrounding context window.
    """
    return line_text(source, starts, line).strip()


def attach_snippets(
    findings: list[dict], source: str, starts: list[int] | None = None
) -> list[dict]:
    """Fill in code_snippet on every finding from its own line of source.

    Called once per scan after the detection pass, so no scanner has to thread
    the source text through its finding builders.
    """
    if starts is None:
        starts = line_starts(source)
    for finding in findings:
        finding["code_snippet"] = snippet_at(source, starts, finding["line"])
    return findings


def normalize_attack_vector(value):
    """Real None for "there is no attack vector", never the string "None".

    Safe and info findings carry the literal string "None" — in CRYPTO_DB and
    in the scanners' own synthetic notes — which is truthy. Anything testing
    `if finding["attack_vector"]` then treats it as a real answer, and a
    prompt built from it reads "Attack vector: None".
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text.lower() == "none":
        return None
    return text

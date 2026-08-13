"""Apply an AI-generated unified diff to real file content, or refuse.

This is the module standing between "flagship feature" and "the thing that
broke someone's repository". Everything here is deliberately strict, because
the inputs are two things that can both be wrong: a code snippet captured at
scan time (the file may have changed since), and a diff written by a language
model (the hunk header line numbers are explicitly documented as approximate
in patch_generator.py).

Three rules, none of them negotiable:

1. Re-validation first. The finding's code_snippet must still sit at the exact
   line the scanner recorded, character for character, in the content just
   fetched from GitHub. Not "somewhere in the file", not "close enough" -- at
   that line. A file that drifted since the scan is skipped, never guessed at.

2. Location by exact content, never by hunk header. The model's "@@ -12,3"
   is approximate, so applying at line 12 would be applying at a line the model
   was estimating. Instead each hunk's before-block (its context and removed
   lines) is searched for as an exact contiguous run of lines. Found once:
   apply there. Found zero times, or more than once: refuse. A unique exact
   match cannot be the wrong location; an ambiguous one might be.

3. No fuzz, ever. There is no whitespace-insensitive fallback, no
   nearest-match, no partial hunk application. Every failure mode above raises
   PatchApplyError and the caller reports the finding as skipped, with the
   reason, in the pull request body.

Line endings are preserved byte for byte on untouched lines: the file is split
with keepends and only the replaced spans are rewritten, each inheriting the
ending of the line it replaces. A CRLF file does not silently become an LF one.
"""

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Line prefixes that mean "this diff describes more than the file we asked
# about". A multi-file patch has no single target to write back, so it is
# refused rather than half-applied.
_FILE_HEADER_PREFIXES = ("--- ", "+++ ", "diff --git ", "index ")


class PatchApplyError(Exception):
    """The patch could not be applied safely. Carries the user-facing reason."""


@dataclass(frozen=True)
class Hunk:
    """One @@ block, as the two sides of the file it describes.

    before is context plus removed lines (what the file must currently say);
    after is context plus added lines (what it should say instead).
    """

    before: tuple[str, ...]
    after: tuple[str, ...]


@dataclass(frozen=True)
class Replacement:
    """A resolved edit: replace [start, end) of the original lines with lines."""

    start: int
    end: int
    lines: tuple[str, ...]

    def overlaps(self, other: "Replacement") -> bool:
        # Touching is not overlapping: [3,5) and [5,7) are adjacent edits and
        # both can stand. Sharing even one line is a conflict.
        return self.start < other.end and other.start < self.end


# --------------------------------------------------------------- parsing


def parse_unified_diff(diff_text: str) -> list[Hunk]:
    """Split a unified diff into hunks. Raises PatchApplyError if unusable."""
    if not diff_text or not diff_text.strip():
        raise PatchApplyError("the generated patch was empty")

    hunks: list[Hunk] = []
    before: list[str] = []
    after: list[str] = []
    in_hunk = False
    seen_hunk = False

    def close() -> None:
        if in_hunk:
            hunks.append(Hunk(tuple(before), tuple(after)))

    for raw in diff_text.splitlines():
        if raw.startswith("@@"):
            close()
            before, after = [], []
            in_hunk = True
            seen_hunk = True
            continue

        if raw.startswith(_FILE_HEADER_PREFIXES):
            if seen_hunk:
                # A header after the first hunk means a second file's diff.
                # One finding, one file: refuse rather than pick one.
                raise PatchApplyError(
                    "the generated patch spans more than one file, which "
                    "cannot be applied to a single finding"
                )
            continue

        if not in_hunk:
            continue  # preamble before the first hunk header

        if raw.startswith("\\"):
            continue  # "\ No newline at end of file"

        if raw.startswith("+"):
            after.append(raw[1:])
        elif raw.startswith("-"):
            before.append(raw[1:])
        elif raw.startswith(" "):
            before.append(raw[1:])
            after.append(raw[1:])
        elif raw == "":
            # An empty line inside a hunk is a context line that happens to be
            # blank -- models routinely drop the leading space on those.
            before.append("")
            after.append("")
        else:
            # Unprefixed prose after the diff. The hunks so far still stand.
            break

    close()

    if not hunks:
        raise PatchApplyError("the generated patch contained no @@ hunks")
    return hunks


# ------------------------------------------------------------ line handling


def _split_keepends(content: str) -> tuple[list[str], list[str]]:
    """Return (lines_without_endings, the_ending_of_each_line)."""
    raw = content.splitlines(keepends=True)
    text: list[str] = []
    endings: list[str] = []
    for line in raw:
        stripped = line.rstrip("\r\n")
        text.append(stripped)
        endings.append(line[len(stripped):])
    return text, endings


def _log_near_misses(haystack: list[str], needle: tuple[str, ...]) -> None:
    """Say which line of the before-block is not in the file, and how it differs.

    "Not present in the current file" is true but useless on its own -- it reads
    as "your file changed" even when the real cause is a patch that was written
    against a file the model never saw, which is exactly how F29's false
    mismatch stayed invisible. Each unmatched line is logged next to the closest
    thing to it in the file, so an indentation-only or whitespace-only
    difference is obvious rather than inferred.

    DEBUG, and built only when DEBUG is on: this runs per rejected hunk and
    holds source code, which does not belong in a default-level log.
    """
    if not logger.isEnabledFor(logging.DEBUG):
        return
    for line in needle:
        if line in haystack:
            continue
        stripped = [
            (index + 1, text)
            for index, text in enumerate(haystack)
            if text.strip() == line.strip() and text.strip()
        ]
        if stripped:
            index, text = stripped[0]
            logger.debug(
                "patch before-block line absent, whitespace-only difference at "
                "file line %d: patch=%r file=%r",
                index,
                line,
                text,
            )
        else:
            logger.debug("patch before-block line absent from file: %r", line)


def _find_unique(haystack: list[str], needle: tuple[str, ...]) -> int:
    """Index of the one exact contiguous occurrence. Raises otherwise."""
    if not needle:
        raise PatchApplyError(
            "a hunk removed and changed nothing, so it has no anchor in the "
            "file to apply against"
        )
    span = len(needle)
    matches = [
        index
        for index in range(len(haystack) - span + 1)
        if tuple(haystack[index:index + span]) == needle
    ]
    if not matches:
        _log_near_misses(haystack, needle)
        raise PatchApplyError(
            "the code the patch expects to change is not present in the "
            "current file"
        )
    if len(matches) > 1:
        raise PatchApplyError(
            f"the code the patch expects to change appears {len(matches)} "
            "times in the current file, so the patch cannot be placed "
            "unambiguously"
        )
    return matches[0]


# --------------------------------------------------------- re-validation


def snippet_matches_at_line(content: str, snippet: str, line: int | None) -> bool:
    """Is the scanner's snippet still exactly at the line it was recorded at?

    Deliberately positional. Accepting the snippet from anywhere in the file
    would apply a patch to code the scanner never looked at, and accepting a
    near-match would apply it to code that has since changed -- both are the
    failure this whole module exists to prevent.

    Compared with each side's surrounding whitespace stripped, and that is
    exactness rather than fuzz: scanner_common.snippet_at defines a
    code_snippet as the flagged line *already* stripped, so the stripped form
    is the whole of what was captured. Comparing raw would be comparing the
    file against indentation the scan never recorded, which would reject every
    indented line in the codebase. Nothing else is normalised -- a changed
    character, a changed quote, a reordered argument all fail.

    The cost of being positional is that an unrelated edit earlier in the file
    shifts every later line and those findings are skipped. That is the safe
    direction to be wrong in: the user re-scans and gets them back.
    """
    if not snippet or not snippet.strip():
        return False
    if line is None or line < 1:
        return False

    file_lines, _ = _split_keepends(content)
    snippet_lines = [item.strip() for item in snippet.splitlines()]
    if not snippet_lines:
        return False

    start = line - 1
    end = start + len(snippet_lines)
    if end > len(file_lines):
        return False
    return [item.strip() for item in file_lines[start:end]] == snippet_lines


# --------------------------------------------------------------- applying


def locate(content: str, hunks: list[Hunk]) -> list[Replacement]:
    """Resolve every hunk to an exact span in content, or raise.

    All-or-nothing per patch: one unlocatable hunk fails the whole finding
    rather than leaving the file with the import added and the call site
    untouched, which would not compile.
    """
    file_lines, _ = _split_keepends(content)
    replacements: list[Replacement] = []
    for hunk in hunks:
        start = _find_unique(file_lines, hunk.before)
        replacements.append(
            Replacement(start, start + len(hunk.before), hunk.after)
        )

    replacements.sort(key=lambda item: item.start)
    for earlier, later in zip(replacements, replacements[1:]):
        if earlier.overlaps(later):
            raise PatchApplyError(
                "two hunks of the same patch cover the same lines, so the "
                "patch contradicts itself"
            )
    return replacements


def apply_replacements(content: str, replacements: list[Replacement]) -> str:
    """Rewrite only the replaced spans, preserving every other byte.

    Each new line inherits the line ending of the first line it replaces, so a
    CRLF file stays CRLF and a file with no trailing newline keeps not having
    one.
    """
    file_lines, endings = _split_keepends(content)
    default_ending = next((item for item in endings if item), "\n")

    output: list[str] = []
    cursor = 0
    for replacement in sorted(replacements, key=lambda item: item.start):
        if replacement.start < cursor:
            raise PatchApplyError("overlapping replacements cannot be applied")
        for index in range(cursor, replacement.start):
            output.append(file_lines[index] + endings[index])

        # The replaced span's own endings, so the new lines look like their
        # neighbours. The final line of a file with no trailing newline keeps
        # that property only if the replacement also ends the file.
        span_endings = endings[replacement.start:replacement.end]
        inherited = next((item for item in span_endings if item), default_ending)
        ends_file = replacement.end >= len(file_lines)
        last_ending = span_endings[-1] if span_endings else inherited
        for position, line in enumerate(replacement.lines):
            is_last = position == len(replacement.lines) - 1
            if is_last and ends_file:
                output.append(line + last_ending)
            else:
                output.append(line + inherited)
        cursor = replacement.end

    for index in range(cursor, len(file_lines)):
        output.append(file_lines[index] + endings[index])
    return "".join(output)


def apply_patch(content: str, diff_text: str) -> tuple[str, list[Replacement]]:
    """Parse, locate and apply in one step. Raises PatchApplyError on refusal."""
    replacements = locate(content, parse_unified_diff(diff_text))
    return apply_replacements(content, replacements), replacements

"""Unit tests for the module that decides whether a patch may touch a file.

Everything here is about refusing. The happy path is one class; the rest are
the ways a stored scan and a live repository can disagree, each of which has
to end in PatchApplyError rather than a plausible-looking wrong edit.
"""

import pytest

from patch_applier import (
    Hunk,
    PatchApplyError,
    Replacement,
    apply_patch,
    apply_replacements,
    locate,
    parse_unified_diff,
    snippet_matches_at_line,
)

SOURCE = (
    "import os\n"
    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
    "\n"
    "def make_key():\n"
    "    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    "    return key\n"
)

DIFF = (
    "--- a/src/crypto.py\n"
    "+++ b/src/crypto.py\n"
    "@@ -4,3 +4,3 @@\n"
    " def make_key():\n"
    "-    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    '+    key = oqs.KeyEncapsulation("ML-KEM-768")\n'
    "     return key\n"
)


class TestParsing:
    def test_hunks_split_into_before_and_after(self):
        hunks = parse_unified_diff(DIFF)
        assert len(hunks) == 1
        assert hunks[0].before == (
            "def make_key():",
            "    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
            "    return key",
        )
        assert hunks[0].after == (
            "def make_key():",
            '    key = oqs.KeyEncapsulation("ML-KEM-768")',
            "    return key",
        )

    def test_multiple_hunks_are_kept_separate(self):
        diff = (
            "--- a/x.py\n+++ b/x.py\n"
            "@@ -1,1 +1,2 @@\n import os\n+import oqs\n"
            "@@ -5,1 +5,1 @@\n-old\n+new\n"
        )
        assert len(parse_unified_diff(diff)) == 2

    def test_bare_blank_line_is_read_as_blank_context(self):
        """Models routinely drop the leading space on an empty context line;
        dropping the line instead would shift every following comparison."""
        diff = "--- a/x.py\n+++ b/x.py\n@@ -1,3 +1,3 @@\n a\n\n-b\n+c\n"
        hunk = parse_unified_diff(diff)[0]
        assert hunk.before == ("a", "", "b")
        assert hunk.after == ("a", "", "c")

    def test_no_newline_marker_is_ignored(self):
        diff = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n"
        assert parse_unified_diff(diff)[0].before == ("a",)

    def test_trailing_prose_ends_the_diff_without_losing_hunks(self):
        diff = DIFF + "\nThis patch replaces RSA with ML-KEM.\n"
        assert len(parse_unified_diff(diff)) == 1

    def test_empty_patch_is_refused(self):
        with pytest.raises(PatchApplyError, match="empty"):
            parse_unified_diff("   \n")

    def test_patch_without_hunks_is_refused(self):
        with pytest.raises(PatchApplyError, match="no @@ hunks"):
            parse_unified_diff("--- a/x.py\n+++ b/x.py\n")

    def test_multi_file_patch_is_refused(self):
        """One finding lives in one file. A diff covering two has no single
        target to write back, so it is refused rather than half-applied."""
        diff = (
            "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"
            "--- a/y.py\n+++ b/y.py\n@@ -1 +1 @@\n-c\n+d\n"
        )
        with pytest.raises(PatchApplyError, match="more than one file"):
            parse_unified_diff(diff)


class TestSnippetRevalidation:
    def test_unchanged_line_at_the_recorded_position_matches(self):
        assert snippet_matches_at_line(
            SOURCE,
            "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
            5,
        )

    def test_indentation_is_not_what_is_compared(self):
        """scanner_common.snippet_at strips the line before storing it, so the
        stripped form is the whole of what was captured; comparing raw would
        reject every indented line in every codebase."""
        assert snippet_matches_at_line(SOURCE, "    return key", 6)
        assert snippet_matches_at_line(SOURCE, "return key", 6)

    def test_a_changed_line_does_not_match(self):
        changed = SOURCE.replace("key_size=2048", "key_size=4096")
        assert not snippet_matches_at_line(
            changed,
            "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
            5,
        )

    def test_the_same_code_at_a_different_line_does_not_match(self):
        """Positional on purpose. Accepting it from anywhere would patch code
        the scanner never looked at."""
        assert not snippet_matches_at_line(
            SOURCE,
            "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
            4,
        )

    def test_line_past_the_end_of_the_file_does_not_match(self):
        assert not snippet_matches_at_line(SOURCE, "return key", 400)

    def test_multi_line_snippet_matches_across_lines(self):
        assert snippet_matches_at_line(SOURCE, "def make_key():\n    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)", 4)

    @pytest.mark.parametrize("line", [None, 0, -3])
    def test_missing_or_impossible_line_never_matches(self, line):
        assert not snippet_matches_at_line(SOURCE, "return key", line)

    @pytest.mark.parametrize("snippet", ["", "   ", "\n"])
    def test_empty_snippet_never_matches(self, snippet):
        assert not snippet_matches_at_line(SOURCE, snippet, 1)


class TestLocating:
    def test_hunk_is_placed_by_content_not_by_hunk_header(self):
        """patch_generator documents its line numbers as approximate, so a
        header of @@ -400 has to land on the real line anyway."""
        diff = DIFF.replace("@@ -4,3 +4,3 @@", "@@ -400,3 +400,3 @@")
        assert locate(SOURCE, parse_unified_diff(diff))[0].start == 3

    def test_absent_context_is_refused(self):
        with pytest.raises(PatchApplyError, match="not present"):
            locate("something else entirely\n", parse_unified_diff(DIFF))

    def test_ambiguous_context_is_refused(self):
        """Two identical places to apply means there is no way to know which
        one the scan meant, so neither is chosen."""
        source = "call()\ncall()\n"
        diff = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-call()\n+safe()\n"
        with pytest.raises(PatchApplyError, match="appears 2 times"):
            locate(source, parse_unified_diff(diff))

    def test_a_hunk_that_removes_nothing_is_refused(self):
        with pytest.raises(PatchApplyError, match="no anchor"):
            locate(SOURCE, [Hunk(before=(), after=("+import oqs",))])

    def test_self_contradicting_hunks_are_refused(self):
        overlapping = [
            Hunk(before=("def make_key():", "    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)"), after=("a",)),
            Hunk(before=("    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)", "    return key"), after=("b",)),
        ]
        with pytest.raises(PatchApplyError, match="contradicts itself"):
            locate(SOURCE, overlapping)


class TestApplying:
    def test_only_the_matched_lines_change(self):
        result, _ = apply_patch(SOURCE, DIFF)
        assert 'oqs.KeyEncapsulation("ML-KEM-768")' in result
        assert "rsa.generate_private_key" not in result
        assert result.startswith("import os\nfrom cryptography")
        assert result.endswith("    return key\n")

    def test_an_added_import_hunk_and_a_call_site_hunk_both_land(self):
        diff = (
            "--- a/src/crypto.py\n+++ b/src/crypto.py\n"
            "@@ -1,1 +1,2 @@\n import os\n+import oqs\n"
            "@@ -5,1 +5,1 @@\n"
            "-    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            '+    key = oqs.KeyEncapsulation("ML-KEM-768")\n'
        )
        result, replacements = apply_patch(SOURCE, diff)
        assert len(replacements) == 2
        assert result.splitlines()[1] == "import oqs"
        assert "ML-KEM-768" in result

    def test_crlf_line_endings_survive(self):
        """A repository checked out on Windows must not come back as a
        whole-file line-ending change hidden inside a crypto migration."""
        result, _ = apply_patch(SOURCE.replace("\n", "\r\n"), DIFF)
        assert "\r\n" in result
        assert "\n" not in result.replace("\r\n", "")

    def test_a_file_without_a_trailing_newline_keeps_that(self):
        source = "a\nb"
        diff = "--- a/x\n+++ b/x\n@@ -2 +2 @@\n-b\n+c\n"
        assert apply_patch(source, diff)[0] == "a\nc"

    def test_untouched_lines_are_returned_byte_for_byte(self):
        source = "keep\r\nthis\nmixed\r\ntarget\n"
        diff = "--- a/x\n+++ b/x\n@@ -4 +4 @@\n-target\n+patched\n"
        assert apply_patch(source, diff)[0] == "keep\r\nthis\nmixed\r\npatched\n"

    def test_overlapping_replacements_are_refused_at_apply_time(self):
        with pytest.raises(PatchApplyError, match="[Oo]verlapping"):
            apply_replacements(
                SOURCE,
                [
                    Replacement(0, 3, ("x",)),
                    Replacement(2, 4, ("y",)),
                ],
            )


class TestReplacementOverlap:
    def test_shared_lines_overlap(self):
        assert Replacement(3, 6, ()).overlaps(Replacement(5, 8, ()))

    def test_adjacent_spans_do_not_overlap(self):
        """[3,5) and [5,7) are two edits that can both stand."""
        assert not Replacement(3, 5, ()).overlaps(Replacement(5, 7, ()))
        assert not Replacement(5, 7, ()).overlaps(Replacement(3, 5, ()))

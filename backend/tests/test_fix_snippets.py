"""The fix_snippet Before/After convention the results UI renders against.

FixPanels in App.jsx splits a snippet into its two columns by finding the
"Before:" and "After:" labels. It matches the label only, not the comment
leader, because the leader is whatever the snippet's language uses. These
tests hold the data to that convention: a migration snippet carries both
labels in every language it ships, and an advisory snippet carries neither.

Without them the frontend regresses silently -- a Go entry that loses its
"// After:" line still renders, just as one flat panel instead of two, which
is exactly how the JS/TS and Go variants used to differ from Python.
"""

import re

import go_scanner
import java_scanner
import js_scanner
from vulnerability_db import CRYPTO_DB

BEFORE_MARKER = re.compile(r"^\s*(?:#|//)\s*Before\b", re.MULTILINE)
AFTER_MARKER = re.compile(r"^\s*(?:#|//)\s*After\b", re.MULTILINE)

LANGUAGE_FIELDS = (
    ("fix_snippet", "python"),
    ("js_fix_snippet", "javascript/typescript"),
    ("go_fix_snippet", "go"),
    ("java_fix_snippet", "java"),
)


def _is_migration(snippet: str) -> bool:
    """True when the snippet splits into Before/After, matching the renderer."""
    match = AFTER_MARKER.search(snippet)
    if not match:
        return False
    return bool(BEFORE_MARKER.search(snippet[: match.start()]))


def test_every_language_variant_of_an_algorithm_renders_the_same_way():
    """A finding must not change shape just because the repo is in Go.

    This is the regression that shipped: Python entries split into two
    columns while the Go and JS/TS entries for the same algorithm fell back
    to a single panel.
    """
    mismatched = {}
    for name, entry in CRYPTO_DB.items():
        shapes = {
            language: _is_migration(entry[field])
            for field, language in LANGUAGE_FIELDS
            if entry.get(field)
        }
        if len(set(shapes.values())) > 1:
            mismatched[name] = shapes
    assert not mismatched, f"language variants render differently: {mismatched}"


def test_migration_snippets_carry_both_labels():
    """An "After:" with no "Before:" above it would split into an empty column."""
    for name, entry in CRYPTO_DB.items():
        for field, language in LANGUAGE_FIELDS:
            snippet = entry.get(field)
            if not snippet or not AFTER_MARKER.search(snippet):
                continue
            after = AFTER_MARKER.search(snippet)
            assert BEFORE_MARKER.search(snippet[: after.start()]), (
                f"{name}.{field} ({language}) has an After label with no "
                "Before label above it"
            )


def test_quantum_vulnerable_algorithms_ship_a_before_after_migration():
    """The findings a user must act on are the ones that need both columns."""
    for name, entry in CRYPTO_DB.items():
        if entry["severity"] not in ("critical", "warning"):
            continue
        assert _is_migration(entry["fix_snippet"]), (
            f"{name} is {entry['severity']} but its Python fix_snippet does "
            "not split into Before/After"
        )


def test_safe_algorithms_are_advisory_notes_not_migrations():
    """Nothing to migrate away from, so nothing to put in a Before column."""
    for name, entry in CRYPTO_DB.items():
        if entry["severity"] != "safe":
            continue
        assert not _is_migration(entry["fix_snippet"]), (
            f"{name} is safe but its fix_snippet is shaped like a migration"
        )


def test_synthetic_scanner_findings_follow_the_same_convention():
    """The scanners' own notes are advisory, so they stay single-panel."""
    for module, label in (
        (go_scanner, "go_scanner"),
        (js_scanner, "js_scanner"),
        (java_scanner, "java_scanner"),
    ):
        for key, entry in getattr(module, "_SYNTHETIC", {}).items():
            snippet = entry.get("fix_snippet")
            if not snippet:
                continue
            if AFTER_MARKER.search(snippet):
                after = AFTER_MARKER.search(snippet)
                assert BEFORE_MARKER.search(snippet[: after.start()]), (
                    f"{label}[{key}] has an After label with no Before label"
                )


def test_the_marker_regexes_match_every_comment_leader_in_use():
    """Guards the assumption the renderer makes: # and // are the only two."""
    leaders = set()
    for entry in CRYPTO_DB.values():
        for field, _ in LANGUAGE_FIELDS:
            for line in (entry.get(field) or "").split("\n"):
                found = re.match(r"^\s*(#|//)\s*(?:Before|After)\b", line)
                if found:
                    leaders.add(found.group(1))
    assert leaders <= {"#", "//"}, f"unhandled comment leader: {leaders - {'#', '//'}}"
    assert leaders == {"#", "//"}, "expected both Python and C-style snippets"

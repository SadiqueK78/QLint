"""AST-based crypto detector for the PQC Migration Scanner.

Parses Python source, walks the tree, and reports cryptographic algorithm
usage found in imports, calls, and string arguments, enriched with data
from vulnerability_db.CRYPTO_DB.
"""

import ast

from scanner_common import attach_snippets, normalize_attack_vector
from vulnerability_db import find_algorithm

# Names that identify a crypto algorithm only in context (too short or too
# generic for vulnerability_db's global alias table). Each maps to an
# identifier that find_algorithm resolves. Applied to imported names and to
# the object part of attribute calls when they come from known crypto modules.
_CONTEXT_ALIASES: dict[str, str] = {
    "ec": "elliptic curve",  # cryptography.hazmat.primitives.asymmetric.ec
}

# Module prefixes that establish crypto context for _CONTEXT_ALIASES.
_CRYPTO_MODULE_PREFIXES = (
    "cryptography.",
    "Crypto.",
    "Cryptodome.",
)

# Calls whose final attribute is one of these get their first string argument
# checked against the DB (hashlib.new("md5"), Cipher.new("DES"), ...).
_STRING_ARG_CONSTRUCTORS = {"new"}


def _lookup(identifier: str) -> dict | None:
    """find_algorithm with context aliases applied to each dotted segment."""
    entry = find_algorithm(identifier)
    if entry is not None:
        return entry
    for segment in identifier.split("."):
        alias = _CONTEXT_ALIASES.get(segment.lower())
        if alias is not None:
            return find_algorithm(alias)
    return None


def _make_finding(
    node: ast.AST, identifier: str, match_type: str, entry: dict
) -> dict:
    return {
        "line": node.lineno,
        "col": node.col_offset,
        "identifier": identifier,
        "match_type": match_type,
        "algorithm": entry["canonical_name"],
        "severity": entry["severity"],
        "quantum_vulnerable": entry["quantum_vulnerable"],
        "classical_vulnerable": entry["classical_vulnerable"],
        "attack_vector": normalize_attack_vector(entry["attack_vector"]),
        "replacement": entry["replacement"],
        # BEFORE: the flagged source line, filled in by attach_snippets once
        # the whole file has been walked. AFTER: the recommended replacement.
        "code_snippet": "",
        "fix_snippet": entry["fix_snippet"],
        "replacement_reason": entry["replacement_reason"],
    }


def _hashlib_import_finding(node: ast.AST) -> dict:
    """`import hashlib` alone proves nothing — flag for deeper inspection."""
    return {
        "line": node.lineno,
        "col": node.col_offset,
        "identifier": "hashlib",
        "match_type": "import",
        "algorithm": "hashlib (requires deeper inspection)",
        "severity": "info",
        "quantum_vulnerable": False,
        "classical_vulnerable": False,
        "attack_vector": None,
        "replacement": None,
        "code_snippet": "",
        "fix_snippet": "# Inspect hashlib usage: md5/sha1 are broken, sha256 is Grover-weakened.",
        "replacement_reason": "The hashlib module itself is not vulnerable; the specific hash calls made through it determine the risk.",
    }


def _dotted_name(node: ast.expr) -> str | None:
    """Rebuild 'a.b.c' from a Name/Attribute chain; None for anything else."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


class CryptoASTVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[dict] = []
        # Names imported from known crypto packages, e.g. {"ec", "rsa"} —
        # lets context aliases apply to later calls like ec.generate_private_key.
        self._crypto_imports: set[str] = set()

    def _add(self, node: ast.AST, identifier: str, match_type: str) -> None:
        entry = _lookup(identifier)
        if entry is not None:
            self.findings.append(_make_finding(node, identifier, match_type, entry))

    # -- imports -------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "hashlib" or alias.name.startswith("hashlib."):
                self.findings.append(_hashlib_import_finding(node))
            else:
                self._add(node, alias.name, "import")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if module == "hashlib":
            self.findings.append(_hashlib_import_finding(node))
        in_crypto_package = module.startswith(_CRYPTO_MODULE_PREFIXES) or module in (
            "cryptography",
            "Crypto",
            "Cryptodome",
        )
        # The module path itself may name an algorithm (from Crypto.Cipher.DES import ...)
        self._add(node, module, "import")
        for alias in node.names:
            identifier = f"{module}.{alias.name}" if module else alias.name
            if in_crypto_package:
                self._crypto_imports.add(alias.asname or alias.name)
                # Context aliases (e.g. "ec") only apply inside crypto packages
                entry = _lookup(alias.name)
            else:
                entry = find_algorithm(identifier)
            if entry is not None:
                self.findings.append(
                    _make_finding(node, identifier, "import", entry)
                )
        self.generic_visit(node)

    # -- calls ---------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted_name(node.func)
        matched_algorithms: set[str] = set()

        if dotted:
            root = dotted.split(".", 1)[0]
            if root in self._crypto_imports:
                entry = _lookup(dotted)
            else:
                entry = find_algorithm(dotted)
            if entry is not None:
                self.findings.append(
                    _make_finding(node, dotted, "function_call", entry)
                )
                matched_algorithms.add(entry["canonical_name"])

        # String first-argument of constructor-style calls: hashlib.new("md5")
        last_segment = dotted.rsplit(".", 1)[-1] if dotted else ""
        if last_segment in _STRING_ARG_CONSTRUCTORS and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                entry = find_algorithm(first.value)
                if entry is not None and entry["canonical_name"] not in matched_algorithms:
                    self.findings.append(
                        _make_finding(first, first.value, "string_arg", entry)
                    )

        self.generic_visit(node)


def scan_python_source(source_code: str, filename: str = "") -> list[dict]:
    """Scan Python source text for crypto usage. Never raises.

    Returns findings sorted by line number, deduplicated so one algorithm is
    reported at most once per line.
    """
    if not source_code or not source_code.strip():
        return []
    try:
        tree = ast.parse(source_code, filename=filename or "<string>")
    except (SyntaxError, ValueError, RecursionError):
        return []

    visitor = CryptoASTVisitor()
    visitor.visit(tree)
    attach_snippets(visitor.findings, source_code)

    # Dedup on (line, algorithm) — import beats call beats string_arg
    priority = {"import": 0, "function_call": 1, "string_arg": 2}
    best: dict[tuple[int, str], dict] = {}
    for finding in visitor.findings:
        key = (finding["line"], finding["algorithm"])
        current = best.get(key)
        if current is None or priority.get(finding["match_type"], 3) < priority.get(
            current["match_type"], 3
        ):
            best[key] = finding

    return sorted(best.values(), key=lambda f: (f["line"], f["col"]))


if __name__ == "__main__":
    test_source = """
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
h = hashlib.md5()
h2 = hashlib.new("sha1")
rsa_key = RSA.generate(2048)
md5_hash = MD5.new()
"""
    findings = scan_python_source(test_source, "test_file.py")
    assert len(findings) > 0, "Should find crypto usage"
    algorithms = [f["algorithm"] for f in findings]
    assert "RSA" in algorithms, "Should detect RSA"
    assert "MD5" in algorithms, "Should detect MD5"
    print(f"ast_scanner.py self-test passed — {len(findings)} findings")
    for f in findings:
        print(
            f"  Line {f['line']}: {f['algorithm']} ({f['severity']}) "
            f"via {f['match_type']}"
        )

"""CycloneDX 1.6 SBOM output for the repository a scan was run against.

The third sibling of sarif_converter.py and cbom_converter.py, and the one
that is not a translation of the scan report. SARIF answers "what is wrong and
where"; the CBOM answers "what cryptography is in here"; an SBOM answers "what
software is in here" -- the libraries the scanned repository declares it
depends on, which is a different inventory built from different input.

That input is the repository's own dependency manifests, fetched from GitHub
when the download is requested rather than captured during the scan. Two
reasons for doing it at download time:

  * The scan stores a findings report. Adding dependency data to it would
    change what every stored scan looks like, and the documents already in the
    collection would not have it.
  * A manifest read now describes the repository now, which is what someone
    downloading a bill of materials is asking for.

Only the repository root is read. A monorepo with a manifest per package is
therefore under-reported, and that is a deliberate limit rather than an
oversight: walking a repository for every manifest it might contain is a
different feature with a different cost, and a root-level answer is the one
most repositories have.

Coverage is reported, never faked. A language whose manifest is missing,
unreadable or unparseable is recorded in metadata.properties as uncovered and
the rest of the document is still produced. A partial SBOM that says which
parts are missing is a correct answer; a 500 is not.

Versions are recorded only where a manifest names exactly one. A constraint
that spans a range ("^18.2.0", ">=1.4", "*") is a statement about what may be
installed, not about what is, so the component carries no version rather than
a guessed one -- the same discipline the CBOM applies to key lengths it cannot
see. What is recorded is the version the manifest names; only a lock file
knows which version a build actually resolved, and a lock file is a different
input than this reads.

Schema: https://cyclonedx.org/docs/1.6/json/
purl:   https://github.com/package-url/purl-spec

Conversion is best-effort by design -- generate_sbom never raises. Anything it
cannot read becomes a coverage note.
"""

import json
import re
import tomllib
import uuid
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone
from urllib.parse import quote

from sarif_converter import QLINT_VERSION, REPO_URL

SPEC_VERSION = "1.6"
BOM_FORMAT = "CycloneDX"

# CycloneDX component.type. Every dependency in a manifest is a library; the
# repository itself is the "application" the document is about.
LIBRARY = "library"

# The manifest each scanner language declares its dependencies in, at the
# repository root. Several languages share one file (a repository with both
# .js and .ts sources has one package.json), which is why the parsed result is
# keyed by manifest rather than by language further down.
MANIFESTS: dict[str, str] = {
    "python": "requirements.txt",
    "javascript": "package.json",
    "typescript": "package.json",
    "go": "go.mod",
    "java": "pom.xml",
    "rust": "Cargo.toml",
}

# Java's other build system. Gradle's DSL is Groovy or Kotlin -- a program,
# not a data format -- so a dependency list cannot be read out of it the way
# one can be read out of pom.xml. Recognized here only so a Gradle project is
# told its dependencies are unsupported rather than left looking like a
# project with none.
GRADLE_MANIFESTS = ("build.gradle", "build.gradle.kts")

# Anything that makes a version string a constraint rather than a single
# version. Kept as one rule for every ecosystem, so "1.2.3" is a version
# wherever it appears and "^1.2.3" is a range wherever it appears.
_RANGE_CHARACTERS = set("^~><*|,= \t")
_WILDCARD_SEGMENTS = {"x", "X", "*", ""}
_EXACT_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.\-+_]*$")


def _exact_version(raw: str | None) -> str | None:
    """The single version a constraint names, or None if it names a range.

    A leading "=" or "==" is stripped first: those are the pin operators, so
    "==1.2.3" and "1.2.3" mean the same thing and both count. Everything else
    -- carets, tildes, inequalities, wildcards, comma-separated clauses, Maven
    "${property}" placeholders, Cargo git and path dependencies -- leaves the
    version unset.

    A leading "v" is kept rather than stripped: in Go it is part of the
    version, and Go is the only ecosystem here that writes one.
    """
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if value.startswith("=="):
        value = value[2:].strip()
    elif value.startswith("="):
        value = value[1:].strip()
    if not value:
        return None
    if any(character in _RANGE_CHARACTERS for character in value):
        return None
    candidate = value[1:] if value[:1] == "v" and value[1:2].isdigit() else value
    if not _EXACT_VERSION_RE.match(candidate):
        return None
    # "1.x" and "2.*" pass the character check as far as the dot-separated
    # shape goes; a wildcard segment still means a range.
    if any(part in _WILDCARD_SEGMENTS for part in candidate.split(".")):
        return None
    return value


def _segment(value: str) -> str:
    """Percent-encode one purl path segment, per the purl specification."""
    return quote(value, safe="")


def _purl(ecosystem: str, name: str, version: str | None,
          namespace: str | None = None) -> str | None:
    """Build a package URL, or None when there is not enough to build one.

    Namespace segments are encoded but their separators are not, which is what
    keeps a Go module path readable as a path. The version, when present, is
    appended after "@" as the spec requires.
    """
    if not name:
        return None
    parts = [ecosystem]
    if namespace:
        parts.append("/".join(_segment(part) for part in namespace.split("/") if part))
    parts.append(_segment(name))
    purl = "pkg:" + "/".join(parts)
    if version:
        purl += f"@{_segment(version)}"
    return purl


# ------------------------------------------------------------ purl per type
#
# Each ecosystem normalizes names differently and the spec says how. Getting
# this wrong produces a purl that looks right and matches nothing.


def _pypi_purl(name: str, version: str | None) -> str | None:
    # PyPI names are case-insensitive and treat "_", "-" and "." alike; the
    # purl spec pins the normalized form as lowercase with hyphens.
    normalized = re.sub(r"[-_.]+", "-", name.strip().lower())
    return _purl("pypi", normalized, version)


def _npm_purl(name: str, version: str | None) -> str | None:
    # A scoped package's "@scope" is the purl namespace, and the "@" has to be
    # percent-encoded there: pkg:npm/%40babel/core@7.0.0.
    lowered = name.strip().lower()
    if lowered.startswith("@") and "/" in lowered:
        scope, _, bare = lowered.partition("/")
        return _purl("npm", bare, version, namespace=scope)
    return _purl("npm", lowered, version)


def _golang_purl(module: str, version: str | None) -> str | None:
    # The module path is namespace + name, lowercased, and its slashes stay
    # slashes. The "v" prefix is part of a Go version and is kept.
    lowered = module.strip().lower().strip("/")
    if not lowered:
        return None
    namespace, _, name = lowered.rpartition("/")
    return _purl("golang", name, version, namespace=namespace or None)


def _maven_purl(group_id: str, artifact_id: str, version: str | None) -> str | None:
    if not group_id or not artifact_id:
        return None
    return _purl("maven", artifact_id, version, namespace=group_id)


def _cargo_purl(name: str, version: str | None) -> str | None:
    return _purl("cargo", name.strip(), version)


# ---------------------------------------------------------- manifest parsers
#
# Each returns a list of (name, version_or_None, purl_or_None) and raises
# nothing that _collect does not catch. A manifest that is present but
# unreadable is treated as unparseable, not as a manifest with no dependencies:
# the two are very different claims to make about a repository.


def parse_requirements_txt(content: str) -> list[dict]:
    """Parse a pip requirements file into components.

    Handles the shapes that actually appear in one: comments, blank lines,
    extras, environment markers, hashes, and the include/editable flags that
    name a file rather than a package.
    """
    components: list[dict] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # -r other.txt, -e ., --hash=..., -c constraints.txt: none of these
        # name a package that can be pinned here.
        if line.startswith("-"):
            continue
        # Drop an inline comment, an environment marker, and any --hash tail.
        line = line.split(" #", 1)[0].split("\t#", 1)[0]
        line = line.split(";", 1)[0]
        line = line.split("--hash", 1)[0]
        line = line.strip().rstrip("\\").strip()
        if not line:
            continue
        # A direct URL requirement ("qlint @ git+https://...") pins a source,
        # not a released version.
        if "@" in line and "==" not in line:
            line = line.split("@", 1)[0].strip()
        match = re.match(r"^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(.*)$", line)
        if not match:
            continue
        name = match.group(1)
        version = _exact_version(match.group(3))
        components.append(
            {"name": name, "version": version, "purl": _pypi_purl(name, version)}
        )
    return components


def parse_package_json(content: str) -> list[dict]:
    """Parse dependencies and devDependencies out of a package.json."""
    data = json.loads(content)
    components: list[dict] = []
    seen: set[str] = set()
    for field in ("dependencies", "devDependencies"):
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for name, constraint in block.items():
            if not isinstance(name, str) or name in seen:
                continue
            seen.add(name)
            version = _exact_version(constraint if isinstance(constraint, str) else None)
            components.append(
                {"name": name, "version": version, "purl": _npm_purl(name, version)}
            )
    return components


_GO_REQUIRE_LINE = re.compile(
    r"^(?P<module>[^\s()]+)\s+(?P<version>v[^\s]+)\s*(?://.*)?$"
)


def parse_go_mod(content: str) -> list[dict]:
    """Parse the require directives of a go.mod.

    Both spellings: a parenthesized require block, and single-line requires.
    Indirect dependencies are included -- they are in the build either way,
    and the "// indirect" comment is a note about why, not a reason to omit.
    """
    components: list[dict] = []
    in_block = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        if in_block:
            if line.startswith(")"):
                in_block = False
                continue
        elif line.startswith("require"):
            remainder = line[len("require"):].strip()
            if remainder.startswith("("):
                in_block = True
                continue
            line = remainder
        else:
            continue
        match = _GO_REQUIRE_LINE.match(line)
        if not match:
            continue
        module = match.group("module")
        version = _exact_version(match.group("version"))
        components.append(
            {
                "name": module,
                "version": version,
                "purl": _golang_purl(module, version),
            }
        )
    return components


def _strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_pom_xml(content: str) -> list[dict]:
    """Parse the dependency elements of a Maven pom.xml.

    Every <dependency> inside a <dependencies> list, wherever that list sits:
    a project's direct dependencies and the ones its <dependencyManagement>
    pins are both things the build depends on. Duplicates collapse on
    group:artifact.

    Only inside a <dependencies> list, though, because a POM has other
    <dependency> elements -- plugin configuration blocks carry them, and the
    ones they carry are frequently "${project.groupId}" placeholders naming
    the project itself rather than a library it depends on. A coordinate
    written as a "${property}" is dropped for the same reason a "${property}"
    version is: resolving it means evaluating the POM's property inheritance,
    which is a Maven implementation, not a parser.
    """
    root = ElementTree.fromstring(content)
    components: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for container in root.iter():
        if _strip_namespace(container.tag) != "dependencies":
            continue
        for element in container:
            if _strip_namespace(element.tag) != "dependency":
                continue
            fields: dict[str, str] = {}
            for child in element:
                name = _strip_namespace(child.tag)
                if name in ("groupId", "artifactId", "version") and child.text:
                    fields[name] = child.text.strip()
            group_id = fields.get("groupId", "")
            artifact_id = fields.get("artifactId", "")
            if not group_id or not artifact_id:
                continue
            if "${" in group_id or "${" in artifact_id:
                continue
            key = (group_id, artifact_id)
            if key in seen:
                continue
            seen.add(key)
            version = _exact_version(fields.get("version"))
            components.append(
                {
                    "name": f"{group_id}:{artifact_id}",
                    "version": version,
                    "purl": _maven_purl(group_id, artifact_id, version),
                }
            )
    return components


def parse_cargo_toml(content: str) -> list[dict]:
    """Parse the [dependencies] table of a Cargo.toml.

    Both spellings the table allows: `name = "1.2"` and
    `name = { version = "1.2", features = [...] }`. A dependency declared by
    path or git has no version to record and is emitted without one.
    """
    data = tomllib.loads(content)
    block = data.get("dependencies")
    if not isinstance(block, dict):
        return []
    components: list[dict] = []
    for name, declaration in block.items():
        if isinstance(declaration, str):
            raw_version = declaration
        elif isinstance(declaration, dict):
            raw_version = declaration.get("version")
        else:
            continue
        version = _exact_version(raw_version)
        components.append(
            {"name": name, "version": version, "purl": _cargo_purl(name, version)}
        )
    return components


PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "package.json": parse_package_json,
    "go.mod": parse_go_mod,
    "pom.xml": parse_pom_xml,
    "Cargo.toml": parse_cargo_toml,
}


# ------------------------------------------------------------------ assembly


def _component(entry: dict) -> dict:
    """One CycloneDX library component. Absent fields are omitted, not null."""
    component: dict = {"type": LIBRARY, "name": entry["name"]}
    if entry.get("version"):
        component["version"] = entry["version"]
    purl = entry.get("purl")
    if purl:
        component["purl"] = purl
        component["bom-ref"] = purl
    else:
        component["bom-ref"] = f"{entry['name']}"
    return component


def _property(name: str, value: str) -> dict:
    return {"name": name, "value": value}


def _manifests_for(languages_scanned) -> dict[str, list[str]]:
    """Manifest file -> the scanned languages that share it, in a stable order."""
    grouped: dict[str, list[str]] = {}
    if not isinstance(languages_scanned, (list, tuple, set)):
        return grouped
    for language in languages_scanned:
        if not isinstance(language, str):
            continue
        manifest = MANIFESTS.get(language.strip().lower())
        if manifest is None:
            continue
        grouped.setdefault(manifest, [])
        if language not in grouped[manifest]:
            grouped[manifest].append(language)
    return {manifest: sorted(names) for manifest, names in sorted(grouped.items())}


async def _fetch(github_client, path: str) -> str | None:
    """Read one repository-root file, or None for anything that goes wrong.

    Missing files are the expected case here, not an error: most repositories
    have one manifest, not five.
    """
    try:
        content = await github_client(path)
    except Exception:
        return None
    return content if isinstance(content, str) else None


async def generate_sbom(
    repo_owner: str,
    repo_name: str,
    languages_scanned: list[str],
    github_client,
) -> dict:
    """Build a CycloneDX 1.6 SBOM for a repository, from its root manifests.

    `github_client` is an async callable taking a repository-root path and
    returning that file's text, or None when it does not exist -- which is
    exactly what a `get_file_content` bound to an owner, repo and token gives
    you. Passing a callable rather than the httpx client keeps this module a
    pure format translation with no HTTP in it, the way its two siblings are,
    and lets a test hand it a dictionary.

    `languages_scanned` decides which manifests are worth asking for: a Python
    repository is not asked for a Cargo.toml. A language QLint does not have a
    manifest parser for is passed over silently -- there is nothing to report
    about it.

    Never raises. Every failure becomes a coverage property on the document.
    """
    components: list[dict] = []
    coverage: list[dict] = []
    seen_refs: set[str] = set()

    try:
        grouped = _manifests_for(languages_scanned)
    except Exception:
        grouped = {}

    for manifest, languages in grouped.items():
        label = "/".join(languages)
        content = await _fetch(github_client, manifest)
        if content is None:
            detail = f"{manifest} not found at the repository root"
            # Java is the one language with a second build system common
            # enough that "no pom.xml" usually means "Gradle", and saying so
            # is more useful than reporting a missing file.
            if manifest == "pom.xml":
                for gradle in GRADLE_MANIFESTS:
                    if await _fetch(github_client, gradle) is not None:
                        detail = (
                            f"{gradle} is present but Gradle build scripts are "
                            "not supported; dependencies could not be determined"
                        )
                        break
            coverage.append(_property(f"qlint:sbom:uncovered:{label}", detail))
            continue

        try:
            parsed = PARSERS[manifest](content)
        except Exception as exc:
            coverage.append(
                _property(
                    f"qlint:sbom:uncovered:{label}",
                    f"{manifest} could not be parsed ({type(exc).__name__})",
                )
            )
            continue

        added = 0
        for entry in parsed:
            try:
                if not entry.get("name"):
                    continue
                component = _component(entry)
                reference = component["bom-ref"]
                if reference in seen_refs:
                    continue
                seen_refs.add(reference)
                components.append(component)
                added += 1
            except Exception:
                continue  # one bad line must not cost the whole manifest
        coverage.append(
            _property(
                f"qlint:sbom:covered:{label}",
                f"{manifest}: {added} dependencies",
            )
        )

    components.sort(key=lambda component: (component["name"].lower(),
                                           component.get("version", "")))

    subject = f"{repo_owner}/{repo_name}" if repo_owner and repo_name else (
        repo_name or repo_owner or "unknown"
    )
    return {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "tools": [
                {
                    "vendor": "QLint",
                    "name": "QLint",
                    "version": QLINT_VERSION,
                    "externalReferences": [{"type": "website", "url": REPO_URL}],
                }
            ],
            "component": {
                "type": "application",
                "name": subject,
                "bom-ref": subject,
            },
            # What was and was not read, per language. A consumer that only
            # reads components would otherwise have no way to tell "no
            # dependencies" from "no manifest".
            "properties": coverage,
        },
        "components": components,
    }

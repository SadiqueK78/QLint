"""Tests for the CycloneDX 1.6 SBOM generator.

Sibling of test_cbom_converter.py and structured the same way: the enum and
key-set assertions come from the CycloneDX 1.6 schema, which sets
additionalProperties:false on the document and on each component, so an
invented field is a validation failure rather than a harmless extra.

The manifests below are realistic rather than minimal on purpose. Every shape
asserted here -- pinned and unpinned requirements, scoped npm packages,
indirect Go modules, Maven property versions, Cargo table dependencies -- is
something a real repository's root manifest contains, and the parser is only
worth anything if it survives them.
"""

import json
import uuid

import pytest

from sbom_converter import (
    SPEC_VERSION,
    generate_sbom,
    parse_cargo_toml,
    parse_go_mod,
    parse_package_json,
    parse_pom_xml,
    parse_requirements_txt,
)

# Every key the CycloneDX 1.6 schema allows on a component.
COMPONENT_KEYS = {
    "type", "mime-type", "bom-ref", "supplier", "manufacturer", "authors",
    "author", "publisher", "group", "name", "version", "description", "scope",
    "hashes", "licenses", "copyright", "cpe", "purl", "omniborId", "swhid",
    "swid", "modified", "pedigree", "externalReferences", "components",
    "evidence", "releaseNotes", "modelCard", "data", "cryptoProperties",
    "properties", "tags", "signature",
}

METADATA_KEYS = {
    "timestamp", "lifecycles", "tools", "manufacture", "manufacturer",
    "authors", "component", "supplier", "licenses", "properties",
}


REQUIREMENTS_TXT = """\
# Web stack
fastapi==0.115.0
uvicorn[standard]==0.32.0
httpx>=0.28.0
python-dotenv ~= 1.0.1
motor==3.4.0  # async mongo driver

# Pinned with a hash, as pip-compile writes them
certifi==2024.8.30 \\
    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000
pytest==8.3.3 ; python_version >= "3.9"
Some_Package==2.0
-r dev-requirements.txt
-e .
qlint @ git+https://github.com/Abhushan187/QLint.git
"""

PACKAGE_JSON = """\
{
  "name": "qlint-frontend",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "react": "18.3.1",
    "react-dom": "^18.3.1",
    "@tanstack/react-query": "5.51.1",
    "lodash": "*"
  },
  "devDependencies": {
    "vite": "5.4.8",
    "@vitejs/plugin-react": "~4.3.1"
  },
  "scripts": {"build": "vite build"}
}
"""

GO_MOD = """\
module github.com/golang-jwt/jwt/v5

go 1.21

require (
\tgithub.com/gorilla/mux v1.8.1
\tgolang.org/x/crypto v0.27.0 // indirect
\tgithub.com/stretchr/testify v1.9.0
)

require github.com/google/uuid v1.6.0

replace github.com/gorilla/mux => ./vendor/mux

exclude github.com/bad/module v0.0.1
"""

POM_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>dev.qlint</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <properties>
    <spring.version>6.1.13</spring.version>
  </properties>
  <build>
    <plugins>
      <plugin>
        <groupId>com.github.siom79.japicmp</groupId>
        <artifactId>japicmp-maven-plugin</artifactId>
        <configuration>
          <oldVersion>
            <dependency>
              <groupId>${project.groupId}</groupId>
              <artifactId>${project.artifactId}</artifactId>
              <version>0.0.0-JAPICMP-OLD</version>
            </dependency>
          </oldVersion>
        </configuration>
      </plugin>
    </plugins>
  </build>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78.1</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"""

CARGO_TOML = """\
[package]
name = "qlint-demo"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0.210", features = ["derive"] }
ring = "0.17.8"
rand = "^0.8"
tokio = { version = "1.40.0", features = ["full"] }
local-helper = { path = "../helper" }

[dev-dependencies]
criterion = "0.5.1"
"""


class FakeRepo:
    """A repository root, as generate_sbom sees it: paths to file contents."""

    def __init__(self, files: dict[str, str]):
        self.files = files
        self.requested: list[str] = []

    async def __call__(self, path: str) -> str | None:
        self.requested.append(path)
        return self.files.get(path)


def components_by_name(sbom: dict) -> dict[str, dict]:
    return {component["name"]: component for component in sbom["components"]}


def coverage(sbom: dict) -> dict[str, str]:
    return {
        entry["name"]: entry["value"]
        for entry in sbom["metadata"].get("properties", [])
    }


# ------------------------------------------------------------------- Python


class TestRequirementsTxt:
    @staticmethod
    @pytest.fixture(scope="class")
    def parsed():
        return {c["name"]: c for c in parse_requirements_txt(REQUIREMENTS_TXT)}

    def test_pinned_requirements_keep_their_version(self, parsed):
        assert parsed["fastapi"]["version"] == "0.115.0"
        assert parsed["motor"]["version"] == "3.4.0"

    def test_extras_are_stripped_from_the_package_name(self, parsed):
        assert parsed["uvicorn"]["version"] == "0.32.0"

    def test_a_range_leaves_the_version_unset(self, parsed):
        assert parsed["httpx"]["version"] is None
        assert parsed["python-dotenv"]["version"] is None

    def test_an_inline_comment_does_not_become_part_of_the_version(self, parsed):
        assert parsed["motor"]["version"] == "3.4.0"

    def test_a_hashed_pin_still_parses(self, parsed):
        assert parsed["certifi"]["version"] == "2024.8.30"

    def test_an_environment_marker_is_dropped(self, parsed):
        assert parsed["pytest"]["version"] == "8.3.3"

    def test_flag_lines_name_no_package(self, parsed):
        assert "dev-requirements.txt" not in parsed
        assert "." not in parsed

    def test_a_direct_url_requirement_has_no_version(self, parsed):
        assert parsed["qlint"]["version"] is None

    def test_purls_are_normalized_the_way_pypi_normalizes_names(self, parsed):
        assert parsed["fastapi"]["purl"] == "pkg:pypi/fastapi@0.115.0"
        # Lowercased, underscores to hyphens: the purl spec's pypi rules.
        assert parsed["Some_Package"]["purl"] == "pkg:pypi/some-package@2.0"

    def test_an_unpinned_package_gets_a_purl_without_a_version(self, parsed):
        assert parsed["httpx"]["purl"] == "pkg:pypi/httpx"


# --------------------------------------------------------------- JavaScript


class TestPackageJson:
    @staticmethod
    @pytest.fixture(scope="class")
    def parsed():
        return {c["name"]: c for c in parse_package_json(PACKAGE_JSON)}

    def test_both_dependency_blocks_are_read(self, parsed):
        assert "react" in parsed  # dependencies
        assert "vite" in parsed  # devDependencies

    def test_an_exact_version_is_kept(self, parsed):
        assert parsed["react"]["version"] == "18.3.1"
        assert parsed["vite"]["version"] == "5.4.8"

    def test_caret_tilde_and_wildcard_ranges_leave_the_version_unset(self, parsed):
        assert parsed["react-dom"]["version"] is None
        assert parsed["@vitejs/plugin-react"]["version"] is None
        assert parsed["lodash"]["version"] is None

    def test_a_scoped_package_puts_the_scope_in_the_purl_namespace(self, parsed):
        # The "@" is percent-encoded in a purl namespace, per the spec.
        assert (
            parsed["@tanstack/react-query"]["purl"]
            == "pkg:npm/%40tanstack/react-query@5.51.1"
        )

    def test_an_unscoped_purl_is_the_plain_form(self, parsed):
        assert parsed["react"]["purl"] == "pkg:npm/react@18.3.1"

    def test_the_project_itself_is_not_one_of_its_dependencies(self, parsed):
        assert "qlint-frontend" not in parsed


# ---------------------------------------------------------------------- Go


class TestGoMod:
    @staticmethod
    @pytest.fixture(scope="class")
    def parsed():
        return {c["name"]: c for c in parse_go_mod(GO_MOD)}

    def test_the_require_block_is_read(self, parsed):
        assert parsed["github.com/gorilla/mux"]["version"] == "v1.8.1"
        assert parsed["github.com/stretchr/testify"]["version"] == "v1.9.0"

    def test_a_single_line_require_is_read_too(self, parsed):
        assert parsed["github.com/google/uuid"]["version"] == "v1.6.0"

    def test_indirect_dependencies_are_included_without_their_comment(self, parsed):
        assert parsed["golang.org/x/crypto"]["version"] == "v0.27.0"

    def test_the_module_directive_is_not_a_dependency(self, parsed):
        assert "github.com/golang-jwt/jwt/v5" not in parsed

    def test_replace_and_exclude_directives_are_ignored(self, parsed):
        assert len(parsed) == 4

    def test_the_module_path_becomes_the_purl_namespace(self, parsed):
        assert (
            parsed["github.com/gorilla/mux"]["purl"]
            == "pkg:golang/github.com/gorilla/mux@v1.8.1"
        )

    def test_the_v_prefix_is_part_of_a_go_version(self, parsed):
        assert parsed["github.com/google/uuid"]["version"].startswith("v")


# -------------------------------------------------------------------- Java


class TestPomXml:
    @staticmethod
    @pytest.fixture(scope="class")
    def parsed():
        return {c["name"]: c for c in parse_pom_xml(POM_XML)}

    def test_dependencies_are_keyed_group_and_artifact(self, parsed):
        assert "org.bouncycastle:bcprov-jdk18on" in parsed
        assert "junit:junit" in parsed

    def test_a_literal_version_is_kept(self, parsed):
        assert parsed["org.bouncycastle:bcprov-jdk18on"]["version"] == "1.78.1"

    def test_a_property_placeholder_is_not_a_version(self, parsed):
        assert parsed["org.springframework:spring-core"]["version"] is None

    def test_the_project_itself_is_not_a_dependency(self, parsed):
        assert "dev.qlint:demo" not in parsed

    def test_a_plugins_own_dependency_block_is_not_a_project_dependency(
        self, parsed
    ):
        """Straight from google/gson, where this produced a junk component.

        The japicmp plugin configures itself with a <dependency> naming
        "${project.groupId}" -- the project, not a library, and written as a
        placeholder no parser here can resolve.
        """
        assert len(parsed) == 3
        assert not any("${" in name for name in parsed)
        assert not any("japicmp" in name for name in parsed)

    def test_the_purl_splits_group_from_artifact(self, parsed):
        assert (
            parsed["org.bouncycastle:bcprov-jdk18on"]["purl"]
            == "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1"
        )

    def test_namespaced_poms_parse_the_same_way(self):
        # The sample above declares the Maven namespace, which ElementTree
        # prefixes onto every tag; a parser matching on raw tags finds nothing.
        assert parse_pom_xml(POM_XML)


# -------------------------------------------------------------------- Rust


class TestCargoToml:
    @staticmethod
    @pytest.fixture(scope="class")
    def parsed():
        return {c["name"]: c for c in parse_cargo_toml(CARGO_TOML)}

    def test_a_plain_string_dependency_is_read(self, parsed):
        assert parsed["ring"]["version"] == "0.17.8"

    def test_a_table_dependency_is_read(self, parsed):
        assert parsed["serde"]["version"] == "1.0.210"
        assert parsed["tokio"]["version"] == "1.40.0"

    def test_a_caret_range_leaves_the_version_unset(self, parsed):
        assert parsed["rand"]["version"] is None

    def test_a_path_dependency_has_no_version(self, parsed):
        assert parsed["local-helper"]["version"] is None

    def test_the_package_section_is_not_a_dependency(self, parsed):
        assert "qlint-demo" not in parsed

    def test_dev_dependencies_are_a_different_table(self, parsed):
        assert "criterion" not in parsed

    def test_the_purl_is_the_cargo_form(self, parsed):
        assert parsed["ring"]["purl"] == "pkg:cargo/ring@0.17.8"


# --------------------------------------------------------------- the document


@pytest.mark.asyncio
class TestGenerateSbom:
    async def test_top_level_structure_is_cyclonedx_1_6(self):
        repo = FakeRepo({"requirements.txt": REQUIREMENTS_TXT})
        sbom = await generate_sbom("paramiko", "paramiko", ["python"], repo)
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == SPEC_VERSION == "1.6"
        assert sbom["version"] == 1
        assert sbom["serialNumber"].startswith("urn:uuid:")
        assert uuid.UUID(sbom["serialNumber"].removeprefix("urn:uuid:")).version == 4

    async def test_metadata_names_the_tool_and_the_repository(self):
        repo = FakeRepo({"requirements.txt": REQUIREMENTS_TXT})
        sbom = await generate_sbom("paramiko", "paramiko", ["python"], repo)
        metadata = sbom["metadata"]
        assert set(metadata) <= METADATA_KEYS
        assert metadata["tools"][0]["vendor"] == "QLint"
        assert metadata["component"]["type"] == "application"
        assert metadata["component"]["name"] == "paramiko/paramiko"

    async def test_every_component_is_a_library_with_schema_legal_keys(self):
        repo = FakeRepo(
            {"requirements.txt": REQUIREMENTS_TXT, "package.json": PACKAGE_JSON}
        )
        sbom = await generate_sbom("acme", "demo", ["python", "javascript"], repo)
        assert sbom["components"]
        for component in sbom["components"]:
            assert component["type"] == "library"
            assert component["name"]
            assert set(component) <= COMPONENT_KEYS
            assert component["bom-ref"]

    async def test_two_languages_are_inventoried_in_one_document(self):
        repo = FakeRepo(
            {"requirements.txt": REQUIREMENTS_TXT, "package.json": PACKAGE_JSON}
        )
        sbom = await generate_sbom("acme", "demo", ["python", "typescript"], repo)
        names = components_by_name(sbom)
        assert "fastapi" in names
        assert "react" in names
        assert names["fastapi"]["purl"].startswith("pkg:pypi/")
        assert names["react"]["purl"].startswith("pkg:npm/")

    async def test_only_the_scanned_languages_manifests_are_requested(self):
        repo = FakeRepo({"requirements.txt": REQUIREMENTS_TXT})
        await generate_sbom("acme", "demo", ["python"], repo)
        assert repo.requested == ["requirements.txt"]

    async def test_javascript_and_typescript_share_one_package_json(self):
        repo = FakeRepo({"package.json": PACKAGE_JSON})
        sbom = await generate_sbom(
            "acme", "demo", ["javascript", "typescript"], repo
        )
        assert repo.requested == ["package.json"]
        # ...and its dependencies are listed once, not twice.
        assert len(sbom["components"]) == len(set(
            component["bom-ref"] for component in sbom["components"]
        ))

    async def test_a_missing_manifest_is_a_coverage_note_not_a_failure(self):
        repo = FakeRepo({"requirements.txt": REQUIREMENTS_TXT})
        sbom = await generate_sbom("acme", "demo", ["python", "rust"], repo)
        notes = coverage(sbom)
        assert "fastapi" in components_by_name(sbom)
        assert "qlint:sbom:uncovered:rust" in notes
        assert "Cargo.toml" in notes["qlint:sbom:uncovered:rust"]
        assert "qlint:sbom:covered:python" in notes

    async def test_an_unparseable_manifest_degrades_gracefully(self):
        repo = FakeRepo(
            {"package.json": "{not json at all", "requirements.txt": REQUIREMENTS_TXT}
        )
        sbom = await generate_sbom("acme", "demo", ["python", "javascript"], repo)
        notes = coverage(sbom)
        assert "could not be parsed" in notes["qlint:sbom:uncovered:javascript"]
        # The other language still made it in.
        assert "fastapi" in components_by_name(sbom)

    async def test_a_repository_with_no_manifests_is_still_a_valid_document(self):
        repo = FakeRepo({})
        sbom = await generate_sbom("acme", "demo", ["python", "go"], repo)
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["components"] == []
        assert len(coverage(sbom)) == 2
        json.dumps(sbom)

    async def test_a_gradle_project_is_reported_as_unsupported_not_missing(self):
        repo = FakeRepo({"build.gradle": "dependencies { implementation 'x:y:1' }"})
        sbom = await generate_sbom("acme", "demo", ["java"], repo)
        note = coverage(sbom)["qlint:sbom:uncovered:java"]
        assert "build.gradle" in note
        assert "not supported" in note

    async def test_a_pom_project_is_read_rather_than_reported_missing(self):
        repo = FakeRepo({"pom.xml": POM_XML})
        sbom = await generate_sbom("acme", "demo", ["java"], repo)
        assert "org.bouncycastle:bcprov-jdk18on" in components_by_name(sbom)
        assert "qlint:sbom:covered:java" in coverage(sbom)

    async def test_a_language_with_no_manifest_parser_is_passed_over(self):
        repo = FakeRepo({"requirements.txt": REQUIREMENTS_TXT})
        sbom = await generate_sbom("acme", "demo", ["python", "cobol"], repo)
        assert "cobol" not in json.dumps(coverage(sbom))

    async def test_a_fetch_that_raises_does_not_fail_the_document(self):
        async def explode(path):
            raise RuntimeError("GitHub is having a day")

        sbom = await generate_sbom("acme", "demo", ["python"], explode)
        assert sbom["components"] == []
        assert "qlint:sbom:uncovered:python" in coverage(sbom)

    async def test_no_languages_at_all_still_produces_a_document(self):
        sbom = await generate_sbom("acme", "demo", [], FakeRepo({}))
        assert sbom["components"] == []
        assert sbom["metadata"]["properties"] == []

    async def test_components_are_sorted_so_two_downloads_read_the_same(self):
        repo = FakeRepo({"requirements.txt": REQUIREMENTS_TXT})
        first = await generate_sbom("acme", "demo", ["python"], repo)
        second = await generate_sbom("acme", "demo", ["python"], repo)
        assert [c["name"] for c in first["components"]] == [
            c["name"] for c in second["components"]
        ]

    async def test_the_document_is_json_serializable(self):
        repo = FakeRepo(
            {
                "requirements.txt": REQUIREMENTS_TXT,
                "package.json": PACKAGE_JSON,
                "go.mod": GO_MOD,
                "pom.xml": POM_XML,
                "Cargo.toml": CARGO_TOML,
            }
        )
        sbom = await generate_sbom(
            "acme",
            "demo",
            ["python", "javascript", "typescript", "go", "java", "rust"],
            repo,
        )
        json.dumps(sbom)
        assert len(coverage(sbom)) == 5  # one note per manifest, not per language
        # Every ecosystem's purl form, in one document.
        purls = {c.get("purl", "") for c in sbom["components"]}
        for prefix in ("pkg:pypi/", "pkg:npm/", "pkg:golang/", "pkg:maven/",
                       "pkg:cargo/"):
            assert any(purl.startswith(prefix) for purl in purls), prefix

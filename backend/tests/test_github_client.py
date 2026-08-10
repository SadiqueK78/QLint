"""Tests for github_client URL parsing and API helpers.

All HTTP is served by httpx.MockTransport — no real GitHub calls.
"""

import asyncio

import httpx
import pytest

from github_client import (
    InvalidRepoURLError,
    check_rate_limit,
    get_file_content,
    get_repo_files,
    language_for_path,
    parse_repo_url,
)


def make_client(handler):
    return httpx.AsyncClient(
        base_url="https://api.github.com",
        transport=httpx.MockTransport(handler),
    )


class TestParseRepoUrl:
    def test_valid_url(self):
        assert parse_repo_url("https://github.com/owner/repo") == ("owner", "repo")

    def test_valid_url_with_git_suffix_and_slash(self):
        assert parse_repo_url("https://github.com/owner/repo.git/") == (
            "owner",
            "repo",
        )

    def test_invalid_url_raises(self):
        with pytest.raises(InvalidRepoURLError):
            parse_repo_url("notaurl")

    def test_non_github_host_raises(self):
        with pytest.raises(InvalidRepoURLError):
            parse_repo_url("https://gitlab.com/owner/repo")


class TestLanguageForPath:
    @pytest.mark.parametrize(
        "path,language",
        [
            ("server.py", "python"),
            ("src/auth.js", "javascript"),
            ("src/auth.jsx", "javascript"),
            ("src/auth.ts", "typescript"),
            ("src/Component.tsx", "typescript"),
            ("types/index.d.ts", "typescript"),
            ("SRC/AUTH.JS", "javascript"),
            ("cmd/main.go", "go"),
            ("src/main/java/com/example/Signer.java", "java"),
            ("SRC/MAIN/JAVA/KEYS.JAVA", "java"),
        ],
    )
    def test_supported_extensions(self, path, language):
        assert language_for_path(path) == language

    @pytest.mark.parametrize(
        "path",
        ["README.md", "go.mod", "style.css", "noextension", "archive.pyc"],
    )
    def test_unsupported_extensions_return_none(self, path):
        assert language_for_path(path) is None


class TestGetRepoFiles:
    def test_returns_tagged_source_files_and_skips_everything_else(self):
        tree = {
            "tree": [
                {"type": "blob", "path": "server.py"},
                {"type": "blob", "path": "src/auth.js"},
                {"type": "blob", "path": "src/Component.tsx"},
                {"type": "blob", "path": "main.go"},
                {"type": "blob", "path": "src/main/java/Keys.java"},
                {"type": "blob", "path": "README.md"},
                {"type": "blob", "path": "go.mod"},
                {"type": "tree", "path": "src"},
            ]
        }

        def handler(request):
            return httpx.Response(200, json=tree)

        async def run():
            async with make_client(handler) as client:
                return await get_repo_files(
                    "https://github.com/acme/demo", "token", client=client
                )

        files = asyncio.run(run())
        assert files == [
            {"path": "server.py", "language": "python"},
            {"path": "src/auth.js", "language": "javascript"},
            {"path": "src/Component.tsx", "language": "typescript"},
            {"path": "main.go", "language": "go"},
            {"path": "src/main/java/Keys.java", "language": "java"},
        ]


class TestGetFileContent:
    def test_returns_none_for_files_over_1mb(self):
        def handler(request):
            return httpx.Response(
                200,
                json={
                    "size": 2 * 1024 * 1024,
                    "encoding": "none",
                    "content": "",
                },
            )

        async def run():
            async with make_client(handler) as client:
                return await get_file_content(
                    "owner", "repo", "big_file.py", "token", client=client
                )

        assert asyncio.run(run()) is None

    def test_decodes_base64_content(self):
        import base64

        encoded = base64.b64encode(b"import os\n").decode()

        def handler(request):
            return httpx.Response(
                200,
                json={"size": 10, "encoding": "base64", "content": encoded},
            )

        async def run():
            async with make_client(handler) as client:
                return await get_file_content(
                    "owner", "repo", "small.py", "token", client=client
                )

        assert asyncio.run(run()) == "import os\n"


class TestCheckRateLimit:
    def test_returns_remaining_and_reset_at(self):
        def handler(request):
            return httpx.Response(
                200,
                json={
                    "resources": {
                        "core": {
                            "limit": 5000,
                            "used": 1,
                            "remaining": 4999,
                            "reset": 1752969600,
                        }
                    }
                },
            )

        async def run():
            async with make_client(handler) as client:
                return await check_rate_limit("token", client=client)

        result = asyncio.run(run())
        assert {"remaining", "reset_at"} <= set(result)
        assert result["remaining"] == 4999
        assert isinstance(result["reset_at"], str)

"""Level 1 scanning: the JavaScript a website actually serves.

The third Level 1 view, after tls_scanner (what the transport negotiated) and
header_scanner (what the application tells the browser to do). This one asks
what code the page runs, and puts that code through the same js_scanner the
repository scanner uses -- so a finding on a live site and a finding in a
GitHub checkout are the same object, produced by the same rules.

Nothing here reimplements the scanner: it calls scanner_engine.scan_source,
which is the one place js_scanner is invoked for a single file's content. The
only thing this module changes is what goes in the `file` field, because a
script on a web page has no repository path -- it is "inline script #2" or the
URL it was downloaded from.

The security point specific to this phase, and the reason it is stated first:

    a <script src> can name any host at all.

The page is validated through ssrf_guard, as in Phases 1 and 2. That is not
enough here. A page on a perfectly public host can carry
`<script src="https://10.0.0.5/x.js">`, and fetching that would be an
attacker-chosen request to an internal address made by this server -- the exact
hole the guard exists to close, reopened one level down. So every external
script URL is put through ssrf_guard.validate_target independently, before it
is fetched, and a script that fails is skipped and reported rather than
fetched. There is no path through this module that fetches a URL the guard has
not judged.

Bounded on three axes, because a page can reference an arbitrary amount of
work: at most MAX_EXTERNAL_SCRIPTS files, at most MAX_SCRIPT_BYTES each, and a
whole-operation budget of OVERALL_TIMEOUT_SECONDS. Hitting any of them degrades
the report -- fewer scripts scanned, noted as such -- rather than failing it.
"""

import asyncio
import time
from html.parser import HTMLParser
from urllib.parse import urljoin

import httpx

from scanner_engine import scan_source
from ssrf_guard import HTTPS_PORT, SSRFGuardError, validate_target

# At most this many external files are downloaded per page. A page referencing
# more is scanned to the cap in document order and the total is reported, so
# the answer says "20 of 34" rather than quietly reading like the whole page.
MAX_EXTERNAL_SCRIPTS = 20

# Per-script ceiling. A bundle over a megabyte is almost always a minified
# vendor blob, and the cost of pulling it is real while the value is not.
MAX_SCRIPT_BYTES = 1024 * 1024

# The HTML itself. Not in this phase's requirements, and here anyway: without
# it the page fetch is the one unbounded read in the module, and a hostile
# server could stream for the whole time budget straight into this process's
# memory. Deliberately looser than the script limit -- real pages do get large.
MAX_PAGE_BYTES = 4 * 1024 * 1024

# The budget for everything: page fetch, every script fetch, and the scanning.
# Enforced as a deadline checked between fetches rather than as a hard cancel,
# so running out of time returns the work already done with a note attached.
OVERALL_TIMEOUT_SECONDS = 15.0

# What counts as JavaScript. An absent type attribute means JavaScript, and so
# do these three. Everything else -- application/ld+json, application/json,
# text/template, text/x-handlebars and friends -- is data or markup that
# happens to live in a script tag, and running it through a JavaScript scanner
# produces findings about text nobody executes.
SCANNABLE_TYPES = frozenset(
    {"", "text/javascript", "application/javascript", "module"}
)

# The `language` js_scanner is registered under in scanner_engine.SCANNERS.
LANGUAGE = "javascript"

# Skip reasons, named once so the module and its tests agree on the wording.
SKIP_EXCLUDED_TYPE = "excluded by type"
SKIP_OVER_CAP = "over the script limit"
SKIP_TOO_LARGE = "larger than 1MB"
SKIP_TIME_LIMIT = "time limit reached"
SKIP_BLOCKED = "blocked"
SKIP_FETCH_FAILED = "fetch failed"


class JSWebScanError(Exception):
    """The page could not be fetched. Nothing to report on."""


# ---------------------------------------------------------------------------
# Finding script tags
# ---------------------------------------------------------------------------


class _ScriptFinder(HTMLParser):
    """Every <script> on the page, in document order.

    html.parser rather than a dependency: finding script tags and reading two
    attributes is exactly what the stdlib parser is good at, and it puts
    <script> into CDATA mode by itself, so inline JavaScript arrives through
    handle_data as written instead of being parsed as markup.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict] = []
        self._open: dict[str, str] | None = None
        self._buffer: list[str] = []

    @staticmethod
    def _attributes(attrs) -> dict[str, str]:
        return {name.lower(): (value or "") for name, value in attrs}

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            return
        # An unclosed previous script: emit what was collected rather than
        # dropping it. Real pages do this, and the parser will not rescue us.
        if self._open is not None:
            self._emit()
        self._open = self._attributes(attrs)
        self._buffer = []

    def handle_startendtag(self, tag, attrs):
        # <script src="..." /> -- self-closing, so no end tag will arrive.
        if tag.lower() != "script":
            return
        self.scripts.append({"attrs": self._attributes(attrs), "text": ""})

    def handle_data(self, data):
        if self._open is not None:
            self._buffer.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._open is not None:
            self._emit()

    def _emit(self) -> None:
        self.scripts.append(
            {"attrs": self._open or {}, "text": "".join(self._buffer)}
        )
        self._open = None
        self._buffer = []

    def finish(self) -> list[dict]:
        """Close the parser and return what it found, unclosed tags included."""
        try:
            self.close()
        except Exception:  # pragma: no cover - html.parser is lenient
            pass
        if self._open is not None:
            self._emit()
        return self.scripts


def _is_scannable_type(raw_type: str) -> bool:
    """Whether a type attribute names executable JavaScript.

    The parameter half of a media type is dropped first: servers really do
    send `text/javascript; charset=utf-8`, and treating that as an unknown
    type would skip ordinary scripts.
    """
    media_type = raw_type.split(";", 1)[0].strip().lower()
    return media_type in SCANNABLE_TYPES


def find_script_references(html: str, page_url: str) -> list[dict]:
    """The page's script tags as inventory rows, before anything is fetched.

    Every tag produces a row, including the ones that will never be scanned:
    the inventory is meant to say what is on the page, and a reference that is
    silently dropped because of its type is exactly the kind of thing a reader
    needs told.
    """
    parser = _ScriptFinder()
    try:
        parser.feed(html)
    except Exception:  # pragma: no cover - html.parser rarely raises
        pass
    tags = parser.finish()

    references: list[dict] = []
    inline_number = 0
    for tag in tags:
        attrs = tag["attrs"]
        raw_type = attrs.get("type", "")
        src = (attrs.get("src") or "").strip()

        if src:
            reference = {
                "kind": "external",
                "url": urljoin(page_url, src),
                "raw_src": src,
                "type": raw_type or None,
                "source": urljoin(page_url, src),
                "scanned": False,
                "skip_reason": None,
                "size_bytes": None,
            }
        else:
            inline_number += 1
            reference = {
                "kind": "inline",
                "url": None,
                "raw_src": None,
                "type": raw_type or None,
                "source": f"inline script #{inline_number}",
                "scanned": False,
                "skip_reason": None,
                "size_bytes": len(tag["text"].encode("utf-8", errors="ignore")),
                # Carried for the scan step, stripped before the response.
                "_text": tag["text"],
            }

        if raw_type and not _is_scannable_type(raw_type):
            reference["skip_reason"] = SKIP_EXCLUDED_TYPE
            reference.pop("_text", None)
        references.append(reference)
    return references


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

_ssl_context = None


def _shared_ssl_context():
    """Built once. See header_scanner for why this is not a micro-optimization:
    a default httpx client reads the whole CA bundle, at about a second each."""
    global _ssl_context
    if _ssl_context is None:
        _ssl_context = httpx.create_ssl_context()
    return _ssl_context


def _client(timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout,
        verify=_shared_ssl_context(),
        # A redirect names a host the guard never judged. Same rule as the TLS
        # and header endpoints, and it applies to script URLs too.
        follow_redirects=False,
    )


def _pinned_url(target) -> httpx.URL:
    """The target's URL with the guard-approved address substituted in.

    The whole DNS-rebinding defence in one line: httpx would resolve the
    hostname again, and the second answer need not match the one the guard
    judged. The name still travels, as Host and SNI, so certificate
    verification is unaffected.
    """
    # target.port, not a constant: the guard judged this exact target on that
    # port, and it judges every script URL independently -- so a script on an
    # allowed non-standard port is fetched on the port it names.
    return httpx.URL(target.url).copy_with(host=target.address, port=target.port)


def _pin_headers(target) -> dict:
    return {"Host": target.hostname}


def _pin_extensions(target) -> dict:
    return {"sni_hostname": target.hostname}


def _decode(raw: bytes, content_type: str) -> str:
    """Bytes to text, preferring the declared charset.

    errors="replace" rather than strict: a mis-declared charset should cost a
    few mangled characters in a snippet, not the whole file's findings.
    """
    charset = ""
    for part in (content_type or "").split(";")[1:]:
        name, _, value = part.partition("=")
        if name.strip().lower() == "charset":
            charset = value.strip().strip('"').lower()
    for candidate in (charset, "utf-8"):
        if not candidate:
            continue
        try:
            return raw.decode(candidate, errors="replace")
        except LookupError:
            continue
    return raw.decode("utf-8", errors="replace")  # pragma: no cover


async def _fetch_bounded(
    client: httpx.AsyncClient, target, limit: int
) -> tuple[int, str, bytes]:
    """GET a guard-approved target, refusing to read past `limit` bytes.

    Streamed rather than read whole: httpx has no maximum-response-size option,
    so a `get` here would let a hostile server decide how much of this
    process's memory to consume. The declared length is checked first for the
    honest case, and the running total is checked for the dishonest one.

    Raises _TooLarge when the body exceeds the limit.
    """
    async with client.stream(
        "GET",
        _pinned_url(target),
        headers=_pin_headers(target),
        extensions=_pin_extensions(target),
    ) as response:
        declared = response.headers.get("content-length")
        if declared:
            try:
                if int(declared) > limit:
                    raise _TooLarge(int(declared))
            except ValueError:
                pass  # unparseable header; the running total still guards us

        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > limit:
                raise _TooLarge(total)
            chunks.append(chunk)

        return (
            response.status_code,
            response.headers.get("content-type", ""),
            b"".join(chunks),
        )


class _TooLarge(Exception):
    def __init__(self, size: int) -> None:
        super().__init__(f"{size} bytes")
        self.size = size


def _remaining(deadline: float) -> float:
    return deadline - time.monotonic()


def _describe_failure(exc: Exception, hostname: str, port: int = HTTPS_PORT) -> str:
    """One sentence, nothing internal in it. Mirrors header_scanner's."""
    if isinstance(exc, httpx.ConnectTimeout):
        return f"{hostname} did not accept a connection in time."
    if isinstance(exc, httpx.TimeoutException):
        return f"{hostname} did not answer in time."
    if isinstance(exc, httpx.ConnectError):
        return (
            f"Could not connect to {hostname} on port {port}: the host "
            "refused the connection or is unreachable."
        )
    if isinstance(exc, httpx.HTTPError):
        return f"The request to {hostname} failed: {type(exc).__name__}."
    return f"The request to {hostname} failed."


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------


async def scan_url(raw_url: str) -> dict:
    """Fetch a page, collect its JavaScript, and scan it.

    Returns two separate things, and they are separate on purpose: `references`
    is the inventory of every script the page mentions and what became of it,
    and `findings` is what js_scanner made of the code that was actually read.
    A page with no findings and eleven references is a meaningful answer; the
    two must not be collapsed into one list.
    """
    deadline = time.monotonic() + OVERALL_TIMEOUT_SECONDS
    notes: list[str] = []

    # The page. Guard first, as in every Level 1 scan.
    page = await validate_target(raw_url)
    try:
        async with _client(max(_remaining(deadline), 0.1)) as client:
            status_code, content_type, raw = await _fetch_bounded(
                client, page, MAX_PAGE_BYTES
            )
    except _TooLarge as exc:
        raise JSWebScanError(
            f"The page at {page.hostname} is larger than "
            f"{MAX_PAGE_BYTES // (1024 * 1024)}MB, which is past what this "
            "scan will download."
        ) from exc
    except Exception as exc:
        try:
            detail = _describe_failure(exc, page.hostname, page.port)
        except Exception:  # pragma: no cover - the belt for the braces
            detail = f"The scan of {page.hostname} failed."
        raise JSWebScanError(detail) from exc

    html = _decode(raw, content_type)
    references = find_script_references(html, page.url)

    external = [r for r in references if r["kind"] == "external"]
    over_cap = external[MAX_EXTERNAL_SCRIPTS:]
    for reference in over_cap:
        if reference["skip_reason"] is None:
            reference["skip_reason"] = SKIP_OVER_CAP
    if over_cap:
        notes.append(
            f"{len(external)} external scripts were found on the page; the "
            f"first {MAX_EXTERNAL_SCRIPTS} in document order were scanned and "
            f"{len(over_cap)} were not."
        )

    time_limited = await _fetch_external_scripts(
        external[:MAX_EXTERNAL_SCRIPTS], deadline
    )
    if time_limited:
        notes.append(
            f"The {OVERALL_TIMEOUT_SECONDS:.0f}-second time budget ran out "
            "before every script could be fetched, so this report covers only "
            "what was read in time."
        )

    findings = _scan_references(references)

    return {
        "host": page.hostname,
        "port": page.port,
        "url": page.url,
        "resolved_ips": page.addresses,
        "scanned_ip": page.address,
        "status_code": status_code,
        # Item one: what the page references, whatever came of it.
        "references": [_public(reference) for reference in references],
        # Item two: what the scanner found in what was read.
        "findings": findings,
        "summary": _summarize(references, findings, len(external)),
        "notes": notes,
        "time_limited": time_limited,
    }


async def _fetch_external_scripts(references: list[dict], deadline: float) -> bool:
    """Download each script, guarding every URL first. Returns whether time ran out.

    Sequential rather than concurrent, deliberately: twenty parallel
    connections from the backend to whatever hosts a page names is a burst that
    looks like an attack from the receiving end, and the time budget already
    bounds the total.
    """
    time_limited = False
    async with _client(OVERALL_TIMEOUT_SECONDS) as client:
        for reference in references:
            if reference["skip_reason"] is not None:
                continue  # excluded by type; never fetched

            remaining = _remaining(deadline)
            if remaining <= 0:
                reference["skip_reason"] = SKIP_TIME_LIMIT
                time_limited = True
                continue

            # THE check this phase exists for: the script's own URL, judged on
            # its own, before it is fetched. The page being safe says nothing
            # about where its <script src> points.
            try:
                target = await validate_target(reference["url"])
            except SSRFGuardError as exc:
                reference["skip_reason"] = f"{SKIP_BLOCKED}: {exc}"
                continue

            client.timeout = httpx.Timeout(remaining)
            try:
                status_code, content_type, raw = await _fetch_bounded(
                    client, target, MAX_SCRIPT_BYTES
                )
            except _TooLarge:
                reference["skip_reason"] = SKIP_TOO_LARGE
                continue
            except Exception as exc:
                reference["skip_reason"] = (
                    f"{SKIP_FETCH_FAILED}: "
                    f"{_describe_failure(exc, target.hostname, target.port)}"
                )
                continue

            if status_code >= 400:
                reference["skip_reason"] = (
                    f"{SKIP_FETCH_FAILED}: the server answered {status_code}"
                )
                continue

            reference["size_bytes"] = len(raw)
            reference["_text"] = _decode(raw, content_type)
    return time_limited


def _scan_references(references: list[dict]) -> list[dict]:
    """Run js_scanner over everything that was read, tagging each by source.

    scanner_engine.scan_source is the existing single-file entry point -- the
    same one the repository scanner uses -- so these findings are the same
    shape as a repo scan's, down to the language tag. The one difference is
    what `file` holds: a page's script has no repository path, so it carries
    "inline script #N" or the URL it came from.
    """
    findings: list[dict] = []
    for reference in references:
        text = reference.get("_text")
        if text is None:
            continue
        reference["scanned"] = True
        findings.extend(scan_source(reference["source"], LANGUAGE, text))
    return findings


def _public(reference: dict) -> dict:
    """The inventory row as it leaves the backend, without the source text."""
    return {key: value for key, value in reference.items() if key != "_text"}


def _summarize(references: list[dict], findings: list[dict], external_found: int) -> dict:
    severity_summary = {"critical": 0, "warning": 0, "safe": 0, "info": 0}
    for finding in findings:
        severity = finding.get("severity")
        if severity in severity_summary:
            severity_summary[severity] += 1
    scanned = [r for r in references if r["scanned"]]
    return {
        "scripts_found": len(references),
        "inline_found": sum(1 for r in references if r["kind"] == "inline"),
        "external_found": external_found,
        "scripts_scanned": len(scanned),
        "scripts_skipped": sum(1 for r in references if r["skip_reason"]),
        "total_findings": len(findings),
        "severity_summary": severity_summary,
        "algorithms_found": sorted(
            {f["algorithm"] for f in findings if f.get("severity") != "info"}
        ),
    }

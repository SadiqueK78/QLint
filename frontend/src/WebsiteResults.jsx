// The report for a Level 1 website scan: POST /web-scan.
//
// A separate view from ResultsView rather than a branch inside it. A
// repository report is built around repo_url, files_scanned and
// findings_by_file, and none of those exist here -- a certificate has no line
// number, a missing header has no file, and the one thing a site report has
// that a code report does not (the inventory of scripts the page references)
// has nowhere to go in a per-file list. Bending one view around both shapes
// would cost every row a "does this kind have that field" check.
//
// What it does share is the visual language: the score card, the severity
// pills, the finding cards and the disclosure are the components already on
// screen elsewhere in the app, reused by class rather than restyled.

import { useState } from "react";

import { Disclosure } from "./PqcBenchmark";
import { API_BASE } from "./api";
import { formatDateTime, scoreClass } from "./format";

// The four domains the backend stamps on every merged finding as `category`.
// Fixed order, and every one of them renders whether or not it has findings:
// an absent section and an empty section read the same, and only one of them
// means "this was checked and there was nothing to say".
const CATEGORIES = [
  {
    key: "TLS",
    label: "TLS",
    blurb: "The protocol version, key exchange and cipher this site negotiated.",
  },
  {
    key: "Certificate",
    label: "Certificate",
    blurb: "The certificate the site served: its signature, its key and its dates.",
  },
  {
    key: "HTTP Header",
    label: "HTTP Header",
    blurb: "The security headers the site sends, present and absent alike.",
  },
  {
    key: "JavaScript",
    label: "JavaScript",
    blurb: "Cryptography used by the scripts the page runs.",
  },
];

// Which sub-scan a category depends on. Three scans feed four categories: the
// TLS scan produces both the TLS and the Certificate findings, so when it
// fails both sections are empty for the same reason. scan_errors names the
// scan, which is why this mapping is needed to explain an empty section.
const CATEGORY_SCAN = {
  TLS: "TLS",
  Certificate: "TLS",
  "HTTP Header": "HTTP Header",
  JavaScript: "JavaScript",
};

const SCAN_LABELS = {
  TLS: "TLS scan",
  "HTTP Header": "header scan",
  JavaScript: "JavaScript scan",
};

// header_scanner rates a header on its own axis. This is the same mapping the
// backend scores those findings through, restated here for one reason only:
// the summary cards below have to add up to what the score was computed from,
// and the response carries the header's own severity rather than the mapped
// one. TLS and JavaScript findings need no mapping -- both already carry
// CRYPTO_DB's verdict, which is the vocabulary the pills are painted in.
const HEADER_TONES = {
  Info: "safe",
  Low: "warning",
  Medium: "warning",
  High: "critical",
  Critical: "critical",
};

const TONES = ["critical", "warning", "safe", "info"];

/** One finding's severity in the four-tone vocabulary the CSS paints. */
function severityTone(finding) {
  if (finding.category === "JavaScript") {
    // Straight from js_scanner, already on CRYPTO_DB's axis.
    return finding.severity || "info";
  }
  if (finding.category === "HTTP Header") {
    return HEADER_TONES[finding.severity] || "info";
  }
  // TLS and Certificate carry two severities on purpose: `severity` is how
  // broken the site is today, db_severity is CRYPTO_DB's own verdict. The
  // second is the one the score is computed from, so it is the one that
  // colours the pill; the first is what the pill says.
  return finding.db_severity || "info";
}

/** FastAPI's error detail, when it is a message a person can read.
 *
 * `detail` is a string for a raised HTTPException and an array of field errors
 * for a rejected request body; only the first is worth showing anyone. The
 * same rule App.jsx applies to the export downloads.
 */
function detailOf(body) {
  return typeof body?.detail === "string" ? body.detail : null;
}

/** The name a finding is filed under in the "Algorithms Detected" row.
 *
 * canonical_algorithm, not algorithm: the three domains spell the same
 * primitive differently -- a TLS key exchange reports "ECDH" where a script
 * reports "ECC" for the same thing -- and the badges are drawn from the
 * backend's canonicalised list. Matching on the raw name would mean clicking
 * "ECC" filtered the key exchange out of its own category.
 *
 * The fallback is for a scan stored before the backend started stamping the
 * canonical name: the two agree for most algorithms, so an old report filters
 * approximately rather than not at all.
 */
function algorithmOf(finding) {
  return finding.canonical_algorithm || finding.algorithm || null;
}

function bytes(size) {
  if (size === null || size === undefined) return null;
  if (size < 1024) return `${size} B`;
  return `${(size / 1024).toFixed(1)} kB`;
}

/** The merged finding flattened into the fields this card can render.
 *
 * The three scanners produce three shapes. TLS, Certificate and HTTP Header
 * findings are already the same shape as each other -- asset, type, purpose,
 * status, recommendation -- because header_scanner was built to match
 * tls_scanner. JavaScript findings are code findings: they come out of the
 * same scan_source a repository scan uses, so they name a file and a line
 * instead of an asset and a status. That one difference is handled here rather
 * than in the card, so the card has a single shape to draw.
 */
function findingView(finding) {
  const tone = severityTone(finding);
  if (finding.category === "JavaScript") {
    return {
      tone,
      severity: finding.severity,
      // A page's script has no repository path, so `file` holds the script's
      // URL or "inline script #N".
      asset: finding.algorithm,
      status: finding.file
        ? `${finding.file}${finding.line ? `:${finding.line}` : ""}`
        : null,
      facts: ["JavaScript"],
      risk: finding.attack_vector ? `Attack vector: ${finding.attack_vector}` : null,
      recommendation: finding.replacement
        ? `Replace with ${finding.replacement}`
        : null,
      detail: finding.replacement_reason,
    };
  }
  return {
    tone,
    severity: finding.severity,
    asset: finding.asset,
    status: finding.status,
    // The algorithm is dropped when it repeats the asset, which is what a
    // cipher-suite or a signature-algorithm finding does.
    facts: [
      finding.type,
      finding.purpose,
      finding.algorithm !== finding.asset ? finding.algorithm : null,
      finding.key_size,
    ].filter(Boolean),
    risk: finding.quantum_risk ? `Quantum risk: ${finding.quantum_risk}` : null,
    recommendation: finding.recommendation,
    detail: finding.observed_value ? `Sent: ${finding.observed_value}` : null,
  };
}

/** The body of an explanation, in the three states it can be in.
 *
 * A copy of ResultsView's ExplainBody in structure and class names rather than
 * an import: App.jsx already imports this module, so importing back out of it
 * would make the graph circular -- the same reason scoreClass and
 * formatDateTime live in format.js. The classes are the shared thing, so the
 * two read identically on screen.
 */
function WebExplainBody({ loading, error, explanation, onRetry }) {
  return (
    <div className="explain-body">
      {loading && (
        <p className="explain-loading">
          {"Asking the model about this finding…"}
        </p>
      )}
      {!loading && error && (
        <div className="explain-error">
          <p>{error}</p>
          <button className="explain-retry" type="button" onClick={onRetry}>
            Try again
          </button>
        </div>
      )}
      {!loading && !error && explanation && (
        <p className="explain-text">{explanation}</p>
      )}
    </div>
  );
}

/** Only the fields /web-scan/explain reads.
 *
 * The website counterpart of App.jsx's findingRequestBody, and deliberately a
 * different set: a website finding has no code_snippet, no fix_snippet, no
 * file and no line, which is exactly why it goes to its own endpoint rather
 * than to /scan/explain. category and severity are the two the backend
 * requires; the rest are sent when the finding has them.
 */
function webFindingRequestBody(finding, view) {
  return {
    category: finding.category,
    severity: String(finding.severity ?? ""),
    // The view's values are the fallbacks, so the model is asked about what
    // the card actually shows. A JavaScript finding is the case that needs
    // them: it names no asset and no recommendation of its own, and findingView
    // is already where those are derived from the algorithm and the
    // replacement.
    asset: finding.asset ?? view.asset ?? null,
    type: finding.type ?? null,
    // Deliberately not view.status: for a JavaScript finding that holds a
    // script URL and a line number, which is a location rather than a verdict,
    // and the backend labels this field "what the scan found".
    status: finding.status ?? null,
    algorithm: finding.algorithm ?? null,
    key_size: finding.key_size == null ? null : String(finding.key_size),
    observed_value: finding.observed_value ?? null,
    quantum_risk: finding.quantum_risk ?? finding.attack_vector ?? null,
    recommendation: finding.recommendation ?? view.recommendation ?? null,
  };
}

function WebFindingCard({ finding, authToken }) {
  const view = findingView(finding);
  const [explainOpen, setExplainOpen] = useState(false);
  const [explainLoading, setExplainLoading] = useState(false);
  const [explainError, setExplainError] = useState(null);
  const [explanation, setExplanation] = useState(null);

  // Same flow as the repository card's: the button toggles the panel, and the
  // request is made once on first open and never again unless it failed.
  const fetchExplanation = async () => {
    setExplainLoading(true);
    setExplainError(null);
    try {
      const res = await fetch(`${API_BASE}/web-scan/explain`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          // Unlike /scan/explain, this endpoint requires a session: it is in
          // the router where every route does.
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
        body: JSON.stringify(webFindingRequestBody(finding, view)),
      });
      const body = await res.json().catch(() => null);
      if (!res.ok) throw new Error(detailOf(body) || `HTTP ${res.status}`);
      setExplanation(body.explanation);
    } catch (err) {
      setExplainError(err.message || "Could not generate an explanation.");
    } finally {
      setExplainLoading(false);
    }
  };

  const toggleExplain = () => {
    if (explainOpen) {
      setExplainOpen(false);
      return;
    }
    setExplainOpen(true);
    if (!explanation && !explainLoading) fetchExplanation();
  };

  const retryExplain = () => {
    setExplanation(null);
    fetchExplanation();
  };

  return (
    <div className="finding">
      <div className="finding-top">
        <div className="finding-title">
          <span className={`sev-badge sev-${view.tone}`}>{view.severity}</span>
          <span className="finding-algo">{view.asset}</span>
        </div>
        {view.status && <span className="finding-line">{view.status}</span>}
      </div>
      {view.facts.length > 0 && (
        <p className="web-finding-facts">{view.facts.join(" · ")}</p>
      )}
      {view.risk && <p className="finding-vector">{view.risk}</p>}
      {view.recommendation && (
        <p className="finding-replacement">
          <span className="finding-replacement-label">Recommendation:</span>{" "}
          {view.recommendation}
        </p>
      )}
      {view.detail && <p className="finding-reason">{view.detail}</p>}
      <div className="finding-actions">
        <button
          className="fix-toggle explain-toggle"
          type="button"
          onClick={toggleExplain}
          disabled={explainLoading}
        >
          {explainLoading
            ? "Explaining…"
            : explainOpen
            ? "Hide explanation"
            : "Explain with AI"}
        </button>
      </div>
      {explainOpen && (
        <WebExplainBody
          loading={explainLoading}
          error={explainError}
          explanation={explanation}
          onRetry={retryExplain}
        />
      )}
    </div>
  );
}

/** The inventory of scripts the page referenced.
 *
 * Its own section rather than a fifth disclosure beside the four categories,
 * because it is not findings: a page that pulls in eleven scripts and produces
 * no finding has said something, and a reader needs to know which of those
 * eleven were actually read before trusting a clean JavaScript section.
 */
function JavaScriptReferences({ references, summary, scanFailed }) {
  return (
    <section className="web-section">
      <div className="algo-label-row">
        <span className="algo-label">JavaScript inventory</span>
        {summary && (
          <span className="web-section-count">
            {summary.scripts_found} referenced, {summary.scripts_scanned} scanned,{" "}
            {summary.scripts_skipped} skipped
          </span>
        )}
      </div>
      {scanFailed ? (
        <div className="no-findings">
          The JavaScript scan did not run, so no scripts were inventoried.
        </div>
      ) : references.length === 0 ? (
        <div className="no-findings">
          This page referenced no scripts.
        </div>
      ) : (
        <div className="file-body">
          {references.map((reference, i) => {
            const source =
              reference.source || reference.url || `inline script #${i + 1}`;
            const facts = [
              reference.kind === "inline" ? "Inline" : "External",
              reference.type,
              bytes(reference.size_bytes),
            ].filter(Boolean);
            return (
              <div className="finding" key={`${source}-${i}`}>
                <div className="finding-top">
                  <div className="finding-title">
                    <span
                      className={`algo-pill pill-${
                        reference.scanned ? "safe" : "info"
                      }`}
                    >
                      {reference.scanned ? "Scanned" : "Skipped"}
                    </span>
                    <span className="finding-algo web-ref-source">{source}</span>
                  </div>
                </div>
                {facts.length > 0 && (
                  <p className="web-finding-facts">{facts.join(" · ")}</p>
                )}
                {!reference.scanned && (
                  <p className="finding-reason">
                    {reference.skip_reason || "Not read."}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

/** The banner above a partial report.
 *
 * A combined scan where one or two of the three checks failed still answers
 * 200, because two thirds of a report is a report. That makes this banner the
 * only thing standing between a partial report and a reader who takes an
 * absent category for a clean one, so it sits above the score rather than
 * beside the section it explains.
 */
function ScanErrorsBanner({ errors }) {
  return (
    <div className="web-warning" role="alert">
      <div className="web-warning-title">
        {errors.length === 1
          ? "One of the three checks did not run, so this report is partial."
          : `${errors.length} of the three checks did not run, so this report is partial.`}
      </div>
      <ul className="web-warning-list">
        {errors.map((entry) => (
          <li key={entry.scan}>
            <span className="web-warning-scan">
              {SCAN_LABELS[entry.scan] || entry.scan}
            </span>
            {": "}
            {entry.error}
          </li>
        ))}
      </ul>
      <p className="web-warning-note">
        The score and the counts below were computed from the checks that did
        finish. Read them as a floor, not a verdict: the sections belonging to a
        failed check are empty because nothing looked, not because nothing was
        found.
      </p>
    </div>
  );
}

export default function WebsiteResultsView({
  result,
  onReset,
  authToken,
  onDownloadCbom,
}) {
  const findings = result.findings || [];
  const references = result.javascript_references || [];
  const errors = result.scan_errors || [];

  // The same interaction the repository report uses: one algorithm at a time,
  // clicking the active one clears it, and a Clear filter control appears
  // beside the label while one is set. Held here rather than lifted into
  // App.jsx because nothing outside this view reads it -- the repository
  // view's equivalent is lifted only because its sibling controls share it.
  const [activeAlgo, setActiveAlgo] = useState(null);
  const toggleAlgo = (algo) =>
    setActiveAlgo((prev) => (prev === algo ? null : algo));

  const [cbomBusy, setCbomBusy] = useState(false);
  const [cbomError, setCbomError] = useState(null);

  const downloadCbom = async () => {
    setCbomBusy(true);
    setCbomError(null);
    try {
      await onDownloadCbom();
    } catch (err) {
      setCbomError(err.message || "Could not build the CBOM file.");
    } finally {
      setCbomBusy(false);
    }
  };

  const failedScans = new Set(errors.map((entry) => entry.scan));
  const errorByScan = {};
  for (const entry of errors) errorByScan[entry.scan] = entry.error;

  // Counted from the findings rather than read off the response: the summary
  // the backend sends counts by category, and these four cards count by
  // severity, which is the axis the score was computed on.
  const counts = { critical: 0, warning: 0, safe: 0, info: 0 };
  for (const finding of findings) {
    const tone = severityTone(finding);
    if (tone in counts) counts[tone] += 1;
  }

  // Worst severity seen per algorithm, for pill colouring -- the repository
  // view computes the same thing from its own findings. Grouped on the
  // canonical name so a pill's colour comes from every finding that pill would
  // filter to, across all four categories.
  const algoTone = {};
  for (const finding of findings) {
    const algorithm = algorithmOf(finding);
    if (!algorithm) continue;
    const tone = severityTone(finding);
    const current = algoTone[algorithm];
    if (current === undefined || TONES.indexOf(tone) < TONES.indexOf(current)) {
      algoTone[algorithm] = tone;
    }
  }

  // The algorithm filter narrows every category at once. A finding that names
  // no algorithm -- a missing header, most often -- matches no filter, which
  // is right: it is not an instance of the algorithm that was clicked.
  const matchesFilter = (finding) =>
    activeAlgo === null || algorithmOf(finding) === activeAlgo;

  const byCategory = {};
  for (const category of CATEGORIES) byCategory[category.key] = [];
  for (const finding of findings) {
    if (byCategory[finding.category] && matchesFilter(finding)) {
      byCategory[finding.category].push(finding);
    }
  }
  // Counted after filtering, so a category's number and its contents cannot
  // disagree: a section headed "HTTP Header (5)" listing one finding reads as
  // a bug in the report rather than as a filter being applied.
  const shownFindings = CATEGORIES.reduce(
    (total, category) => total + byCategory[category.key].length,
    0
  );

  const jsFailed = failedScans.has("JavaScript");

  return (
    <div className="results">
      <div className="results-header">
        <div>
          <div className="results-repo">{result.url}</div>
          <div className="results-meta">
            {[
              result.host,
              result.scanned_at ? `Scanned ${formatDateTime(result.scanned_at)}` : null,
              typeof result.http_status_code === "number"
                ? `HTTP ${result.http_status_code}`
                : null,
            ]
              .filter(Boolean)
              .join(" · ")}
          </div>
        </div>
        <div className="results-actions-wrap">
          <div className="results-actions">
            {/* CBOM and nothing else. SARIF describes results at file
                locations in source code and an SBOM inventories the
                dependencies a repository declares; a live site has neither, and
                the backend answers 422 for both rather than emitting a
                document full of locations that do not exist. */}
            <button
              className="btn-ghost btn-small"
              type="button"
              onClick={downloadCbom}
              disabled={cbomBusy}
              title="CycloneDX 1.6 CBOM: an inventory of the cryptography this site serves"
            >
              {cbomBusy ? "Building CBOM..." : "Download CBOM"}
            </button>
            <button className="btn-primary btn-small" type="button" onClick={onReset}>
              Scan Another Site
            </button>
          </div>
          {cbomError && <div className="sarif-error">{cbomError}</div>}
        </div>
      </div>

      {errors.length > 0 && <ScanErrorsBanner errors={errors} />}

      <div className="score-row">
        <div className="score-card">
          <div className="card-label">PQC Readiness Score</div>
          <div className={`score-value ${scoreClass(result.pqc_readiness_score)}`}>
            {result.pqc_readiness_score}
          </div>
          <div className="score-out-of">out of 100</div>
        </div>
        {TONES.map((tone) => (
          <div className={`sum-card sum-${tone}`} key={tone}>
            <div className="card-label">{tone}</div>
            <div className="sum-count">{counts[tone]}</div>
          </div>
        ))}
      </div>

      {result.algorithms_found?.length > 0 && (
        <>
          <div className="algo-label-row">
            <span className="algo-label">Algorithms Detected</span>
            {activeAlgo !== null && (
              <button
                type="button"
                className="algo-clear-btn"
                onClick={() => setActiveAlgo(null)}
                title={`Clear the ${activeAlgo} filter and show every algorithm`}
              >
                <span className="algo-clear-x" aria-hidden="true">
                  &times;
                </span>
                Clear filter
              </button>
            )}
          </div>
          <div className="algo-row">
            {result.algorithms_found.map((algo) => {
              const active = activeAlgo === algo;
              return (
                <button
                  type="button"
                  className={`algo-pill algo-pill-btn pill-${
                    algoTone[algo] ?? "warning"
                  }${active ? " algo-pill-active" : ""}`}
                  key={algo}
                  onClick={() => toggleAlgo(algo)}
                  aria-pressed={active}
                  title={
                    active
                      ? `Clear the ${algo} filter`
                      : `Show only ${algo} findings`
                  }
                >
                  {algo}
                </button>
              );
            })}
          </div>
        </>
      )}

      <section className="web-section">
        <div className="algo-label-row">
          <span className="algo-label">Findings by category</span>
          <span className="web-section-count">
            {activeAlgo === null
              ? `${findings.length} ${
                  findings.length === 1 ? "finding" : "findings"
                }`
              : `${shownFindings} of ${findings.length} ${
                  findings.length === 1 ? "finding" : "findings"
                } · ${activeAlgo}`}
          </span>
        </div>
        {/* The wrapper is what widens the disclosures: the component is the
            one the benchmark page uses, and there it sits in a 780px column. */}
        <div className="web-disclosures">
          {CATEGORIES.map((category) => {
            const scan = CATEGORY_SCAN[category.key];
            const failed = failedScans.has(scan);
            const items = byCategory[category.key];
            const label = failed
              ? `${category.label} (not scanned)`
              : `${category.label} (${items.length})`;
            return (
              <Disclosure key={category.key} label={label}>
                <p className="web-section-blurb">{category.blurb}</p>
                {failed ? (
                  <p className="web-section-note">
                    The {SCAN_LABELS[scan] || scan} did not run, so nothing here
                    was checked: {errorByScan[scan]}
                  </p>
                ) : items.length === 0 ? (
                  <p className="web-section-note">
                    {activeAlgo === null
                      ? "Nothing to report in this category."
                      : `No ${activeAlgo} findings in this category.`}
                  </p>
                ) : (
                  <div className="file-body web-finding-list">
                    {items.map((finding, i) => (
                      <WebFindingCard
                        key={`${category.key}-${i}`}
                        finding={finding}
                        authToken={authToken}
                      />
                    ))}
                  </div>
                )}
              </Disclosure>
            );
          })}
        </div>
      </section>

      <JavaScriptReferences
        references={references}
        summary={result.javascript_summary}
        scanFailed={jsFailed}
      />
    </div>
  );
}

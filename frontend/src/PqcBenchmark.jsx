import { useState } from "react";

import { API_BASE } from "./api";
import { ChevronIcon } from "./icons";

const ITERATIONS = 50;

// Must match the allow-lists in benchmark_router.py: anything outside them is
// a 400, and the dropdown is the only thing that populates the query string.
const KEM_LEVELS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];
const SIG_LEVELS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];
// FIPS 205, the hash-based signature family. Only the fast-signing "f" sets
// are offered: the "s" sets buy a smaller signature with roughly fifteen times
// the signing cost, which a live request cannot afford. The backend measures
// this row over fewer iterations than the rest for the same reason, and says
// so in the row's own iteration count.
const SLH_DSA_LEVELS = [
  "SLH-DSA-SHA2-128f",
  "SLH-DSA-SHAKE-128f",
  "SLH-DSA-SHA2-192f",
];

// Sizes are small enough that plain bytes read better than any unit prefix.
function bytes(value) {
  if (value === null || value === undefined) return "—";
  return `${value.toLocaleString()} B`;
}

function rate(value) {
  if (value === null || value === undefined) return "—";
  if (value >= 100) return Math.round(value).toLocaleString();
  return value.toFixed(1);
}

function familyLabel(family) {
  return family === "classical" ? "Classical" : "Post-quantum";
}

// Collapsed by default: both blocks it wraps are reference material rather
// than something a reader needs before pressing the button, and always-visible
// prose was crowding out the numbers this page exists to show. Same
// button-plus-chevron shape as the Help accordion, so a disclosure behaves the
// same wherever it appears.
function Disclosure({ label, children }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`pqc-disclosure${open ? " pqc-disclosure-open" : ""}`}>
      <button
        className="pqc-disclosure-toggle"
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((prev) => !prev)}
      >
        <span className="pqc-disclosure-label">{label}</span>
        <span
          className={`pqc-disclosure-chevron${
            open ? " pqc-disclosure-chevron-open" : ""
          }`}
        >
          <ChevronIcon />
        </span>
      </button>
      {open && <div className="pqc-disclosure-body">{children}</div>}
    </div>
  );
}

// One entry per NIST standard the page exercises, spelled out as full URLs so
// the destination is visible before the click.
const FIPS_LINKS = [
  { label: "ML-KEM — FIPS 203", url: "https://csrc.nist.gov/pubs/fips/203/final" },
  { label: "ML-DSA — FIPS 204", url: "https://csrc.nist.gov/pubs/fips/204/final" },
  { label: "SLH-DSA — FIPS 205", url: "https://csrc.nist.gov/pubs/fips/205/final" },
];

// One algorithm failing does not take the run down, so it gets a row saying
// what went wrong rather than being dropped from the table.
function ErrorRow({ entry, columns }) {
  return (
    <tr className="pqc-row-error">
      <td className="pqc-algo">{entry.algorithm}</td>
      <td colSpan={columns - 1}>{entry.error}</td>
    </tr>
  );
}

function KemTable({ rows }) {
  return (
    <table className="pqc-table">
      <thead>
        <tr>
          <th>Algorithm</th>
          <th>Family</th>
          <th>Keygen /sec</th>
          <th>Encapsulate /sec</th>
          <th>Decapsulate /sec</th>
          <th>Public key</th>
          <th>Ciphertext</th>
          <th>Shared secret</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((entry) =>
          entry.error ? (
            <ErrorRow key={entry.algorithm} entry={entry} columns={8} />
          ) : (
            <tr
              key={entry.algorithm}
              className={
                entry.family === "classical" ? undefined : "pqc-row-pqc"
              }
            >
              <td className="pqc-algo">{entry.algorithm}</td>
              <td>{familyLabel(entry.family)}</td>
              <td>{rate(entry.keygen_ops_per_sec)}</td>
              <td>{rate(entry.encap_ops_per_sec)}</td>
              <td>{rate(entry.decap_ops_per_sec)}</td>
              <td>{bytes(entry.public_key_bytes)}</td>
              <td>{bytes(entry.ciphertext_bytes)}</td>
              <td>{bytes(entry.shared_secret_bytes)}</td>
            </tr>
          )
        )}
      </tbody>
    </table>
  );
}

function SigTable({ rows }) {
  return (
    <table className="pqc-table">
      <thead>
        <tr>
          <th>Algorithm</th>
          <th>Family</th>
          <th>Keygen /sec</th>
          <th>Sign /sec</th>
          <th>Verify /sec</th>
          <th>Public key</th>
          <th>Signature</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((entry) =>
          entry.error ? (
            <ErrorRow key={entry.algorithm} entry={entry} columns={7} />
          ) : (
            <tr
              key={entry.algorithm}
              className={
                entry.family === "classical" ? undefined : "pqc-row-pqc"
              }
            >
              <td className="pqc-algo">{entry.algorithm}</td>
              <td>{familyLabel(entry.family)}</td>
              <td>{rate(entry.keygen_ops_per_sec)}</td>
              <td>{rate(entry.sign_ops_per_sec)}</td>
              <td>{rate(entry.verify_ops_per_sec)}</td>
              <td>{bytes(entry.public_key_bytes)}</td>
              <td>{bytes(entry.signature_bytes)}</td>
            </tr>
          )
        )}
      </tbody>
    </table>
  );
}

// Flattens one size metric out of a finished run into chart rows, largest
// first. It reads whichever algorithms that run actually measured, so picking
// a different security level moves the bars with no extra fetch. Rows that
// errored have null sizes and are dropped: a bar of unknown length is worse
// than no bar, and the tables below already report what went wrong.
function sizeRows(result, kemField, sigField) {
  const pick = (entries, field) =>
    entries
      .filter((entry) => !entry.error && typeof entry[field] === "number")
      .map((entry) => ({
        algorithm: entry.algorithm,
        family: entry.family,
        bytes: entry[field],
      }));

  return [
    ...pick(result.kem_results, kemField),
    ...pick(result.sig_results, sigField),
  ].sort((a, b) => b.bytes - a.bytes);
}

// Bars are scaled against the largest value in their own chart, so the two
// charts are each internally honest rather than sharing one axis that would
// squash the smaller of them. The byte count sits outside the bar, which keeps
// it readable on the classical rows where the bar is only a few pixels wide --
// and those few pixels are the entire point of drawing this.
function SizeChart({ title, description, rows }) {
  if (rows.length === 0) return null;

  const largest = rows[0];
  const smallest = rows[rows.length - 1];
  const ratio = smallest.bytes > 0 ? largest.bytes / smallest.bytes : null;

  return (
    <div className="pqc-chart">
      <h3 className="pqc-chart-title">{title}</h3>
      <div className="pqc-chart-body">
        {rows.map((row) => (
          <div className="pqc-bar-row" key={row.algorithm}>
            <div className="pqc-bar-label">{row.algorithm}</div>
            <div className="pqc-bar-track">
              <div
                className={
                  row.family === "classical"
                    ? "pqc-bar pqc-bar-classical"
                    : "pqc-bar pqc-bar-pqc"
                }
                style={{ width: `${(row.bytes / largest.bytes) * 100}%` }}
              />
            </div>
            <div className="pqc-bar-value">{bytes(row.bytes)}</div>
          </div>
        ))}
      </div>
      <p className="pqc-chart-caption">
        {description}
        {ratio !== null && rows.length > 1
          ? ` ${largest.algorithm} is ${
              ratio >= 10 ? Math.round(ratio) : ratio.toFixed(1)
            }x the size of ${smallest.algorithm}.`
          : ""}
      </p>
    </div>
  );
}

export default function PqcBenchmark() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [runCount, setRunCount] = useState(0);
  const [kemLevel, setKemLevel] = useState("ML-KEM-768");
  const [sigLevel, setSigLevel] = useState("ML-DSA-65");
  const [slhDsaLevel, setSlhDsaLevel] = useState("SLH-DSA-SHA2-128f");

  const runBenchmark = async () => {
    setLoading(true);
    setError(null);
    try {
      // no-store, because the point of the page is that every click is a
      // fresh measurement rather than a replayed response.
      const query = new URLSearchParams({
        iterations: String(ITERATIONS),
        kem_algorithm: kemLevel,
        sig_algorithm: sigLevel,
        slh_dsa_algorithm: slhDsaLevel,
      });
      const res = await fetch(`${API_BASE}/benchmark/run?${query}`, {
        cache: "no-store",
      });
      const body = await res.json().catch(() => null);
      if (!res.ok) {
        throw new Error(
          (body && typeof body.detail === "string" && body.detail) ||
            `HTTP ${res.status}`
        );
      }
      setResult(body);
      setRunCount((prev) => prev + 1);
    } catch (err) {
      setResult(null);
      setError(
        err instanceof TypeError
          ? "Could not reach the QLint backend."
          : err.message || "The benchmark failed to run."
      );
    } finally {
      setLoading(false);
    }
  };

  // Every note the backend attached, deduplicated: they explain how the sizes
  // were measured, which is the part a reader is most likely to challenge.
  const notes = result
    ? Array.from(
        new Set(
          [...result.kem_results, ...result.sig_results]
            .map((entry) => entry.notes)
            .filter(Boolean)
        )
      )
    : [];

  const publicKeyRows = result
    ? sizeRows(result, "public_key_bytes", "public_key_bytes")
    : [];
  const payloadRows = result
    ? sizeRows(result, "ciphertext_bytes", "signature_bytes")
    : [];

  const cappedKeygen = result
    ? [...result.sig_results].find(
        (entry) =>
          !entry.error && entry.keygen_iterations < entry.iterations
      )
    : null;

  // Rows the backend measured over fewer iterations than the run asked for --
  // SLH-DSA today. Read off the rows themselves rather than hardcoding which
  // algorithm is slow, so the note follows the backend's cap instead of
  // restating it and going stale.
  const cappedRows = result
    ? [...result.kem_results, ...result.sig_results].filter(
        (entry) => entry.iterations < result.iterations
      )
    : [];

  return (
    <div className="pqc-page">
      <div className="pqc-header">
        <h1 className="pqc-title">PQC Benchmark Lab</h1>
        <p className="pqc-lede">
          Press Run Benchmark to see how fast real quantum-safe cryptography
          runs on this server, next to the algorithms in use today.
        </p>
        <p className="pqc-intro">
          This page runs real post-quantum cryptography on the QLint server, on
          demand. Clicking the button below generates keys, encapsulates and
          decapsulates shared secrets with ML-KEM, and signs and verifies a
          message with ML-DSA and SLH-DSA, the three algorithms NIST
          standardized in 2024, then does the same work with classical RSA and
          ECDSA for comparison.
          Every number in the table is timed during that run, and every key and
          signature size is measured from the bytes the algorithm actually
          produced. Nothing here is a published figure looked up from a table.
        </p>
        <Disclosure label="Know more about these PQC algorithms">
          {FIPS_LINKS.map((entry) => (
            <a
              className="pqc-disclosure-link"
              key={entry.url}
              href={entry.url}
              target="_blank"
              rel="noopener noreferrer"
            >
              {entry.label}: {entry.url}
            </a>
          ))}
        </Disclosure>
      </div>

      <div className="pqc-levels">
        <label className="pqc-level">
          <span className="pqc-level-label">PQC KEM level</span>
          <select
            className="pqc-select"
            value={kemLevel}
            onChange={(event) => setKemLevel(event.target.value)}
            disabled={loading}
          >
            {KEM_LEVELS.map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </select>
        </label>
        <label className="pqc-level">
          <span className="pqc-level-label">PQC signature level</span>
          <select
            className="pqc-select"
            value={sigLevel}
            onChange={(event) => setSigLevel(event.target.value)}
            disabled={loading}
          >
            {SIG_LEVELS.map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </select>
        </label>
        <label className="pqc-level">
          <span className="pqc-level-label">SLH-DSA parameter set</span>
          <select
            className="pqc-select"
            value={slhDsaLevel}
            onChange={(event) => setSlhDsaLevel(event.target.value)}
            disabled={loading}
          >
            {SLH_DSA_LEVELS.map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </select>
        </label>
        <span className="pqc-level-hint">
          RSA-2048 and ECDSA P-256 are fixed: they are the baseline the
          post-quantum numbers are read against.
        </span>
      </div>

      <div className="pqc-controls">
        <button
          className="btn-primary pqc-run"
          type="button"
          onClick={runBenchmark}
          disabled={loading}
        >
          {loading ? "Running benchmark..." : "Run Benchmark"}
        </button>
        <span className="pqc-hint">
          {loading
            ? "Running the algorithms now. This takes a few seconds, most of it RSA key generation."
            : `${ITERATIONS} iterations per operation. Expect a few seconds of real computation.`}
        </span>
      </div>

      {error && <div className="pqc-error">{error}</div>}

      {result && (
        <div className="pqc-results">
          <div className="pqc-meta">
            Run {runCount} completed in {result.total_seconds}s at{" "}
            {new Date(result.generated_at).toLocaleTimeString()}, {result.iterations}{" "}
            iterations per operation
            {result.liboqs_version ? `, liboqs ${result.liboqs_version}` : ""}.
          </div>

          <h2 className="pqc-section-title">Key Encapsulation</h2>
          <div className="pqc-table-scroll">
            <KemTable rows={result.kem_results} />
          </div>

          <h2 className="pqc-section-title">Digital Signatures</h2>
          <div className="pqc-table-scroll">
            <SigTable rows={result.sig_results} />
          </div>

          <h2 className="pqc-section-title">Size Comparison</h2>
          <div className="pqc-charts">
            <SizeChart
              title="Public key size"
              description="Every public key this run produced, measured in bytes."
              rows={publicKeyRows}
            />
            <SizeChart
              title="Signature and ciphertext size"
              description="The bytes each algorithm puts on the wire per operation: a ciphertext for the KEM, a signature for the rest."
              rows={payloadRows}
            />
          </div>

          {/* Takeaway, keygen caveat, and the backend's measurement notes used
              to sit here as three always-visible paragraphs in two different
              sizes. They are one collapsed block now, at one size: the reader
              who wants to challenge a number opens it, everyone else sees the
              tables. */}
          <Disclosure label="Methodology notes">
            <p className="pqc-method-text">
              The post-quantum algorithms here are competitive on speed but
              carry far larger keys and signatures than RSA and ECDSA, and that
              is the trade: those bytes buy security believed to hold against a
              quantum computer, which RSA and ECDSA will not.
            </p>

            {cappedRows.length > 0 && (
              <p className="pqc-method-text">
                {cappedRows.map((entry) => entry.algorithm).join(", ")} ran{" "}
                {cappedRows[0].iterations} iterations rather than{" "}
                {result.iterations}. SLH-DSA is hash-based: one signature is
                thousands of hash calls, tens of milliseconds against ML-DSA's
                one or two, so the full count would spend most of a minute on a
                single row. The rates are per-operation either way, and each
                row's iteration count is the one it was measured over.
              </p>
            )}

            {cappedKeygen && (
              <p className="pqc-method-text">
                {cappedKeygen.algorithm} key generation is measured over{" "}
                {cappedKeygen.keygen_iterations} iterations rather than{" "}
                {cappedKeygen.iterations}: it costs roughly a thousand times
                what every other operation on this page costs, and running the
                full count would dominate the wait. Signing and verification use
                the full count.
              </p>
            )}
            {notes.map((note) => (
              <p className="pqc-method-text" key={note}>
                {note}
              </p>
            ))}
          </Disclosure>
        </div>
      )}
    </div>
  );
}

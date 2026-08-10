import { useState } from "react";

// The Before/After fix renderer, lifted out of App.jsx so it can be rendered
// and asserted on directly. One component serves Python, JavaScript,
// TypeScript, Go, Java, and Rust: it branches on whether a snippet carries the
// two labels, never on which language produced it.

// Every migration snippet in vulnerability_db.py labels its two halves with
// the same words, "Before:" and "After:" -- only the comment leader changes
// with the language (# in Python, // in Go, JavaScript, TypeScript, Java,
// and Rust).
// Matching the leader along with the label is what used to restrict the
// two-column split to Python and drop every Go/JS/TS finding into the single
// flat panel. Matching the label alone is what makes one renderer serve every
// language.
const BEFORE_MARKER = /^\s*(?:#|\/\/)\s*Before\b/;
const AFTER_MARKER = /^\s*(?:#|\/\/)\s*After\b/;

export function splitFixSnippet(snippet) {
  const lines = snippet.split("\n");
  const splitIndex = lines.findIndex((line) => AFTER_MARKER.test(line));
  if (splitIndex === -1) return null;
  // Advisory entries -- "AES-256 is already quantum-safe", the hashlib and
  // crypto-module notes -- carry neither label and are a single block of
  // guidance, not a migration. They keep the one-panel rendering on purpose.
  if (!lines.slice(0, splitIndex).some((line) => BEFORE_MARKER.test(line))) {
    return null;
  }
  return {
    before: lines.slice(0, splitIndex).join("\n").trim(),
    after: lines.slice(splitIndex).join("\n").trim(),
  };
}

function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text);
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  document.body.removeChild(textarea);
  return Promise.resolve();
}

export function CopyButton({ text, variant }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    copyText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button
      className={`copy-btn copy-${variant}`}
      type="button"
      onClick={handleCopy}
    >
      {copied ? "Copied!" : "Copy"}
    </button>
  );
}

export function FixPanels({ snippet }) {
  const parts = splitFixSnippet(snippet);
  if (!parts) {
    return (
      <div className="fix-panels">
        <div className="fix-panel fix-panel-neutral">
          <div className="fix-panel-header fix-header-neutral">
            <span className="fix-panel-title fix-title-neutral">
              Migration Pattern
            </span>
            <CopyButton text={snippet} variant="neutral" />
          </div>
          <pre className="fix-panel-body fix-body-neutral">{snippet}</pre>
        </div>
      </div>
    );
  }
  return (
    <div className="fix-panels">
      <div className="fix-panel fix-panel-before">
        <div className="fix-panel-header fix-header-before">
          <span className="fix-panel-title fix-title-before">
            Before (Vulnerable)
          </span>
          <CopyButton text={parts.before} variant="before" />
        </div>
        <pre className="fix-panel-body fix-body-before">{parts.before}</pre>
      </div>
      <div className="fix-panel fix-panel-after">
        <div className="fix-panel-header fix-header-after">
          <span className="fix-panel-title fix-title-after">
            After (Quantum-Safe)
          </span>
          <CopyButton text={parts.after} variant="after" />
        </div>
        <pre className="fix-panel-body fix-body-after">{parts.after}</pre>
      </div>
    </div>
  );
}

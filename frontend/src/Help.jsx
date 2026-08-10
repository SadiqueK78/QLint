import { useState } from "react";
import { ChevronIcon } from "./icons";

// Single-open accordion: opening an entry closes whatever else was open, so
// the page never turns into the wall of prose it replaced. State is the index
// of the open entry, or null -- one value rather than a map of booleans,
// because "one at a time" is the rule rather than a coincidence.

const FAQ = [
  {
    q: "How do I scan a repository?",
    a: [
      "Paste a public GitHub repository URL into the field on the home page and press Scan Repository. Nothing is installed and no account is required. QLint reads the repository through the GitHub API, analyses it in memory, and discards the source; only the report is kept.",
      "A scan covers Python, JavaScript, TypeScript, Go, Java, and Rust files. Everything else is skipped, along with vendored trees like node_modules and __pycache__.",
    ],
  },
  {
    q: "What does signing in unlock?",
    a: [
      "Scanning itself never needs an account. Signing in adds two things that require a scan saved against your name: My Scans, which keeps your past reports so you can reopen or delete them, and the HNDL Risk Calculator, which scores one of those saved reports.",
      "Signing in with GitHub also supplies the API credential automatically, so you no longer need to paste a personal access token. Anonymous scans still produce the full report, the AI features, and the SARIF download.",
    ],
  },
  {
    q: "What do Critical, Warning, Safe, and Info mean?",
    a: [
      "Critical means a quantum computer breaks the algorithm outright and it must be migrated: RSA, ECC, and Ed25519, along with MD5 and SHA-1, which are already broken classically.",
      "Warning means weakened rather than broken, such as AES-128 and SHA-256 against Grover's algorithm. Plan the migration, but there is no emergency. Safe means no action is needed. Info marks a line a human should look at where the scanner cannot decide alone, such as a bare hashlib import or an AES call whose key length is not visible on that line.",
    ],
  },
  {
    q: "What is the PQC Readiness Score?",
    a: [
      "It summarises the same findings as one number out of 100. The score starts at 100 and deducts 15 points for each critical finding and 7 for each warning; safe and info findings cost nothing, and it never falls below 0.",
      "Read it as a rough measure of migration distance, not a compliance grade. A large codebase calling one vulnerable algorithm from many places will score lower than a small one with exactly the same underlying problem.",
    ],
  },
  {
    q: "What is HNDL risk, and how do I use the calculator?",
    a: [
      "Harvest Now, Decrypt Later is the risk that somebody records your encrypted traffic today and decrypts it years from now, once a cryptographically relevant quantum computer exists. Whether that matters to you depends on how long your data stays worth reading, when such a machine arrives, and how long this codebase would take to migrate.",
      "The calculator sits below the results of a saved scan. Choose a data sensitivity profile and a CRQC timeline scenario, and it reports whether your data is exposed along with the years of exposure it derives from the findings in that scan. It needs a scan held under your account, so sign in before scanning or open one from My Scans.",
    ],
  },
  {
    q: "What does \"Explain with AI\" do?",
    a: [
      "It sends one finding to a language model and returns a short plain-language account of why that specific line is a problem and what replacing it would involve. The answer is grounded in the code QLint actually found rather than a generic description of the algorithm.",
      "Only the finding is sent: the algorithm, its severity, the recommended replacement, the file and line, and the single flagged line of source. Your repository is not uploaded. Answers are cached, so asking again about the same finding does not spend another model call.",
    ],
  },
  {
    q: "What does \"Generate Patch\" do, and is it safe to apply directly?",
    a: [
      "It produces a unified diff that migrates the flagged code to the recommended quantum-safe algorithm, which you can copy straight into your editor.",
      "Do not apply it unread. The diff is model-generated, the line numbers in its hunk header are approximate, and only you can tell whether the surrounding code and its callers survive the change. Treat it as a well-informed first draft, review it as you would any pull request from a stranger, and run your tests. The same caution appears under every generated patch in the results view.",
    ],
  },
  {
    q: "What is SARIF, and why would I download it?",
    a: [
      "SARIF is the Static Analysis Results Interchange Format, a standard file format that security tools use to describe findings. Because it is a standard, tools that have never heard of QLint can still read a QLint report.",
      "GitHub understands it natively: upload the file to a repository and the findings appear in that repository's Security tab, annotated on the exact lines that produced them. It is also the way to feed QLint results into dashboards, code review tooling, or anything else that consumes analysis output. The Download SARIF button on a results page produces the same file the CLI writes.",
    ],
  },
  {
    q: "How do I add a personal access token, and why would I need one?",
    a: [
      "A personal access token, or PAT, is a string GitHub issues that acts on your behalf when software talks to the API. QLint uses one for two reasons: to reach private repositories, which are invisible without it, and to lift the API rate limit, since unauthenticated requests are capped low enough that a handful of scans can exhaust them.",
      "Generate one on GitHub under Settings, then Developer settings, then Personal access tokens. A fine-grained token with read-only repository contents access is enough; a classic token needs the repo scope for private repositories or public_repo for public ones. Then press Add token on the home page and paste it in.",
      "The token is sent with that one scan request and never stored, so you will paste it again next time. Signing in with GitHub avoids that entirely, because the OAuth token QLint receives is used instead.",
    ],
  },
  {
    q: "How do I use QLint in CI?",
    a: [
      "The same scanners run outside the web app. qlint_cli.py is a standalone command-line scanner that walks a directory already on disk and needs no server, database, or credentials, and it emits the same SARIF the web app produces.",
      "A composite GitHub Action wraps it, so a workflow can scan on every push and pull request, fail the build on findings at or above a severity you choose, and upload the SARIF into the repository's Security tab. Flags, exclusion patterns, and a complete workflow example are in the Use QLint in CI section of the README.",
    ],
    link: {
      href: "https://github.com/Abhushan187/QLint#use-qlint-in-ci",
      label: "Read the CI setup guide",
    },
  },
];

function FaqItem({ entry, open, onToggle }) {
  return (
    <div className={`faq-item${open ? " faq-item-open" : ""}`}>
      <button
        className="faq-question"
        type="button"
        aria-expanded={open}
        onClick={onToggle}
      >
        <span className="faq-question-text">{entry.q}</span>
        <span className={`faq-chevron${open ? " faq-chevron-open" : ""}`}>
          <ChevronIcon />
        </span>
      </button>
      {open && (
        <div className="faq-answer">
          {entry.a.map((paragraph) => (
            <p className="faq-text" key={paragraph.slice(0, 40)}>
              {paragraph}
            </p>
          ))}
          {entry.link && (
            <a
              className="faq-link"
              href={entry.link.href}
              target="_blank"
              rel="noopener noreferrer"
            >
              {entry.link.label}
            </a>
          )}
        </div>
      )}
    </div>
  );
}

export default function Help() {
  const [openIndex, setOpenIndex] = useState(0);

  return (
    <div className="page page-doc">
      <div className="page-header">
        <h1 className="page-title">Help</h1>
        <p className="page-intro">
          Common questions about scanning, reading results, and the tools around
          them. QLint is free to use and needs no account to scan.
        </p>
      </div>

      <div className="faq-list">
        {FAQ.map((entry, index) => (
          <FaqItem
            key={entry.q}
            entry={entry}
            open={openIndex === index}
            onToggle={() => setOpenIndex(openIndex === index ? null : index)}
          />
        ))}
      </div>
    </div>
  );
}

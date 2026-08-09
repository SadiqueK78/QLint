import { useEffect, useState } from "react";
import "./App.css";
import PqcBenchmark from "./PqcBenchmark";
import { API_BASE } from "./api";

// The app is a single view-switcher, so "routing" here is just the two paths
// that have to be linkable from outside: the scanner and the public benchmark
// page. Vite serves index.html for both, so a direct visit works.
const HOME_PATH = "/";
const BENCHMARK_PATH = "/benchmark";
const SEVERITY_RANK = { critical: 0, warning: 1, safe: 2, info: 3 };
const FILTER_TABS = [
  { key: "all", label: "All Issues" },
  { key: "critical", label: "Critical" },
  { key: "warning", label: "Warning" },
  { key: "safe", label: "Safe" },
  { key: "info", label: "Info" },
];

const TOKEN_KEY = "qlint_token";
const GITHUB_LOGIN_URL = `${API_BASE}/auth/github/login`;

const startGithubOAuth = () => {
  window.location.href = GITHUB_LOGIN_URL;
};

function repoNameFromUrl(url) {
  const match = url.match(/github\.com\/([^/]+)\/([^/#?]+)/);
  if (!match) return url;
  return `${match[1]}/${match[2].replace(/\.git$/, "")}`;
}

function truncateEmail(email, max = 20) {
  if (!email || email.length <= max) return email;
  return `${email.slice(0, max - 3)}...`;
}

function relativeTime(iso) {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "recently";
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function formatDateTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  const day = date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
  const time = date.toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
  });
  return `${day} at ${time}`;
}

/** Open the files that hold something worth acting on. */
function expandedFromResult(data) {
  const expanded = {};
  for (const [file, findings] of Object.entries(data.findings_by_file || {})) {
    expanded[file] = findings.some(
      (f) => f.severity === "critical" || f.severity === "warning"
    );
  }
  return expanded;
}

function Logo({ onNavigate }) {
  return (
    <a
      href={HOME_PATH}
      className="logo"
      onClick={(e) => {
        e.preventDefault();
        onNavigate(HOME_PATH);
      }}
    >
      <svg width="32" height="32" viewBox="0 0 32 32" aria-hidden="true">
        <polygon
          points="28,16 22,26.39 10,26.39 4,16 10,5.61 22,5.61"
          fill="none"
          stroke="#FFFFFF"
          strokeWidth="1.5"
        />
        <circle
          cx="16"
          cy="15.5"
          r="5.5"
          fill="none"
          stroke="#FFFFFF"
          strokeWidth="1.5"
        />
        <line
          x1="19.6"
          y1="19.2"
          x2="23"
          y2="22.6"
          stroke="#FFFFFF"
          strokeWidth="1.5"
          strokeLinecap="round"
        />
      </svg>
      <span className="logo-text">QLint</span>
    </a>
  );
}

function ThemeToggle({ theme, onToggle, extraClass = "" }) {
  return (
    <button
      className={`theme-toggle ${extraClass}`.trim()}
      type="button"
      onClick={onToggle}
      aria-label="Toggle theme"
    >
      {theme === "light" ? (
        <svg
          width="18"
          height="18"
          viewBox="0 0 24 24"
          fill="none"
          stroke="#FFFFFF"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
        </svg>
      ) : (
        <svg
          width="18"
          height="18"
          viewBox="0 0 24 24"
          fill="none"
          stroke="#00FF41"
          strokeWidth="1.5"
          strokeLinecap="round"
        >
          <circle cx="12" cy="12" r="4" />
          <line x1="12" y1="2" x2="12" y2="4.5" />
          <line x1="12" y1="19.5" x2="12" y2="22" />
          <line x1="2" y1="12" x2="4.5" y2="12" />
          <line x1="19.5" y1="12" x2="22" y2="12" />
          <line x1="5" y1="5" x2="6.8" y2="6.8" />
          <line x1="17.2" y1="17.2" x2="19" y2="19" />
          <line x1="5" y1="19" x2="6.8" y2="17.2" />
          <line x1="17.2" y1="6.8" x2="19" y2="5" />
        </svg>
      )}
    </button>
  );
}

function PersonIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="#FFFFFF"
      strokeWidth="1.5"
      strokeLinecap="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="8" r="3.5" />
      <path d="M4.5 20a7.5 7.5 0 0 1 15 0" />
    </svg>
  );
}

/** Simple geometric octocat: round head, two ears, a tentacle stub. */
function GitHubIcon({ stroke = "#FFFFFF", size = 16 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={stroke}
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="7.5" />
      <path d="M7 5.5 L6 2.5 L9 4" />
      <path d="M17 5.5 L18 2.5 L15 4" />
      <path d="M9.5 21.5 v-3 a2.5 2.5 0 0 1 5 0 v3" />
    </svg>
  );
}

function Toast({ message }) {
  return <div className="toast">{message}</div>;
}

function Navbar({
  theme,
  onToggleTheme,
  user,
  onLogin,
  onSignup,
  onLogout,
  onShowHistory,
  onShowAdmin,
  onDisconnectGithub,
  route,
  onNavigate,
}) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const closeSidebar = () => setSidebarOpen(false);
  return (
    <header className="navbar">
      <div className="navbar-inner">
        <div className="navbar-left">
          <button
            className="hamburger"
            type="button"
            aria-label="Menu"
            onClick={() => setSidebarOpen((prev) => !prev)}
          >
            <span className="hamburger-line" />
            <span className="hamburger-line" />
            <span className="hamburger-line" />
          </button>
          <Logo onNavigate={onNavigate} />
        </div>
        <div className="nav-actions">
          <ThemeToggle theme={theme} onToggle={onToggleTheme} />
          <a
            className={`nav-btn${
              route === BENCHMARK_PATH ? " nav-btn-active" : ""
            }`}
            href={BENCHMARK_PATH}
            onClick={(e) => {
              e.preventDefault();
              onNavigate(BENCHMARK_PATH);
            }}
          >
            PQC Benchmark Lab
          </a>
          <a
            className="nav-btn"
            href="https://github.com/Abhushan187/QLint"
            target="_blank"
            rel="noreferrer"
          >
            GitHub
          </a>
          {user ? (
            <>
              <span className="nav-user" title={user.email}>
                <PersonIcon />
                <span className="nav-user-email">
                  {truncateEmail(user.email)}
                </span>
              </span>
              {user.github_connected ? (
                <span className="gh-status" title={user.github_username ?? ""}>
                  <span className="gh-status-label">GitHub Connected</span>
                  <button
                    className="gh-disconnect"
                    type="button"
                    onClick={onDisconnectGithub}
                  >
                    Disconnect
                  </button>
                </span>
              ) : (
                <button
                  className="nav-btn nav-btn-icon"
                  type="button"
                  onClick={startGithubOAuth}
                >
                  <GitHubIcon />
                  Connect GitHub
                </button>
              )}
              <button
                className="nav-btn"
                type="button"
                onClick={onShowHistory}
              >
                My Scans
              </button>
              {user.role === "admin" && (
                <button
                  className="nav-btn"
                  type="button"
                  onClick={onShowAdmin}
                >
                  Admin
                </button>
              )}
              <button className="nav-btn" type="button" onClick={onLogout}>
                Log out
              </button>
            </>
          ) : (
            <>
              <button className="nav-btn" type="button" onClick={onLogin}>
                Log in
              </button>
              <button className="nav-btn" type="button" onClick={onSignup}>
                Sign up
              </button>
            </>
          )}
        </div>
      </div>
      {sidebarOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setSidebarOpen(false)}
        />
      )}
      <nav className={`sidebar${sidebarOpen ? " sidebar-open" : ""}`}>
        <a
          className="sidebar-item"
          href={BENCHMARK_PATH}
          onClick={(e) => {
            e.preventDefault();
            closeSidebar();
            onNavigate(BENCHMARK_PATH);
          }}
        >
          PQC Benchmark Lab
        </a>
        <a
          className="sidebar-item"
          href="https://github.com/Abhushan187/QLint"
          target="_blank"
          rel="noreferrer"
        >
          GitHub
        </a>
        {user ? (
          <>
            <span className="sidebar-item" title={user.email}>
              {truncateEmail(user.email)}
            </span>
            <button
              className="sidebar-item"
              type="button"
              onClick={() => {
                closeSidebar();
                onShowHistory();
              }}
            >
              My Scans
            </button>
            {user.role === "admin" && (
              <button
                className="sidebar-item"
                type="button"
                onClick={() => {
                  closeSidebar();
                  onShowAdmin();
                }}
              >
                Admin
              </button>
            )}
            {/* .nav-btn and .gh-status are hidden on mobile, so the GitHub
                connection is managed from here instead. */}
            <button
              className="sidebar-item"
              type="button"
              onClick={() => {
                closeSidebar();
                if (user.github_connected) onDisconnectGithub();
                else startGithubOAuth();
              }}
            >
              {user.github_connected ? "Disconnect GitHub" : "Connect GitHub"}
            </button>
            <button
              className="sidebar-item"
              type="button"
              onClick={() => {
                closeSidebar();
                onLogout();
              }}
            >
              Log out
            </button>
          </>
        ) : (
          <>
            <button
              className="sidebar-item"
              type="button"
              onClick={() => {
                closeSidebar();
                onLogin();
              }}
            >
              Log in
            </button>
            <button
              className="sidebar-item"
              type="button"
              onClick={() => {
                closeSidebar();
                onSignup();
              }}
            >
              Sign up
            </button>
          </>
        )}
      </nav>
    </header>
  );
}

function Hero() {
  return (
    <section className="hero">
      <div className="hero-inner">
        <div className="hero-badge">
          <span className="dot dot-safe" />
          <span>PQC &amp; Cryptography Security Scanner</span>
        </div>
        <h1>Is your codebase quantum-ready? Find out in seconds.</h1>
        <p className="hero-sub">
          QLint scans your codebase for quantum-vulnerable cryptographic
          algorithms and generates a NIST PQC 2024 compliant migration report.
        </p>
      </div>
    </section>
  );
}

function RateLimitBar({ rateLimit, statusFailed }) {
  if (statusFailed) {
    return (
      <div className="rate-bar">
        <span className="rate-text">GitHub API status unavailable</span>
      </div>
    );
  }
  if (!rateLimit) {
    return (
      <div className="rate-bar">
        <span className="rate-text">Checking GitHub API status...</span>
      </div>
    );
  }
  const { remaining, reset_at } = rateLimit;
  const dotClass =
    remaining > 500 ? "dot-safe" : remaining >= 100 ? "dot-warning" : "dot-critical";
  return (
    <div className="rate-bar-wrap">
      <div className="rate-bar">
        <span className={`dot dot-8 ${dotClass}`} />
        <span className="rate-text">
          GitHub API: {remaining} requests remaining
        </span>
      </div>
      {remaining < 100 && (
        <p className="rate-warning">
          Rate limit too low. Resets at {reset_at}. Add a GitHub token above
          for higher limits.
        </p>
      )}
    </div>
  );
}

function ScanInputCard({
  repoUrl,
  setRepoUrl,
  githubToken,
  setGithubToken,
  tokenVisible,
  setTokenVisible,
  urlError,
  rateLimit,
  statusFailed,
  scanning,
  onScan,
  error,
  onClearError,
  user,
}) {
  const rateTooLow = rateLimit != null && rateLimit.remaining < 100;
  // A connected GitHub account supplies the credential, so the manual token
  // field is redundant.
  const usingConnectedGithub = !!user?.github_connected;
  return (
    <section className="scan-section" id="scan-input">
      <div className="scan-card">
        <div className="scan-label">Enter GitHub repository URL</div>
        <div className="scan-row">
          <input
            className="scan-input"
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onScan();
            }}
            placeholder="https://github.com/username/repository"
          />
          {!usingConnectedGithub && (
            <button
              className="token-toggle"
              type="button"
              onClick={() => setTokenVisible(!tokenVisible)}
            >
              {tokenVisible ? "Hide token" : "Add token"}
            </button>
          )}
          <button
            className="scan-btn"
            type="button"
            onClick={onScan}
            disabled={scanning || rateTooLow}
          >
            Scan Repository
          </button>
        </div>
        {urlError && <p className="url-error">{urlError}</p>}
        {usingConnectedGithub && (
          <p className="gh-using-note">
            Using your connected GitHub account for API access
          </p>
        )}
        {tokenVisible && !usingConnectedGithub && (
          <div className="token-section">
            <div className="token-label">GitHub Personal Access Token</div>
            <input
              className="scan-input token-input"
              type="password"
              value={githubToken}
              onChange={(e) => setGithubToken(e.target.value)}
              placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
            />
            <p className="token-note">
              Your token is used only for this request and never stored.
              Required for private repos and higher rate limits.
            </p>
          </div>
        )}
        <RateLimitBar rateLimit={rateLimit} statusFailed={statusFailed} />
      </div>
      {error && (
        <div className="error-card">
          <div className="error-title">Scan failed</div>
          <div className="error-message">{error}</div>
          <button className="error-retry" type="button" onClick={onClearError}>
            Try again
          </button>
        </div>
      )}
      <p className="privacy-note">
        We only read public repositories. Your code is never stored on our
        servers.
      </p>
    </section>
  );
}

function LanguagesStrip() {
  const active = ["Python", "JavaScript", "TypeScript", "Go"];
  const comingSoon = ["Java", "Rust"];
  return (
    <section className="langs">
      <div className="langs-inner">
        <div className="langs-label">Supported Languages</div>
        <div className="langs-row">
          {active.map((name) => (
            <span className="lang-pill lang-active" key={name}>
              {name}
              <span className="lang-tag tag-active">Active</span>
            </span>
          ))}
          {comingSoon.map((name) => (
            <span className="lang-pill lang-soon" key={name}>
              {name}
              <span className="lang-tag tag-soon">Coming Soon</span>
            </span>
          ))}
        </div>
        <p className="langs-desc">
          More languages are in active development. Python, JavaScript,
          TypeScript, and Go scanning are available now.
        </p>
      </div>
    </section>
  );
}

const PRICING_PLANS = [
  {
    name: "Free",
    price: "$0",
    period: "forever",
    features: [
      "5 repository scans",
      "Python codebase support",
      "NIST PQC migration report",
      "Standard fix snippets",
    ],
    cta: "Get started",
    highlighted: false,
  },
  {
    name: "Developer",
    price: "$9",
    period: "/ month",
    features: [
      "20 repository scans / month",
      "Python codebase support",
      "NIST PQC migration report",
      "Standard fix snippets",
      "Scan history",
    ],
    cta: "Start free trial",
    highlighted: false,
  },
  {
    name: "Team",
    price: "$29",
    period: "/ month",
    features: [
      "100 repository scans / month",
      "Python + JS/TS support (Q4 2026)",
      "NIST PQC migration report",
      "Standard fix snippets",
      "Scan history + team dashboard",
      "Priority support",
    ],
    cta: "Get started",
    highlighted: true,
  },
  {
    name: "Enterprise",
    price: "$79",
    period: "/ month",
    features: [
      "Unlimited repository scans",
      "All supported languages",
      "NIST PQC migration report",
      "AI context-aware patches (coming soon)",
      "Admin dashboard + usage analytics",
      "GitHub App integration",
      "Dedicated support",
    ],
    cta: "Contact us",
    highlighted: false,
  },
];

function Pricing() {
  return (
    <section className="pricing">
      <div className="pricing-inner">
        <h2>Simple, transparent pricing</h2>
        <p className="pricing-sub">Start free. Scale as you grow.</p>
        <div className="pricing-cards">
        {PRICING_PLANS.map((plan) => (
          <div
            className={`price-card${plan.highlighted ? " price-popular" : ""}`}
            key={plan.name}
          >
            {plan.highlighted && (
              <span className="popular-badge">Most Popular</span>
            )}
            <div className="plan-name">{plan.name}</div>
            <div className="plan-price">{plan.price}</div>
            <div className="plan-period">{plan.period}</div>
            <div className="plan-divider" />
            <div className="plan-features">
              {plan.features.map((feature) => (
                <div key={feature}>{feature}</div>
              ))}
            </div>
            <button
              className={plan.highlighted ? "cta-navy" : "cta-ghost"}
              type="button"
            >
              {plan.cta}
            </button>
          </div>
        ))}
        </div>
      </div>
    </section>
  );
}

function ScanningView({ repoUrl }) {
  return (
    <div className="scanning-wrap">
      <div className="scanning-card">
        <div className="scanning-label">Scanning repository</div>
        <div className="scanning-repo">{repoNameFromUrl(repoUrl)}</div>
        <div className="progress">
          <div className="progress-inner" />
        </div>
        <p className="scanning-status">Fetching repository files...</p>
        <p className="scanning-note">
          This typically takes 10 to 30 seconds depending on repository size.
        </p>
      </div>
    </div>
  );
}

function scoreClass(score) {
  if (score < 40) return "score-critical";
  if (score < 70) return "score-warning";
  return "score-safe";
}

function buildReportText(result) {
  const date = new Date().toISOString().slice(0, 10);
  const lines = [
    "QLint PQC Migration Report",
    `Repository: ${result.repo}`,
    `Scan date: ${date}`,
    `PQC Readiness Score: ${result.pqc_readiness_score} / 100`,
    `Files scanned: ${result.scanned_files}`,
    `Total findings: ${result.total_findings}`,
    "",
  ];
  for (const findings of Object.values(result.findings_by_file)) {
    for (const f of findings) {
      lines.push(
        `FILE: ${f.file} | LINE: ${f.line} | ALGORITHM: ${f.algorithm} | ` +
          `SEVERITY: ${f.severity} | REPLACEMENT: ${f.replacement ?? "None"}`
      );
      lines.push("");
    }
  }
  return lines.join("\n");
}

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function reportFilename(result, extension) {
  const date = new Date().toISOString().slice(0, 10);
  return `qlint-report-${result.repo.replace("/", "-")}-${date}.${extension}`;
}

function downloadReport(result) {
  const blob = new Blob([buildReportText(result)], { type: "text/plain" });
  saveBlob(blob, reportFilename(result, "txt"));
}

// SARIF is built server-side so the rule catalog and severity mapping stay in
// one place. A signed-in user's scan has an id to address; an anonymous one
// does not, so that path asks the scan endpoint to render the cached result
// as SARIF instead.
async function downloadSarif(result, authToken) {
  const response =
    result.scan_id && authToken
      ? await fetch(`${API_BASE}/user/scans/${result.scan_id}/sarif`, {
          headers: { Authorization: `Bearer ${authToken}` },
        })
      : await fetch(`${API_BASE}/scan?format=sarif`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ repo_url: `https://github.com/${result.repo}` }),
        });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.detail || `HTTP ${response.status}`);
  }
  saveBlob(await response.blob(), reportFilename(result, "sarif"));
}

function splitFixSnippet(snippet) {
  const lines = snippet.split("\n");
  const splitIndex = lines.findIndex((line) => {
    const trimmed = line.trim();
    return trimmed.startsWith("# After:") || trimmed.startsWith("# After ");
  });
  if (splitIndex === -1) return null;
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

// Only the fields the backend actually reads get sent. That includes the
// flagged line (code_snippet) and the suggested fix (fix_snippet): without
// them the model can only describe the algorithm in the abstract, which is
// the one thing its prompt tells it not to do.
//
// /scan/explain and /scan/patch take the same shape, so one builder serves
// both. The two snippets are merely important to an explanation but required
// by a patch, which refuses with a 400 rather than invent a diff against code
// it was never shown.
function findingRequestBody(finding) {
  return {
    algorithm: finding.algorithm,
    severity: finding.severity,
    attack_vector: finding.attack_vector,
    replacement: finding.replacement,
    replacement_reason: finding.replacement_reason,
    identifier: finding.identifier,
    match_type: finding.match_type,
    language: finding.language,
    quantum_vulnerable: finding.quantum_vulnerable,
    classical_vulnerable: finding.classical_vulnerable,
    file: finding.file,
    line: finding.line,
    code_snippet: finding.code_snippet,
    fix_snippet: finding.fix_snippet,
  };
}

function CopyButton({ text, variant }) {
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

function FixPanels({ snippet }) {
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

function ExplainBody({ loading, error, explanation, onRetry }) {
  return (
    <div className="explain-body">
      {loading && (
        <p className="explain-loading">
          {"Asking the model about this finding\u2026"}
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

// A unified diff is only readable if the three line kinds are told apart at a
// glance, so each line is classed by its first character -- the same signal
// the diff format itself uses. Everything else (file headers, hunk headers)
// is chrome around those.
function diffLineClass(line) {
  if (line.startsWith("+++") || line.startsWith("---")) return "diff-file";
  if (line.startsWith("@@")) return "diff-hunk";
  if (line.startsWith("+")) return "diff-add";
  if (line.startsWith("-")) return "diff-del";
  return "diff-ctx";
}

function DiffView({ patch }) {
  return (
    <pre className="diff-body">
      {patch.split("\n").map((line, index) => (
        // Lines have no identity of their own and the list never reorders,
        // so the index is the honest key here.
        <span className={`diff-line ${diffLineClass(line)}`} key={index}>
          {line || " "}
        </span>
      ))}
    </pre>
  );
}

function PatchBody({ loading, error, patch, model, cached, onRetry }) {
  return (
    <div className="patch-body">
      {loading && (
        <p className="explain-loading">
          {"Generating a migration patch for this finding…"}
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
      {!loading && !error && patch && (
        <div className="patch-panel">
          <div className="patch-header">
            <span className="fix-panel-title patch-title">
              Migration Patch
            </span>
            <div className="patch-header-right">
              {model && <span className="patch-model">{model}</span>}
              {cached && <span className="patch-cached">cached</span>}
              <CopyButton text={patch} variant="neutral" />
            </div>
          </div>
          <DiffView patch={patch} />
          <p className="patch-note">
            AI-generated. Review the diff before applying it &mdash; line
            numbers in the hunk header are approximate.
          </p>
        </div>
      )}
    </div>
  );
}

function FindingRow({ finding, fixKey, fixExpanded, onToggleFix }) {
  const [explainOpen, setExplainOpen] = useState(false);
  const [explainLoading, setExplainLoading] = useState(false);
  const [explainError, setExplainError] = useState(null);
  const [explanation, setExplanation] = useState(null);
  const [patchOpen, setPatchOpen] = useState(false);
  const [patchLoading, setPatchLoading] = useState(false);
  const [patchError, setPatchError] = useState(null);
  const [patch, setPatch] = useState(null);

  // /scan/patch requires both snippets and 400s without them. Every scanner
  // emits both today, so this only ever guards against a finding that reached
  // the UI from somewhere else -- cheaper than spending a request to be told.
  const canPatch = !!(finding.code_snippet && finding.fix_snippet);

  const fetchExplanation = async () => {
    setExplainLoading(true);
    setExplainError(null);
    try {
      const res = await fetch(`${API_BASE}/scan/explain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(findingRequestBody(finding)),
      });
      const body = await res.json().catch(() => null);
      if (!res.ok) throw new Error(body?.detail || `HTTP ${res.status}`);
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

  const fetchPatch = async () => {
    setPatchLoading(true);
    setPatchError(null);
    try {
      const res = await fetch(`${API_BASE}/scan/patch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(findingRequestBody(finding)),
      });
      const body = await res.json().catch(() => null);
      if (!res.ok) throw new Error(body?.detail || `HTTP ${res.status}`);
      setPatch({
        diff: body.patch,
        model: body.model,
        cached: body.cached,
      });
    } catch (err) {
      setPatchError(err.message || "Could not generate a patch.");
    } finally {
      setPatchLoading(false);
    }
  };

  const togglePatch = () => {
    if (patchOpen) {
      setPatchOpen(false);
      return;
    }
    setPatchOpen(true);
    // The patch is kept once fetched, so reopening the panel is free.
    if (!patch && !patchLoading) fetchPatch();
  };

  const retryPatch = () => {
    setPatch(null);
    fetchPatch();
  };

  return (
    <div className="finding">
      <div className="finding-top">
        <div className="finding-title">
          <span className={`sev-badge sev-${finding.severity}`}>
            {finding.severity}
          </span>
          <span className="finding-algo">{finding.algorithm}</span>
        </div>
        <span className="finding-line">
          Line {finding.line}:{finding.col}
        </span>
      </div>
      {finding.attack_vector != null && (
        <p className="finding-vector">
          Attack vector: {finding.attack_vector}
        </p>
      )}
      {finding.replacement != null && (
        <p className="finding-replacement">
          <span className="finding-replacement-label">Replace with:</span>{" "}
          {finding.replacement}
        </p>
      )}
      <p className="finding-reason">{finding.replacement_reason}</p>
      <div className="finding-actions">
        <button
          className="fix-toggle"
          type="button"
          onClick={() => onToggleFix(fixKey)}
        >
          {fixExpanded ? "Hide fix" : "Show fix"}
        </button>
        <button
          className="fix-toggle explain-toggle"
          type="button"
          onClick={toggleExplain}
          disabled={explainLoading}
        >
          {explainLoading
            ? "Explaining\u2026"
            : explainOpen
            ? "Hide explanation"
            : "Explain with AI"}
        </button>
        {canPatch && (
          <button
            className="fix-toggle patch-toggle"
            type="button"
            onClick={togglePatch}
            disabled={patchLoading}
          >
            {patchLoading
              ? "Generating…"
              : patchOpen
              ? "Hide patch"
              : "Generate Patch"}
          </button>
        )}
      </div>
      {fixExpanded && <FixPanels snippet={finding.fix_snippet} />}
      {explainOpen && (
        <ExplainBody
          loading={explainLoading}
          error={explainError}
          explanation={explanation}
          onRetry={retryExplain}
        />
      )}
      {patchOpen && (
        <PatchBody
          loading={patchLoading}
          error={patchError}
          patch={patch?.diff}
          model={patch?.model}
          cached={patch?.cached}
          onRetry={retryPatch}
        />
      )}
    </div>
  );
}

function HndlCalculator({ scanId, authToken }) {
  const [open, setOpen] = useState(false);
  const [profiles, setProfiles] = useState(null);
  const [sensitivity, setSensitivity] = useState("personal_data");
  const [scenario, setScenario] = useState("moderate");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [risk, setRisk] = useState(null);

  const available = !!scanId && !!authToken;

  // Options are fetched from the backend rather than mirrored here, so the
  // shelf-life and CRQC numbers only ever live in hndl_calculator.py.
  useEffect(() => {
    if (!open || profiles) return;
    fetch(`${API_BASE}/hndl/profiles`)
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(setProfiles)
      .catch(() => setError("Could not load calculator options."));
  }, [open, profiles]);

  const calculate = async () => {
    if (!available) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/hndl/calculate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          scan_id: scanId,
          data_sensitivity: sensitivity,
          crqc_scenario: scenario,
        }),
      });
      const body = await res.json().catch(() => null);
      if (!res.ok) throw new Error(body?.detail || `HTTP ${res.status}`);
      setRisk(body);
    } catch (err) {
      setRisk(null);
      setError(err.message || "Could not calculate HNDL risk.");
    } finally {
      setLoading(false);
    }
  };

  const sensitivityOptions = Object.entries(
    profiles?.data_sensitivity_profiles || {}
  );
  const scenarioOptions = Object.entries(profiles?.crqc_scenarios || {});

  return (
    <div className="file-section hndl-section">
      <div
        className={`file-header${open ? " file-header-open" : ""}`}
        onClick={() => setOpen((prev) => !prev)}
      >
        <span className="hndl-title">HNDL Risk Calculator</span>
        <span className="file-header-right">
          <span className="file-badge">Harvest Now, Decrypt Later</span>
          <span className={`chevron${open ? " chevron-open" : ""}`}>v</span>
        </span>
      </div>
      {open && (
        <div className="file-body hndl-body">
          <p className="hndl-intro">
            An adversary can record encrypted traffic today and decrypt it once
            a cryptographically relevant quantum computer (CRQC) exists. Whether
            that matters here depends on how long your data stays valuable,
            when a CRQC arrives, and how long this codebase takes to migrate.
          </p>

          {!available ? (
            <div className="hndl-note">
              This calculator runs against a saved scan. Sign in before scanning,
              or open a scan from My Scans, and it will score that result.
            </div>
          ) : (
            <>
              <div className="hndl-controls">
                <label className="hndl-field">
                  <span className="hndl-label">Data Sensitivity</span>
                  <select
                    className="hndl-select"
                    value={sensitivity}
                    onChange={(e) => setSensitivity(e.target.value)}
                    disabled={!profiles}
                  >
                    {sensitivityOptions.map(([key, profile]) => (
                      <option value={key} key={key}>
                        {profile.label} ({profile.shelf_life_years} yr shelf life)
                      </option>
                    ))}
                  </select>
                </label>
                <label className="hndl-field">
                  <span className="hndl-label">CRQC Timeline Scenario</span>
                  <select
                    className="hndl-select"
                    value={scenario}
                    onChange={(e) => setScenario(e.target.value)}
                    disabled={!profiles}
                  >
                    {scenarioOptions.map(([key, option]) => (
                      <option value={key} key={key}>
                        {option.label} ({option.years_from_now} yr)
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  className="btn-primary btn-small hndl-btn"
                  type="button"
                  onClick={calculate}
                  disabled={loading || !profiles}
                >
                  {loading ? "Calculating..." : "Calculate Risk"}
                </button>
              </div>

              {error && <div className="hndl-error">{error}</div>}

              {risk && (
                <div className="hndl-result">
                  <div
                    className={`hndl-verdict ${
                      risk.exposed ? "hndl-exposed" : "hndl-clear"
                    }`}
                  >
                    <div className="hndl-verdict-main">
                      <span className="hndl-status">
                        {risk.exposed ? "Exposed" : "Not Exposed"}
                      </span>
                      <span className="hndl-status-sub">
                        {risk.data_sensitivity_label}
                      </span>
                    </div>
                    <div className="hndl-metrics">
                      <div className="hndl-metric">
                        <span className="hndl-metric-value">
                          {risk.risk_window_years}
                        </span>
                        <span className="hndl-metric-label">
                          risk window (yr)
                        </span>
                      </div>
                      <div className="hndl-metric">
                        <span className="hndl-metric-value">
                          {risk.shelf_life_years}
                        </span>
                        <span className="hndl-metric-label">
                          data shelf life (yr)
                        </span>
                      </div>
                      <div className="hndl-metric">
                        <span className="hndl-metric-value">
                          {risk.migration_time_years}
                        </span>
                        <span className="hndl-metric-label">
                          est. migration (yr)
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="hndl-prose">
                    <div className="hndl-prose-label">Verdict</div>
                    <p>{risk.verdict}</p>
                  </div>
                  <div className="hndl-prose">
                    <div className="hndl-prose-label">Recommendation</div>
                    <p>{risk.recommendation}</p>
                  </div>

                  <div className="hndl-prose-label">
                    How much the verdict rests on the CRQC estimate
                  </div>
                  <table className="hndl-table">
                    <thead>
                      <tr>
                        <th>CRQC scenario</th>
                        <th>Risk window</th>
                        <th>Exposed</th>
                      </tr>
                    </thead>
                    <tbody>
                      {risk.all_scenarios.map((row) => (
                        <tr
                          key={row.scenario}
                          className={
                            row.scenario === risk.crqc_scenario
                              ? "hndl-row-active"
                              : undefined
                          }
                        >
                          <td>{row.label || row.scenario}</td>
                          <td>{row.risk_window_years} yr</td>
                          <td
                            className={
                              row.exposed ? "hndl-yes" : "hndl-no"
                            }
                          >
                            {row.exposed ? "Yes" : "No"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function ResultsView({
  result,
  activeFilter,
  setActiveFilter,
  expandedFiles,
  setExpandedFiles,
  expandedFixes,
  setExpandedFixes,
  onReset,
  onRescan,
  authToken,
}) {
  const allFindings = Object.values(result.findings_by_file).flat();

  // Highest severity seen per algorithm, for pill coloring
  const algoSeverity = {};
  for (const f of allFindings) {
    const current = algoSeverity[f.algorithm];
    if (
      current === undefined ||
      SEVERITY_RANK[f.severity] < SEVERITY_RANK[current]
    ) {
      algoSeverity[f.algorithm] = f.severity;
    }
  }

  const tabCounts = {
    all: result.total_findings,
    critical: result.severity_summary.critical,
    warning: result.severity_summary.warning,
    safe: result.severity_summary.safe,
    info: result.severity_summary.info,
  };

  const visibleFiles = Object.entries(result.findings_by_file)
    .map(([file, findings]) => [
      file,
      activeFilter === "all"
        ? findings
        : findings.filter((f) => f.severity === activeFilter),
    ])
    .filter(([, findings]) => findings.length > 0);

  const [sarifBusy, setSarifBusy] = useState(false);
  const [sarifError, setSarifError] = useState(null);

  const getSarif = async () => {
    setSarifBusy(true);
    setSarifError(null);
    try {
      await downloadSarif(result, authToken);
    } catch (err) {
      setSarifError(err.message || "Could not build the SARIF file.");
    } finally {
      setSarifBusy(false);
    }
  };

  const toggleFile = (file) =>
    setExpandedFiles((prev) => ({ ...prev, [file]: !prev[file] }));
  const toggleFix = (key) =>
    setExpandedFixes((prev) => ({ ...prev, [key]: !prev[key] }));

  return (
    <div className="results">
      <div className="results-header">
        <div>
          <div className="results-repo">{result.repo}</div>
          {result.cached && (
            <div className="cached-row">
              <span className="cached-pill">
                Cached result from {relativeTime(result.cached_at)}
              </span>
              <button className="rescan-btn" type="button" onClick={onRescan}>
                Re-scan
              </button>
            </div>
          )}
          <div className="results-meta">
            Scanned {result.scanned_files} files in{" "}
            {result.scan_duration_seconds}s
          </div>
        </div>
        <div className="results-actions-wrap">
          <div className="results-actions">
            <button
              className="btn-ghost btn-small"
              type="button"
              onClick={() => downloadReport(result)}
            >
              Download Report
            </button>
            <button
              className="btn-ghost btn-small"
              type="button"
              onClick={getSarif}
              disabled={sarifBusy}
              title="SARIF 2.1.0, for GitHub Code Scanning and SARIF viewers"
            >
              {sarifBusy ? "Building SARIF..." : "Download SARIF"}
            </button>
            <button
              className="btn-primary btn-small"
              type="button"
              onClick={onReset}
            >
              Scan Another Repository
            </button>
          </div>
          {sarifError && <div className="sarif-error">{sarifError}</div>}
        </div>
      </div>

      <div className="score-row">
        <div className="score-card">
          <div className="card-label">PQC Readiness Score</div>
          <div
            className={`score-value ${scoreClass(result.pqc_readiness_score)}`}
          >
            {result.pqc_readiness_score}
          </div>
          <div className="score-out-of">out of 100</div>
        </div>
        {["critical", "warning", "safe", "info"].map((sev) => (
          <div className={`sum-card sum-${sev}`} key={sev}>
            <div className="card-label">{sev}</div>
            <div className="sum-count">{result.severity_summary[sev]}</div>
          </div>
        ))}
      </div>

      {result.algorithms_found.length > 0 && (
        <>
          <div className="algo-label">Algorithms Detected</div>
          <div className="algo-row">
            {result.algorithms_found.map((algo) => (
              <span
                className={`algo-pill pill-${algoSeverity[algo] ?? "info"}`}
                key={algo}
              >
                {algo}
              </span>
            ))}
          </div>
        </>
      )}

      <HndlCalculator scanId={result.scan_id} authToken={authToken} />

      {result.total_findings === 0 ? (
        <div className="empty-state">
          <div className="empty-heading">
            No quantum-vulnerable algorithms detected.
          </div>
          <p className="empty-sub">
            This repository appears PQC-ready based on NIST 2024 standards.
          </p>
        </div>
      ) : (
        <>
          <div className="tabs">
            {FILTER_TABS.map((tab) => (
              <button
                key={tab.key}
                type="button"
                className={`tab${activeFilter === tab.key ? " tab-active" : ""}`}
                onClick={() => setActiveFilter(tab.key)}
              >
                {tab.label} ({tabCounts[tab.key]})
              </button>
            ))}
          </div>

          {visibleFiles.length === 0 ? (
            <div className="no-findings">No {activeFilter} findings.</div>
          ) : (
            visibleFiles.map(([file, findings]) => {
              const expanded = !!expandedFiles[file];
              const hasCritical = findings.some(
                (f) => f.severity === "critical"
              );
              return (
                <div className="file-section" key={file}>
                  <div
                    className={`file-header${expanded ? " file-header-open" : ""}`}
                    onClick={() => toggleFile(file)}
                  >
                    <span className="file-name">{file}</span>
                    <span className="file-header-right">
                      <span
                        className={`file-badge${
                          hasCritical ? " file-badge-critical" : ""
                        }`}
                      >
                        {findings.length}
                      </span>
                      <span
                        className={`chevron${expanded ? " chevron-open" : ""}`}
                      >
                        v
                      </span>
                    </span>
                  </div>
                  {expanded && (
                    <div className="file-body">
                      {findings.map((finding, i) => {
                        const fixKey = `${file}:${finding.line}:${i}`;
                        return (
                          <FindingRow
                            key={fixKey}
                            finding={finding}
                            fixKey={fixKey}
                            fixExpanded={!!expandedFixes[fixKey]}
                            onToggleFix={toggleFix}
                          />
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </>
      )}
    </div>
  );
}

function AuthModal({ mode, loading, error, onSubmit, onClose, onSwitch }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const isSignup = mode === "signup";

  const submit = () => {
    if (loading) return;
    onSubmit(email.trim(), password);
  };

  return (
    <div
      className="modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="auth-modal">
        <button
          className="auth-close"
          type="button"
          onClick={onClose}
          aria-label="Close"
        >
          X
        </button>
        <div className="auth-title">
          {isSignup ? "Create account" : "Welcome back"}
        </div>
        <p className="auth-sub">
          {isSignup
            ? "Start scanning for quantum vulnerabilities"
            : "Sign in to your QLint account"}
        </p>

        <div className="auth-field">
          <label className="auth-label" htmlFor="auth-email">
            Email
          </label>
          <input
            id="auth-email"
            className="auth-input"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") submit();
            }}
            placeholder="you@example.com"
          />
        </div>

        <div className="auth-field">
          <label className="auth-label" htmlFor="auth-password">
            Password
          </label>
          <input
            id="auth-password"
            className="auth-input"
            type="password"
            autoComplete={isSignup ? "new-password" : "current-password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") submit();
            }}
            placeholder="********"
          />
          {isSignup && <p className="auth-hint">Minimum 8 characters</p>}
        </div>

        {error && <div className="auth-error">{error}</div>}

        <button
          className="auth-submit"
          type="button"
          onClick={submit}
          disabled={loading}
        >
          {loading ? "Please wait..." : isSignup ? "Create account" : "Log in"}
        </button>

        <div className="auth-divider">
          <span className="auth-divider-text">or</span>
        </div>

        <button
          className="auth-github-btn"
          type="button"
          onClick={startGithubOAuth}
        >
          <GitHubIcon stroke="currentColor" />
          Continue with GitHub
        </button>

        <p className="auth-switch">
          {isSignup ? "Already have an account? " : "Don't have an account? "}
          <span className="auth-switch-action" onClick={onSwitch}>
            {isSignup ? "Log in" : "Sign up"}
          </span>
        </p>
      </div>
    </div>
  );
}

function HistoryPanel({ user, scans, loading, error, onClose, onOpen, onDelete }) {
  return (
    <div className="history-overlay">
      <div className="history-inner">
        <div className="history-header">
          <div>
            <div className="history-title">Scan History</div>
            <div className="history-count">
              {user?.scan_count ?? 0} scans
            </div>
          </div>
          <button
            className="history-close"
            type="button"
            onClick={onClose}
            aria-label="Close scan history"
          >
            X
          </button>
        </div>

        {loading && <div className="history-message">Loading scans...</div>}
        {!loading && error && <div className="history-message">{error}</div>}
        {!loading && !error && scans.length === 0 && (
          <div className="history-message">
            No scans yet. Scan a repository to get started.
          </div>
        )}

        {!loading &&
          !error &&
          scans.map((scan) => (
            <div
              className="history-card"
              key={scan.id}
              onClick={() => onOpen(scan)}
            >
              <div className="history-card-top">
                <span className="history-repo">
                  {repoNameFromUrl(scan.repo_url)}
                </span>
                <button
                  className="history-delete"
                  type="button"
                  aria-label="Delete scan"
                  onClick={(e) => {
                    e.stopPropagation();
                    onDelete(scan.id);
                  }}
                >
                  X
                </button>
              </div>
              <div className="history-stats">
                <span
                  className={`history-stat ${scoreClass(
                    scan.pqc_readiness_score
                  )}`}
                >
                  Score: {scan.pqc_readiness_score}/100
                </span>
                <span className="history-stat">
                  {scan.scanned_files} files
                </span>
                <span className="history-stat">
                  {scan.total_findings} findings
                </span>
              </div>
              {scan.algorithms_found.length > 0 && (
                <div className="history-algos">
                  {scan.algorithms_found.map((algo) => (
                    <span
                      className={`algo-pill pill-${
                        (scan.algo_severity || {})[algo] ?? "info"
                      }`}
                      key={algo}
                    >
                      {algo}
                    </span>
                  ))}
                </div>
              )}
              <div className="history-date">
                {formatDateTime(scan.created_at)}
                {scan.cached ? " (cached)" : ""}
              </div>
            </div>
          ))}
      </div>
    </div>
  );
}

function StatCard({ label, value }) {
  return (
    <div className="admin-stat-card">
      <div className="admin-stat-label">{label}</div>
      <div className="admin-stat-value">{value}</div>
    </div>
  );
}

function TopList({ title, rows, emptyText }) {
  return (
    <div className="admin-card">
      <div className="admin-card-title">{title}</div>
      {rows.length === 0 ? (
        <div className="admin-list-value">{emptyText}</div>
      ) : (
        rows.map((row) => (
          <div className="admin-list-row" key={row.key}>
            <span className="admin-list-key" title={row.title ?? row.key}>
              {row.label}
            </span>
            <span className="admin-list-value">{row.count}</span>
          </div>
        ))
      )}
    </div>
  );
}

function AdminPanel({
  stats,
  loading,
  error,
  users,
  usersPage,
  usersPages,
  usersTotal,
  currentUserId,
  onClose,
  onPageChange,
  onDeleteUser,
}) {
  const cacheRate =
    stats && stats.total_scans > 0
      ? `${Math.round((stats.cached_scans / stats.total_scans) * 100)}%`
      : "0%";

  const algorithms = stats?.algorithms_most_found ?? [];
  const maxAlgoCount = algorithms.reduce((max, a) => Math.max(max, a.count), 0);

  return (
    <div className="admin-overlay">
      <div className="admin-inner">
        <div className="admin-header">
          <div>
            <div className="admin-title">Admin Dashboard</div>
            <div className="admin-sub">QLint usage overview</div>
          </div>
          <button
            className="admin-close"
            type="button"
            onClick={onClose}
            aria-label="Close admin dashboard"
          >
            X
          </button>
        </div>

        {loading && <div className="admin-message">Loading stats...</div>}
        {!loading && error && <div className="admin-message">{error}</div>}

        {!loading && !error && stats && (
          <>
            <div className="admin-stats">
              <StatCard label="Total Users" value={stats.total_users} />
              <StatCard label="Total Scans" value={stats.total_scans} />
              <StatCard label="Scans Today" value={stats.scans_today} />
              <StatCard label="Scans This Week" value={stats.scans_this_week} />
              <StatCard label="Cached Results" value={stats.cached_scans} />
              <StatCard label="Cache Hit Rate" value={cacheRate} />
            </div>

            <div className="admin-columns">
              <TopList
                title="Most Scanned Repositories"
                emptyText="No scans yet."
                rows={stats.most_scanned_repos.map((repo) => ({
                  key: repo.repo_url,
                  title: repo.repo_url,
                  label: repoNameFromUrl(repo.repo_url),
                  count: repo.scan_count,
                }))}
              />
              <TopList
                title="Most Active Users"
                emptyText="No users yet."
                rows={stats.top_users.map((entry) => ({
                  key: entry.email,
                  title: entry.email,
                  label: truncateEmail(entry.email, 28),
                  count: entry.scan_count,
                }))}
              />
            </div>

            <div className="admin-card admin-chart">
              <div className="admin-card-title">Most Detected Algorithms</div>
              {algorithms.length === 0 ? (
                <div className="admin-list-value">
                  No algorithms detected yet.
                </div>
              ) : (
                algorithms.map((algo) => (
                  <div className="admin-bar-row" key={algo.algorithm}>
                    <span className="admin-bar-label" title={algo.algorithm}>
                      {algo.algorithm}
                    </span>
                    <span className="admin-bar-track">
                      <span
                        className={`admin-bar admin-bar-${
                          algo.severity ?? "info"
                        }`}
                        style={{
                          display: "block",
                          width: `${
                            maxAlgoCount > 0
                              ? (algo.count / maxAlgoCount) * 100
                              : 0
                          }%`,
                        }}
                      />
                    </span>
                    <span className="admin-bar-count">{algo.count}</span>
                  </div>
                ))
              )}
            </div>

            <div className="admin-card admin-table-card">
              <div className="admin-card-title">All Users ({usersTotal})</div>
              <div className="admin-table-wrap">
                <table className="admin-table">
                  <thead>
                    <tr>
                      <th>Email</th>
                      <th>Role</th>
                      <th>Scans</th>
                      <th>Joined</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((row) => (
                      <tr key={row.id}>
                        <td>{row.email}</td>
                        <td>
                          <span className={`role-pill role-${row.role}`}>
                            {row.role}
                          </span>
                        </td>
                        <td>{row.scan_count}</td>
                        <td>{formatDateTime(row.created_at)}</td>
                        <td>
                          {row.id === currentUserId ? (
                            <span className="admin-self">&mdash;</span>
                          ) : (
                            <button
                              className="admin-delete-btn"
                              type="button"
                              onClick={() => onDeleteUser(row)}
                            >
                              Delete
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="admin-pager">
                <button
                  className="admin-pager-btn"
                  type="button"
                  disabled={usersPage <= 1}
                  onClick={() => onPageChange(usersPage - 1)}
                >
                  Prev
                </button>
                <span className="admin-pager-info">
                  Page {usersPage} of {Math.max(usersPages, 1)}
                </span>
                <button
                  className="admin-pager-btn"
                  type="button"
                  disabled={usersPage >= usersPages}
                  onClick={() => onPageChange(usersPage + 1)}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function FooterCTA() {
  const scrollToScan = () => {
    const el = document.getElementById("scan-input");
    if (el) el.scrollIntoView({ behavior: "smooth" });
  };
  return (
    <section className="cta-banner">
      <div className="cta-inner">
        <h2>Ready to secure your entire organization?</h2>
        <p>
          Connect QLint with your GitHub organization to continuously scan
          repositories and prevent quantum-vulnerable code from shipping.
        </p>
        <button className="cta-white" type="button" onClick={scrollToScan}>
          Get Started
        </button>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="footer">
      <div className="footer-inner">
        <div className="footer-left">
          <a href="#">Terms of Service</a>
          <a href="#">Privacy Policy</a>
          <a href="mailto:abhushan4625@gmail.com">Support</a>
        </div>
        <div className="footer-copy">QLint &copy; 2026</div>
      </div>
    </footer>
  );
}

export default function App() {
  const [route, setRoute] = useState(() => window.location.pathname);
  const [view, setView] = useState("input");
  const [theme, setTheme] = useState("light");
  const [repoUrl, setRepoUrl] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [tokenVisible, setTokenVisible] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const [rateLimit, setRateLimit] = useState(null);
  const [statusFailed, setStatusFailed] = useState(false);
  const [activeFilter, setActiveFilter] = useState("all");
  const [expandedFiles, setExpandedFiles] = useState({});
  const [expandedFixes, setExpandedFixes] = useState({});
  const [urlError, setUrlError] = useState(null);

  const [user, setUser] = useState(null);
  const [authToken, setAuthToken] = useState(null);
  const [authView, setAuthView] = useState("none");
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState(null);
  const [userScans, setUserScans] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState(null);

  const [toast, setToast] = useState(null);

  const [showAdmin, setShowAdmin] = useState(false);
  const [adminStats, setAdminStats] = useState(null);
  const [adminLoading, setAdminLoading] = useState(false);
  const [adminError, setAdminError] = useState(null);
  const [adminUsers, setAdminUsers] = useState([]);
  const [adminUsersPage, setAdminUsersPage] = useState(1);
  const [adminUsersPages, setAdminUsersPages] = useState(1);
  const [adminUsersTotal, setAdminUsersTotal] = useState(0);

  const fetchRateLimit = () => {
    fetch(`${API_BASE}/scan/status`)
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => {
        setRateLimit(data);
        setStatusFailed(false);
      })
      .catch(() => {
        setRateLimit(null);
        setStatusFailed(true);
      });
  };

  useEffect(fetchRateLimit, []);

  // Keep the back button working now that there is more than one path.
  useEffect(() => {
    const onPopState = () => setRoute(window.location.pathname);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const navigate = (path) => {
    if (window.location.pathname !== path) {
      window.history.pushState({}, "", path);
    }
    setRoute(path);
    window.scrollTo(0, 0);
  };

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const showToast = (message) => {
    setToast(message);
    setTimeout(() => setToast(null), 2000);
  };

  // Handle the OAuth callback landing before anything else touches the token:
  // /?github_token=...&github_user=... on success, /?github_error=... on failure.
  // Read during the first render, because the effect below strips the params.
  const [oauthLanding] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    return {
      token: params.get("github_token"),
      error: params.get("github_error"),
    };
  });

  useEffect(() => {
    const oauthToken = oauthLanding.token;
    const oauthError = oauthLanding.error;
    if (!oauthToken && !oauthError) return;

    // Drop the params so a refresh does not replay the callback.
    window.history.replaceState({}, "", window.location.pathname);

    if (oauthError) {
      showToast("GitHub connection failed");
      return;
    }

    localStorage.setItem(TOKEN_KEY, oauthToken);
    fetch(`${API_BASE}/auth/me`, {
      headers: { Authorization: `Bearer ${oauthToken}` },
    })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => {
        setUser(data);
        setAuthToken(oauthToken);
        showToast("GitHub connected successfully");
      })
      .catch(() => {
        localStorage.removeItem(TOKEN_KEY);
        showToast("GitHub connection failed");
      });
  }, []);

  // Restore a previous session from localStorage, dropping a token the
  // backend no longer accepts.
  useEffect(() => {
    const stored = localStorage.getItem(TOKEN_KEY);
    if (!stored) return;
    // The OAuth effect above owns this render pass when it just landed.
    if (oauthLanding.token) return;
    fetch(`${API_BASE}/auth/me`, {
      headers: { Authorization: `Bearer ${stored}` },
    })
      .then((res) => {
        if (res.status === 401) {
          localStorage.removeItem(TOKEN_KEY);
          return null;
        }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => {
        if (data) {
          setUser(data);
          setAuthToken(stored);
        }
      })
      .catch(() => {
        // Backend unreachable: keep the token, it may still be valid later.
      });
  }, []);

  const toggleTheme = () =>
    setTheme((prev) => (prev === "light" ? "dark" : "light"));

  const openAuth = (mode) => {
    setAuthError(null);
    setAuthView(mode);
  };

  const closeAuth = () => {
    setAuthError(null);
    setAuthView("none");
  };

  const submitAuth = async (mode, email, password) => {
    setAuthError(null);
    if (!email || !password) {
      setAuthError("Email and password are required.");
      return;
    }
    if (mode === "signup" && password.length < 8) {
      setAuthError("Password must be at least 8 characters.");
      return;
    }
    setAuthLoading(true);
    try {
      const path = mode === "signup" ? "/auth/register" : "/auth/login";
      const res = await fetch(`${API_BASE}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) {
        if (mode === "signup" && res.status === 409) {
          setAuthError("Email already registered");
        } else if (mode === "login" && res.status === 401) {
          setAuthError("Invalid email or password");
        } else {
          setAuthError(
            mode === "signup"
              ? "Signup failed. Try again."
              : "Login failed. Try again."
          );
        }
        return;
      }
      const data = await res.json();
      localStorage.setItem(TOKEN_KEY, data.access_token);
      setAuthToken(data.access_token);
      setUser(data.user);
      setAuthView("none");
    } catch {
      setAuthError(
        mode === "signup"
          ? "Signup failed. Try again."
          : "Login failed. Try again."
      );
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = () => {
    if (authToken) {
      // Stateless JWT: the server has nothing to invalidate, so do not await.
      fetch(`${API_BASE}/auth/logout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${authToken}` },
      }).catch(() => {});
    }
    localStorage.removeItem(TOKEN_KEY);
    setAuthToken(null);
    setUser(null);
    setUserScans([]);
    setHistoryError(null);
    setAdminStats(null);
    setAdminUsers([]);
    setAdminError(null);
    if (showAdmin) setShowAdmin(false);
    if (showHistory) setShowHistory(false);
    if (view === "results") {
      setScanResult(null);
      setView("input");
    }
  };

  const loadHistory = async (token) => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const res = await fetch(`${API_BASE}/user/scans?page=1&limit=50`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setUserScans(data.scans || []);
    } catch {
      setHistoryError("Could not load your scan history.");
      setUserScans([]);
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    if (showHistory && authToken) loadHistory(authToken);
  }, [showHistory, authToken]);

  const openHistoryScan = async (scan) => {
    if (!authToken) return;
    try {
      const res = await fetch(`${API_BASE}/user/scans/${scan.id}/full`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setRepoUrl(scan.repo_url);
      setScanResult(data);
      setExpandedFiles(expandedFromResult(data));
      setExpandedFixes({});
      setActiveFilter("all");
      setView("results");
      setShowHistory(false);
    } catch {
      setHistoryError("Could not open that scan.");
    }
  };

  const deleteHistoryScan = async (scanId) => {
    if (!authToken) return;
    setUserScans((prev) => prev.filter((s) => s.id !== scanId));
    try {
      await fetch(`${API_BASE}/user/scans/${scanId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${authToken}` },
      });
    } catch {
      // Optimistic removal stands; the next open refetches the real list.
    }
  };

  const disconnectGithub = async () => {
    if (!authToken) return;
    try {
      const res = await fetch(`${API_BASE}/auth/github/disconnect`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setUser((prev) =>
        prev
          ? { ...prev, github_connected: false, github_username: null }
          : prev
      );
      showToast("GitHub disconnected");
    } catch {
      showToast("Could not disconnect GitHub");
    }
  };

  const loadAdminStats = async (token) => {
    setAdminLoading(true);
    setAdminError(null);
    try {
      const res = await fetch(`${API_BASE}/admin/stats`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 403) throw new Error("forbidden");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setAdminStats(await res.json());
    } catch (err) {
      setAdminStats(null);
      setAdminError(
        err.message === "forbidden"
          ? "Admin access required."
          : "Could not load admin stats."
      );
    } finally {
      setAdminLoading(false);
    }
  };

  const loadAdminUsers = async (token, page) => {
    try {
      const res = await fetch(
        `${API_BASE}/admin/users?page=${page}&limit=20`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setAdminUsers(data.users || []);
      setAdminUsersPages(data.pages || 1);
      setAdminUsersTotal(data.total || 0);
    } catch {
      setAdminUsers([]);
    }
  };

  useEffect(() => {
    if (showAdmin && authToken) loadAdminStats(authToken);
  }, [showAdmin, authToken]);

  useEffect(() => {
    if (showAdmin && authToken) loadAdminUsers(authToken, adminUsersPage);
  }, [showAdmin, authToken, adminUsersPage]);

  const deleteAdminUser = async (row) => {
    if (!authToken) return;
    const confirmed = window.confirm(
      `Delete ${row.email} and all their scans? This cannot be undone.`
    );
    if (!confirmed) return;
    try {
      const res = await fetch(`${API_BASE}/admin/users/${row.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setAdminUsers((prev) => prev.filter((u) => u.id !== row.id));
      setAdminUsersTotal((prev) => Math.max(0, prev - 1));
      // Deleting an account changes the totals, so refresh the cards.
      loadAdminStats(authToken);
    } catch {
      setAdminError(`Could not delete ${row.email}.`);
    }
  };

  const handleScan = async (forceRefresh = false) => {
    setUrlError(null);
    setError(null);
    const trimmed = repoUrl.trim();
    if (!trimmed.startsWith("https://github.com/")) {
      setUrlError("Please enter a valid GitHub repository URL");
      return;
    }
    setView("scanning");
    try {
      const post = (body) => {
        const headers = { "Content-Type": "application/json" };
        if (authToken) headers.Authorization = `Bearer ${authToken}`;
        return fetch(`${API_BASE}/scan`, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        });
      };

      const base = { repo_url: trimmed, force_refresh: forceRefresh };
      let res = await post(
        githubToken ? { ...base, github_token: githubToken } : base
      );
      if (res.status === 422 && githubToken) {
        res = await post(base);
      }

      const data = await res.json().catch(() => null);
      if (!res.ok) {
        const detail =
          data && typeof data.detail === "string" ? data.detail : null;
        throw new Error(
          detail || "Scan failed. Please check the URL and try again."
        );
      }

      setScanResult(data);
      setExpandedFiles(expandedFromResult(data));
      setExpandedFixes({});
      setActiveFilter("all");
      setView("results");
      // The backend only counts scans it actually ran, so mirror that here
      // instead of refetching /auth/me for a single number.
      if (user && !data.cached) {
        setUser((prev) =>
          prev ? { ...prev, scan_count: prev.scan_count + 1 } : prev
        );
      }
      fetchRateLimit();
    } catch (err) {
      const message =
        err instanceof TypeError
          ? "Scan failed. Could not reach the QLint backend."
          : err.message || "Scan failed. Please check the URL and try again.";
      setError(message);
      setView("input");
    }
  };

  const handleReset = () => {
    setRepoUrl("");
    setGithubToken("");
    setTokenVisible(false);
    setScanResult(null);
    setActiveFilter("all");
    setExpandedFiles({});
    setExpandedFixes({});
    setError(null);
    setUrlError(null);
    setView("input");
    fetchRateLimit();
  };

  return (
    <div className="app-wrapper">
      <Navbar
        theme={theme}
        onToggleTheme={toggleTheme}
        user={user}
        onLogin={() => openAuth("login")}
        onSignup={() => openAuth("signup")}
        onLogout={handleLogout}
        onShowHistory={() => setShowHistory(true)}
        onShowAdmin={() => {
          setAdminUsersPage(1);
          setShowAdmin(true);
        }}
        onDisconnectGithub={disconnectGithub}
        route={route}
        onNavigate={navigate}
      />
      {toast && <Toast message={toast} />}
      <div className="main-content">
        <main className="main">
          {route === BENCHMARK_PATH && <PqcBenchmark />}
          {route !== BENCHMARK_PATH && view === "input" && (
            <>
              <Hero />
              <ScanInputCard
                repoUrl={repoUrl}
                setRepoUrl={setRepoUrl}
                githubToken={githubToken}
                setGithubToken={setGithubToken}
                tokenVisible={tokenVisible}
                setTokenVisible={setTokenVisible}
                urlError={urlError}
                rateLimit={rateLimit}
                statusFailed={statusFailed}
                scanning={false}
                onScan={() => handleScan(false)}
                user={user}
                error={error}
                onClearError={() => setError(null)}
              />
              <LanguagesStrip />
              <Pricing />
              <FooterCTA />
            </>
          )}
          {route !== BENCHMARK_PATH && view === "scanning" && (
            <ScanningView repoUrl={repoUrl} />
          )}
          {route !== BENCHMARK_PATH && view === "results" && scanResult && (
            <ResultsView
              result={scanResult}
              activeFilter={activeFilter}
              setActiveFilter={setActiveFilter}
              expandedFiles={expandedFiles}
              setExpandedFiles={setExpandedFiles}
              expandedFixes={expandedFixes}
              setExpandedFixes={setExpandedFixes}
              onReset={handleReset}
              onRescan={() => handleScan(true)}
              authToken={authToken}
            />
          )}
        </main>
      </div>
      <Footer />
      {authView !== "none" && (
        <AuthModal
          mode={authView}
          loading={authLoading}
          error={authError}
          onClose={closeAuth}
          onSubmit={(email, password) =>
            submitAuth(authView, email, password)
          }
          onSwitch={() => {
            setAuthError(null);
            setAuthView(authView === "signup" ? "login" : "signup");
          }}
        />
      )}
      {showHistory && (
        <HistoryPanel
          user={user}
          scans={userScans}
          loading={historyLoading}
          error={historyError}
          onClose={() => setShowHistory(false)}
          onOpen={openHistoryScan}
          onDelete={deleteHistoryScan}
        />
      )}
      {showAdmin && (
        <AdminPanel
          stats={adminStats}
          loading={adminLoading}
          error={adminError}
          users={adminUsers}
          usersPage={adminUsersPage}
          usersPages={adminUsersPages}
          usersTotal={adminUsersTotal}
          currentUserId={user?.id}
          onClose={() => setShowAdmin(false)}
          onPageChange={setAdminUsersPage}
          onDeleteUser={deleteAdminUser}
        />
      )}
    </div>
  );
}

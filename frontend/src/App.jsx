import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import "./App.css";
import PqcBenchmark from "./PqcBenchmark";
import About from "./About";
import Help from "./Help";
import Terms from "./Terms";
import Privacy from "./Privacy";
import { CopyButton, FixPanels } from "./FixPanels";
import { ChevronIcon } from "./icons";
import { API_BASE } from "./api";

// The app is a single view-switcher, so "routing" here is just the paths that
// have to be linkable from outside: the scanner and the standalone pages.
// Vite serves index.html for all of them, so a direct visit works.
const HOME_PATH = "/";
const BENCHMARK_PATH = "/benchmark";
const ABOUT_PATH = "/about";
const HELP_PATH = "/help";
const TERMS_PATH = "/terms";
const PRIVACY_PATH = "/privacy";

// Each standalone page renders instead of the scanner. Keeping them in one
// table means the navbar, the sidebar, the footer, and the main switch all
// agree on what counts as "not the scanner" without four copies of the same
// path list. `nav` marks the ones the top bar shows; the legal pages are
// reachable from the footer only.
const PAGES = [
  {
    path: BENCHMARK_PATH,
    label: "PQC Benchmark Lab",
    nav: true,
    render: () => <PqcBenchmark />,
  },
  { path: ABOUT_PATH, label: "About Us", nav: true, render: () => <About /> },
  { path: HELP_PATH, label: "Help", nav: true, render: () => <Help /> },
  { path: TERMS_PATH, label: "Terms of Service", render: () => <Terms /> },
  { path: PRIVACY_PATH, label: "Privacy Policy", render: () => <Privacy /> },
];

const NAV_PAGES = PAGES.filter((page) => page.nav);

// Shown in place of Generate Patch on findings stored before the scanners
// began attaching the flagged source line. Nothing is broken -- the data to
// diff against simply is not in that saved report.
const PATCH_UNAVAILABLE_HINT =
  "This saved scan predates per-finding source capture, so there is no original line to generate a diff against. Scan the repository again and the button returns.";

const README_URL = "https://github.com/Abhushan187/QLint#readme";
const REPO_URL = "https://github.com/Abhushan187/QLint";
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

// The callback redirects here with one of these codes when sign-in did not
// complete. Each one has a different fix, so each gets its own sentence
// instead of the single "GitHub connection failed" that used to cover them
// all -- a database outage and a rejected code are not the same problem.
const GITHUB_ERROR_MESSAGES = {
  not_configured:
    "GitHub sign-in is not configured on the server. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in backend/.env.",
  no_code: "GitHub did not send an authorization code. Try signing in again.",
  token_exchange_failed:
    "GitHub rejected the sign-in request. The code may have expired, or the server's GitHub client secret may be wrong.",
  profile_unavailable:
    "GitHub signed you in but would not share your account details, so there was nothing to create an account from.",
  db_unavailable:
    "GitHub signed you in, but QLint could not reach its database to save the session. Start MongoDB and try again.",
  server_error: "Something went wrong while completing GitHub sign-in.",
};

function githubErrorMessage(code) {
  return GITHUB_ERROR_MESSAGES[code] || GITHUB_ERROR_MESSAGES.server_error;
}

// The write connection's own failures, on their own channel. They share none
// of the messages above on purpose: "could not connect write access" and
// "could not sign you in" call for different next steps, and a write failure
// must never read as having lost the session.
const GITHUB_WRITE_ERROR_MESSAGES = {
  no_code: "GitHub did not send an authorization code. Try connecting again.",
  token_exchange_failed:
    "GitHub rejected the write connection request. The code may have expired. Try again.",
  scope_denied:
    "GitHub did not grant the repository access QLint needs to open a pull request, so nothing was saved. Try again and leave the repository permission checked.",
  db_unavailable:
    "GitHub granted write access, but QLint could not reach its database to save it. Start MongoDB and try again.",
  unknown_account:
    "The write connection did not match a QLint account. Sign in again and retry.",
  server_error: "Something went wrong while connecting GitHub write access.",
};

function githubWriteErrorMessage(code) {
  return (
    GITHUB_WRITE_ERROR_MESSAGES[code] || GITHUB_WRITE_ERROR_MESSAGES.server_error
  );
}

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

function Logo({ onGoHome }) {
  return (
    <a
      href={HOME_PATH}
      className="logo"
      onClick={(e) => {
        e.preventDefault();
        onGoHome();
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

function PersonIcon({ size = 16 }) {
  return (
    <svg
      width={size}
      height={size}
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

// One dismiss glyph for every close/delete affordance, so the scan-history
// entries, the history panel, the auth modal, and the notice banner stop each
// drawing their own bare "X" character at a different size.
function CloseIcon({ size = 14 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      aria-hidden="true"
    >
      <path d="M18 6 L6 18" />
      <path d="M6 6 L18 18" />
    </svg>
  );
}

function TrashIcon({ size = 14 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M4 7 h16" />
      <path d="M10 4 h4" />
      <path d="M6 7 l1 13 h10 l1 -13" />
      <path d="M10 11 v6" />
      <path d="M14 11 v6" />
    </svg>
  );
}

function HomeIcon({ size = 16 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M3 11 L12 3 L21 11" />
      <path d="M5.5 9.5 V20 h13 V9.5" />
    </svg>
  );
}

function Toast({ message }) {
  return <div className="toast">{message}</div>;
}

function Navbar({
  theme,
  onToggleTheme,
  onGoHome,
  user,
  onLogin,
  onSignup,
  onLogout,
  onShowHistory,
  onShowAdmin,
  onDisconnectGithub,
  onConnectGithubWrite,
  onDisconnectGithubWrite,
  route,
  onNavigate,
}) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
  const accountRef = useRef(null);
  const closeSidebar = () => setSidebarOpen(false);

  // The profile menu dismisses on everything that means "I am done here":
  // a click anywhere outside it, Escape, or choosing one of its items. The
  // first two matter because its items navigate away or open GitHub -- a
  // menu left hanging over the page after that reads as a stuck dropdown.
  useEffect(() => {
    if (!accountOpen) return undefined;
    const onPointerDown = (event) => {
      if (!accountRef.current?.contains(event.target)) setAccountOpen(false);
    };
    const onKeyDown = (event) => {
      if (event.key === "Escape") setAccountOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [accountOpen]);

  const fromAccountMenu = (action) => () => {
    setAccountOpen(false);
    action();
  };

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
          <Logo onGoHome={onGoHome} />
        </div>
        <div className="nav-actions">
          <ThemeToggle theme={theme} onToggle={onToggleTheme} />
          {NAV_PAGES.map((page) => (
            <a
              key={page.path}
              className={`nav-btn${
                route === page.path ? " nav-btn-active" : ""
              }`}
              href={page.path}
              onClick={(e) => {
                e.preventDefault();
                onNavigate(page.path);
              }}
            >
              {page.label}
            </a>
          ))}
          {/* Same destination the "GitHub" button had; the label says what
              the link is for rather than where it points. */}
          <a
            className="nav-btn"
            href={REPO_URL}
            target="_blank"
            rel="noreferrer"
          >
            Contribute
          </a>
          {/* Everything account-shaped lives behind this one icon. The bar
              used to carry the email, both GitHub connections, My Scans,
              Admin and Log out side by side -- more chrome than the three
              pages it sat next to, and most of it rarely touched. */}
          <div className="nav-account" ref={accountRef}>
            <button
              className="nav-profile"
              type="button"
              title={user ? user.email : "Account"}
              aria-label={user ? `Account: ${user.email}` : "Account"}
              aria-haspopup="menu"
              aria-expanded={accountOpen}
              onClick={() => setAccountOpen((prev) => !prev)}
            >
              <PersonIcon size={18} />
            </button>
            {accountOpen && (
              <div className="account-menu" role="menu">
                {user ? (
                  <>
                    <div className="account-menu-head">
                      <span className="account-menu-email">{user.email}</span>
                      <span className="account-menu-sub">
                        {user.role === "admin" ? "Administrator" : "Signed in"}
                      </span>
                    </div>
                    {/* The two GitHub grants, stacked but kept visibly
                        separate: read is what scanning uses, write is what
                        opening a pull request needs, and they are distinct
                        tokens with distinct scopes. Neither row closes the
                        menu -- the point of acting here is watching the
                        status on the same line change. */}
                    <div className="account-menu-row">
                      <span className="account-menu-row-text">
                        <span className="account-menu-row-label">GitHub</span>
                        <span className="account-menu-row-value">
                          {user.github_connected
                            ? `Connected${
                                user.github_username
                                  ? ` as ${user.github_username}`
                                  : ""
                              }`
                            : "Not connected"}
                        </span>
                      </span>
                      <button
                        className="account-menu-link"
                        type="button"
                        onClick={
                          user.github_connected
                            ? onDisconnectGithub
                            : startGithubOAuth
                        }
                      >
                        {user.github_connected ? "Disconnect" : "Connect"}
                      </button>
                    </div>
                    <div className="account-menu-row">
                      <span className="account-menu-row-text">
                        <span className="account-menu-row-label">
                          Write access
                        </span>
                        <span className="account-menu-row-value">
                          {user.github_write_connected
                            ? `On as ${
                                user.github_write_username || "GitHub"
                              }`
                            : "Off"}
                        </span>
                      </span>
                      <button
                        className={`switch${
                          user.github_write_connected ? " switch-on" : ""
                        }`}
                        type="button"
                        role="switch"
                        aria-checked={Boolean(user.github_write_connected)}
                        aria-label="GitHub write access"
                        onClick={
                          user.github_write_connected
                            ? onDisconnectGithubWrite
                            : onConnectGithubWrite
                        }
                      >
                        <span className="switch-knob" />
                      </button>
                    </div>
                    <div className="account-menu-sep" />
                    <button
                      className="account-menu-item"
                      type="button"
                      role="menuitem"
                      onClick={fromAccountMenu(onShowHistory)}
                    >
                      My Scans
                    </button>
                    {user.role === "admin" && (
                      <button
                        className="account-menu-item"
                        type="button"
                        role="menuitem"
                        onClick={fromAccountMenu(onShowAdmin)}
                      >
                        Admin
                      </button>
                    )}
                    <button
                      className="account-menu-item"
                      type="button"
                      role="menuitem"
                      onClick={fromAccountMenu(onLogout)}
                    >
                      Log out
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      className="account-menu-item"
                      type="button"
                      role="menuitem"
                      onClick={fromAccountMenu(onLogin)}
                    >
                      Log in
                    </button>
                    <button
                      className="account-menu-item"
                      type="button"
                      role="menuitem"
                      onClick={fromAccountMenu(onSignup)}
                    >
                      Sign up
                    </button>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
      {sidebarOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setSidebarOpen(false)}
        />
      )}
      <nav className={`sidebar${sidebarOpen ? " sidebar-open" : ""}`}>
        {NAV_PAGES.map((page) => (
          <a
            key={page.path}
            className={`sidebar-item${
              route === page.path ? " sidebar-item-active" : ""
            }`}
            href={page.path}
            onClick={(e) => {
              e.preventDefault();
              closeSidebar();
              onNavigate(page.path);
            }}
          >
            {page.label}
          </a>
        ))}
        <a
          className="sidebar-item"
          href={REPO_URL}
          target="_blank"
          rel="noreferrer"
        >
          Contribute
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
            {/* The profile menu stays reachable on mobile, but the sidebar
                keeps its own copy of the GitHub controls: it is the menu a
                narrow viewport opens by habit. */}
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
            {/* The write connection is managed separately from the one above,
                because it is a separate grant with a separate token. */}
            <button
              className="sidebar-item"
              type="button"
              onClick={() => {
                closeSidebar();
                if (user.github_write_connected) onDisconnectGithubWrite();
                else onConnectGithubWrite();
              }}
            >
              {user.github_write_connected
                ? "Disconnect write access"
                : "Connect write access"}
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

// What each scanner actually reads, rather than a row of language names with
// nothing behind them. The detail is the point: it is what tells a reader
// whether their codebase is covered before they spend a scan finding out.
const LANGUAGES = [
  {
    name: "Python",
    status: "active",
    extensions: ".py",
    detail: "Full AST walk: imports, calls, and attribute access",
  },
  {
    name: "JavaScript",
    status: "active",
    extensions: ".js .jsx .mjs .cjs",
    detail: "node:crypto, WebCrypto, and common library calls",
  },
  {
    name: "TypeScript",
    status: "active",
    extensions: ".ts .tsx",
    detail: "Same detection as JavaScript, type syntax tolerated",
  },
  {
    name: "Go",
    status: "active",
    extensions: ".go",
    detail: "crypto/* imports, tls.Config, and key generation",
  },
  {
    name: "Java",
    status: "active",
    extensions: ".java",
    detail: "JCA/JCE getInstance calls and Bouncy Castle classes",
  },
  {
    name: "Rust",
    status: "active",
    extensions: ".rs",
    detail: "RustCrypto, ring, and openssl crate paths",
  },
];

function LanguagesStrip() {
  // Counted from the table rather than written out, so the caption cannot go
  // stale the next time a language ships.
  const active = LANGUAGES.filter((lang) => lang.status === "active").length;
  const planned = LANGUAGES.length - active;
  return (
    <section className="langs">
      <div className="langs-inner">
        <div className="section-head">
          <h2 className="section-title">Supported languages</h2>
          <span className="section-meta">
            {planned ? `${active} active / ${planned} planned` : `${active} active`}
          </span>
        </div>
        <div className="lang-grid">
          {LANGUAGES.map((lang) => (
            <div
              className={`lang-card${
                lang.status === "soon" ? " lang-card-soon" : ""
              }`}
              key={lang.name}
            >
              <div className="lang-card-top">
                <span className="lang-name">{lang.name}</span>
                <span className={`lang-tag tag-${lang.status}`}>
                  {lang.status === "active" ? "Active" : "Planned"}
                </span>
              </div>
              <div className="lang-ext">{lang.extensions}</div>
              <div className="lang-detail">{lang.detail}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function ScanningView({ repoUrl, onCancel }) {
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
        <button
          className="scanning-cancel"
          type="button"
          onClick={onCancel}
          title="Stop this scan and return home"
        >
          Cancel scan
        </button>
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

// SARIF and CBOM are both built server-side so the rule catalog, severity
// mapping and CycloneDX enums stay in one place. A signed-in user's scan has
// an id to address; an anonymous one does not, so that path asks the scan
// endpoint to render the cached result in the requested format instead.
//
// The two downloads answer different questions and are offered side by side:
// SARIF is "what is wrong and where", for code scanning tools; the CBOM is the
// cryptographic inventory a PQC migration programme tracks progress against.
const EXPORT_FORMATS = {
  sarif: { path: "sarif", extension: "sarif" },
  cbom: { path: "cbom", extension: "cbom.json" },
};

async function downloadExport(result, authToken, format) {
  const { path, extension } = EXPORT_FORMATS[format];
  const response =
    result.scan_id && authToken
      ? await fetch(`${API_BASE}/user/scans/${result.scan_id}/${path}`, {
          headers: { Authorization: `Bearer ${authToken}` },
        })
      : await fetch(`${API_BASE}/scan?format=${format}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ repo_url: `https://github.com/${result.repo}` }),
        });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.detail || `HTTP ${response.status}`);
  }
  saveBlob(await response.blob(), reportFilename(result, extension));
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

// ---------------------------------------------------------------------------
// F29: one-click migration pull requests.
//
// The button below is the only thing in QLint that can change a user's
// repository, so the flow is built around two separations that are easy to
// collapse by accident and expensive to get wrong.
//
// Separation one is the connection: scanning uses a read-only GitHub token,
// creating a pull request uses a different token from a different button with
// a different scope. The feature stays visible without it -- hiding it would
// make "why can't I do this" unanswerable -- but the confirm button is not
// reachable until write access is connected.
//
// Separation two is the click: opening the confirmation screen and creating
// the pull request are two deliberate actions. Nothing reaches GitHub on the
// first one.
// ---------------------------------------------------------------------------

// A finding can go into a pull request only if there is real code to change
// and a real replacement to change it to -- the same two fields /scan/patch
// refuses to work without. Safe and info findings are excluded because there
// is nothing to migrate: they are already quantum-safe.
function isPatchable(finding) {
  return Boolean(
    finding.code_snippet &&
      finding.fix_snippet &&
      (finding.severity === "critical" || finding.severity === "warning")
  );
}

function patchableFindings(result) {
  return Object.entries(result.findings_by_file || {}).flatMap(
    ([file, findings]) =>
      (findings || []).filter(isPatchable).map((finding) => ({
        ...finding,
        file: finding.file || file,
      }))
  );
}

function findingKey(finding) {
  return `${finding.file}:${finding.line}`;
}

async function createPullRequest(scanId, authToken, findings) {
  const response = await fetch(`${API_BASE}/scan/${scanId}/create-pr`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${authToken}`,
    },
    body: JSON.stringify({
      findings: findings.map((f) => ({ file: f.file, line: f.line })),
    }),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(data?.detail || `Pull request failed (HTTP ${response.status})`);
  }
  return data;
}

// Shown in place of the consent screen when the write connection is missing.
// A prompt rather than a hidden button: the user should be able to find out
// this feature exists before deciding whether to grant anything.
function WriteAccessPrompt({ onConnect, connecting }) {
  return (
    <div className="pr-connect">
      <p className="pr-connect-lead">
        Creating a pull request needs a separate GitHub connection from the
        read-only one QLint uses to scan.
      </p>
      <ul className="pr-facts">
        <li>
          It asks for the <code>public_repo</code> scope, the narrowest GitHub
          offers that can create a branch, a commit and a pull request.
        </li>
        <li>
          It is stored separately from your scanning connection. Disconnecting
          one leaves the other alone.
        </li>
        <li>
          Nothing is written to any repository until you confirm a specific
          pull request on the next screen.
        </li>
      </ul>
      <button
        className="btn-primary btn-small"
        type="button"
        onClick={onConnect}
        disabled={connecting}
      >
        {connecting ? "Opening GitHub..." : "Connect write access"}
      </button>
    </div>
  );
}

function PRConsentModal({
  repo,
  findings,
  selected,
  onToggle,
  onToggleFile,
  writeConnected,
  connecting,
  onConnect,
  creating,
  error,
  onCancel,
  onConfirm,
}) {
  const chosen = findings.filter((f) => selected.has(findingKey(f)));
  const files = [...new Set(chosen.map((f) => f.file))].sort();
  const byFile = findings.reduce((groups, finding) => {
    (groups[finding.file] = groups[finding.file] || []).push(finding);
    return groups;
  }, {});

  // Rendered into document.body rather than in place: the consent screen
  // lives deep inside the results tree, and a portal is the only way its
  // stacking is guaranteed not to be capped by some ancestor between here
  // and the root picking up a stacking context later.
  return createPortal(
    <div className="modal-overlay" onClick={creating ? undefined : onCancel}>
      <div
        className="pr-modal"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Create pull request"
      >
        <button
          className="icon-btn auth-close"
          type="button"
          aria-label="Close"
          onClick={onCancel}
          disabled={creating}
        >
          <CloseIcon />
        </button>
        <div className="auth-title">Create a pull request</div>
        <p className="auth-sub">
          Review what QLint is about to do before anything reaches GitHub.
        </p>

        {!writeConnected ? (
          <WriteAccessPrompt onConnect={onConnect} connecting={connecting} />
        ) : (
          <>
            <div className="pr-target">
              <span className="pr-target-label">Repository</span>
              <span className="pr-target-repo">{repo}</span>
            </div>

            {/* The four promises this screen makes, stated rather than
                implied. Each one is a thing a user could reasonably fear is
                happening when they hand over write access. */}
            <ul className="pr-facts">
              <li>
                QLint creates a <strong>new branch</strong> and opens a{" "}
                <strong>new pull request</strong> from it.
              </li>
              <li>
                Your default branch is <strong>not modified directly</strong>.
              </li>
              <li>
                Nothing is <strong>merged automatically</strong>. You review and
                merge it yourself, or you do not.
              </li>
              <li>
                You can <strong>close the pull request without merging</strong>{" "}
                at any time, exactly like any other pull request. Closing it
                leaves your repository as it is today.
              </li>
            </ul>

            <div className="pr-summary-row">
              <span className="pr-count">
                {chosen.length} of {findings.length} finding
                {findings.length === 1 ? "" : "s"} selected
              </span>
              <span className="pr-count">
                {files.length} file{files.length === 1 ? "" : "s"} will be
                changed
              </span>
            </div>

            <div className="pr-file-list">
              {Object.entries(byFile).map(([file, fileFindings]) => {
                const allOn = fileFindings.every((f) =>
                  selected.has(findingKey(f))
                );
                return (
                  <div className="pr-file" key={file}>
                    <label className="pr-file-header">
                      <input
                        type="checkbox"
                        checked={allOn}
                        onChange={() => onToggleFile(file, !allOn)}
                        disabled={creating}
                      />
                      <span className="pr-file-name">{file}</span>
                      <span className="file-badge">{fileFindings.length}</span>
                    </label>
                    {fileFindings.map((finding) => {
                      const key = findingKey(finding);
                      return (
                        <label className="pr-finding" key={key}>
                          <input
                            type="checkbox"
                            checked={selected.has(key)}
                            onChange={() => onToggle(key)}
                            disabled={creating}
                          />
                          <span className={`algo-pill pill-${finding.severity}`}>
                            {finding.algorithm}
                          </span>
                          <span className="pr-finding-line">
                            line {finding.line}
                          </span>
                          <code className="pr-finding-code">
                            {finding.code_snippet}
                          </code>
                        </label>
                      );
                    })}
                  </div>
                );
              })}
            </div>

            <p className="pr-revalidate-note">
              Before patching, QLint re-reads each file from GitHub and skips
              any finding whose code has changed since the scan rather than
              applying the patch to the wrong place. Anything skipped is listed
              in the pull request and shown to you here.
            </p>

            {error && <div className="auth-error">{error}</div>}

            <div className="pr-actions">
              <button
                className="btn-ghost btn-small"
                type="button"
                onClick={onCancel}
                disabled={creating}
              >
                Cancel
              </button>
              <button
                className="btn-primary btn-small"
                type="button"
                onClick={onConfirm}
                disabled={creating || chosen.length === 0}
              >
                {creating
                  ? "Creating pull request..."
                  : `Create Pull Request (${chosen.length})`}
              </button>
            </div>
          </>
        )}
      </div>
    </div>,
    document.body
  );
}

function PRResultModal({ result, onClose }) {
  const applied = result.applied || [];
  const skipped = result.skipped || [];
  return createPortal(
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="pr-modal"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Pull request result"
      >
        <button
          className="icon-btn auth-close"
          type="button"
          aria-label="Close"
          onClick={onClose}
        >
          <CloseIcon />
        </button>
        <div className="auth-title">
          {result.created ? "Pull request created" : "No pull request created"}
        </div>
        <p className="auth-sub">
          {result.created
            ? "Nothing has been merged. Review it on GitHub, or close it."
            : result.detail}
        </p>

        {result.created && (
          <a
            className="pr-link"
            href={result.pr_url}
            target="_blank"
            rel="noreferrer"
          >
            {`Open pull request #${result.pr_number} on GitHub`}
          </a>
        )}

        <div className="pr-result-counts">
          <span className="pr-badge pr-badge-applied">
            {applied.length} applied
          </span>
          <span className="pr-badge pr-badge-skipped">
            {skipped.length} skipped
          </span>
          {result.created && (
            <span className="pr-badge pr-badge-branch">{result.branch}</span>
          )}
        </div>

        {applied.length > 0 && (
          <div className="pr-outcome-group">
            <div className="fix-panel-title">Patched</div>
            {applied.map((item) => (
              <div className="pr-outcome" key={findingKey(item.finding)}>
                <span
                  className={`algo-pill pill-${item.finding.severity}`}
                >
                  {item.finding.algorithm}
                </span>
                <code className="pr-outcome-loc">
                  {item.finding.file}:{item.finding.line}
                </code>
              </div>
            ))}
          </div>
        )}

        {skipped.length > 0 && (
          <div className="pr-outcome-group">
            <div className="fix-panel-title">Skipped, and why</div>
            {skipped.map((item) => (
              <div className="pr-outcome pr-outcome-skipped" key={findingKey(item.finding)}>
                <span className={`algo-pill pill-${item.finding.severity}`}>
                  {item.finding.algorithm}
                </span>
                <code className="pr-outcome-loc">
                  {item.finding.file}:{item.finding.line}
                </code>
                <span className="pr-outcome-reason">{item.reason}</span>
              </div>
            ))}
          </div>
        )}

        <div className="pr-actions">
          <button className="btn-primary btn-small" type="button" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </div>,
    document.body
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
        {!canPatch && (
          // Findings saved before scanners started attaching code_snippet
          // (F22) have no flagged line to diff against, so the patch endpoint
          // would refuse them anyway. Say why instead of silently omitting
          // the button -- a fresh scan of the same repository restores it.
          <span className="patch-unavailable" title={PATCH_UNAVAILABLE_HINT}>
            Re-scan to enable patch generation
          </span>
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
          <span className={`chevron${open ? " chevron-open" : ""}`}>
            <ChevronIcon />
          </span>
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
  activeAlgo,
  setActiveAlgo,
  expandedFiles,
  setExpandedFiles,
  expandedFixes,
  setExpandedFixes,
  onReset,
  onRescan,
  authToken,
  user,
  onConnectWrite,
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

  // With an algorithm pill active the tab numbers have to be recounted from
  // the findings themselves, otherwise the tabs would keep advertising the
  // repository-wide totals while the list below shows a subset.
  const tabCounts = activeAlgo
    ? allFindings.reduce(
        (counts, f) => {
          if (f.algorithm !== activeAlgo) return counts;
          counts.all += 1;
          counts[f.severity] += 1;
          return counts;
        },
        { all: 0, critical: 0, warning: 0, safe: 0, info: 0 }
      )
    : {
        all: result.total_findings,
        critical: result.severity_summary.critical,
        warning: result.severity_summary.warning,
        safe: result.severity_summary.safe,
        info: result.severity_summary.info,
      };

  // Severity tab and algorithm pill are two independent dimensions and both
  // narrow the same list; a file left with nothing to show drops out rather
  // than rendering as an empty expandable row.
  const matchesFilters = (f) =>
    (activeFilter === "all" || f.severity === activeFilter) &&
    (activeAlgo === null || f.algorithm === activeAlgo);

  const visibleFiles = Object.entries(result.findings_by_file)
    .map(([file, findings]) => [file, findings.filter(matchesFilters)])
    .filter(([, findings]) => findings.length > 0);

  const toggleAlgo = (algo) =>
    setActiveAlgo((prev) => (prev === algo ? null : algo));

  // One busy flag holding the format being built, rather than one flag per
  // button: only one export can be in flight at a time, and the error line
  // below the row belongs to whichever one failed.
  const [exportBusy, setExportBusy] = useState(null);
  const [exportError, setExportError] = useState(null);

  const getExport = (format, label) => async () => {
    setExportBusy(format);
    setExportError(null);
    try {
      await downloadExport(result, authToken, format);
    } catch (err) {
      setExportError(err.message || `Could not build the ${label} file.`);
    } finally {
      setExportBusy(null);
    }
  };

  const toggleFile = (file) =>
    setExpandedFiles((prev) => ({ ...prev, [file]: !prev[file] }));
  const toggleFix = (key) =>
    setExpandedFixes((prev) => ({ ...prev, [key]: !prev[key] }));

  // --- pull request flow -------------------------------------------------
  // Three stages, and the transition between the first two is the consent
  // gate: opening the modal reaches nothing, only "Create Pull Request"
  // inside it does.
  const [prStage, setPrStage] = useState(null); // null | "consent" | "result"
  const [prSelected, setPrSelected] = useState(() => new Set());
  const [prCreating, setPrCreating] = useState(false);
  const [prConnecting, setPrConnecting] = useState(false);
  const [prError, setPrError] = useState(null);
  const [prResult, setPrResult] = useState(null);

  const prFindings = patchableFindings(result);
  const writeConnected = Boolean(user?.github_write_connected);
  // Anonymous scans are not stored against an account, so there is no scan id
  // to address and nothing to prove ownership of.
  const prAvailable = Boolean(result.scan_id && authToken);

  const openPrConsent = () => {
    setPrError(null);
    setPrResult(null);
    setPrSelected(new Set(prFindings.map(findingKey)));
    setPrStage("consent");
  };

  const togglePrFinding = (key) =>
    setPrSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const togglePrFile = (file, on) =>
    setPrSelected((prev) => {
      const next = new Set(prev);
      for (const finding of prFindings.filter((f) => f.file === file)) {
        if (on) next.add(findingKey(finding));
        else next.delete(findingKey(finding));
      }
      return next;
    });

  const confirmCreatePr = async () => {
    setPrCreating(true);
    setPrError(null);
    try {
      const chosen = prFindings.filter((f) => prSelected.has(findingKey(f)));
      const created = await createPullRequest(result.scan_id, authToken, chosen);
      setPrResult(created);
      setPrStage("result");
    } catch (err) {
      setPrError(err.message || "Could not create the pull request.");
    } finally {
      setPrCreating(false);
    }
  };

  const startWriteConnect = async () => {
    setPrConnecting(true);
    try {
      await onConnectWrite();
    } finally {
      setPrConnecting(false);
    }
  };

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
              onClick={getExport("sarif", "SARIF")}
              disabled={exportBusy !== null}
              title="SARIF 2.1.0, for GitHub Code Scanning and SARIF viewers"
            >
              {exportBusy === "sarif" ? "Building SARIF..." : "Download SARIF"}
            </button>
            <button
              className="btn-ghost btn-small"
              type="button"
              onClick={getExport("cbom", "CBOM")}
              disabled={exportBusy !== null}
              title="CycloneDX 1.6 CBOM: an inventory of the cryptography this repository uses"
            >
              {exportBusy === "cbom" ? "Building CBOM..." : "Download CBOM"}
            </button>
            {/* Shown whenever there is something to patch, connected or not.
                Hiding it until write access exists would make the feature
                undiscoverable to exactly the people who have not granted it
                yet; the consent screen explains what is missing instead. */}
            {prFindings.length > 0 && (
              <button
                className="btn-ghost btn-small pr-open-btn"
                type="button"
                onClick={openPrConsent}
                disabled={!prAvailable}
                title={
                  prAvailable
                    ? "Open a pull request migrating the patchable findings"
                    : "Sign in and re-scan to create a pull request: only a saved scan can be turned into one"
                }
              >
                {`Create Pull Request (${prFindings.length})`}
              </button>
            )}
            <button
              className="btn-primary btn-small"
              type="button"
              onClick={onReset}
            >
              Scan Another Repository
            </button>
          </div>
          {exportError && <div className="sarif-error">{exportError}</div>}
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
                    algoSeverity[algo] ?? "info"
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
            <div className="no-findings">
              No {activeFilter === "all" ? "" : `${activeFilter} `}
              {activeAlgo ? `${activeAlgo} ` : ""}findings.
            </div>
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
                        <ChevronIcon />
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

      {prStage === "consent" && (
        <PRConsentModal
          repo={result.repo}
          findings={prFindings}
          selected={prSelected}
          onToggle={togglePrFinding}
          onToggleFile={togglePrFile}
          writeConnected={writeConnected}
          connecting={prConnecting}
          onConnect={startWriteConnect}
          creating={prCreating}
          error={prError}
          onCancel={() => setPrStage(null)}
          onConfirm={confirmCreatePr}
        />
      )}
      {prStage === "result" && prResult && (
        <PRResultModal result={prResult} onClose={() => setPrStage(null)} />
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
          className="icon-btn auth-close"
          type="button"
          onClick={onClose}
          aria-label="Close"
        >
          <CloseIcon size={16} />
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

// The header count is derived from `scans`, the same array the list below
// renders, so the two cannot disagree. It used to read user.scan_count, which
// counts every scan the account has ever run and is not decremented by a
// delete -- so emptying the history left the header claiming "4 scans" above
// the empty-state message.
function HistoryPanel({ scans, loading, error, onGoHome, onOpen, onDelete }) {
  return (
    <div className="history-overlay">
      <div className="history-inner">
        <div className="history-header">
          <div>
            <div className="history-title">Scan History</div>
            <div className="history-count">
              {scans.length} {scans.length === 1 ? "scan" : "scans"}
            </div>
          </div>
          <button
            className="icon-btn"
            type="button"
            onClick={onGoHome}
            aria-label="Go home"
            title="Home"
          >
            <HomeIcon />
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
                  className="icon-btn icon-btn-danger"
                  type="button"
                  aria-label="Delete scan"
                  title="Delete this scan"
                  onClick={(e) => {
                    e.stopPropagation();
                    onDelete(scan.id);
                  }}
                >
                  <TrashIcon />
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
  onGoHome,
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
            className="icon-btn"
            type="button"
            onClick={onGoHome}
            aria-label="Go home"
            title="Home"
          >
            <HomeIcon />
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

function FooterColumn({ title, children }) {
  return (
    <div className="footer-col">
      <div className="footer-col-title">{title}</div>
      <div className="footer-col-links">{children}</div>
    </div>
  );
}

function Footer({ onNavigate }) {
  // Internal links keep their href so they stay middle-clickable and
  // copyable, and hand off to the router on a plain click.
  const internal = (path, label) => (
    <a
      href={path}
      key={path}
      onClick={(e) => {
        e.preventDefault();
        onNavigate(path);
      }}
    >
      {label}
    </a>
  );

  return (
    <footer className="footer">
      <div className="footer-inner">
        <div className="footer-grid">
          <div className="footer-brand">
            <div className="footer-wordmark">QLint</div>
            <p className="footer-tagline">
              Post-quantum cryptography scanning for source repositories.
            </p>
            {/* Stacked under the tagline rather than set apart on its own
                row, which read as a second footer below the first. */}
            <div className="footer-copy">QLint &copy; 2026</div>
          </div>

          <FooterColumn title="Product">
            {internal(BENCHMARK_PATH, "PQC Benchmark Lab")}
            {internal(HELP_PATH, "Help")}
            {internal(ABOUT_PATH, "About Us")}
          </FooterColumn>

          <FooterColumn title="Resources">
            <a href={REPO_URL} target="_blank" rel="noopener noreferrer">
              GitHub
            </a>
            <a href={README_URL} target="_blank" rel="noopener noreferrer">
              Documentation
            </a>
            <a
              href={`${REPO_URL}/issues`}
              target="_blank"
              rel="noopener noreferrer"
            >
              Report an issue
            </a>
          </FooterColumn>

          <FooterColumn title="Legal">
            {internal(TERMS_PATH, "Terms of Service")}
            {internal(PRIVACY_PATH, "Privacy Policy")}
            <a href="mailto:abhushan4625@gmail.com">Contact</a>
          </FooterColumn>
        </div>
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
  // Algorithm filter, applied on top of the severity tab. null means "any
  // algorithm"; it lives here rather than in ResultsView so it survives the
  // same resets as the severity tab.
  const [activeAlgo, setActiveAlgo] = useState(null);
  const [expandedFiles, setExpandedFiles] = useState({});
  const [expandedFixes, setExpandedFixes] = useState({});
  const [urlError, setUrlError] = useState(null);
  // The in-flight POST /scan, so it can be aborted from outside handleScan. A
  // ref rather than state: aborting is a side effect, and nothing renders it.
  const scanAbortRef = useRef(null);

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
  const [authNotice, setAuthNotice] = useState(null);

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

  const activePage = PAGES.find((page) => page.path === route) ?? null;

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
      // The write connection comes back on its own two parameters, so a
      // failed write connection never reads as a failed sign-in.
      write: params.get("github_write"),
      writeError: params.get("github_write_error"),
    };
  });

  // The write connection lands here. Separate effect from sign-in because it
  // is a separate thing: the session is untouched, only the account's write
  // status has changed, so /auth/me is re-read rather than a token stored.
  useEffect(() => {
    const { write, writeError } = oauthLanding;
    if (!write && !writeError) return;
    window.history.replaceState({}, "", window.location.pathname);

    if (writeError) {
      setAuthNotice(githubWriteErrorMessage(writeError));
      return;
    }
    const stored = localStorage.getItem(TOKEN_KEY);
    if (!stored) return;
    fetch(`${API_BASE}/auth/me`, {
      headers: { Authorization: `Bearer ${stored}` },
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) {
          setUser(data);
          setAuthToken(stored);
          showToast("GitHub write access connected");
        }
      })
      .catch(() => {
        setAuthNotice(
          "GitHub granted write access, but QLint could not refresh your account. Reload the page."
        );
      });
  }, []);

  useEffect(() => {
    const oauthToken = oauthLanding.token;
    const oauthError = oauthLanding.error;
    if (!oauthToken && !oauthError) return;

    // Drop the params so a refresh does not replay the callback.
    window.history.replaceState({}, "", window.location.pathname);

    if (oauthError) {
      // A banner rather than a toast: the toast cleared itself after two
      // seconds, which is how a failed sign-in came to look like nothing
      // happening at all.
      setAuthNotice(githubErrorMessage(oauthError));
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
        showToast("Signed in with GitHub");
      })
      .catch(() => {
        localStorage.removeItem(TOKEN_KEY);
        setAuthNotice(
          "GitHub signed you in, but QLint could not confirm the session. Is the backend running?"
        );
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
      // Every file starts collapsed: the report opens as a list of files
      // and their counts, and a file is only unpacked when asked for.
      setExpandedFiles({});
      setExpandedFixes({});
      setActiveFilter("all");
      setActiveAlgo(null);
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

  // The write connection, kept entirely separate from startGithubOAuth above.
  // A POST rather than a plain link so the session token travels in a header
  // instead of a query string; the backend answers with the GitHub consent
  // URL and the browser goes there.
  const connectGithubWrite = async () => {
    if (!authToken) {
      setAuthNotice("Sign in before connecting GitHub write access.");
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/auth/github/write/authorize`, {
        method: "POST",
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      window.location.href = data.authorize_url;
    } catch {
      setAuthNotice(
        "Could not start the GitHub write connection. Is the backend running?"
      );
    }
  };

  const disconnectGithubWrite = async () => {
    if (!authToken) return;
    try {
      const res = await fetch(`${API_BASE}/auth/github/write/disconnect`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setUser((prev) =>
        prev
          ? { ...prev, github_write_connected: false, github_write_username: null }
          : prev
      );
      showToast("GitHub write access disconnected");
    } catch {
      showToast("Could not disconnect write access");
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
    // Aborting this closes the socket, which is what the backend watches for:
    // it polls request.is_disconnected() between batches of files and stops
    // scanning rather than finishing a report nobody is waiting for.
    const controller = new AbortController();
    scanAbortRef.current = controller;
    setView("scanning");
    try {
      const post = (body) => {
        const headers = { "Content-Type": "application/json" };
        if (authToken) headers.Authorization = `Bearer ${authToken}`;
        return fetch(`${API_BASE}/scan`, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
          signal: controller.signal,
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
      // Every file starts collapsed: the report opens as a list of files
      // and their counts, and a file is only unpacked when asked for.
      setExpandedFiles({});
      setExpandedFixes({});
      setActiveFilter("all");
      setActiveAlgo(null);
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
      // A cancel is not a failure: cancelScan has already put the user back on
      // the input view, and showing an error there would report their own
      // deliberate action as something going wrong.
      if (err.name === "AbortError") return;
      const message =
        err instanceof TypeError
          ? "Scan failed. Could not reach the QLint backend."
          : err.message || "Scan failed. Please check the URL and try again.";
      setError(message);
      setView("input");
    } finally {
      if (scanAbortRef.current === controller) scanAbortRef.current = null;
    }
  };

  // Shared by the Cancel button and by any in-app navigation away from a
  // running scan, so leaving the page mid-scan drops the request instead of
  // letting it finish unwatched.
  const abortActiveScan = () => {
    scanAbortRef.current?.abort();
    scanAbortRef.current = null;
  };

  const cancelScan = () => {
    abortActiveScan();
    setError(null);
    setUrlError(null);
    setView("input");
  };

  const handleReset = () => {
    // Reset is also how the user leaves a running scan (the home button), so
    // drop the request rather than leaving the backend fetching for a view
    // that is already gone.
    abortActiveScan();
    setRepoUrl("");
    setGithubToken("");
    setTokenVisible(false);
    setScanResult(null);
    setActiveFilter("all");
    setActiveAlgo(null);
    setExpandedFiles({});
    setExpandedFixes({});
    setError(null);
    setUrlError(null);
    setView("input");
    fetchRateLimit();
  };

  const goHome = () => {
    handleReset();
    navigate(HOME_PATH);
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
        onConnectGithubWrite={connectGithubWrite}
        onDisconnectGithubWrite={disconnectGithubWrite}
        route={route}
        onNavigate={navigate}
        onGoHome={goHome}
      />
      {toast && <Toast message={toast} />}
      {authNotice && (
        <div className="auth-notice" role="alert">
          <span className="auth-notice-text">{authNotice}</span>
          <button
            className="icon-btn auth-notice-close"
            type="button"
            aria-label="Dismiss"
            onClick={() => setAuthNotice(null)}
          >
            <CloseIcon />
          </button>
        </div>
      )}
      <div className="main-content">
        <main className="main">
          {activePage && activePage.render()}
          {!activePage && view === "input" && (
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
            </>
          )}
          {!activePage && view === "scanning" && (
            <ScanningView repoUrl={repoUrl} onCancel={cancelScan} />
          )}
          {!activePage && view === "results" && scanResult && (
            <ResultsView
              result={scanResult}
              activeFilter={activeFilter}
              setActiveFilter={setActiveFilter}
              activeAlgo={activeAlgo}
              setActiveAlgo={setActiveAlgo}
              expandedFiles={expandedFiles}
              setExpandedFiles={setExpandedFiles}
              expandedFixes={expandedFixes}
              setExpandedFixes={setExpandedFixes}
              onReset={handleReset}
              onRescan={() => handleScan(true)}
              authToken={authToken}
              user={user}
              onConnectWrite={connectGithubWrite}
            />
          )}
        </main>
      </div>
      <Footer onNavigate={navigate} />
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
          scans={userScans}
          loading={historyLoading}
          error={historyError}
          onGoHome={() => {
            setShowHistory(false);
            goHome();
          }}
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
          onGoHome={() => {
            setShowAdmin(false);
            goHome();
          }}
          onPageChange={setAdminUsersPage}
          onDeleteUser={deleteAdminUser}
        />
      )}
    </div>
  );
}

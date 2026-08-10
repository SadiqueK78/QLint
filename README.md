# QLint — PQC Migration Scanner

Scan GitHub repositories for quantum-vulnerable cryptographic algorithms and get NIST PQC 2024 compliant migration reports.

## What it does

QLint scans the Python, JavaScript, TypeScript, Go, Java, and Rust code in any public GitHub repository and detects cryptographic algorithms that will be broken (RSA, ECC, DSA, Diffie-Hellman) or weakened (AES-128, SHA-256) by quantum computers. Python detection is AST-based — it parses real syntax trees instead of grepping text, so algorithm names in comments or strings never produce false positives. JavaScript and TypeScript have no stdlib parser to lean on, so they are scanned with context-aware patterns that strip comments and string noise before matching. Every finding comes with a severity rating, the quantum attack vector, and a ready-to-use fix snippet showing the migration to the NIST-standardized post-quantum replacement (ML-KEM, ML-DSA, SLH-DSA). Any finding can also be explained in plain English or turned into a copy-paste unified diff, both generated against your actual code. The whole repository is summarized into a PQC readiness score from 0 to 100.

## Tech Stack

- **Backend:** Python 3.13, FastAPI, httpx
- **Database:** MongoDB (Motor async driver)
- **Auth:** JWT (python-jose) + bcrypt password hashing (passlib)
- **Frontend:** React 18, Vite
- **Scanners:** Python `ast` module; context-aware pattern matching for JS/TS/Go/Java/Rust
- **Output:** SARIF 2.1.0 (GitHub Code Scanning, VS Code), CycloneDX 1.6 CBOM, plus the native JSON report
- **CI:** standalone CLI and a composite GitHub Action, no server or database needed
- **Standards:** NIST FIPS 203, 204, 205 (2024)

## Project Structure

```
QLint/
├── .github/
│   ├── actions/qlint-scan/action.yml   # composite Action wrapping the CLI
│   └── workflows/qlint-self-scan.yml   # dogfooding workflow
├── backend/
│   ├── main.py                  # FastAPI app + router wiring
│   ├── database.py              # Motor client, indexes
│   ├── auth.py                  # JWT, password hashing, current-user deps
│   ├── models.py
│   ├── routers/
│   │   ├── admin_router.py
│   │   ├── auth_router.py
│   │   ├── benchmark_router.py  # PQC benchmark lab
│   │   ├── explain_router.py    # AI explanations, cached
│   │   ├── hndl_router.py       # Harvest Now, Decrypt Later risk
│   │   ├── oauth_router.py
│   │   ├── patch_router.py      # AI migration patches, cached
│   │   ├── scan_router.py
│   │   └── user_router.py
│   ├── ai_explainer.py          # OpenRouter prompt for plain-English answers
│   ├── patch_generator.py       # OpenRouter prompt for unified-diff patches
│   ├── github_client.py         # repo/file fetching, extension mapping
│   ├── vulnerability_db.py      # CRYPTO_DB: severities, fixes, NIST standards
│   ├── ast_scanner.py           # Python (AST)
│   ├── js_scanner.py            # JavaScript / TypeScript
│   ├── go_scanner.py            # Go
│   ├── java_scanner.py          # Java
│   ├── rust_scanner.py          # Rust
│   ├── scanner_engine.py        # orchestration: GitHub repo or local directory
│   ├── sarif_converter.py       # scan report -> SARIF 2.1.0
│   ├── cbom_converter.py        # scan report -> CycloneDX 1.6 CBOM
│   ├── hndl_calculator.py
│   ├── pqc_benchmark.py         # liboqs benchmarks (optional dependency)
│   ├── qlint_cli.py             # standalone CI scanner, no server or database
│   ├── requirements.txt
│   ├── requirements-pqc.txt     # liboqs, only for the benchmark lab
│   ├── pytest.ini
│   ├── .env.example
│   └── tests/                   # one test module per source module
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── PqcBenchmark.jsx
│   │   ├── api.js
│   │   └── main.jsx
│   ├── index.html
│   └── package.json
└── README.md
```

## Setup

### Backend

```bash
cd backend
python -m venv .venv

# Windows (Git Bash):
source .venv/Scripts/activate
# Windows (PowerShell / CMD):
# .venv\Scripts\activate
# Mac / Linux:
# source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env   # then add your GitHub token (see below)
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5174 in your browser.

### GitHub OAuth App

Needed for the **Connect GitHub** and **Continue with GitHub** buttons.

1. Go to github.com -> **Settings** -> **Developer Settings** -> **OAuth Apps**
   -> **New OAuth App**
2. Application name: `QLint`
3. Homepage URL: `http://localhost:5174`
4. Authorization callback URL: `http://localhost:8000/auth/github/callback`
5. Click **Register application**
6. Copy the **Client ID** into `GITHUB_CLIENT_ID` in `backend/.env`
7. Click **Generate a new client secret** and copy it into `GITHUB_CLIENT_SECRET`
8. Restart uvicorn

The frontend dev server is pinned to port 5174 (`frontend/vite.config.js`) so
the callback URL always matches.

### MongoDB

QLint stores accounts, scan history, and the scan cache in MongoDB. It must be
running on `localhost:27017` before you start the backend.

**Windows:**

1. Download the MongoDB Community Server MSI from
   https://www.mongodb.com/try/download/community
2. Run the installer and keep **Install MongoDB as a Service** checked — this
   starts `mongod` on port 27017 automatically at boot.
3. Verify it is running:

```bash
# PowerShell
Get-Service MongoDB
# or, in Git Bash
sc query MongoDB
```

If the service is stopped, start it with `net start MongoDB` (run the terminal
as Administrator).

The `qlint` database and its indexes are created automatically on first
startup — no manual setup needed. If MongoDB is unreachable the API still
starts and anonymous scanning keeps working; accounts, history, and caching are
disabled until it comes back.

### GitHub Token

1. Go to github.com → **Settings** → **Developer Settings** → **Personal Access Tokens** → **Tokens (classic)**
2. Click **Generate new token (classic)**
3. Select only the **public_repo** scope
4. Copy the token and paste it into `backend/.env`:

```
GITHUB_TOKEN=your_token_here
```

### Environment Variables

| Variable               | Default                     | Purpose                                    |
| ---------------------- | --------------------------- | ------------------------------------------ |
| `GITHUB_TOKEN`         | —                           | GitHub API access (required for scanning)  |
| `MONGODB_URI`          | `mongodb://localhost:27017` | MongoDB connection string                  |
| `JWT_SECRET`           | —                           | Signing key for access tokens — change it  |
| `JWT_ALGORITHM`        | `HS256`                     | JWT signing algorithm                      |
| `JWT_EXPIRE_MINUTES`   | `1440`                      | Token lifetime (24 hours)                  |
| `SCAN_CACHE_TTL_HOURS` | `24`                        | How long a cached scan result stays fresh  |
| `ADMIN_SECRET`         | —                           | Shared secret for the one-time admin bootstrap |
| `GITHUB_CLIENT_ID`     | —                           | GitHub OAuth app client ID                 |
| `GITHUB_CLIENT_SECRET` | —                           | GitHub OAuth app client secret             |
| `GITHUB_OAUTH_REDIRECT_URI` | `http://localhost:8000/auth/github/callback` | Must match the OAuth app callback |
| `FRONTEND_URL`         | `http://localhost:5174`     | Where the OAuth callback sends the browser |
| `OPENROUTER_API_KEY`   | —                           | Enables `/scan/explain` (AI explanations) and `/scan/patch` (AI migration patches). Get one at [openrouter.ai/keys](https://openrouter.ai/keys) |
| `OPENROUTER_MODEL`     | `openai/gpt-4o-mini`        | Any model slug OpenRouter hosts (GPT, Claude, Llama, ...) |
| `OPENROUTER_SITE_URL`  | `http://localhost:5174`     | Sent as `HTTP-Referer` per OpenRouter's app-identification convention |
| `OPENROUTER_SITE_NAME` | `QLint`                     | Sent as `X-Title` per OpenRouter's app-identification convention |

## Running Tests

```bash
cd backend
pytest
```

Expected: all tests pass.

## Use QLint in CI

`backend/qlint_cli.py` is a standalone scanner: it walks a directory that is
already on disk and needs no server, database, credentials, or GitHub API
calls. It runs the same scanners and emits the same SARIF 2.1.0 and CycloneDX
CBOM as the web app.

```bash
python backend/qlint_cli.py --path . --output qlint-results.sarif
python backend/qlint_cli.py --path . --format cbom --output qlint-cbom.json
python backend/qlint_cli.py --path ./src --format json --fail-on warning
python backend/qlint_cli.py --path . --exclude "benchmarks/*,vendor/legacy.py"
```

| Flag        | Default               | Description                                              |
| ----------- | --------------------- | -------------------------------------------------------- |
| `--path`    | `.`                   | Directory to scan                                        |
| `--output`  | `qlint-results.sarif` | Where to write results                                   |
| `--format`  | `sarif`               | `sarif` (2.1.0), `cbom` (CycloneDX 1.6), or `json` (the raw report shape) |
| `--exclude` | none                  | Glob patterns to skip; repeatable or comma-separated      |
| `--fail-on` | `critical`            | Exit 1 on findings at or above this level; `none` never fails |

`--fail-on` is what blocks a pull request: `critical` fails on quantum-broken
algorithms (RSA, ECC, Ed25519, MD5, SHA-1), `warning` also fails on weakened
ones (AES-128, SHA-256), `none` reports without gating.

`--exclude` matches repo-relative paths, on top of the built-in pruning of
dot-directories and vendored trees (`node_modules`, `__pycache__`, `dist`, ...).
A pattern that matches a directory excludes everything under it, and excluded
files are never read — they do not count toward `files scanned`. Matching is
case-sensitive on every platform, so a pattern behaves the same on a developer's
machine and on a Linux runner. Use it for code that holds classical algorithms
on purpose: test fixtures, compatibility shims, benchmark baselines.

## CBOM output

A CBOM (Cryptography Bill of Materials) is CycloneDX's standard inventory of
the cryptographic assets a codebase contains. QLint emits CycloneDX 1.6, the
sibling of the SARIF output and built from the same scan.

The two answer different questions. SARIF is "what is wrong and where", one
result per finding, for GitHub Code Scanning and SARIF viewers. A CBOM is "what
cryptography is in here", one component per algorithm with every place it was
seen collected underneath — the artifact a post-quantum migration programme
tracks progress against.

```bash
# CLI
python backend/qlint_cli.py --path . --format cbom --output qlint-cbom.json

# API, anonymous
curl -X POST "http://localhost:8000/scan?format=cbom" \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/owner/repo"}'

# API, a saved scan from your history
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/user/scans/<scan_id>/cbom
```

Each algorithm becomes one `cryptographic-asset` component:

```json
{
  "type": "cryptographic-asset",
  "bom-ref": "crypto/rsa",
  "name": "RSA",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "signature",
      "executionEnvironment": "software-plain-ram",
      "implementationPlatform": "generic",
      "cryptoFunctions": ["keygen", "encrypt", "decrypt", "sign", "verify"],
      "nistQuantumSecurityLevel": 0
    }
  },
  "evidence": {
    "occurrences": [
      { "location": "src/auth.py", "line": 12 },
      { "location": "src/keys.go", "line": 8 }
    ]
  }
}
```

`nistQuantumSecurityLevel: 0` is the field that makes the document useful for
migration tracking: it marks an algorithm as providing no post-quantum
security, and it is emitted only for the quantum-exposed ones. A quantum-safe
component (AES-256, SHA-384, ML-KEM) leaves the field off entirely, so counting
level-0 components across a fleet of CBOMs measures the remaining work.

Two deliberate differences from the SARIF output:

- **The inventory is the scan, not the catalog.** SARIF ships every rule QLint
  knows about whether this scan hit it or not, because tools cache rule
  definitions across runs. A CBOM lists only what was found — an inventory
  naming algorithms the code does not contain would be a false inventory.
- **Library-level notes are not assets.** "This file imports openssl" is a
  finding worth reporting in SARIF, but it names no algorithm, so it is not a
  part a bill of materials can list. An AES usage whose key length the scanner
  could not read *is* listed, with `parameterSetIdentifier` left off.

### GitHub Action

QLint ships a composite Action at `.github/actions/qlint-scan`. To use it from
another repository, point at a tagged release and upload the SARIF so findings
land in that repo's Security tab:

```yaml
name: PQC Scan
on: [push, pull_request]

jobs:
  qlint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: Abhushan187/QLint/.github/actions/qlint-scan@v1
        with:
          fail-on: critical
          exclude: tests/fixtures/*
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: qlint-results.sarif
```

`if: always()` matters: a scan that fails the build is exactly the one whose
results you want uploaded. The Action installs `backend/requirements.txt` only
— static scanning needs no liboqs, so there is no native build step.

`.github/workflows/qlint-self-scan.yml` runs this against QLint itself on every
push and pull request.

## API Endpoints

| Method | Endpoint        | Description              | Example                                                    |
| ------ | --------------- | ------------------------ | ---------------------------------------------------------- |
| GET    | `/health`       | Health check             | Returns `{"status": "ok", "service": "PQC Migration Scanner"}` |
| GET    | `/scan/status`  | GitHub rate limit        | Returns remaining requests + reset time                    |
| POST   | `/scan/preview` | List scannable source files | Body: `{"repo_url": "https://github.com/owner/repo"}`   |
| POST   | `/scan`         | Full vulnerability scan  | Body: `{"repo_url": "https://github.com/owner/repo", "force_refresh": false}` |
| POST   | `/scan/explain` | Explain one finding in plain English (AI) | Body: a finding object from a scan report |
| POST   | `/scan/patch`   | Generate a migration patch for one finding (AI) | Body: a finding object; `code_snippet` and `fix_snippet` required |

Authentication is **optional** on `/scan`. Anonymous scans work as before; send
`Authorization: Bearer <token>` to attribute the scan to an account and have it
appear in that user's history.

### AI Explanations

`POST /scan/explain` turns one finding from a scan report into a short,
plain-English write-up: what the flagged algorithm does, why it's
quantum-vulnerable (or weakened), what actually happens if it's broken, and
how urgent migrating it is. It's powered by [OpenRouter](https://openrouter.ai),
so any model OpenRouter hosts — GPT, Claude, Llama, etc. — can be used by
changing one env var, no code changes required.

Send back the finding exactly as the scan returned it (extra fields are
ignored):

```
{
  "algorithm": "RSA",
  "severity": "critical",
  "attack_vector": "Shor's Algorithm",
  "replacement": "ML-KEM (FIPS 203) for encryption; ML-DSA (FIPS 204) for signatures",
  "replacement_reason": "Shor's Algorithm factors the RSA modulus in polynomial time...",
  "identifier": "rsa.generate_private_key",
  "match_type": "call",
  "language": "python",
  "quantum_vulnerable": true,
  "classical_vulnerable": false,
  "file": "src/crypto.py",
  "line": 12,
  "code_snippet": "private_key = rsa.generate_private_key(key_size=2048)",
  "fix_snippet": "import oqs\nkem = oqs.KeyEncapsulation('ML-KEM-768')"
}
```

`code_snippet` (the flagged line, captured by the scanner) and `fix_snippet`
(the recommended replacement) are what make the answer specific to your code
rather than a description of RSA in general. Every scanner emits both; send
them.

which returns:

```
{"explanation": "...", "model": "openai/gpt-4o-mini", "cached": false}
```

Explanations are cached in MongoDB for 30 days, keyed by the *content* of the
finding — algorithm, severity, attack vector, identifier, match type,
language, and the two code snippets — rather than by file or repo. Two
identical lines of `RSA` anywhere in a codebase share one cached explanation
and one OpenRouter call; two different lines never do, because an explanation
that names one file's variables must not be served for another's. If MongoDB
is unreachable, caching is skipped and every call goes straight to OpenRouter;
the feature still works, it's just not free.

Because each cache miss costs a completion, the endpoint is rate limited to 30
requests per 10 minutes per client address, and answers `429` beyond that. The
window is per backend process: it resets on restart and is not shared between
workers.

Requires `OPENROUTER_API_KEY` (see Environment Variables below). Without it,
`/scan/explain` returns `502` with a message telling you to set it — the rest
of the app is unaffected.

### AI Migration Patches

Where `/scan/explain` answers *why is this a problem*, `POST /scan/patch`
answers *what exactly do I change*. It returns a unified diff migrating one
finding from the flagged code to its quantum-safe replacement — the same
format `git apply` and every code review tool already understands.

In the UI, each finding gets a **Generate Patch** button next to *Explain with
AI*. The diff renders with added, removed, and context lines colour-coded, and
a **Copy** button puts the whole patch on your clipboard.

Send the finding exactly as the scan returned it, the same shape
`/scan/explain` takes:

```
curl -X POST http://localhost:8000/scan/patch \
  -H 'Content-Type: application/json' \
  -d '{
    "algorithm": "RSA",
    "severity": "critical",
    "file": "src/crypto.py",
    "line": 12,
    "language": "python",
    "code_snippet": "private_key = rsa.generate_private_key(key_size=2048)",
    "fix_snippet": "import oqs\nkem = oqs.KeyEncapsulation(\"ML-KEM-768\")"
  }'
```

which returns:

```
{
  "patch": "--- a/src/crypto.py\n+++ b/src/crypto.py\n@@ -12,1 +12,2 @@\n-private_key = rsa.generate_private_key(key_size=2048)\n+kem = oqs.KeyEncapsulation('ML-KEM-768')\n+public_key = kem.generate_keypair()\n",
  "model": "openai/gpt-4o-mini",
  "cached": false
}
```

**`code_snippet` and `fix_snippet` are required here**, unlike on
`/scan/explain` where they are merely strongly recommended. A patch without the
real code is a fabricated diff against lines that may not exist, and a
developer could try to apply it — so the endpoint returns `400` naming the
missing field instead of guessing. Every scanner emits both fields on every
finding, so a finding taken straight from a scan report always qualifies.

The model is instructed to remove the flagged line character for character,
match the surrounding indentation and naming style, change only what the
migration requires, and add any needed imports as a separate hunk at the
import block. A response cut off by the token limit is rejected rather than
returned, because a truncated hunk is not a short patch — it is an unapplyable
one.

Patches are cached in MongoDB for 30 days in their own `patches` collection,
keyed by finding content including both snippets, on the same terms as
explanations: two identical vulnerable lines share one patch and one
OpenRouter call, two different ones never do. If MongoDB is unreachable,
caching is skipped and the feature still works.

Rate limited to **15 requests per 10 minutes** per client address — tighter
than the explainer's 30, because a diff is a longer completion at a larger
token cap. The two limits are separate buckets, so working through patches
cannot lock you out of explanations, or the reverse.

Requires `OPENROUTER_API_KEY`, the same key the explainer uses; there is no new
configuration for this feature. Without it, `/scan/patch` returns `502`.

> AI-generated patches are a starting point, not a merge candidate. Review the
> diff before applying it — hunk header line numbers are approximate.

### Auth

| Method | Endpoint         | Auth | Description                                        |
| ------ | ---------------- | ---- | -------------------------------------------------- |
| POST   | `/auth/register` | —    | Body: `{"email", "password"}` (min 8 chars) → token |
| POST   | `/auth/login`    | —    | Body: `{"email", "password"}` → token              |
| GET    | `/auth/me`       | JWT  | Current user                                       |
| POST   | `/auth/logout`   | JWT  | Client drops the token (stateless JWT)             |

### User

| Method | Endpoint                  | Auth | Description                                     |
| ------ | ------------------------- | ---- | ----------------------------------------------- |
| GET    | `/user/scans`             | JWT  | Paginated history (`page`, `limit` — max 50)    |
| GET    | `/user/scans/{id}/full`   | JWT  | Full stored report for one scan                 |
| DELETE | `/user/scans/{id}`        | JWT  | Delete one of your own scans                    |

### GitHub OAuth

| Method | Endpoint                   | Auth | Description                                  |
| ------ | -------------------------- | ---- | -------------------------------------------- |
| GET    | `/auth/github/login`       | —    | Redirects to GitHub's consent screen         |
| GET    | `/auth/github/callback`    | —    | Exchanges the code, then redirects to the frontend with a JWT |
| GET    | `/auth/github/disconnect`  | JWT  | Clears the stored OAuth token                |

Connecting GitHub stores that user's OAuth token on their account. `POST /scan`
then picks a credential in this order:

1. `github_token` in the request body (a token pasted into the form)
2. the signed-in user's connected GitHub account
3. `GITHUB_TOKEN` from the environment

So a user with GitHub connected never has to paste a token. Signing in through
GitHub also works for brand new accounts: they are created with no password and
can only sign in through GitHub afterwards.

### Admin

Every `/admin` route requires a valid token belonging to an account with
`role: "admin"`, and returns **403 Admin access required** otherwise.

| Method | Endpoint             | Auth   | Description                                    |
| ------ | -------------------- | ------ | ---------------------------------------------- |
| POST   | `/admin/make-admin`  | secret | Bootstrap: `{"email", "secret"}` promotes an account |
| GET    | `/admin/stats`       | admin  | Usage totals, top repos/users/algorithms       |
| GET    | `/admin/users`       | admin  | Paginated user list (`page`, `limit` — max 100) |
| GET    | `/admin/scans`       | admin  | Paginated scan list across all users           |
| DELETE | `/admin/users/{id}`  | admin  | Delete a user and all their scans              |

New accounts are created with `role: "user"`. Grant yourself admin once, using
the `ADMIN_SECRET` from `backend/.env`:

```bash
curl -X POST http://localhost:8000/admin/make-admin -H "Content-Type: application/json" -d '{"email": "you@example.com", "secret": "your_admin_secret"}'
```

`/admin/make-admin` is deliberately unauthenticated — it is the only way to
create the first admin — but it is useless without the secret. An admin cannot
delete their own account.

## Scan Caching

Every completed scan is stored in the `scans` collection with an expiry of
`SCAN_CACHE_TTL_HOURS`. A repeat scan of the same repository within that window
returns the stored report with `"cached": true` plus `cached_at` and
`cache_expires_at`, skipping the GitHub API entirely. Send
`{"force_refresh": true}` (the **Re-scan** button in the UI) to bypass the cache
and run a fresh scan.

Cache keys are normalized, so `.../repo`, `.../repo/`, and `.../repo.git` all
share one entry.

## Supported Languages

| Language   | Status      | Extensions       | Scanner                            |
| ---------- | ----------- | ---------------- | ---------------------------------- |
| Python     | Available   | `.py`            | AST-based (zero false positives)   |
| JavaScript | Available   | `.js`, `.jsx`    | Context-aware pattern matching     |
| TypeScript | Available   | `.ts`, `.tsx`    | Context-aware pattern matching     |
| Go         | Available   | `.go`            | Context-aware pattern matching     |
| Java       | Available   | `.java`          | Context-aware pattern matching     |
| Rust       | Available   | `.rs`            | Context-aware pattern matching     |

A scan report lists every language it touched under `languages_scanned`, and
each finding carries a `language` field.

### JavaScript / TypeScript detection

`js_scanner.py` covers Node `crypto` (createSign/createVerify, createHash,
createCipheriv, createECDH, createDiffieHellman), node-forge, the Web Crypto
`{ name: ... }` algorithm objects, JOSE/JWT algorithm identifiers
(RS/PS/ES/HS/EdDSA), and common libraries (NodeRSA, jsrsasign, elliptic,
@noble). Before any pattern runs, a scanner pass blanks out `//` comments,
`/* */` blocks, and template literals while preserving byte offsets, so a
`// TODO: replace RSA` note never becomes a finding and a URL inside a string
is never mistaken for a comment.

**Note on Ed25519:** QLint classifies Ed25519 and EdDSA as **critical**. Ed25519
is EdDSA over Curve25519 — an elliptic-curve scheme — so Shor's Algorithm breaks
it just as it breaks ECDSA, despite Ed25519 being strong against classical
attacks.

## Roadmap

Shipped:

- ~~F9: Auth (JWT + MongoDB), user accounts, scan history, scan caching~~
- ~~F11: Admin dashboard~~
- ~~F12: GitHub OAuth~~
- ~~F13: JavaScript / TypeScript scanning~~
- ~~F16: Go scanning~~
- ~~F17: HNDL (Harvest Now, Decrypt Later) risk calculator~~
- ~~F18: PQC benchmark lab (liboqs)~~
- ~~F19: SARIF 2.1.0 output~~
- ~~CycloneDX 1.6 CBOM output~~
- ~~F20: Standalone CLI + GitHub Action~~
- ~~F26: Java scanning~~
- ~~F27: Rust scanning~~

Planned:

- F10: Team workspaces
- F14: Stripe integration
- F15: AI context-aware patches

## License

MIT

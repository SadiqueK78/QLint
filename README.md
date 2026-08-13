# QLint — PQC Migration Scanner

Scan GitHub repositories for quantum-vulnerable cryptographic algorithms and get NIST PQC 2024 compliant migration reports.

**Live app:** https://qlint-frontend.onrender.com

## What it does

QLint scans the Python, JavaScript, TypeScript, Go, Java, and Rust code in any public GitHub repository and detects cryptographic algorithms that will be broken (RSA, ECC, DSA, Diffie-Hellman) or weakened (AES-128, SHA-256) by quantum computers. Python detection is AST-based — it parses real syntax trees instead of grepping text, so algorithm names in comments or strings never produce false positives. JavaScript and TypeScript have no stdlib parser to lean on, so they are scanned with context-aware patterns that strip comments and string noise before matching.

Every finding comes with a severity rating, the quantum attack vector, and a ready-to-use fix snippet showing the migration to the NIST-standardized post-quantum replacement (ML-KEM, ML-DSA, SLH-DSA). Any finding can also be explained in plain English or turned into a copy-paste unified diff, both generated against your actual code. The whole repository is summarized into a PQC readiness score from 0 to 100.

Beyond the scan, QLint includes a PQC Benchmark Lab — real, on-demand liboqs execution comparing ML-KEM/ML-DSA against RSA/ECDSA performance and key sizes on this server, not looked-up figures — and an HNDL (Harvest Now, Decrypt Later) risk calculator, which frames a scan's findings against how long the underlying data needs to stay confidential.

## Architecture

QLint is a standard three-tier web app, plus a standalone CLI that reuses the same scanning core outside the web stack: a React/Vite frontend talks to a FastAPI backend, which talks to MongoDB for persistence and to two external services — the GitHub API for repo/file fetching, and OpenRouter for AI explain/patch generation.

Scanning pipeline: a scan request resolves a GitHub repo, walks its files by extension, and routes each file to a language-specific scanner (ast_scanner.py for Python, pattern-based scanners for JS/TS/Go/Java/Rust). Each scanner shares common helpers — line/position tracking, comment-stripping, snippet extraction — through scanner_common.py, so every finding across every language carries the same shape: algorithm, severity, attack vector, and both the vulnerable code and its fix as real, position-accurate snippets. scanner_engine.py orchestrates this whether the source is a GitHub repo (web app) or a local directory (CLI/CI), so both paths run identical detection logic.

Report generation: the scan output feeds three formats — the app's native JSON report, SARIF 2.1.0 (for GitHub Code Scanning and other SARIF viewers), and CycloneDX 1.6 CBOM (a standard cryptography-asset inventory for tracking migration progress across a codebase or fleet).

AI features: the explain and patch endpoints call OpenRouter, grounding every prompt in the real surrounding file content (not just the isolated flagged line) so generated patches match actual indentation and context rather than hallucinating structure. Both are cached in MongoDB, keyed by finding content, so identical vulnerable code anywhere shares one cached result.

One-click PR creation: the flagship feature applies AI-generated patches directly to a user's repository through a real pull request. It uses a separate, explicitly-granted OAuth scope from the read-only scanning connection, re-validates every file against GitHub immediately before patching (skipping anything that changed since the scan rather than guessing), and conservatively skips overlapping findings in the same file rather than merging them automatically.

## Tech Stack

- Backend: Python 3.13, FastAPI, httpx
- Database: MongoDB (Motor async driver)
- Auth: JWT (python-jose) + bcrypt password hashing (passlib), plus GitHub OAuth
- Frontend: React 18, Vite
- Scanners: Python ast module; context-aware pattern matching for JS/TS/Go/Java/Rust
- Output: SARIF 2.1.0, CycloneDX 1.6 CBOM, native JSON
- CI: standalone CLI and a composite GitHub Action, no server or database needed
- PQC: liboqs, compiled from source in the backend Docker image
- Standards: NIST FIPS 203, 204, 205 (2024)

## Project Structure

```
QLint/
├── .github/
│   ├── actions/qlint-scan/action.yml   (composite Action wrapping the CLI)
│   └── workflows/qlint-self-scan.yml   (dogfooding workflow)
├── backend/
│   ├── main.py                  (FastAPI app + router wiring)
│   ├── database.py              (Motor client, indexes)
│   ├── auth.py                  (JWT, password hashing, current-user deps)
│   ├── routers/                 (one router per feature area)
│   ├── ast_scanner.py           (Python, AST-based)
│   ├── js_scanner.py            (JavaScript / TypeScript)
│   ├── go_scanner.py            (Go)
│   ├── java_scanner.py          (Java)
│   ├── rust_scanner.py          (Rust)
│   ├── scanner_engine.py        (orchestration: GitHub repo or local directory)
│   ├── sarif_converter.py       (scan report -> SARIF 2.1.0)
│   ├── cbom_converter.py        (scan report -> CycloneDX 1.6 CBOM)
│   ├── pqc_benchmark.py         (liboqs benchmarks)
│   ├── qlint_cli.py             (standalone CI scanner, no server or database)
│   ├── Dockerfile               (builds liboqs from source, then runs uvicorn)
│   └── tests/                   (one test module per source module)
├── frontend/
│   ├── src/
│   ├── Dockerfile               (vite build -> nginx)
│   └── nginx.conf               (SPA fallback for client-side routes)
├── docker-compose.yml            (mongodb + backend + frontend)
└── README.md
```

## Getting Started

Clone the repo and configure your own environment — nothing here needs a shared secret from anyone else:

```bash
git clone https://github.com/Abhushan187/QLint.git
cd QLint
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
docker compose up --build
```

Frontend runs on http://localhost:5174, backend on http://localhost:8000. MongoDB runs in its own container with a named volume — docker compose down keeps your data, down -v erases it.

Prefer running natively instead of Docker? See backend/requirements.txt and frontend/package.json — standard pip install / npm install plus uvicorn main:app --reload and npm run dev work the same way, minus the PQC Benchmark Lab, which needs liboqs (Docker handles this automatically; a native Windows setup cannot build liboqs directly).

You'll need your own GitHub OAuth App (for the "Continue with GitHub" flow) and, optionally, an OpenRouter API key (for AI explain/patch features) — see backend/.env.example for every variable the app reads.

## Running Tests

```bash
cd backend
pytest
```

## Use QLint in CI

backend/qlint_cli.py is a standalone scanner: it walks a directory already on disk and needs no server, database, credentials, or GitHub API calls. It runs the same scanners and emits the same SARIF/CBOM output as the web app.

```bash
python backend/qlint_cli.py --path . --output qlint-results.sarif
python backend/qlint_cli.py --path . --format cbom --output qlint-cbom.json
python backend/qlint_cli.py --path ./src --format json --fail-on warning
```

QLint also ships a composite GitHub Action at .github/actions/qlint-scan for dropping straight into another repo's CI — see .github/workflows/qlint-self-scan.yml for a working example (QLint scanning itself on every push).

## Supported Languages

Python (.py) — AST-based, zero false positives
JavaScript (.js, .jsx) — context-aware pattern matching
TypeScript (.ts, .tsx) — context-aware pattern matching
Go (.go) — context-aware pattern matching
Java (.java) — context-aware pattern matching
Rust (.rs) — context-aware pattern matching

## Contributing

Contributions are welcome. To get started:

1. Fork the repo and clone your fork
2. Follow the Getting Started steps above to get a local environment running
3. Make your change on a feature branch
4. Run pytest in backend/ and confirm the frontend still builds with npm run build
5. Open a pull request describing what changed and why

For a new language scanner: look at js_scanner.py as a reference implementation, keep the same finding shape (algorithm, severity, attack vector, code_snippet/fix_snippet with accurate line positions), and add corresponding entries to vulnerability_db.py. For anything larger — a new feature area, a new output format — opening an issue first to discuss the approach is appreciated before investing time in a PR.

Bug reports and feature suggestions are just as welcome as code — open an issue either way.

## License

MIT

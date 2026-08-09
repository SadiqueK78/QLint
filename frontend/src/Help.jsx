// Reference page. Everything here describes behaviour that exists today; when
// a feature changes, this file changes with it rather than drifting into a
// second, wrong description of the product.

export default function Help() {
  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Help</h1>
        <p className="page-intro">
          A short reference for what QLint does and how to read what it gives
          back. QLint is free to use and needs no account to scan.
        </p>
      </div>

      <section className="doc-section">
        <h2 className="doc-heading">Scanning a repository</h2>
        <p className="doc-text">
          Paste a public GitHub repository URL into the field on the home page
          and press Scan Repository. Nothing is installed and no account is
          required; QLint reads the repository through the GitHub API and never
          stores your code. For a private repository, or when GitHub's
          unauthenticated rate limit is running low, open Add token and supply a
          personal access token &mdash; it is used for that one request and
          never saved. Signing in connects your GitHub account instead, so the
          token field is no longer needed.
        </p>
        <p className="doc-text">
          Signing in also unlocks the parts of QLint that need a scan to be
          saved against your account: My Scans, which keeps your past scans so
          you can reopen or delete them, and the HNDL Risk Calculator, which
          scores a saved scan. Anonymous scans still produce the full report and
          a SARIF download, they simply are not kept under your name.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">Reading your results</h2>
        <p className="doc-text">
          Every finding carries one of four severities. Critical means the
          algorithm is broken by a quantum computer and must be migrated &mdash;
          RSA, ECC, Ed25519, and the classically broken MD5 and SHA-1 land here.
          Warning means weakened rather than broken, such as AES-128 and SHA-256
          against Grover's algorithm: plan the migration, but there is no
          emergency. Safe means the construction needs no action, and Info marks
          a line worth a human look where the scanner cannot tell on its own
          &mdash; a bare <code>import hashlib</code>, or an AES call whose key
          length is not visible.
        </p>
        <p className="doc-text">
          The PQC Readiness Score summarises the same findings as a single
          number out of 100. It starts at 100 and deducts 15 points for each
          critical finding and 7 for each warning; safe and info findings cost
          nothing, and the score never falls below 0. Treat it as a rough
          measure of migration distance rather than a compliance grade &mdash; a
          large codebase with many call sites for one algorithm will score lower
          than a small one with the same underlying problem.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">HNDL Risk Calculator</h2>
        <p className="doc-text">
          Harvest Now, Decrypt Later is the risk that an adversary records your
          encrypted traffic today and decrypts it years from now, once a
          cryptographically relevant quantum computer exists. Whether that
          matters depends on three things: how long your data stays worth
          reading, when such a machine arrives, and how long this codebase would
          take to migrate. The calculator sits below the results of a saved
          scan; pick a data sensitivity profile and a CRQC timeline scenario,
          and it reports whether the data is exposed along with the years of
          exposure it derives from the findings in that scan. It needs a scan
          held under your account, so sign in before scanning or open one from
          My Scans.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">AI Explain and Migration Patches</h2>
        <p className="doc-text">
          Explain with AI takes one finding and returns a short plain-language
          account of why that specific line is a problem and what replacing it
          would involve. It is grounded in the code QLint actually found, not a
          generic description of the algorithm, and repeated requests for the
          same finding are served from a cache.
        </p>
        <p className="doc-text">
          Generate Patch goes one step further and produces a unified diff that
          migrates the flagged code. Review it before applying it: the diff is
          model-generated, the line numbers in the hunk header are approximate,
          and only you can tell whether the surrounding code and its callers
          survive the change. The same caution appears under every patch in the
          results view. Both features are rate limited per client, since each
          request costs a model call.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">PQC Benchmark Lab</h2>
        <p className="doc-text">
          The Benchmark Lab runs post-quantum cryptography on the QLint server
          when you press the button, then charts the result. It generates keys
          and exchanges shared secrets with ML-KEM, signs and verifies a message
          with ML-DSA, and does the comparable work with classical RSA and ECDSA
          for contrast. Every timing is measured during that run and every key
          and signature size is read from the bytes the algorithm produced, so
          the numbers reflect the machine serving the page rather than a
          published table. The trade it makes visible is the point: the
          post-quantum algorithms are competitive on speed but carry far larger
          keys and signatures.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">Using QLint in CI</h2>
        <p className="doc-text">
          The same scanners run outside the web app. <code>qlint_cli.py</code>{" "}
          is a standalone command-line scanner that walks a directory already on
          disk and needs no server, database, or credentials, and it emits the
          same SARIF 2.1.0 the web app produces. A composite GitHub Action wraps
          it so a workflow can scan on every push and pull request, fail the
          build on findings at or above a severity you choose, and upload the
          SARIF into the repository's Security tab. Flags, exclusion patterns,
          and a complete workflow example are in the{" "}
          <a
            href="https://github.com/Abhushan187/QLint#use-qlint-in-ci"
            target="_blank"
            rel="noopener noreferrer"
          >
            Use QLint in CI
          </a>{" "}
          section of the README.
        </p>
      </section>
    </div>
  );
}

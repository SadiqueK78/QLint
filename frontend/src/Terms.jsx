// Plain-language terms describing how QLint actually behaves. Not reviewed by
// a lawyer, and the page says so rather than implying otherwise.

export default function Terms() {
  return (
    <div className="page page-doc">
      <div className="page-header">
        <h1 className="page-title">Terms of Service</h1>
        <p className="page-intro">
          These terms describe what QLint is, what you can expect from it, and
          what we ask of you in return. They are written to be read, not to be
          skipped. Last updated August 2026.
        </p>
      </div>

      <section className="doc-section">
        <h2 className="doc-heading">What QLint is</h2>
        <p className="doc-text">
          QLint is a static analysis tool that reads a source repository and
          reports where it uses cryptography that a quantum computer would
          break, together with the NIST-standardised algorithms that replace it.
          It scans Python, JavaScript, TypeScript, and Go. It also runs
          post-quantum benchmarks on demand, estimates Harvest Now Decrypt Later
          exposure, and can generate written explanations and migration diffs
          for individual findings.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">The service is free and provided as-is</h2>
        <p className="doc-text">
          QLint costs nothing to use and carries no paid tiers. Scanning does
          not require an account. Because it is free and offered as-is, we make
          no promise that it will be available, that a scan will succeed, or
          that your saved data will survive indefinitely. Features may change or
          be removed. We may take the service down without notice.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">Acceptable use</h2>
        <p className="doc-text">
          Scan repositories you own or are otherwise allowed to analyse. Do not
          use QLint to attack, overload, or probe infrastructure that is not
          yours. The scanning, AI explanation, and patch generation endpoints
          are rate limited per client because each one costs us either GitHub
          API quota or model spend; do not attempt to work around those limits
          through automation, distributed clients, or forged headers. Do not use
          the AI endpoints to generate content unrelated to cryptographic
          migration.
        </p>
        <p className="doc-text">
          We may block clients that ignore these limits, and we may remove
          accounts used to do so.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">Results are informational</h2>
        <p className="doc-text">
          A QLint scan is pattern matching over source code. It will miss things.
          It will occasionally flag code that is fine in context, such as a
          classical algorithm kept deliberately for compatibility. The PQC
          Readiness Score is a rough measure of migration distance, not a
          compliance grade or a certification.
        </p>
        <p className="doc-text">
          AI explanations and generated migration patches are produced by a
          language model and are not verified. Read every generated diff before
          applying it; line numbers in a patch are approximate and only you can
          judge whether the surrounding code and its callers survive the change.
          Nothing QLint produces is a substitute for review by a qualified
          security engineer, and it is not legal or compliance advice.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">Your code and your account</h2>
        <p className="doc-text">
          You keep all rights to the code you scan. QLint reads repositories
          through the GitHub API and does not store their contents. If you sign
          in, we store the scan reports generated for your account so you can
          reopen them, and you can delete any of them from My Scans. The{" "}
          <a href="/privacy">Privacy Policy</a> sets out what is collected in
          detail.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">Disclaimer of warranty and liability</h2>
        <p className="doc-text">
          QLint is provided without warranty of any kind, express or implied,
          including any implied warranty of merchantability, fitness for a
          particular purpose, or non-infringement. To the fullest extent
          permitted by law, the project and its contributors are not liable for
          any loss or damage arising from your use of the service or from
          decisions made on the basis of its output, including any security
          incident involving code QLint scanned.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">Changes and contact</h2>
        <p className="doc-text">
          We may update these terms as the project changes; the date at the top
          reflects the last revision. Questions about these terms can go to{" "}
          <a href="mailto:abhushan4625@gmail.com">abhushan4625@gmail.com</a> or
          to the{" "}
          <a
            href="https://github.com/Abhushan187/QLint/issues"
            target="_blank"
            rel="noopener noreferrer"
          >
            issue tracker
          </a>
          .
        </p>
      </section>
    </div>
  );
}

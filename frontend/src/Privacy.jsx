// Describes what QLint actually stores and sends, checked against the
// backend rather than written from a template.

export default function Privacy() {
  return (
    <div className="page page-doc">
      <div className="page-header">
        <h1 className="page-title">Privacy Policy</h1>
        <p className="page-intro">
          What QLint collects, what it never collects, and where data goes when
          it leaves our server. Last updated August 2026.
        </p>
      </div>

      <section className="doc-section">
        <h2 className="doc-heading">Your repository code is never stored</h2>
        <p className="doc-text">
          QLint reads repository files through GitHub&apos;s API, analyses them
          in memory, and discards them. The source itself is never written to
          our database or to disk. What is kept from a scan is the report: the
          list of findings, each one naming a file, a line number, the algorithm
          matched, and the single flagged line of code that produced the match.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">If you are signed in</h2>
        <p className="doc-text">
          Signing in with GitHub stores your email address, your GitHub
          username, an account creation date, a scan counter, and the OAuth
          access token GitHub issues us. That token is what lets QLint scan
          private repositories on your behalf without you pasting a personal
          access token; you can revoke it at any time with Disconnect in the
          navbar, or from your GitHub account settings. Signing in with an email
          and password stores the email and a bcrypt hash of the password. We
          never store a password in readable form.
        </p>
        <p className="doc-text">
          Scan reports created while you are signed in are saved against your
          account so that My Scans can reopen them, and so the HNDL calculator
          has a scan to score. You can delete any of them from My Scans, which
          removes the report from the database.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">If you are not signed in</h2>
        <p className="doc-text">
          Anonymous scans are not linked to any account and produce no user
          record. The resulting report is still written to a shared results
          cache, recorded against the repository URL and the label
          &quot;anonymous&quot;, so that scanning the same public repository
          again does not spend GitHub API quota repeating work. Cached reports
          expire automatically 24 hours after they are created. Since a scan
          only ever covers a repository you gave us the URL for, nothing in that
          cache identifies you.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">AI features and OpenRouter</h2>
        <p className="doc-text">
          Explain with AI and Generate Patch send one finding at a time to a
          language model hosted by OpenRouter. What is sent is the finding: the
          algorithm name, its severity and attack vector, the recommended
          replacement, the file name and line number, the single flagged line of
          source, and the reference fix from our own database. Your repository
          is not uploaded, and no file is sent in full.
        </p>
        <p className="doc-text">
          Those requests are subject to OpenRouter&apos;s handling of data and
          the policies of whichever model provider serves them. If a finding&apos;s
          flagged line would itself be sensitive, do not use these two features
          on it. Generated explanations and diffs are cached on our side, keyed
          by a hash of the finding, so that asking twice does not send it twice.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">Sessions, cookies, and analytics</h2>
        <p className="doc-text">
          QLint does not set tracking cookies and runs no analytics or
          advertising scripts. A signed-in session is a JSON Web Token held in
          your browser&apos;s local storage and sent on requests that need it;
          logging out deletes it. The token expires on its own after 24 hours.
          Standard web server request logs, which include IP addresses, are
          produced by the backend and are also what the per-client rate limits
          on the scanning and AI endpoints count against.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">Third parties we talk to</h2>
        <p className="doc-text">
          Three, and only when a feature needs them: GitHub, to read repository
          contents and to authenticate you if you choose to sign in with it;
          OpenRouter, for the two AI features described above; and nothing else.
          We do not sell data, and we do not share it with anyone beyond what a
          request you made requires.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">Deleting your data</h2>
        <p className="doc-text">
          Individual scan reports can be deleted from My Scans. To remove an
          account and everything attached to it, email{" "}
          <a href="mailto:abhushan4625@gmail.com">abhushan4625@gmail.com</a> or
          open an issue on the{" "}
          <a
            href="https://github.com/Abhushan187/QLint/issues"
            target="_blank"
            rel="noopener noreferrer"
          >
            issue tracker
          </a>
          . Revoking QLint&apos;s GitHub authorisation from your GitHub settings
          immediately stops us using the stored token.
        </p>
      </section>
    </div>
  );
}

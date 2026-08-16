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
        <h2 className="doc-heading">When you scan a website</h2>
        <p className="doc-text">
          A scan can be pointed at a website instead of a GitHub repository.
          When it is, QLint connects to that live site over the network from
          our server and looks at three things: the TLS configuration it
          negotiates, the HTTP response headers it returns, and the JavaScript
          files the page references, which are fetched and analysed the same
          way repository source is. What is kept is the report — the findings,
          the algorithms matched, and the URLs of the scripts that were read.
        </p>
        <p className="doc-text">
          Only public destinations can be reached this way. QLint does not scan
          private, internal, or otherwise non-public network addresses, and it
          has safeguards that refuse such a target rather than leaving it to
          the person typing the URL. The connection is made from our server, so
          it is our address the scanned site sees, not yours.
        </p>
        <p className="doc-text">
          Website scan reports are saved against your account exactly as
          repository reports are: they appear in My Scans, they can be reopened,
          and you can delete them from the same place. Unlike a repository scan,
          a website scan is never served from the shared results cache described
          below — a live site is the thing whose answer should not be a day old,
          so every website scan is a fresh connection.
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
          navbar, or from your GitHub account settings. GitHub is the only way
          to sign in, so QLint never asks for, receives, or stores a password.
        </p>
        <p className="doc-text">
          Scan reports created while you are signed in are saved against your
          account so that My Scans can reopen them, and so the HNDL calculator
          has a scan to score. You can delete any of them from My Scans, which
          removes the report from the database.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">The shared results cache</h2>
        <p className="doc-text">
          Every scan report is also written to a results cache recorded against
          the repository URL, so that scanning the same public repository again
          does not spend GitHub API quota repeating work. That cache is shared
          across accounts: a report you were served may have been produced by
          somebody else&apos;s scan of the same public repository, and yours may
          be served to them. Cached reports expire automatically 24 hours after
          they are created. Since a scan only ever covers a repository whose URL
          was given to us, nothing in the cache is about you rather than about
          the repository.
        </p>
        <p className="doc-text">
          Reports created before scanning required an account are still labelled
          &quot;anonymous&quot; and are not linked to anyone.
        </p>
      </section>

      <section className="doc-section">
        <h2 className="doc-heading">AI features and OpenRouter</h2>
        <p className="doc-text">
          Explain with AI and Generate Patch send one finding at a time to a
          language model hosted by OpenRouter. This applies to both kinds of
          finding: a code finding from a repository scan and a website finding
          from a TLS, header, or JavaScript check are each sent the same way
          when you ask for an explanation of one.
        </p>
        <p className="doc-text">
          What is sent is that finding and nothing around it. For a code
          finding: the algorithm name, its severity and attack vector, the
          recommended replacement, the file name and line number, the single
          flagged line of source, and the reference fix from our own database.
          For a website finding: the URL that was scanned, what was observed —
          the protocol, cipher suite, certificate detail, header, or script
          reference the finding is about — and the same severity and
          recommendation. Your repository is not uploaded, no file is sent in
          full, and nothing is sent about a site beyond the finding itself.
        </p>
        <p className="doc-text">
          Those requests are subject to OpenRouter&apos;s handling of data and
          the policies of whichever model provider serves them. If a finding&apos;s
          flagged line, or the URL it names, would itself be sensitive, do not
          use these features
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
          Two services, and only when a feature needs them: GitHub, to read
          repository
          contents and to authenticate you if you choose to sign in with it;
          and OpenRouter, for the two AI features described above. Beyond those,
          the only other host QLint contacts is a site you have asked it to
          scan, which it reaches directly and only for that scan.
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

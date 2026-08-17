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
      "Sign in, paste a public GitHub repository URL into the field on the home page, and press Scan Repository. Nothing is installed and nothing is cloned to your machine: QLint reads the repository through the GitHub API, analyses it in memory, and discards the source; only the report is kept.",
      "A scan covers Python, JavaScript, TypeScript, Go, Java, and Rust files. Everything else is skipped, along with vendored trees like node_modules and __pycache__.",
    ],
  },
  {
    q: "What does signing in unlock?",
    a: [
      "Scanning itself, first of all: a scan spends GitHub API quota and writes a stored report, so it runs against an account rather than anonymously. Every scan you run is then saved under your name, which is what My Scans lists and what the HNDL Risk Calculator scores.",
      "Signing in is GitHub only — there is no separate QLint password to create or remember, and continuing with GitHub the first time is what creates your account. It also supplies the API credential automatically, so you no longer need to paste a personal access token, and it is the connection the SARIF, CBOM, and SBOM downloads are served against. Creating pull requests needs a second, separate grant on top of it.",
    ],
  },
  {
    q: "How do I scan a website instead of a repository?",
    a: [
      "Use the dropdown to the left of the scan field on the home page and change it from Repository to Website. The field and the button change with it: paste the address of the site you want to look at, such as https://example.com, and press Scan Website.",
      "A website scan looks at a live site as it is served to a browser right now, where a repository scan reads source code. They answer different questions, so neither replaces the other, and both are saved under your account and listed together in My Scans.",
    ],
  },
  {
    q: "What does a website scan actually check?",
    a: [
      "Three things, all of them what an ordinary visitor's browser would see. First, the secure connection itself: which version of TLS the site negotiates, the encryption it agrees to use, and the certificate it presents, including what signed that certificate and how long it is still valid for. Second, the response headers the site sends back, the settings that tell a browser how strictly to treat the connection. Third, the JavaScript the page pulls in, which QLint fetches and reads for cryptographic code the same way it reads a repository.",
      "The point of all three is the same as a repository scan: finding cryptography that a quantum computer would break. The difference is that nothing here needs access to your source code, so you can point it at any public site, including one you did not build.",
    ],
  },
  {
    q: "Why does my website report say some checks did not run?",
    a: [
      "A report covers three checks, and when one cannot complete the other results are still shown rather than the whole scan being thrown away. The report names each check that did not run and why, so a partial answer never looks like a clean one.",
      "The most common reason is a site whose certificate has expired or is otherwise not valid. The certificate check copes with that on purpose, because an expired certificate is itself worth reporting, so that section fills in normally and tells you what is wrong with it. The header and JavaScript checks cannot: both need a working secure connection before there is anything to read, and on that site there is not one. So a scan of a site with a bad certificate typically gives you a full certificate section and those two checks marked as not run.",
    ],
  },
  {
    q: "Why can't I scan an internal or private website?",
    a: [
      "Only public sites, reachable from the open internet, can be scanned. An address on a private network, a machine on your own computer, or anything else that is only visible from inside a network is refused before the scan starts.",
      "This is a safety rule rather than a limitation we expect to lift. A website scan is performed by QLint's own servers rather than by your browser, so the sites it will agree to visit are deliberately limited to ones anybody could visit anyway. Scanning code that is not public is what repository scanning is for, and that works on private repositories once you have connected an account that can read them.",
    ],
  },
  {
    q: "How many website scans can I run a day?",
    a: [
      "Five a day, counted against your account. A website scan reaches out to somebody else's server and does real work there, so the limit keeps QLint from looking like a nuisance to the sites being scanned.",
      "It is a separate allowance from repository scanning: running website scans does not use up repository scans, and repository scans do not use up website scans. The allowance refills as the day rolls forward rather than resetting at a fixed hour, so the earliest of your five becomes available again twenty-four hours after you used it.",
    ],
  },
  {
    q: "Do the CBOM download and Explain with AI work for website scans?",
    a: [
      "Both work. Explain with AI sits on a website finding exactly as it does on a code finding, and returns the same kind of short plain-language account of what the finding means and what fixing it would involve. The CBOM download is on the results page and inventories the cryptography the scan found on that site.",
      "CBOM is the only report you can download from a website scan, and SARIF and SBOM are not offered. Both of those describe a codebase: SARIF annotates findings against files and line numbers, which a live site does not have, and an SBOM lists the dependencies declared in a repository's manifests, which are not visible from outside. A CBOM is an inventory of cryptography in use, which is exactly what a website scan produces.",
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
    q: "What does \"Create Pull Request\" do?",
    a: [
      "It takes the findings you tick on the consent screen, applies the generated patches to the files they came from, and opens a pull request on your repository with the result. QLint always creates a new branch for those commits; your default branch is never written to directly.",
      "Nothing is merged automatically. The pull request sits there like any other, and you review it, ask for changes, merge it, or close it. If a finding cannot be patched cleanly it is left out and listed as skipped rather than forced in.",
    ],
  },
  {
    q: "Why do I need to connect write access separately?",
    a: [
      "The connection QLint uses to scan is read-only: it can list files and read their contents, and that is all it can do. Creating a branch, a commit, and a pull request needs permission to write, which is a different and higher level of access.",
      "Keeping them apart means signing in to scan never quietly grants the ability to change your repositories. You grant write access as its own deliberate step, from the profile menu or from the pull request screen, and you can disconnect it again without affecting scanning. The write grant asks for the public_repo scope, the narrowest GitHub offers that can open a pull request.",
    ],
  },
  {
    q: "Can I create a pull request on a repository I don't own?",
    a: [
      "Only if the connected GitHub account has write access to that particular repository, which in practice means you own it or somebody has added you as a collaborator. Connecting write access grants QLint permission to act as you; it does not grant you permission you do not already have, and GitHub decides that repository by repository.",
      "QLint checks this before it writes anything, so a repository you cannot push to gives you a plain explanation rather than a confusing half-finished failure partway through. The work is not wasted either way: the generated patches stay on the results screen for you to review and apply by hand, or you can fork the repository on GitHub, scan your fork, and open the pull request from there.",
    ],
  },
  {
    q: "What happens if my code changed since I scanned it?",
    a: [
      "QLint re-reads every file from GitHub immediately before patching it and compares each finding against the line the scan recorded. If that line has moved, changed, or gone, the patch is not applied: guessing where it went would mean editing code nobody has looked at.",
      "Those findings are skipped, not silently dropped. The result screen shows a \"Skipped, and why\" section naming each one, its file and line, and the reason it was left alone, and the same list appears in the pull request body. Re-scan the repository and create the pull request again to pick them up against the current code.",
    ],
  },
  {
    q: "Is it safe to just click Create Pull Request?",
    a: [
      "It is a pull request, not a merge. Nothing lands on your default branch, and closing the pull request without merging leaves your repository exactly as it is today; the branch it created can be deleted like any other.",
      "That said, the changes are model-generated, the same as the patches in the results view. Read the diff before merging, check the callers of anything it touched, and run your tests. Treat it as a well-informed first draft from a contributor who has not seen the rest of your codebase.",
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
    q: "What is an SBOM, and how is it different from the CBOM?",
    a: [
      "They answer different questions about the same repository. A CBOM, a cryptography bill of materials, inventories the cryptographic algorithms QLint found in the code: every place each one is used, and whether a quantum computer breaks it. An SBOM, a software bill of materials, inventories the packages the repository depends on, with versions where its manifests name exactly one.",
      "Both are CycloneDX 1.6, the same industry standard, so either file drops into the supply-chain tooling your organisation already runs. The SBOM is built when you press the button, by reading the repository's own dependency manifests from its root: requirements.txt, package.json, go.mod, pom.xml, or Cargo.toml. If one of those is missing or cannot be parsed, the file says which language it could not cover instead of quietly leaving it out.",
    ],
  },
  {
    q: "What is SLH-DSA, and why is it in the Benchmark Lab?",
    a: [
      "SLH-DSA is FIPS 205, one of the three algorithms NIST standardized in 2024 and the second of its two signature schemes. Where ML-DSA's security rests on the hardness of lattice problems, SLH-DSA's rests on nothing beyond the hash functions it is built from, which is a much older and more thoroughly studied foundation.",
      "That is the reason both were standardized rather than only the faster one: if lattice cryptography is ever broken, a signature scheme resting on entirely different mathematics does not fall with it. The cost of that insurance is visible in the measured numbers on the Benchmark Lab page, where SLH-DSA signs roughly forty times slower than ML-DSA and produces signatures several times larger. That is also why the page measures it over fewer iterations than the other rows, and says so beside the result.",
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
          them. QLint is free to use; scanning runs against an account, so every
          report is saved under yours.
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

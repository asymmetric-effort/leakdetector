import { createElement, useHead } from "@asymmetric-effort/specifyjs";

export function Home() {
  useHead({
    title: "leakdetector — Secret Detection for Git Repositories",
    description:
      "A zero-dependency Go CLI tool for detecting leaked secrets and sensitive information in git repositories.",
    canonical: "https://leakdetector.asymmetric-effort.com/",
    og: {
      title: "leakdetector — Secret Detection for Git Repositories",
      description:
        "A zero-dependency Go CLI tool for detecting leaked secrets and sensitive information in git repositories.",
      url: "https://leakdetector.asymmetric-effort.com/",
      type: "website",
    },
  });

  return (
    <div>
      <div class="hero">
        <img src="/logo.png" alt="leakdetector logo" class="hero-logo" width="100" height="100" />
        <h1>leakdetector</h1>
        <p>
          A fast, zero-dependency CLI tool for detecting leaked secrets in git repositories.
          Built in Go with 250+ built-in detection rules, Shannon entropy filtering,
          and comprehensive output formats.
        </p>
        <div class="hero-badges">
          <span class="badge badge-primary">Zero Dependencies</span>
          <span class="badge badge-primary">Go 1.26+</span>
          <span class="badge badge-success">MIT License</span>
          <span class="badge badge-success">98%+ Coverage</span>
          <span class="badge badge-primary">250+ Rules</span>
        </div>
      </div>

      <div class="section">
        <h2>Installation</h2>
        <p>Build from source using the included Makefile:</p>
        <pre><code>{`git clone https://github.com/asymmetric-effort/leakdetector.git
cd leakdetector
make build`}</code></pre>
        <p>The compiled binary will be placed in the <code>build/</code> directory.</p>
      </div>

      <div class="section">
        <h2>Quick Start</h2>

        <h3>Scan the current repository</h3>
        <pre><code>{`leakdetector`}</code></pre>

        <h3>Scan a specific directory with JSON output</h3>
        <pre><code>{`leakdetector --format json --report results.json /path/to/repo`}</code></pre>

        <h3>Scan staged changes before committing</h3>
        <pre><code>{`leakdetector --staged`}</code></pre>
      </div>

      <div class="section">
        <h2>Features</h2>
        <div class="feature-cards">
          <div class="feature-card">
            <h3>250+ Built-in Rules</h3>
            <p>Detect AWS keys, GitHub tokens, private keys, database URIs, and more</p>
          </div>
          <div class="feature-card">
            <h3>Zero Dependencies</h3>
            <p>Pure Go standard library — no external runtime dependencies</p>
          </div>
          <div class="feature-card">
            <h3>Shannon Entropy</h3>
            <p>Filter findings by information entropy to reduce false positives</p>
          </div>
          <div class="feature-card">
            <h3>Archive Scanning</h3>
            <p>Scan inside zip, tar, gzip, and bzip2 archives</p>
          </div>
          <div class="feature-card">
            <h3>Proximity / Composite Rules</h3>
            <p>Combine multiple patterns that must appear near each other</p>
          </div>
          <div class="feature-card">
            <h3>Multiple Output Formats</h3>
            <p>JSON, CSV, JUnit XML, SARIF 2.1.0, and custom Go templates</p>
          </div>
          <div class="feature-card">
            <h3>YAML Configuration</h3>
            <p>Configure via <code>.leakdetector.yml</code> with allowlists and rule overrides</p>
          </div>
          <div class="feature-card">
            <h3>Allowlists &amp; Baselines</h3>
            <p>Suppress known findings with allowlists, baselines, and inline comments</p>
          </div>
          <div class="feature-card">
            <h3>Platform Links</h3>
            <p>Generate direct links to findings on GitHub or GitLab</p>
          </div>
          <div class="feature-card">
            <h3>.leakdetectorignore</h3>
            <p>Gitignore-style file to exclude paths from scanning</p>
          </div>
        </div>
      </div>

      <div class="section">
        <h2>Scanning Modes</h2>
        <table>
          <thead>
            <tr>
              <th>Mode</th>
              <th>Flag</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Full History</td>
              <td><em>(default)</em></td>
              <td>Scan every commit in the repository history</td>
            </tr>
            <tr>
              <td>Skip History</td>
              <td><code>--skip-history</code></td>
              <td>Scan only the current working tree, ignoring git history</td>
            </tr>
            <tr>
              <td>Branch</td>
              <td><code>{"--branch <name>"}</code></td>
              <td>Scan commits reachable from a specific branch</td>
            </tr>
            <tr>
              <td>Staged</td>
              <td><code>--staged</code></td>
              <td>Scan only staged (indexed) changes, ideal for pre-commit hooks</td>
            </tr>
            <tr>
              <td>Stdin</td>
              <td><code>--stdin</code></td>
              <td>Read content from standard input for scanning</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

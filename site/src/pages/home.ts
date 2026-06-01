export function HomePage(): string {
  return `
<div class="hero">
  <img src="/logo.png" alt="leakdetector logo" class="hero-logo">
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
  <pre><code>git clone https://github.com/asymmetric-effort/leakdetector.git
cd leakdetector
make build</code></pre>
  <p>The compiled binary will be placed in the <code>build/</code> directory.</p>
</div>

<div class="section">
  <h2>Quick Start</h2>

  <h3>Scan the current repository</h3>
  <pre><code>leakdetector</code></pre>

  <h3>Scan a specific directory with JSON output</h3>
  <pre><code>leakdetector --format json --report results.json /path/to/repo</code></pre>

  <h3>Scan staged changes before committing</h3>
  <pre><code>leakdetector --staged</code></pre>
</div>

<div class="section">
  <h2>Features</h2>
  <table>
    <thead>
      <tr>
        <th>Feature</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>250+ Built-in Rules</td>
        <td>Detect AWS keys, GitHub tokens, private keys, database URIs, and more</td>
      </tr>
      <tr>
        <td>Zero Dependencies</td>
        <td>Pure Go standard library &mdash; no external runtime dependencies</td>
      </tr>
      <tr>
        <td>Shannon Entropy</td>
        <td>Filter findings by information entropy to reduce false positives</td>
      </tr>
      <tr>
        <td>Archive Scanning</td>
        <td>Scan inside zip, tar, gzip, and bzip2 archives</td>
      </tr>
      <tr>
        <td>Proximity / Composite Rules</td>
        <td>Combine multiple patterns that must appear near each other</td>
      </tr>
      <tr>
        <td>Multiple Output Formats</td>
        <td>JSON, CSV, JUnit XML, SARIF 2.1.0, and custom Go templates</td>
      </tr>
      <tr>
        <td>YAML Configuration</td>
        <td>Configure via <code>.leakdetector.yml</code> with allowlists and rule overrides</td>
      </tr>
      <tr>
        <td>Allowlists &amp; Baselines</td>
        <td>Suppress known findings with allowlists, baselines, and inline comments</td>
      </tr>
      <tr>
        <td>Platform Links</td>
        <td>Generate direct links to findings on GitHub or GitLab</td>
      </tr>
      <tr>
        <td>.leakdetectorignore</td>
        <td>Gitignore-style file to exclude paths from scanning</td>
      </tr>
    </tbody>
  </table>
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
        <td><code>--branch &lt;name&gt;</code></td>
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
`;
}

import { createElement, useHead } from "@asymmetric-effort/specifyjs";

export function Usage() {
  useHead({
    title: "Usage — leakdetector",
    description:
      "CLI reference, flags, examples, exit codes, and CI/CD integration for leakdetector.",
    canonical: "https://leakdetector.asymmetric-effort.com/#/usage",
    og: {
      title: "Usage — leakdetector",
      description:
        "CLI reference, flags, examples, exit codes, and CI/CD integration for leakdetector.",
      url: "https://leakdetector.asymmetric-effort.com/#/usage",
      type: "website",
    },
  });

  return (
    <div>
      <div class="section">
        <h2>CLI Reference</h2>
        <p>
          <code>leakdetector</code> scans git repositories for leaked secrets.
          Run it with no arguments to scan the current directory, or pass a path to scan a specific repository.
        </p>
        <pre><code>{`leakdetector [flags] [path]`}</code></pre>
      </div>

      <div class="section">
        <h2>Flags</h2>
        <table>
          <thead>
            <tr>
              <th>Flag</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>--skip-history</code></td>
              <td>Scan only the working tree, skipping git history</td>
            </tr>
            <tr>
              <td><code>{"--branch <name>"}</code></td>
              <td>Scan commits reachable from the specified branch</td>
            </tr>
            <tr>
              <td><code>--staged</code></td>
              <td>Scan only staged (indexed) changes</td>
            </tr>
            <tr>
              <td><code>{"--config <path>"}</code></td>
              <td>Path to a <code>.leakdetector.yml</code> configuration file</td>
            </tr>
            <tr>
              <td><code>{"--report <path>"}</code></td>
              <td>Write findings to the specified file instead of stdout</td>
            </tr>
            <tr>
              <td><code>{"--format <fmt>"}</code></td>
              <td>Output format: <code>json</code>, <code>csv</code>, <code>junit</code>, <code>sarif</code>, or <code>template</code></td>
            </tr>
            <tr>
              <td><code>{"--redact <pct>"}</code></td>
              <td>Redact secrets in output, replacing the given percentage of characters</td>
            </tr>
            <tr>
              <td><code>--verbose</code></td>
              <td>Enable verbose logging to stderr</td>
            </tr>
            <tr>
              <td><code>{"--enable-rule <id>"}</code></td>
              <td>Enable only the specified rule(s); may be repeated</td>
            </tr>
            <tr>
              <td><code>{"--max-findings <n>"}</code></td>
              <td>Stop scanning after <em>n</em> findings</td>
            </tr>
            <tr>
              <td><code>{"--max-file-size <bytes>"}</code></td>
              <td>Skip files larger than the given size in bytes</td>
            </tr>
            <tr>
              <td><code>{"--max-decode-depth <n>"}</code></td>
              <td>Maximum depth for recursive Base64 / hex decoding</td>
            </tr>
            <tr>
              <td><code>{"--max-archive-depth <n>"}</code></td>
              <td>Maximum depth for nested archive extraction (zip, tar, gzip, bzip2)</td>
            </tr>
            <tr>
              <td><code>--follow-symlinks</code></td>
              <td>Follow symbolic links when scanning the working tree</td>
            </tr>
            <tr>
              <td><code>{"--timeout <duration>"}</code></td>
              <td>Maximum scan duration (e.g. <code>5m</code>, <code>1h</code>)</td>
            </tr>
            <tr>
              <td><code>{"--platform <name>"}</code></td>
              <td>Generate links to findings on <code>github</code> or <code>gitlab</code></td>
            </tr>
            <tr>
              <td><code>{"--baseline <path>"}</code></td>
              <td>Path to a baseline report; only new findings are reported</td>
            </tr>
            <tr>
              <td><code>--stdin</code></td>
              <td>Read content from standard input instead of a git repository</td>
            </tr>
            <tr>
              <td><code>--version</code></td>
              <td>Print the version and exit</td>
            </tr>
            <tr>
              <td><code>--help</code></td>
              <td>Show help message and exit</td>
            </tr>
            <tr>
              <td><code>{"--exit-code <n>"}</code></td>
              <td>Override the exit code used when leaks are found</td>
            </tr>
            <tr>
              <td><code>--no-color</code></td>
              <td>Disable colored output</td>
            </tr>
            <tr>
              <td><code>{"--report-template <path>"}</code></td>
              <td>Path to a Go <code>text/template</code> file for custom output (use with <code>--format template</code>)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="section">
        <h2>Examples</h2>

        <h3>Scan the current repository</h3>
        <pre><code>{`leakdetector`}</code></pre>

        <h3>Scan with JSON output written to a file</h3>
        <pre><code>{`leakdetector --format json --report findings.json`}</code></pre>

        <h3>Scan only staged changes</h3>
        <pre><code>{`leakdetector --staged`}</code></pre>

        <h3>Scan a specific branch with redacted output</h3>
        <pre><code>{`leakdetector --branch main --redact 80`}</code></pre>

        <h3>Scan with a baseline to find only new leaks</h3>
        <pre><code>{`leakdetector --baseline baseline.json --format json`}</code></pre>

        <h3>Scan from stdin</h3>
        <pre><code>{`cat secrets.txt | leakdetector --stdin`}</code></pre>

        <h3>Generate SARIF output with GitHub links</h3>
        <pre><code>{`leakdetector --format sarif --platform github --report results.sarif`}</code></pre>
      </div>

      <div class="section">
        <h2>Exit Codes</h2>
        <table>
          <thead>
            <tr>
              <th>Code</th>
              <th>Meaning</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>0</code></td>
              <td>No leaks found</td>
            </tr>
            <tr>
              <td><code>1</code></td>
              <td>Leaks found</td>
            </tr>
            <tr>
              <td><code>2</code></td>
              <td>Error (invalid arguments, I/O failure, etc.)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="section">
        <h2>CI/CD Integration</h2>

        <h3>GitHub Actions with SARIF Upload</h3>
        <pre><code>{`name: Leak Detection
on: [push, pull_request]

jobs:
  leakdetector:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Build leakdetector
        run: |
          git clone https://github.com/asymmetric-effort/leakdetector.git /tmp/ld
          cd /tmp/ld && make build
          cp /tmp/ld/build/leakdetector /usr/local/bin/

      - name: Run leakdetector
        run: leakdetector --format sarif --report results.sarif --platform github

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif`}</code></pre>

        <h3>Pre-commit Hook</h3>
        <p>
          Add the following to <code>.git/hooks/pre-commit</code> (or use a pre-commit framework):
        </p>
        <pre><code>{`#!/usr/bin/env bash
set -euo pipefail
leakdetector --staged`}</code></pre>
        <p>Make it executable:</p>
        <pre><code>{`chmod +x .git/hooks/pre-commit`}</code></pre>
      </div>
    </div>
  );
}

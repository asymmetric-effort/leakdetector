import { createElement, useHead } from "@asymmetric-effort/specifyjs";

export function Output() {
  useHead({
    title: "Output Formats — leakdetector",
    description:
      "leakdetector output formats: JSON, CSV, JUnit XML, SARIF 2.1.0, custom templates, redaction, baselines, and platform links.",
    canonical: "https://leakdetector.asymmetric-effort.com/#/output",
    og: {
      title: "Output Formats — leakdetector",
      description:
        "leakdetector output formats: JSON, CSV, JUnit XML, SARIF 2.1.0, custom templates, redaction, baselines, and platform links.",
      url: "https://leakdetector.asymmetric-effort.com/#/output",
      type: "website",
    },
  });

  return (
    <div>
      <div class="section">
        <h2>Output Formats</h2>
        <p>
          leakdetector supports multiple output formats via the <code>--format</code> flag.
          Output is written to stdout by default; use <code>{"--report <path>"}</code> to write to a file.
        </p>
        <table>
          <thead>
            <tr>
              <th>Format</th>
              <th>Flag Value</th>
              <th>Use Case</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>JSON</td>
              <td><code>json</code></td>
              <td>Programmatic consumption, CI/CD pipelines, baseline files</td>
            </tr>
            <tr>
              <td>CSV</td>
              <td><code>csv</code></td>
              <td>Spreadsheet analysis, data import</td>
            </tr>
            <tr>
              <td>JUnit XML</td>
              <td><code>junit</code></td>
              <td>CI/CD test reporting (Jenkins, GitLab CI, etc.)</td>
            </tr>
            <tr>
              <td>SARIF 2.1.0</td>
              <td><code>sarif</code></td>
              <td>GitHub Code Scanning, IDE integration, security dashboards</td>
            </tr>
            <tr>
              <td>Custom Template</td>
              <td><code>template</code></td>
              <td>Any custom format via Go <code>text/template</code></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="section">
        <h2>JSON</h2>
        <p>
          The default machine-readable format. Each finding is an object in the top-level array.
        </p>
        <pre><code>{`leakdetector --format json --report findings.json`}</code></pre>
        <pre><code>{`[
  {
    "rule_id": "aws-access-key",
    "description": "AWS Access Key ID",
    "secret": "AKIAIOSFODNN7EXAMPLE",
    "file": "config/credentials.yml",
    "line": 12,
    "commit": "a1b2c3d4e5f6",
    "author": "developer@example.com",
    "date": "2026-01-15T10:30:00Z",
    "entropy": 3.82,
    "severity": "critical",
    "tags": ["aws", "cloud"],
    "link": "https://github.com/org/repo/blob/a1b2c3d/config/credentials.yml#L12"
  }
]`}</code></pre>
      </div>

      <div class="section">
        <h2>CSV</h2>
        <p>
          Comma-separated values with a header row. Suitable for importing into spreadsheets or databases.
        </p>
        <pre><code>{`leakdetector --format csv --report findings.csv`}</code></pre>
        <pre><code>{`rule_id,description,secret,file,line,commit,author,date,entropy,severity
aws-access-key,AWS Access Key ID,AKIAIOSFODNN7EXAMPLE,config/credentials.yml,12,a1b2c3d4e5f6,developer@example.com,2026-01-15T10:30:00Z,3.82,critical`}</code></pre>
      </div>

      <div class="section">
        <h2>JUnit XML</h2>
        <p>
          JUnit-compatible XML for CI/CD systems that consume test results.
          Each finding is reported as a test failure.
        </p>
        <pre><code>{`leakdetector --format junit --report findings.xml`}</code></pre>
        <pre><code>{`<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="leakdetector" tests="1" failures="1">
    <testcase
      name="aws-access-key"
      classname="config/credentials.yml">
      <failure
        message="AWS Access Key ID"
        type="critical">
        File: config/credentials.yml
        Line: 12
        Commit: a1b2c3d4e5f6
        Secret: AKIAIOSFODNN7EXAMPLE
      </failure>
    </testcase>
  </testsuite>
</testsuites>`}</code></pre>
      </div>

      <div class="section">
        <h2>SARIF 2.1.0</h2>
        <p>
          Static Analysis Results Interchange Format, supported by GitHub Code Scanning,
          VS Code, and other security tools.
        </p>
        <pre><code>{`leakdetector --format sarif --report results.sarif`}</code></pre>
        <pre><code>{`{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "leakdetector",
          "informationUri": "https://github.com/asymmetric-effort/leakdetector",
          "rules": [
            {
              "id": "aws-access-key",
              "shortDescription": {
                "text": "AWS Access Key ID"
              },
              "defaultConfiguration": {
                "level": "error"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "aws-access-key",
          "level": "error",
          "message": {
            "text": "AWS Access Key ID found in config/credentials.yml"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "config/credentials.yml"
                },
                "region": {
                  "startLine": 12
                }
              }
            }
          ]
        }
      ]
    }
  ]
}`}</code></pre>
      </div>

      <div class="section">
        <h2>Custom Templates</h2>
        <p>
          Use Go <code>text/template</code> syntax to define any output format. Specify the
          template file with <code>--report-template</code> and set <code>--format template</code>.
        </p>
        <pre><code>{`leakdetector --format template --report-template report.tmpl`}</code></pre>
        <p>
          The template receives a list of findings. Each finding exposes the following fields:
        </p>
        <table>
          <thead>
            <tr>
              <th>Field</th>
              <th>Type</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>.RuleID</code></td>
              <td>string</td>
              <td>The rule identifier</td>
            </tr>
            <tr>
              <td><code>.Description</code></td>
              <td>string</td>
              <td>Human-readable rule description</td>
            </tr>
            <tr>
              <td><code>.Secret</code></td>
              <td>string</td>
              <td>The matched secret value</td>
            </tr>
            <tr>
              <td><code>.File</code></td>
              <td>string</td>
              <td>File path where the secret was found</td>
            </tr>
            <tr>
              <td><code>.Line</code></td>
              <td>int</td>
              <td>Line number of the finding</td>
            </tr>
            <tr>
              <td><code>.Commit</code></td>
              <td>string</td>
              <td>Commit SHA (empty for working-tree scans)</td>
            </tr>
            <tr>
              <td><code>.Author</code></td>
              <td>string</td>
              <td>Commit author email</td>
            </tr>
            <tr>
              <td><code>.Date</code></td>
              <td>string</td>
              <td>Commit date in RFC 3339 format</td>
            </tr>
            <tr>
              <td><code>.Entropy</code></td>
              <td>float64</td>
              <td>Shannon entropy of the matched secret</td>
            </tr>
            <tr>
              <td><code>.Severity</code></td>
              <td>string</td>
              <td>Rule severity level</td>
            </tr>
            <tr>
              <td><code>.Link</code></td>
              <td>string</td>
              <td>Platform link (if <code>--platform</code> is set)</td>
            </tr>
          </tbody>
        </table>

        <h3>Example Template</h3>
        <pre><code>{`{{- range . -}}
[{{ .Severity | upper }}] {{ .RuleID }}: {{ .Description }}
  File:   {{ .File }}:{{ .Line }}
  Commit: {{ .Commit }}
  Secret: {{ .Secret }}

{{ end -}}
Total: {{ len . }} finding(s)`}</code></pre>
      </div>

      <div class="section">
        <h2>Redaction</h2>
        <p>
          Use <code>--redact</code> to replace a percentage of secret characters with asterisks
          in the output. This allows sharing reports without exposing full secret values.
        </p>
        <pre><code>{`leakdetector --redact 80 --format json`}</code></pre>
        <p>
          With <code>--redact 80</code>, a secret like <code>AKIAIOSFODNN7EXAMPLE</code> becomes{" "}
          <code>AKIA****************</code> (80% of characters replaced).
        </p>
        <table>
          <thead>
            <tr>
              <th>Redact Value</th>
              <th>Behavior</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>0</code> (default)</td>
              <td>No redaction; full secret is shown</td>
            </tr>
            <tr>
              <td><code>50</code></td>
              <td>Half of the secret characters are replaced</td>
            </tr>
            <tr>
              <td><code>80</code></td>
              <td>Most characters are replaced, preserving a short prefix</td>
            </tr>
            <tr>
              <td><code>100</code></td>
              <td>Entire secret is replaced with asterisks</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="section">
        <h2>Baseline Scanning</h2>
        <p>
          Use <code>{"--baseline <path>"}</code> to compare findings against a previously
          generated report. Only findings that are <strong>not</strong> present in the baseline
          are included in the output. This is useful for incremental scanning in CI/CD:
        </p>
        <pre><code>{`# Generate a baseline on the main branch
leakdetector --format json --report baseline.json

# On a feature branch, report only new findings
leakdetector --baseline baseline.json --format json`}</code></pre>
        <p>
          Findings are matched by rule ID, file path, line content, and secret value.
          If a finding exists in the baseline, it is suppressed regardless of the commit SHA.
        </p>
      </div>

      <div class="section">
        <h2>Platform Links</h2>
        <p>
          Use <code>{"--platform <name>"}</code> to include direct links to each finding
          in the hosting platform's web UI.
        </p>
        <table>
          <thead>
            <tr>
              <th>Platform</th>
              <th>Flag Value</th>
              <th>Link Format</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>GitHub</td>
              <td><code>github</code></td>
              <td><code>{"https://github.com/org/repo/blob/{commit}/{file}#L{line}"}</code></td>
            </tr>
            <tr>
              <td>GitLab</td>
              <td><code>gitlab</code></td>
              <td><code>{"https://gitlab.com/org/repo/-/blob/{commit}/{file}#L{line}"}</code></td>
            </tr>
          </tbody>
        </table>
        <pre><code>{`leakdetector --format json --platform github`}</code></pre>
        <p>
          The <code>link</code> field in each finding will contain a clickable URL pointing
          to the exact file and line where the secret was found.
        </p>
      </div>
    </div>
  );
}

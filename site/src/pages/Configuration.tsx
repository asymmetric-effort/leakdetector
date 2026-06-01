import { createElement, useHead } from "@asymmetric-effort/specifyjs";

export function Configuration() {
  useHead({
    title: "Configuration — leakdetector",
    description:
      "Configure leakdetector with .leakdetector.yml, .leakdetectorignore, and inline suppression comments.",
    canonical: "https://leakdetector.asymmetric-effort.com/#/configuration",
    og: {
      title: "Configuration — leakdetector",
      description:
        "Configure leakdetector with .leakdetector.yml, .leakdetectorignore, and inline suppression comments.",
      url: "https://leakdetector.asymmetric-effort.com/#/configuration",
      type: "website",
    },
  });

  return (
    <div>
      <div class="section">
        <h2>Configuration</h2>
        <p>
          leakdetector is configured via a <code>.leakdetector.yml</code> file placed in the repository root.
          Pass a custom path with <code>{"--config <path>"}</code>.
        </p>
      </div>

      <div class="section">
        <h2>Configuration Reference</h2>

        <h3>exclude_commits</h3>
        <p>A list of commit SHAs to skip during history scanning.</p>
        <pre><code>{`exclude_commits:
  - "abc123def456"
  - "789fed321cba"`}</code></pre>

        <h3>exclude_paths</h3>
        <p>A list of path glob patterns to exclude from scanning.</p>
        <pre><code>{`exclude_paths:
  - "vendor/**"
  - "node_modules/**"
  - "*.min.js"
  - "testdata/**"`}</code></pre>

        <h3>rules</h3>
        <p>Define custom detection rules or override built-in rules.</p>
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
              <td><code>id</code></td>
              <td>string</td>
              <td>Unique identifier for the rule</td>
            </tr>
            <tr>
              <td><code>description</code></td>
              <td>string</td>
              <td>Human-readable description of what the rule detects</td>
            </tr>
            <tr>
              <td><code>regex</code></td>
              <td>string</td>
              <td>Regular expression pattern to match secrets</td>
            </tr>
            <tr>
              <td><code>keywords</code></td>
              <td>list</td>
              <td>Keywords that must appear in the line for the rule to trigger</td>
            </tr>
            <tr>
              <td><code>path</code></td>
              <td>string</td>
              <td>Regex pattern to restrict the rule to specific file paths</td>
            </tr>
            <tr>
              <td><code>entropy</code></td>
              <td>float</td>
              <td>Minimum Shannon entropy threshold for the matched secret</td>
            </tr>
            <tr>
              <td><code>secret_group</code></td>
              <td>int</td>
              <td>Regex capture group index containing the secret (default 0 = full match)</td>
            </tr>
            <tr>
              <td><code>tags</code></td>
              <td>list</td>
              <td>Metadata tags for categorizing rules</td>
            </tr>
            <tr>
              <td><code>severity</code></td>
              <td>string</td>
              <td>Severity level: <code>critical</code>, <code>high</code>, <code>medium</code>, <code>low</code>, <code>info</code></td>
            </tr>
          </tbody>
        </table>

        <h3>allowlists</h3>
        <p>
          Define patterns to suppress false positives. Each allowlist entry has a{" "}
          <code>condition</code> and a <code>regex_target</code>.
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
              <td><code>condition</code></td>
              <td>string</td>
              <td>
                When to apply: <code>match</code> (suppress if regex matches the finding),{" "}
                <code>line</code> (suppress if regex matches the entire line)
              </td>
            </tr>
            <tr>
              <td><code>regex_target</code></td>
              <td>string</td>
              <td>What to match against: <code>secret</code>, <code>line</code>, <code>path</code>, <code>commit</code></td>
            </tr>
            <tr>
              <td><code>regexes</code></td>
              <td>list</td>
              <td>Regex patterns; if any matches, the finding is suppressed</td>
            </tr>
            <tr>
              <td><code>paths</code></td>
              <td>list</td>
              <td>Path glob patterns to restrict allowlist scope</td>
            </tr>
            <tr>
              <td><code>commits</code></td>
              <td>list</td>
              <td>Commit SHAs to restrict allowlist scope</td>
            </tr>
            <tr>
              <td><code>rule_ids</code></td>
              <td>list</td>
              <td>Apply allowlist only to specific rule IDs</td>
            </tr>
          </tbody>
        </table>

        <h3>extend</h3>
        <p>Control how the configuration extends or overrides the default rule set.</p>
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
              <td><code>use_default</code></td>
              <td>bool</td>
              <td>Whether to include the built-in 250+ rules (default <code>true</code>)</td>
            </tr>
            <tr>
              <td><code>path</code></td>
              <td>string</td>
              <td>Path to an additional config file to merge</td>
            </tr>
            <tr>
              <td><code>disabled_rules</code></td>
              <td>list</td>
              <td>List of built-in rule IDs to disable</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="section">
        <h2>Complete Example</h2>
        <pre><code>{`extend:
  use_default: true
  disabled_rules:
    - "generic-api-key"

exclude_commits:
  - "abc123def456"

exclude_paths:
  - "vendor/**"
  - "node_modules/**"
  - "*.min.js"
  - "testdata/**"

rules:
  - id: "custom-internal-token"
    description: "Internal service token"
    regex: "INTERNAL_TOKEN_[A-Za-z0-9]{32}"
    keywords:
      - "INTERNAL_TOKEN"
    entropy: 3.5
    secret_group: 0
    severity: "high"
    tags:
      - "internal"
      - "token"

  - id: "custom-db-password"
    description: "Database password in connection string"
    regex: "postgres://[^:]+:([^@]+)@"
    path: "\\\\.env$"
    secret_group: 1
    severity: "critical"
    tags:
      - "database"
      - "password"

allowlists:
  - condition: "match"
    regex_target: "secret"
    regexes:
      - "EXAMPLE_[A-Z]+"
      - "test-token-\\\\d+"
    rule_ids:
      - "generic-api-key"

  - condition: "line"
    regex_target: "line"
    regexes:
      - "# leakdetector:allow"
    paths:
      - "config/defaults.yml"`}</code></pre>
      </div>

      <div class="section">
        <h2>.leakdetectorignore</h2>
        <p>
          Create a <code>.leakdetectorignore</code> file in the repository root to exclude paths from scanning.
          The format follows the same conventions as <code>.gitignore</code>:
        </p>
        <ul>
          <li>One pattern per line</li>
          <li>Blank lines and lines starting with <code>#</code> are ignored</li>
          <li>Standard glob patterns are supported</li>
          <li>A trailing <code>/</code> matches directories only</li>
          <li>A leading <code>!</code> negates the pattern</li>
        </ul>
        <pre><code>{`# Ignore vendored dependencies
vendor/
node_modules/

# Ignore test fixtures
testdata/
**/fixtures/**

# Ignore minified files
*.min.js
*.min.css

# But do scan this specific config
!config/production.env`}</code></pre>
      </div>

      <div class="section">
        <h2>Inline Suppression</h2>
        <p>
          Add a <code>leakdetector:allow</code> comment on the same line as a finding to suppress it:
        </p>
        <pre><code>{`API_KEY="test-key-not-real" # leakdetector:allow`}</code></pre>
        <p>
          This is useful for test fixtures, documentation examples, and other known safe values.
          The suppression applies only to the specific line where the comment appears.
        </p>
      </div>
    </div>
  );
}

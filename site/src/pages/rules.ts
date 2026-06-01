export function RulesPage(): string {
  return `
<div class="section">
  <h2>Detection Rules</h2>
  <p>
    leakdetector ships with 250+ built-in rules for detecting leaked secrets.
    Each rule combines one or more detection strategies: regular expression matching,
    keyword pre-filtering, Shannon entropy thresholds, path restrictions, and
    secret group extraction via regex capture groups.
  </p>
</div>

<div class="section">
  <h2>How Rules Work</h2>

  <h3>Regex Matching</h3>
  <p>
    Every rule defines a <code>regex</code> pattern. When a line matches the pattern,
    the matched text is extracted as a potential secret.
  </p>

  <h3>Keyword Pre-filtering</h3>
  <p>
    Rules may specify <code>keywords</code> &mdash; fast substring checks performed before
    the regex. If a line does not contain any of the keywords, the regex is skipped entirely.
    This significantly improves scanning performance.
  </p>

  <h3>Shannon Entropy</h3>
  <p>
    Rules may set an <code>entropy</code> threshold. After a match is found, the Shannon
    entropy of the matched secret is calculated. If the entropy is below the threshold,
    the finding is discarded. This reduces false positives from placeholder values and
    non-random strings.
  </p>

  <h3>Path Filters</h3>
  <p>
    The <code>path</code> field restricts a rule to files matching a regex pattern.
    For example, a rule targeting <code>.env</code> files can set
    <code>path: "\\.env$"</code> to avoid scanning unrelated files.
  </p>

  <h3>Secret Groups</h3>
  <p>
    The <code>secret_group</code> field (default <code>0</code>) specifies which regex
    capture group contains the actual secret. This allows rules to match context around
    the secret (e.g. a key prefix) while extracting only the sensitive portion.
  </p>
</div>

<div class="section">
  <h2>Rule Categories</h2>
  <table>
    <thead>
      <tr>
        <th>Category</th>
        <th>Examples</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Cloud</td>
        <td>AWS, Azure, GCP, DigitalOcean, Heroku, Alibaba Cloud</td>
        <td>Cloud provider access keys, secret keys, connection strings, and service tokens</td>
      </tr>
      <tr>
        <td>VCS</td>
        <td>GitHub, GitLab, Bitbucket</td>
        <td>Personal access tokens, OAuth tokens, deploy keys, and app credentials</td>
      </tr>
      <tr>
        <td>CI/CD</td>
        <td>Jenkins, CircleCI, Travis CI, Drone, BuildKite</td>
        <td>Build system tokens, webhook secrets, and pipeline credentials</td>
      </tr>
      <tr>
        <td>Payment</td>
        <td>Stripe, Square, PayPal, Braintree</td>
        <td>API keys, merchant IDs, and payment processing secrets</td>
      </tr>
      <tr>
        <td>Messaging</td>
        <td>Slack, Twilio, SendGrid, Mailgun, Discord</td>
        <td>Webhook URLs, API keys, bot tokens, and auth tokens</td>
      </tr>
      <tr>
        <td>AI/ML</td>
        <td>OpenAI, HuggingFace, Anthropic, Cohere</td>
        <td>API keys and access tokens for AI/ML platforms</td>
      </tr>
      <tr>
        <td>Infrastructure</td>
        <td>Docker, Kubernetes, Terraform, Vault, Consul</td>
        <td>Registry credentials, service account tokens, and infrastructure secrets</td>
      </tr>
      <tr>
        <td>Databases</td>
        <td>PostgreSQL, MySQL, MongoDB, Redis, Elasticsearch</td>
        <td>Connection strings, passwords, and authentication credentials</td>
      </tr>
      <tr>
        <td>Crypto</td>
        <td>RSA, EC, PGP, SSH</td>
        <td>Private keys, certificates, and key material</td>
      </tr>
      <tr>
        <td>Generic</td>
        <td>Passwords, API keys, tokens, secrets</td>
        <td>Broad patterns for common secret formats not covered by specific rules</td>
      </tr>
    </tbody>
  </table>
</div>

<div class="section">
  <h2>Shannon Entropy</h2>
  <p>
    Shannon entropy measures the randomness of a string. Higher entropy indicates more
    randomness, which is typical of real secrets. Lower entropy suggests predictable
    values like placeholders or example strings.
  </p>
  <table>
    <thead>
      <tr>
        <th>Entropy Range</th>
        <th>Example</th>
        <th>Interpretation</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>0.0 &ndash; 1.5</td>
        <td><code>aaaaaaa</code></td>
        <td>Very low randomness &mdash; likely a placeholder or constant</td>
      </tr>
      <tr>
        <td>1.5 &ndash; 3.0</td>
        <td><code>password123</code></td>
        <td>Low randomness &mdash; common patterns, dictionary words</td>
      </tr>
      <tr>
        <td>3.0 &ndash; 4.0</td>
        <td><code>myS3cr3tK3y!</code></td>
        <td>Moderate randomness &mdash; could be a weak secret</td>
      </tr>
      <tr>
        <td>4.0 &ndash; 5.0</td>
        <td><code>aK8x#mP2qL9w</code></td>
        <td>High randomness &mdash; likely a real secret</td>
      </tr>
      <tr>
        <td>5.0+</td>
        <td><code>f8a3b1c9e7d2a4f6</code></td>
        <td>Very high randomness &mdash; almost certainly a real secret or hash</td>
      </tr>
    </tbody>
  </table>
  <p>
    Most built-in rules use entropy thresholds between 3.0 and 4.5 depending on the
    expected format of the secret. You can override the threshold in custom rules.
  </p>
</div>

<div class="section">
  <h2>Custom Rules</h2>
  <p>
    Define custom rules in <code>.leakdetector.yml</code> to detect organization-specific
    secrets or internal token formats.
  </p>
  <pre><code>rules:
  - id: "acme-internal-api-key"
    description: "ACME Corp internal API key"
    regex: "ACME_KEY_[A-Za-z0-9]{40}"
    keywords:
      - "ACME_KEY"
    entropy: 3.5
    secret_group: 0
    severity: "critical"
    path: "\\.(go|py|js|ts|yaml|yml|json|env)$"
    tags:
      - "acme"
      - "internal"</code></pre>
  <p>
    Custom rules are merged with the built-in rules by default. Set
    <code>extend.use_default: false</code> to use only your custom rules.
  </p>
</div>

<div class="section">
  <h2>Proximity / Composite Rules</h2>
  <p>
    Proximity rules detect secrets that consist of multiple related values appearing
    near each other in the same file. For example, an AWS access key and secret key
    that appear within a few lines of each other are more likely to be real credentials
    than either pattern appearing alone.
  </p>
  <p>
    Composite rules combine multiple patterns that must all match within a configurable
    line distance. This reduces false positives for patterns that are individually common
    but collectively indicate a real secret.
  </p>
  <pre><code>rules:
  - id: "aws-key-pair"
    description: "AWS access key and secret key in proximity"
    regex: "AKIA[0-9A-Z]{16}"
    keywords:
      - "AKIA"
    proximity:
      - pattern: "[A-Za-z0-9/+=]{40}"
        keywords:
          - "aws_secret"
          - "secret_access_key"
        max_lines: 5
    severity: "critical"
    tags:
      - "aws"
      - "composite"</code></pre>
  <p>
    The <code>proximity</code> field defines additional patterns that must be found
    within <code>max_lines</code> of the primary match. All proximity patterns must
    match for the rule to trigger.
  </p>
</div>
`;
}

# Detection Rules

leakdetector ships with 250+ built-in detection rules covering secrets,
credentials, API keys, and tokens from major platforms and services.

## How Rules Work

Each rule consists of:

1. **Regex Pattern**: A Go regular expression that matches potential secrets.
2. **Keywords** (optional): Fast pre-filter strings checked before regex
   evaluation. If keywords are specified, at least one must appear in the line
   (case-insensitive) before the regex is evaluated.
3. **Entropy Threshold** (optional): Minimum Shannon entropy for the matched
   secret. Filters out low-entropy false positives like placeholder values.
4. **Path Filter** (optional): Regex pattern restricting which files the rule
   applies to.
5. **Secret Group** (optional): Capture group index containing just the secret
   value (0 = full regex match).

## Rule Evaluation Order

For each line of content:

1. **Path filter**: If the rule has a path filter, check if the file path
   matches. Skip if not.
2. **Keyword pre-filter**: If keywords are defined, check if any appear in the
   line. Skip if none found.
3. **Regex match**: Apply the regex pattern to the line.
4. **Secret extraction**: Extract the secret from the specified capture group.
5. **Entropy check**: Calculate Shannon entropy of the secret. Skip if below
   threshold.
6. **Allowlist check**: Check rule-level and global allowlists. Skip if
   allowed.
7. **Finding generated**: Create a finding with the match details.

## Built-in Rule Categories

### Cloud Providers

| Rule ID | Service | Description |
|---------|---------|-------------|
| `aws-access-key-id` | AWS | Access key IDs (AKIA...) |
| `aws-secret-access-key` | AWS | Secret access keys |
| `aws-session-token` | AWS | Session/security tokens |
| `aws-mws-auth-token` | AWS | MWS authorization tokens |
| `azure-client-secret` | Azure | AD client secrets |
| `azure-storage-account-key` | Azure | Storage account keys |
| `azure-sas-token` | Azure | Shared Access Signature tokens |
| `azure-connection-string` | Azure | Connection strings |
| `gcp-api-key` | GCP | API keys (AIza...) |
| `gcp-service-account-key` | GCP | Service account private keys |
| `gcp-oauth-client-secret` | GCP | OAuth client secrets |
| `alibaba-access-key-id` | Alibaba | Access key IDs |
| `digitalocean-pat` | DigitalOcean | Personal access tokens (dop_v1_) |
| `heroku-api-key` | Heroku | API keys |
| `linode-pat` | Linode | Personal access tokens |

### Version Control

| Rule ID | Service | Description |
|---------|---------|-------------|
| `github-pat` | GitHub | Personal access tokens (ghp_) |
| `github-oauth` | GitHub | OAuth tokens (gho_) |
| `github-fine-grained-pat` | GitHub | Fine-grained PATs (github_pat_) |
| `github-app-token` | GitHub | App tokens (ghs_, ghr_) |
| `gitlab-pat` | GitLab | Personal access tokens (glpat-) |
| `gitlab-pipeline-trigger` | GitLab | Pipeline trigger tokens |
| `bitbucket-client-secret` | Bitbucket | Client secrets |
| `gitea-access-token` | Gitea | Access tokens |

### CI/CD

| Rule ID | Service | Description |
|---------|---------|-------------|
| `travis-ci-token` | Travis CI | API tokens |
| `drone-ci-token` | Drone CI | Personal tokens |
| `circleci-token` | CircleCI | API tokens |
| `jenkins-token` | Jenkins | API tokens |
| `buildkite-token` | Buildkite | Agent/API tokens |

### Payment Processing

| Rule ID | Service | Description |
|---------|---------|-------------|
| `stripe-secret-key` | Stripe | Secret keys (sk_live_) |
| `stripe-publishable-key` | Stripe | Publishable keys (pk_live_) |
| `stripe-restricted-key` | Stripe | Restricted keys (rk_live_) |
| `square-access-token` | Square | Access tokens |
| `shopify-shared-secret` | Shopify | Shared secrets |
| `shopify-access-token` | Shopify | Access tokens |

### Communication

| Rule ID | Service | Description |
|---------|---------|-------------|
| `slack-bot-token` | Slack | Bot tokens (xoxb-) |
| `slack-user-token` | Slack | User tokens (xoxp-) |
| `slack-webhook` | Slack | Webhook URLs |
| `discord-bot-token` | Discord | Bot tokens |
| `discord-webhook` | Discord | Webhook URLs |
| `twilio-account-sid` | Twilio | Account SIDs |
| `twilio-auth-token` | Twilio | Auth tokens |
| `telegram-bot-token` | Telegram | Bot tokens |

### AI/ML

| Rule ID | Service | Description |
|---------|---------|-------------|
| `openai-api-key` | OpenAI | API keys (sk-) |
| `anthropic-api-key` | Anthropic | API keys (sk-ant-) |
| `huggingface-token` | Hugging Face | Access tokens (hf_) |
| `google-ai-api-key` | Google AI | Gemini/AI API keys |
| `cohere-api-key` | Cohere | API keys |
| `replicate-api-token` | Replicate | API tokens |

### Infrastructure

| Rule ID | Service | Description |
|---------|---------|-------------|
| `vault-service-token` | HashiCorp Vault | Service tokens (hvs.) |
| `vault-batch-token` | HashiCorp Vault | Batch tokens (hvb.) |
| `terraform-cloud-token` | Terraform | Cloud API tokens |
| `pulumi-access-token` | Pulumi | Access tokens (pul-) |
| `kubernetes-secret` | Kubernetes | Secrets in YAML |

### Databases

| Rule ID | Service | Description |
|---------|---------|-------------|
| `mongodb-connection-string` | MongoDB | Connection strings |
| `mysql-connection-string` | MySQL | Connection strings |
| `postgresql-connection-string` | PostgreSQL | Connection strings |
| `redis-connection-string` | Redis | Connection URIs |
| `databricks-api-token` | Databricks | API tokens |

### Cryptographic Material

| Rule ID | Description |
|---------|-------------|
| `private-key-rsa` | RSA private keys |
| `private-key-ec` | EC private keys |
| `private-key-dsa` | DSA private keys |
| `private-key-openssh` | OpenSSH private keys |
| `private-key-pgp` | PGP private keys |
| `jwt-token` | JSON Web Tokens |
| `age-secret-key` | Age encryption keys |

### Generic Patterns

| Rule ID | Description |
|---------|-------------|
| `generic-api-key` | Generic API key assignments |
| `generic-secret` | Generic secret assignments |
| `generic-password` | Generic password assignments |
| `basic-auth-url` | Credentials in URLs |
| `env-file-secret` | Secrets in .env files |

## Custom Rules

See [Configuration](configuration.md) for adding custom rules.

## Shannon Entropy

Shannon entropy measures the randomness of a string on a scale of 0 to 8.0:

| Entropy | Meaning | Example |
|---------|---------|---------|
| 0.0     | Uniform | `aaaaaaaaaa` |
| 1.0     | Very low | `aabbaabb` |
| 2.0-3.0 | Low | Common words, placeholders |
| 3.0-4.0 | Medium | Mixed-case words |
| 4.0-5.0 | High | Likely a real credential |
| 5.0+    | Very high | Strong random secret |

Generic rules use entropy thresholds (typically 3.0-4.5) to distinguish real
secrets from placeholder values like `your-api-key-here`.

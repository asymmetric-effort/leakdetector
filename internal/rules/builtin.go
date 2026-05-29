package rules

import (
	"github.com/asymmetric-effort/leakdetector/internal/config"
)

// BuiltinRules returns the default set of detection rules covering
// cloud platforms, version control, CI/CD, package registries, APIs,
// infrastructure, databases, authentication, AI/ML, and more.
func BuiltinRules() []config.RuleConfig {
	return []config.RuleConfig{
		// =====================================================================
		// AWS (1-8)
		// =====================================================================
		{
			ID:          "aws-access-key-id",
			Description: "AWS Access Key ID",
			Regex:       `\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`,
			SecretGroup: 1,
			Keywords:    []string{"AKIA", "ABIA", "ACCA", "ASIA"},
			Tags:        []string{"aws", "cloud", "key"},
		},
		{
			ID:          "aws-secret-access-key",
			Description: "AWS Secret Access Key",
			Regex:       `(?i)(?:aws[_\-\.]?secret[_\-\.]?access[_\-\.]?key|aws_secret_key|secret_access_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"aws", "secret"},
			Tags:        []string{"aws", "cloud", "secret"},
		},
		{
			ID:          "aws-session-token",
			Description: "AWS Session Token",
			Regex:       `(?i)(?:aws[_\-]?session[_\-]?token)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"aws_session_token", "aws-session-token"},
			Tags:        []string{"aws", "cloud", "token"},
		},
		{
			ID:          "aws-mws-auth-token",
			Description: "AWS MWS Auth Token",
			Regex:       `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
			Keywords:    []string{"amzn.mws."},
			Tags:        []string{"aws", "mws", "token"},
		},
		{
			ID:          "aws-account-id",
			Description: "AWS Account ID in ARN",
			Regex:       `arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:(\d{12}):`,
			SecretGroup: 1,
			Keywords:    []string{"arn:aws:"},
			Tags:        []string{"aws", "cloud", "account"},
		},
		{
			ID:          "aws-s3-presigned-url",
			Description: "AWS S3 Presigned URL with credentials",
			Regex:       `https?://[a-zA-Z0-9\-]+\.s3[.\-][a-zA-Z0-9\-]+\.amazonaws\.com/[^\s]*(?:X-Amz-Credential|AWSAccessKeyId)=[^\s&]+`,
			Keywords:    []string{"amazonaws.com", "X-Amz-Credential", "AWSAccessKeyId"},
			Tags:        []string{"aws", "s3", "url"},
		},
		{
			ID:          "aws-ses-smtp-password",
			Description: "AWS SES SMTP Password",
			Regex:       `(?i)(?:ses[_\-]?smtp[_\-]?password|smtp_password)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{44})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"ses", "smtp_password", "smtp-password"},
			Tags:        []string{"aws", "ses", "password"},
		},
		{
			ID:          "aws-app-client-secret",
			Description: "AWS Cognito App Client Secret",
			Regex:       `(?i)(?:cognito[_\-]?(?:app[_\-]?)?client[_\-]?secret)\s*[:=]\s*["\']?([A-Za-z0-9]{52})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"cognito", "client_secret"},
			Tags:        []string{"aws", "cognito", "secret"},
		},

		// =====================================================================
		// Azure (9-18)
		// =====================================================================
		{
			ID:          "azure-client-secret",
			Description: "Azure AD Client Secret",
			Regex:       `(?i)(?:azure[_\-]?client[_\-]?secret|client[_\-]?secret|aad[_\-]?client[_\-]?secret)\s*[:=]\s*["\']?([a-zA-Z0-9~._\-]{34,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"azure", "client_secret", "client-secret"},
			Tags:        []string{"azure", "cloud", "secret"},
		},
		{
			ID:          "azure-storage-account-key",
			Description: "Azure Storage Account Key",
			Regex:       `(?i)(?:account[_\-]?key|storage[_\-]?key|azure[_\-]?storage[_\-]?key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{88})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"accountkey", "account_key", "storage_key", "storagekey"},
			Tags:        []string{"azure", "cloud", "storage"},
		},
		{
			ID:          "azure-sas-token",
			Description: "Azure Shared Access Signature Token",
			Regex:       `(?:sv=\d{4}-\d{2}-\d{2}[^&\s]*&(?:sig|se|sp|spr|st|ss)=[^\s"']+)`,
			Keywords:    []string{"sv=", "sig="},
			Tags:        []string{"azure", "cloud", "sas"},
		},
		{
			ID:          "azure-connection-string",
			Description: "Azure Connection String",
			Regex:       `(?i)(?:DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9/+=]{88};EndpointSuffix=[^\s"';]+)`,
			Keywords:    []string{"DefaultEndpointsProtocol", "AccountKey"},
			Tags:        []string{"azure", "cloud", "connection-string"},
		},
		{
			ID:          "azure-sql-connection-string",
			Description: "Azure SQL Connection String",
			Regex:       `(?i)Server=tcp:[^;]+;.*(?:Password|pwd)\s*=\s*([^;\s"']+)`,
			SecretGroup: 1,
			Keywords:    []string{"Server=tcp:", "Password=", "pwd="},
			Tags:        []string{"azure", "sql", "connection-string"},
		},
		{
			ID:          "azure-devops-pat",
			Description: "Azure DevOps Personal Access Token",
			Regex:       `(?i)(?:azure[_\-]?devops|ado|vsts)[_\-]?(?:pat|token)\s*[:=]\s*["\']?([a-z0-9]{52})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"azure_devops", "ado_pat", "vsts"},
			Tags:        []string{"azure", "devops", "token"},
		},
		{
			ID:          "azure-tenant-id",
			Description: "Azure Tenant ID exposed with secrets",
			Regex:       `(?i)(?:tenant[_\-]?id|AZURE_TENANT_ID)\s*[:=]\s*["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"tenant_id", "tenant-id", "AZURE_TENANT_ID"},
			Tags:        []string{"azure", "cloud", "tenant"},
		},
		{
			ID:          "azure-function-key",
			Description: "Azure Function Key",
			Regex:       `(?i)(?:x-functions-key|azure[_\-]?function[_\-]?key)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{40,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"functions-key", "function_key", "x-functions-key"},
			Tags:        []string{"azure", "function", "key"},
		},
		{
			ID:          "azure-cosmosdb-key",
			Description: "Azure Cosmos DB Key",
			Regex:       `(?i)(?:cosmosdb[_\-]?key|cosmos[_\-]?primary[_\-]?key|AccountKey)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{88})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"cosmosdb", "cosmos", "AccountKey"},
			Tags:        []string{"azure", "cosmosdb", "key"},
		},
		{
			ID:          "azure-app-config-connection",
			Description: "Azure App Configuration Connection String",
			Regex:       `Endpoint=https://[^;]+\.azconfig\.io;Id=[^;]+;Secret=[A-Za-z0-9/+=]+`,
			Keywords:    []string{"azconfig.io", "Secret="},
			Tags:        []string{"azure", "appconfig", "connection-string"},
		},

		// =====================================================================
		// GCP (19-25)
		// =====================================================================
		{
			ID:          "gcp-api-key",
			Description: "GCP API Key",
			Regex:       `\bAIza[0-9A-Za-z_\-]{35}\b`,
			Keywords:    []string{"AIza"},
			Tags:        []string{"gcp", "cloud", "api-key"},
		},
		{
			ID:          "gcp-service-account-key",
			Description: "GCP Service Account Key JSON",
			Regex:       `(?i)"type"\s*:\s*"service_account"`,
			Keywords:    []string{"service_account"},
			Path:        `\.json$`,
			Tags:        []string{"gcp", "cloud", "service-account"},
		},
		{
			ID:          "gcp-oauth-client-secret",
			Description: "GCP OAuth Client Secret",
			Regex:       `(?i)(?:client_secret|GOOGLE_CLIENT_SECRET)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{24,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"client_secret", "GOOGLE_CLIENT_SECRET"},
			Tags:        []string{"gcp", "cloud", "oauth"},
		},
		{
			ID:          "gcp-oauth-refresh-token",
			Description: "GCP OAuth Refresh Token",
			Regex:       `(?i)(?:refresh_token|GOOGLE_REFRESH_TOKEN)\s*[:=]\s*["\']?(1//[A-Za-z0-9_\-]{40,})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"refresh_token", "1//"},
			Tags:        []string{"gcp", "cloud", "oauth"},
		},
		{
			ID:          "gcp-firebase-url",
			Description: "Firebase Database URL with credentials",
			Regex:       `https://[a-zA-Z0-9\-]+\.firebaseio\.com`,
			Keywords:    []string{"firebaseio.com"},
			Tags:        []string{"gcp", "firebase", "url"},
		},
		{
			ID:          "gcp-firebase-cloud-messaging",
			Description: "Firebase Cloud Messaging Server Key",
			Regex:       `(?i)(?:fcm[_\-]?server[_\-]?key|firebase[_\-]?server[_\-]?key)\s*[:=]\s*["\']?(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"fcm", "firebase", "server_key"},
			Tags:        []string{"gcp", "firebase", "key"},
		},
		{
			ID:          "gcp-project-credentials-file",
			Description: "GCP Application Default Credentials file reference",
			Regex:       `(?i)GOOGLE_APPLICATION_CREDENTIALS\s*[:=]\s*["\']?([^\s"']+\.json)["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"GOOGLE_APPLICATION_CREDENTIALS"},
			Tags:        []string{"gcp", "cloud", "credentials"},
		},

		// =====================================================================
		// Alibaba Cloud (26-27)
		// =====================================================================
		{
			ID:          "alibaba-access-key-id",
			Description: "Alibaba Cloud Access Key ID",
			Regex:       `\b(LTAI[0-9A-Za-z]{12,20})\b`,
			SecretGroup: 1,
			Keywords:    []string{"LTAI"},
			Tags:        []string{"alibaba", "cloud", "key"},
		},
		{
			ID:          "alibaba-secret-key",
			Description: "Alibaba Cloud Secret Access Key",
			Regex:       `(?i)(?:alibaba[_\-]?(?:cloud[_\-]?)?secret[_\-]?(?:access[_\-]?)?key|aliyun[_\-]?secret)\s*[:=]\s*["\']?([A-Za-z0-9]{30})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"alibaba", "aliyun", "secret_key"},
			Tags:        []string{"alibaba", "cloud", "secret"},
		},

		// =====================================================================
		// DigitalOcean (28-30)
		// =====================================================================
		{
			ID:          "digitalocean-pat",
			Description: "DigitalOcean Personal Access Token",
			Regex:       `\b(dop_v1_[a-f0-9]{64})\b`,
			SecretGroup: 1,
			Keywords:    []string{"dop_v1_"},
			Tags:        []string{"digitalocean", "cloud", "token"},
		},
		{
			ID:          "digitalocean-oauth-token",
			Description: "DigitalOcean OAuth Access Token",
			Regex:       `\b(doo_v1_[a-f0-9]{64})\b`,
			SecretGroup: 1,
			Keywords:    []string{"doo_v1_"},
			Tags:        []string{"digitalocean", "cloud", "oauth"},
		},
		{
			ID:          "digitalocean-refresh-token",
			Description: "DigitalOcean OAuth Refresh Token",
			Regex:       `\b(dor_v1_[a-f0-9]{64})\b`,
			SecretGroup: 1,
			Keywords:    []string{"dor_v1_"},
			Tags:        []string{"digitalocean", "cloud", "refresh-token"},
		},

		// =====================================================================
		// Heroku (31)
		// =====================================================================
		{
			ID:          "heroku-api-key",
			Description: "Heroku API Key",
			Regex:       `(?i)(?:heroku[_\-]?api[_\-]?key|HEROKU_API_KEY)\s*[:=]\s*["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"heroku"},
			Tags:        []string{"heroku", "cloud", "api-key"},
		},

		// =====================================================================
		// Linode (32)
		// =====================================================================
		{
			ID:          "linode-pat",
			Description: "Linode Personal Access Token",
			Regex:       `(?i)(?:linode[_\-]?(?:personal[_\-]?)?(?:access[_\-]?)?token|LINODE_TOKEN)\s*[:=]\s*["\']?([a-f0-9]{64})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"linode"},
			Tags:        []string{"linode", "cloud", "token"},
		},

		// =====================================================================
		// GitHub (33-37)
		// =====================================================================
		{
			ID:          "github-pat",
			Description: "GitHub Personal Access Token",
			Regex:       `\b(ghp_[A-Za-z0-9]{36,255})\b`,
			SecretGroup: 1,
			Keywords:    []string{"ghp_"},
			Tags:        []string{"github", "vcs", "token"},
		},
		{
			ID:          "github-oauth",
			Description: "GitHub OAuth Access Token",
			Regex:       `\b(gho_[A-Za-z0-9]{36,255})\b`,
			SecretGroup: 1,
			Keywords:    []string{"gho_"},
			Tags:        []string{"github", "vcs", "oauth"},
		},
		{
			ID:          "github-fine-grained-pat",
			Description: "GitHub Fine-Grained Personal Access Token",
			Regex:       `\b(github_pat_[A-Za-z0-9_]{82,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"github_pat_"},
			Tags:        []string{"github", "vcs", "token"},
		},
		{
			ID:          "github-app-token",
			Description: "GitHub App Installation Token",
			Regex:       `\b(ghs_[A-Za-z0-9]{36,255})\b`,
			SecretGroup: 1,
			Keywords:    []string{"ghs_"},
			Tags:        []string{"github", "vcs", "token"},
		},
		{
			ID:          "github-refresh-token",
			Description: "GitHub App Refresh Token",
			Regex:       `\b(ghr_[A-Za-z0-9]{36,255})\b`,
			SecretGroup: 1,
			Keywords:    []string{"ghr_"},
			Tags:        []string{"github", "vcs", "token"},
		},

		// =====================================================================
		// GitLab (38-40)
		// =====================================================================
		{
			ID:          "gitlab-pat",
			Description: "GitLab Personal Access Token",
			Regex:       `\b(glpat-[A-Za-z0-9_\-]{20,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"glpat-"},
			Tags:        []string{"gitlab", "vcs", "token"},
		},
		{
			ID:          "gitlab-pipeline-trigger",
			Description: "GitLab Pipeline Trigger Token",
			Regex:       `(?i)(?:gitlab[_\-]?)?(?:pipeline[_\-]?)?trigger[_\-]?token\s*[:=]\s*["\']?([a-f0-9]{40})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"trigger_token", "trigger-token", "gitlab"},
			Tags:        []string{"gitlab", "vcs", "ci"},
		},
		{
			ID:          "gitlab-runner-registration",
			Description: "GitLab Runner Registration Token",
			Regex:       `(?i)(?:gitlab[_\-]?)?runner[_\-]?(?:registration[_\-]?)?token\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"runner", "registration_token", "gitlab"},
			Tags:        []string{"gitlab", "vcs", "ci"},
		},

		// =====================================================================
		// Bitbucket (41-42)
		// =====================================================================
		{
			ID:          "bitbucket-app-password",
			Description: "Bitbucket App Password",
			Regex:       `(?i)(?:bitbucket[_\-]?(?:app[_\-]?)?password|BITBUCKET_PASSWORD)\s*[:=]\s*["\']?([A-Za-z0-9]{18,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"bitbucket"},
			Tags:        []string{"bitbucket", "vcs", "password"},
		},
		{
			ID:          "bitbucket-client-secret",
			Description: "Bitbucket Client Secret",
			Regex:       `(?i)(?:bitbucket[_\-]?client[_\-]?secret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{32,})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"bitbucket", "client_secret"},
			Tags:        []string{"bitbucket", "vcs", "secret"},
		},

		// =====================================================================
		// Gitea (43)
		// =====================================================================
		{
			ID:          "gitea-access-token",
			Description: "Gitea Access Token",
			Regex:       `(?i)(?:gitea[_\-]?(?:access[_\-]?)?token)\s*[:=]\s*["\']?([a-f0-9]{40})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"gitea"},
			Tags:        []string{"gitea", "vcs", "token"},
		},

		// =====================================================================
		// CI/CD (44-46)
		// =====================================================================
		{
			ID:          "travis-ci-token",
			Description: "Travis CI Access Token",
			Regex:       `(?i)(?:travis[_\-]?(?:ci[_\-]?)?(?:api[_\-]?)?token|TRAVIS_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"travis"},
			Tags:        []string{"travis", "ci", "token"},
		},
		{
			ID:          "drone-ci-token",
			Description: "Drone CI Token",
			Regex:       `(?i)(?:drone[_\-]?(?:ci[_\-]?)?(?:server[_\-]?)?token|DRONE_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9]{32,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"drone"},
			Tags:        []string{"drone", "ci", "token"},
		},
		{
			ID:          "circleci-token",
			Description: "CircleCI Personal API Token",
			Regex:       `(?i)(?:circle[_\-]?ci[_\-]?(?:api[_\-]?)?token|CIRCLECI_TOKEN)\s*[:=]\s*["\']?([a-f0-9]{40})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"circleci", "circle_ci", "circle-ci"},
			Tags:        []string{"circleci", "ci", "token"},
		},

		// =====================================================================
		// Package Registries (47-50)
		// =====================================================================
		{
			ID:          "npm-auth-token",
			Description: "NPM Auth Token",
			Regex:       `(?i)(?:_authToken|npm_token|NPM_AUTH_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9\-_.]{36,})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"_authToken", "npm_token", "NPM_AUTH_TOKEN"},
			Tags:        []string{"npm", "package-registry", "token"},
		},
		{
			ID:          "npm-access-token-v2",
			Description: "NPM Access Token (npm_ prefix)",
			Regex:       `\b(npm_[A-Za-z0-9]{36,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"npm_"},
			Tags:        []string{"npm", "package-registry", "token"},
		},
		{
			ID:          "pypi-api-token",
			Description: "PyPI API Token",
			Regex:       `\b(pypi-[A-Za-z0-9_\-]{50,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"pypi-"},
			Tags:        []string{"pypi", "package-registry", "token"},
		},
		{
			ID:          "rubygems-api-key",
			Description: "RubyGems API Key",
			Regex:       `\b(rubygems_[a-f0-9]{48})\b`,
			SecretGroup: 1,
			Keywords:    []string{"rubygems_"},
			Tags:        []string{"rubygems", "package-registry", "key"},
		},

		// =====================================================================
		// NuGet (51)
		// =====================================================================
		{
			ID:          "nuget-api-key",
			Description: "NuGet API Key",
			Regex:       `(?i)(?:nuget[_\-]?api[_\-]?key|NUGET_KEY)\s*[:=]\s*["\']?(oy2[a-z0-9]{43})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"nuget", "oy2"},
			Tags:        []string{"nuget", "package-registry", "key"},
		},

		// =====================================================================
		// Stripe (52-54)
		// =====================================================================
		{
			ID:          "stripe-secret-key",
			Description: "Stripe Secret Key",
			Regex:       `\b(sk_live_[A-Za-z0-9]{20,99})\b`,
			SecretGroup: 1,
			Keywords:    []string{"sk_live_"},
			Tags:        []string{"stripe", "payment", "secret"},
		},
		{
			ID:          "stripe-publishable-key",
			Description: "Stripe Publishable Key",
			Regex:       `\b(pk_live_[A-Za-z0-9]{20,99})\b`,
			SecretGroup: 1,
			Keywords:    []string{"pk_live_"},
			Tags:        []string{"stripe", "payment", "key"},
		},
		{
			ID:          "stripe-restricted-key",
			Description: "Stripe Restricted API Key",
			Regex:       `\b(rk_live_[A-Za-z0-9]{20,99})\b`,
			SecretGroup: 1,
			Keywords:    []string{"rk_live_"},
			Tags:        []string{"stripe", "payment", "key"},
		},

		// =====================================================================
		// Slack (55-58)
		// =====================================================================
		{
			ID:          "slack-bot-token",
			Description: "Slack Bot Token",
			Regex:       `\b(xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*)\b`,
			SecretGroup: 1,
			Keywords:    []string{"xoxb-"},
			Tags:        []string{"slack", "messaging", "token"},
		},
		{
			ID:          "slack-user-token",
			Description: "Slack User Token",
			Regex:       `\b(xoxp-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*)\b`,
			SecretGroup: 1,
			Keywords:    []string{"xoxp-"},
			Tags:        []string{"slack", "messaging", "token"},
		},
		{
			ID:          "slack-app-token",
			Description: "Slack App-Level Token",
			Regex:       `\b(xapp-[0-9]+-[A-Za-z0-9]+-[0-9]+-[a-f0-9]+)\b`,
			SecretGroup: 1,
			Keywords:    []string{"xapp-"},
			Tags:        []string{"slack", "messaging", "token"},
		},
		{
			ID:          "slack-webhook",
			Description: "Slack Incoming Webhook URL",
			Regex:       `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`,
			Keywords:    []string{"hooks.slack.com"},
			Tags:        []string{"slack", "messaging", "webhook"},
		},

		// =====================================================================
		// Discord (59-60)
		// =====================================================================
		{
			ID:          "discord-bot-token",
			Description: "Discord Bot Token",
			Regex:       `(?i)(?:discord[_\-]?(?:bot[_\-]?)?token)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"discord"},
			Tags:        []string{"discord", "messaging", "token"},
		},
		{
			ID:          "discord-webhook",
			Description: "Discord Webhook URL",
			Regex:       `https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+`,
			Keywords:    []string{"discord", "webhooks"},
			Tags:        []string{"discord", "messaging", "webhook"},
		},

		// =====================================================================
		// Twilio (61-63)
		// =====================================================================
		{
			ID:          "twilio-account-sid",
			Description: "Twilio Account SID",
			Regex:       `\b(AC[0-9a-f]{32})\b`,
			SecretGroup: 1,
			Keywords:    []string{"AC", "twilio"},
			Tags:        []string{"twilio", "communication", "sid"},
		},
		{
			ID:          "twilio-auth-token",
			Description: "Twilio Auth Token",
			Regex:       `(?i)(?:twilio[_\-]?auth[_\-]?token|TWILIO_AUTH_TOKEN)\s*[:=]\s*["\']?([a-f0-9]{32})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"twilio"},
			Tags:        []string{"twilio", "communication", "token"},
		},
		{
			ID:          "twilio-api-key",
			Description: "Twilio API Key SID",
			Regex:       `\b(SK[0-9a-f]{32})\b`,
			SecretGroup: 1,
			Keywords:    []string{"SK", "twilio"},
			Tags:        []string{"twilio", "communication", "key"},
		},

		// =====================================================================
		// SendGrid (64)
		// =====================================================================
		{
			ID:          "sendgrid-api-key",
			Description: "SendGrid API Key",
			Regex:       `\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b`,
			SecretGroup: 1,
			Keywords:    []string{"SG."},
			Tags:        []string{"sendgrid", "email", "api-key"},
		},

		// =====================================================================
		// Mailgun (65)
		// =====================================================================
		{
			ID:          "mailgun-api-key",
			Description: "Mailgun API Key",
			Regex:       `(?i)(?:mailgun[_\-]?api[_\-]?key|MAILGUN_API_KEY)\s*[:=]\s*["\']?(key-[a-f0-9]{32})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"mailgun", "key-"},
			Tags:        []string{"mailgun", "email", "api-key"},
		},

		// =====================================================================
		// Mailchimp (66)
		// =====================================================================
		{
			ID:          "mailchimp-api-key",
			Description: "Mailchimp API Key",
			Regex:       `\b([a-f0-9]{32}-us[0-9]{1,2})\b`,
			SecretGroup: 1,
			Keywords:    []string{"mailchimp", "-us"},
			Tags:        []string{"mailchimp", "email", "api-key"},
		},

		// =====================================================================
		// Datadog (67-68)
		// =====================================================================
		{
			ID:          "datadog-api-key",
			Description: "Datadog API Key",
			Regex:       `(?i)(?:datadog[_\-]?api[_\-]?key|DD_API_KEY)\s*[:=]\s*["\']?([a-f0-9]{32})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"datadog", "DD_API_KEY"},
			Tags:        []string{"datadog", "monitoring", "api-key"},
		},
		{
			ID:          "datadog-app-key",
			Description: "Datadog Application Key",
			Regex:       `(?i)(?:datadog[_\-]?app(?:lication)?[_\-]?key|DD_APP_KEY)\s*[:=]\s*["\']?([a-f0-9]{40})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"datadog", "DD_APP_KEY"},
			Tags:        []string{"datadog", "monitoring", "app-key"},
		},

		// =====================================================================
		// New Relic (69-70)
		// =====================================================================
		{
			ID:          "newrelic-license-key",
			Description: "New Relic License Key",
			Regex:       `(?i)(?:new[_\-]?relic[_\-]?license[_\-]?key|NEWRELIC_LICENSE_KEY|NR_LICENSE_KEY)\s*[:=]\s*["\']?([a-f0-9]{40})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"newrelic", "new_relic", "new-relic", "NR_LICENSE"},
			Tags:        []string{"newrelic", "monitoring", "license"},
		},
		{
			ID:          "newrelic-api-key",
			Description: "New Relic API Key (NRAK prefix)",
			Regex:       `\b(NRAK-[A-Z0-9]{27})\b`,
			SecretGroup: 1,
			Keywords:    []string{"NRAK-"},
			Tags:        []string{"newrelic", "monitoring", "api-key"},
		},

		// =====================================================================
		// Sentry (71-72)
		// =====================================================================
		{
			ID:          "sentry-dsn",
			Description: "Sentry DSN with embedded credentials",
			Regex:       `https://[a-f0-9]{32}@[a-z0-9\-\.]+\.ingest\.sentry\.io/[0-9]+`,
			Keywords:    []string{"sentry.io"},
			Tags:        []string{"sentry", "monitoring", "dsn"},
		},
		{
			ID:          "sentry-auth-token",
			Description: "Sentry Auth Token",
			Regex:       `(?i)(?:sentry[_\-]?auth[_\-]?token|SENTRY_AUTH_TOKEN)\s*[:=]\s*["\']?([a-f0-9]{64})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"sentry"},
			Tags:        []string{"sentry", "monitoring", "token"},
		},

		// =====================================================================
		// Grafana (73-74)
		// =====================================================================
		{
			ID:          "grafana-api-key",
			Description: "Grafana API Key",
			Regex:       `\b(eyJrIjoi[A-Za-z0-9+/=]{40,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"eyJrIjoi"},
			Tags:        []string{"grafana", "monitoring", "api-key"},
		},
		{
			ID:          "grafana-service-account-token",
			Description: "Grafana Service Account Token",
			Regex:       `\b(glsa_[A-Za-z0-9]{32}_[a-f0-9]{8})\b`,
			SecretGroup: 1,
			Keywords:    []string{"glsa_"},
			Tags:        []string{"grafana", "monitoring", "token"},
		},

		// =====================================================================
		// Grafana Cloud (75)
		// =====================================================================
		{
			ID:          "grafana-cloud-api-token",
			Description: "Grafana Cloud API Token",
			Regex:       `\b(glc_[A-Za-z0-9+/=]{32,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"glc_"},
			Tags:        []string{"grafana", "monitoring", "cloud"},
		},

		// =====================================================================
		// Shopify (76-78)
		// =====================================================================
		{
			ID:          "shopify-shared-secret",
			Description: "Shopify Shared Secret",
			Regex:       `\b(shpss_[a-fA-F0-9]{32})\b`,
			SecretGroup: 1,
			Keywords:    []string{"shpss_"},
			Tags:        []string{"shopify", "ecommerce", "secret"},
		},
		{
			ID:          "shopify-access-token",
			Description: "Shopify Access Token",
			Regex:       `\b(shpat_[a-fA-F0-9]{32})\b`,
			SecretGroup: 1,
			Keywords:    []string{"shpat_"},
			Tags:        []string{"shopify", "ecommerce", "token"},
		},
		{
			ID:          "shopify-custom-app-token",
			Description: "Shopify Custom App Access Token",
			Regex:       `\b(shpca_[a-fA-F0-9]{32})\b`,
			SecretGroup: 1,
			Keywords:    []string{"shpca_"},
			Tags:        []string{"shopify", "ecommerce", "token"},
		},

		// =====================================================================
		// Shopify Private App (79)
		// =====================================================================
		{
			ID:          "shopify-private-app-token",
			Description: "Shopify Private App Access Token",
			Regex:       `\b(shppa_[a-fA-F0-9]{32})\b`,
			SecretGroup: 1,
			Keywords:    []string{"shppa_"},
			Tags:        []string{"shopify", "ecommerce", "token"},
		},

		// =====================================================================
		// Square (80-81)
		// =====================================================================
		{
			ID:          "square-access-token",
			Description: "Square Access Token",
			Regex:       `\b(sq0atp-[A-Za-z0-9_\-]{22,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"sq0atp-"},
			Tags:        []string{"square", "payment", "token"},
		},
		{
			ID:          "square-oauth-secret",
			Description: "Square OAuth Secret",
			Regex:       `\b(sq0csp-[A-Za-z0-9_\-]{43,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"sq0csp-"},
			Tags:        []string{"square", "payment", "secret"},
		},

		// =====================================================================
		// Telegram (82)
		// =====================================================================
		{
			ID:          "telegram-bot-token",
			Description: "Telegram Bot API Token",
			Regex:       `\b([0-9]{8,10}:[A-Za-z0-9_\-]{35})\b`,
			SecretGroup: 1,
			Keywords:    []string{"telegram", "bot", "t.me"},
			Tags:        []string{"telegram", "messaging", "token"},
		},

		// =====================================================================
		// HubSpot (83)
		// =====================================================================
		{
			ID:          "hubspot-api-key",
			Description: "HubSpot API Key",
			Regex:       `(?i)(?:hubspot[_\-]?api[_\-]?key|HUBSPOT_API_KEY)\s*[:=]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"hubspot"},
			Tags:        []string{"hubspot", "crm", "api-key"},
		},

		// =====================================================================
		// HubSpot Private App (84)
		// =====================================================================
		{
			ID:          "hubspot-private-app-token",
			Description: "HubSpot Private App Access Token",
			Regex:       `(?i)(?:hubspot[_\-]?(?:private[_\-]?)?(?:app[_\-]?)?(?:access[_\-]?)?token)\s*[:=]\s*["\']?(pat-[a-z]{2}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"hubspot", "pat-"},
			Tags:        []string{"hubspot", "crm", "token"},
		},

		// =====================================================================
		// Salesforce (85)
		// =====================================================================
		{
			ID:          "salesforce-access-token",
			Description: "Salesforce Access Token / Session ID",
			Regex:       `(?i)(?:salesforce[_\-]?(?:access[_\-]?)?token|SF_ACCESS_TOKEN)\s*[:=]\s*["\']?([a-zA-Z0-9!.]{50,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"salesforce", "SF_ACCESS_TOKEN"},
			Tags:        []string{"salesforce", "crm", "token"},
		},

		// =====================================================================
		// Asana (86)
		// =====================================================================
		{
			ID:          "asana-pat",
			Description: "Asana Personal Access Token",
			Regex:       `(?i)(?:asana[_\-]?(?:personal[_\-]?)?(?:access[_\-]?)?token|ASANA_TOKEN)\s*[:=]\s*["\']?(0/[a-f0-9]{32})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"asana"},
			Tags:        []string{"asana", "project-management", "token"},
		},

		// =====================================================================
		// Monday.com (87)
		// =====================================================================
		{
			ID:          "monday-api-token",
			Description: "Monday.com API Token",
			Regex:       `(?i)(?:monday[_\-]?api[_\-]?(?:token|key)|MONDAY_TOKEN)\s*[:=]\s*["\']?(eyJhbGciOi[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"monday"},
			Tags:        []string{"monday", "project-management", "token"},
		},

		// =====================================================================
		// Notion (88)
		// =====================================================================
		{
			ID:          "notion-integration-token",
			Description: "Notion Integration Token",
			Regex:       `\b(secret_[A-Za-z0-9]{43})\b`,
			SecretGroup: 1,
			Keywords:    []string{"notion", "secret_"},
			Tags:        []string{"notion", "productivity", "token"},
		},

		// =====================================================================
		// Notion v2 (89)
		// =====================================================================
		{
			ID:          "notion-integration-token-v2",
			Description: "Notion Internal Integration Token (ntn_ prefix)",
			Regex:       `\b(ntn_[A-Za-z0-9]{43,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"ntn_"},
			Tags:        []string{"notion", "productivity", "token"},
		},

		// =====================================================================
		// Coinbase (90)
		// =====================================================================
		{
			ID:          "coinbase-api-key",
			Description: "Coinbase API Key/Secret",
			Regex:       `(?i)(?:coinbase[_\-]?(?:api[_\-]?)?(?:key|secret))\s*[:=]\s*["\']?([A-Za-z0-9]{16,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"coinbase"},
			Tags:        []string{"coinbase", "crypto", "api-key"},
		},

		// =====================================================================
		// PayPal (91)
		// =====================================================================
		{
			ID:          "paypal-braintree-token",
			Description: "PayPal Braintree Access Token",
			Regex:       `access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}`,
			Keywords:    []string{"access_token$production$"},
			Tags:        []string{"paypal", "payment", "token"},
		},

		// =====================================================================
		// Mattermost (92)
		// =====================================================================
		{
			ID:          "mattermost-webhook",
			Description: "Mattermost Incoming Webhook URL",
			Regex:       `https://[^\s/]+/hooks/[a-z0-9]{26}`,
			Keywords:    []string{"/hooks/", "mattermost"},
			Tags:        []string{"mattermost", "messaging", "webhook"},
		},

		// =====================================================================
		// Jira (93)
		// =====================================================================
		{
			ID:          "jira-api-token",
			Description: "Jira API Token",
			Regex:       `(?i)(?:jira[_\-]?(?:api[_\-]?)?token|JIRA_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9+/=]{24,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"jira"},
			Tags:        []string{"jira", "project-management", "token"},
		},

		// =====================================================================
		// Confluence (94)
		// =====================================================================
		{
			ID:          "confluence-api-token",
			Description: "Confluence API Token",
			Regex:       `(?i)(?:confluence[_\-]?(?:api[_\-]?)?token|CONFLUENCE_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9+/=]{24,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"confluence"},
			Tags:        []string{"confluence", "documentation", "token"},
		},

		// =====================================================================
		// HashiCorp Vault (95)
		// =====================================================================
		{
			ID:          "vault-token",
			Description: "HashiCorp Vault Token",
			Regex:       `(?i)(?:VAULT_TOKEN|vault[_\-]?token)\s*[:=]\s*["\']?(hvs\.[A-Za-z0-9_\-]{24,}|s\.[A-Za-z0-9]{24})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"vault", "hvs.", "VAULT_TOKEN"},
			Tags:        []string{"vault", "infrastructure", "token"},
		},

		// =====================================================================
		// Vault Batch Token (96)
		// =====================================================================
		{
			ID:          "vault-batch-token",
			Description: "HashiCorp Vault Batch Token",
			Regex:       `\b(hvb\.[A-Za-z0-9_\-]{100,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"hvb."},
			Tags:        []string{"vault", "infrastructure", "token"},
		},

		// =====================================================================
		// Terraform (97)
		// =====================================================================
		{
			ID:          "terraform-cloud-token",
			Description: "Terraform Cloud / Enterprise API Token",
			Regex:       `(?i)(?:TFE_TOKEN|terraform[_\-]?(?:cloud[_\-]?)?token)\s*[:=]\s*["\']?([A-Za-z0-9.]{14,170})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"terraform", "TFE_TOKEN"},
			Tags:        []string{"terraform", "infrastructure", "token"},
		},

		// =====================================================================
		// Terraform TFC prefix (98)
		// =====================================================================
		{
			ID:          "terraform-cloud-api-token",
			Description: "Terraform Cloud API Token (atlasv1 prefix)",
			Regex:       `\b(atlasv1\.[A-Za-z0-9_\-]{64,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"atlasv1."},
			Tags:        []string{"terraform", "infrastructure", "token"},
		},

		// =====================================================================
		// Pulumi (99)
		// =====================================================================
		{
			ID:          "pulumi-access-token",
			Description: "Pulumi Access Token",
			Regex:       `\b(pul-[a-f0-9]{40})\b`,
			SecretGroup: 1,
			Keywords:    []string{"pul-"},
			Tags:        []string{"pulumi", "infrastructure", "token"},
		},

		// =====================================================================
		// Docker (100)
		// =====================================================================
		{
			ID:          "docker-registry-password",
			Description: "Docker Registry Password in config",
			Regex:       `(?i)(?:docker[_\-]?(?:registry[_\-]?)?password|DOCKER_PASSWORD)\s*[:=]\s*["\']?([^\s"']{8,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"docker", "registry", "password"},
			Tags:        []string{"docker", "infrastructure", "password"},
		},

		// =====================================================================
		// Docker Auth (101)
		// =====================================================================
		{
			ID:          "docker-config-auth",
			Description: "Docker config.json auth",
			Regex:       `"auth"\s*:\s*"([A-Za-z0-9+/=]{20,})"`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"auth"},
			Path:        `(?:\.docker/config\.json|docker.*config)`,
			Tags:        []string{"docker", "infrastructure", "auth"},
		},

		// =====================================================================
		// Kubernetes (102-103)
		// =====================================================================
		{
			ID:          "kubernetes-secret-yaml",
			Description: "Kubernetes Secret in YAML manifest",
			Regex:       `(?i)kind:\s*Secret[\s\S]*data:[\s\S]*:\s*([A-Za-z0-9+/=]{20,})`,
			Keywords:    []string{"kind:", "Secret", "data:"},
			Path:        `\.ya?ml$`,
			Tags:        []string{"kubernetes", "infrastructure", "secret"},
		},
		{
			ID:          "kubernetes-service-account-token",
			Description: "Kubernetes Service Account Token",
			Regex:       `\beyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`,
			Keywords:    []string{"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"},
			Tags:        []string{"kubernetes", "infrastructure", "token"},
		},

		// =====================================================================
		// MongoDB (104)
		// =====================================================================
		{
			ID:          "mongodb-connection-string",
			Description: "MongoDB Connection String with credentials",
			Regex:       `mongodb(?:\+srv)?://[^\s"'<>{}|\\^` + "`" + `]+:[^\s"'<>{}|\\^` + "`" + `]+@[^\s"'<>{}|\\^` + "`" + `]+`,
			Keywords:    []string{"mongodb://", "mongodb+srv://"},
			Tags:        []string{"mongodb", "database", "connection-string"},
		},

		// =====================================================================
		// MySQL (105)
		// =====================================================================
		{
			ID:          "mysql-connection-string",
			Description: "MySQL Connection String with credentials",
			Regex:       `mysql://[^\s"'<>{}|\\^` + "`" + `]+:[^\s"'<>{}|\\^` + "`" + `]+@[^\s"'<>{}|\\^` + "`" + `]+`,
			Keywords:    []string{"mysql://"},
			Tags:        []string{"mysql", "database", "connection-string"},
		},

		// =====================================================================
		// PostgreSQL (106)
		// =====================================================================
		{
			ID:          "postgresql-connection-string",
			Description: "PostgreSQL Connection String with credentials",
			Regex:       `postgres(?:ql)?://[^\s"'<>{}|\\^` + "`" + `]+:[^\s"'<>{}|\\^` + "`" + `]+@[^\s"'<>{}|\\^` + "`" + `]+`,
			Keywords:    []string{"postgres://", "postgresql://"},
			Tags:        []string{"postgresql", "database", "connection-string"},
		},

		// =====================================================================
		// Redis (107)
		// =====================================================================
		{
			ID:          "redis-connection-string",
			Description: "Redis Connection String with credentials",
			Regex:       `redis://[^\s"'<>{}|\\^` + "`" + `]*:[^\s"'<>{}|\\^` + "`" + `]+@[^\s"'<>{}|\\^` + "`" + `]+`,
			Keywords:    []string{"redis://"},
			Tags:        []string{"redis", "database", "connection-string"},
		},

		// =====================================================================
		// Databricks (108)
		// =====================================================================
		{
			ID:          "databricks-api-token",
			Description: "Databricks API Token",
			Regex:       `\b(dapi[a-f0-9]{32})\b`,
			SecretGroup: 1,
			Keywords:    []string{"dapi"},
			Tags:        []string{"databricks", "database", "token"},
		},

		// =====================================================================
		// ClickHouse (109)
		// =====================================================================
		{
			ID:          "clickhouse-credentials",
			Description: "ClickHouse Connection Credentials",
			Regex:       `(?i)(?:clickhouse[_\-]?password)\s*[:=]\s*["\']?([^\s"']{8,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"clickhouse", "password"},
			Tags:        []string{"clickhouse", "database", "password"},
		},

		// =====================================================================
		// JDBC (110)
		// =====================================================================
		{
			ID:          "jdbc-connection-string",
			Description: "JDBC Connection String with credentials",
			Regex:       `(?i)jdbc:[a-z0-9]+://[^\s"']+(?:password|pwd)\s*=\s*([^\s&"';]+)`,
			SecretGroup: 1,
			Keywords:    []string{"jdbc:"},
			Tags:        []string{"jdbc", "database", "connection-string"},
		},

		// =====================================================================
		// ODBC (111)
		// =====================================================================
		{
			ID:          "odbc-connection-string",
			Description: "ODBC Connection String with credentials",
			Regex:       `(?i)(?:Driver|DSN)\s*=[^;]*;[^;]*(?:Pwd|Password)\s*=\s*([^;\s"']+)`,
			SecretGroup: 1,
			Keywords:    []string{"Driver=", "DSN=", "Pwd=", "Password="},
			Tags:        []string{"odbc", "database", "connection-string"},
		},

		// =====================================================================
		// Generic DB Password (112)
		// =====================================================================
		{
			ID:          "generic-db-password",
			Description: "Generic Database Password Assignment",
			Regex:       `(?i)(?:db[_\-]?pass(?:word)?|database[_\-]?pass(?:word)?|DB_PASSWORD)\s*[:=]\s*["\']([^\s"']{8,})["\']`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"db_pass", "db_password", "database_password", "DB_PASSWORD"},
			Tags:        []string{"database", "password", "generic"},
		},

		// =====================================================================
		// JWT (113)
		// =====================================================================
		{
			ID:          "jwt-token",
			Description: "JSON Web Token",
			Regex:       `\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"eyJ"},
			Tags:        []string{"jwt", "auth", "token"},
		},

		// =====================================================================
		// Private Keys (114-120)
		// =====================================================================
		{
			ID:          "private-key-rsa",
			Description: "RSA Private Key",
			Regex:       `-----BEGIN RSA PRIVATE KEY-----`,
			Keywords:    []string{"BEGIN RSA PRIVATE KEY"},
			Tags:        []string{"rsa", "crypto", "private-key"},
		},
		{
			ID:          "private-key-ec",
			Description: "EC Private Key",
			Regex:       `-----BEGIN EC PRIVATE KEY-----`,
			Keywords:    []string{"BEGIN EC PRIVATE KEY"},
			Tags:        []string{"ec", "crypto", "private-key"},
		},
		{
			ID:          "private-key-dsa",
			Description: "DSA Private Key",
			Regex:       `-----BEGIN DSA PRIVATE KEY-----`,
			Keywords:    []string{"BEGIN DSA PRIVATE KEY"},
			Tags:        []string{"dsa", "crypto", "private-key"},
		},
		{
			ID:          "private-key-openssh",
			Description: "OpenSSH Private Key",
			Regex:       `-----BEGIN OPENSSH PRIVATE KEY-----`,
			Keywords:    []string{"BEGIN OPENSSH PRIVATE KEY"},
			Tags:        []string{"ssh", "crypto", "private-key"},
		},
		{
			ID:          "private-key-pgp",
			Description: "PGP Private Key Block",
			Regex:       `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
			Keywords:    []string{"BEGIN PGP PRIVATE KEY BLOCK"},
			Tags:        []string{"pgp", "crypto", "private-key"},
		},
		{
			ID:          "private-key-generic",
			Description: "Generic Private Key",
			Regex:       `-----BEGIN PRIVATE KEY-----`,
			Keywords:    []string{"BEGIN PRIVATE KEY"},
			Tags:        []string{"crypto", "private-key"},
		},
		{
			ID:          "private-key-encrypted",
			Description: "Encrypted Private Key",
			Regex:       `-----BEGIN ENCRYPTED PRIVATE KEY-----`,
			Keywords:    []string{"BEGIN ENCRYPTED PRIVATE KEY"},
			Tags:        []string{"crypto", "private-key"},
		},

		// =====================================================================
		// PKCS12/PFX (121)
		// =====================================================================
		{
			ID:          "pkcs12-pfx-file",
			Description: "PKCS12/PFX File Reference with Password",
			Regex:       `(?i)(?:pfx[_\-]?password|pkcs12[_\-]?password|keystore[_\-]?password)\s*[:=]\s*["\']?([^\s"']{4,})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"pfx_password", "pkcs12", "keystore_password"},
			Tags:        []string{"pkcs12", "crypto", "password"},
		},

		// =====================================================================
		// Age encryption key (122)
		// =====================================================================
		{
			ID:          "age-secret-key",
			Description: "Age Encryption Secret Key",
			Regex:       `\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b`,
			Keywords:    []string{"AGE-SECRET-KEY-"},
			Tags:        []string{"age", "crypto", "key"},
		},

		// =====================================================================
		// Bearer Token (123)
		// =====================================================================
		{
			ID:          "bearer-token",
			Description: "Bearer Token in Authorization Header",
			Regex:       `(?i)(?:Authorization|Bearer)\s*[:=]\s*["\']?Bearer\s+([A-Za-z0-9_\-\.=]+)["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"bearer", "authorization"},
			Tags:        []string{"auth", "bearer", "token"},
		},

		// =====================================================================
		// Basic Auth in URL (124)
		// =====================================================================
		{
			ID:          "basic-auth-url",
			Description: "Basic Auth Credentials in URL",
			Regex:       `https?://([^\s/'"<>{}|\\^` + "`" + `]+:[^\s/'"<>{}|\\^` + "`" + `]+)@[^\s/'"<>{}|\\^` + "`" + `]+`,
			SecretGroup: 1,
			Entropy:     1.0,
			Keywords:    []string{"://"},
			Tags:        []string{"auth", "url", "credentials"},
			Allowlists: []config.Allowlist{
				{
					Description: "Ignore placeholder credentials",
					StopWords:   []string{"username", "password", "user", "pass", "example", "xxx", "your_", "<"},
				},
			},
		},

		// =====================================================================
		// Curl Auth (125)
		// =====================================================================
		{
			ID:          "curl-auth-header",
			Description: "Curl Command with Authentication Header",
			Regex:       `(?i)curl\s[^\n]*-[Hh]\s*["\']?Authorization:\s*(Basic|Bearer)\s+([A-Za-z0-9+/=_\-\.]{20,})["\']?`,
			SecretGroup: 2,
			Entropy:     3.0,
			Keywords:    []string{"curl", "Authorization"},
			Tags:        []string{"auth", "curl", "header"},
		},

		// =====================================================================
		// Curl User (126)
		// =====================================================================
		{
			ID:          "curl-user-credentials",
			Description: "Curl Command with User Credentials",
			Regex:       `(?i)curl\s[^\n]*-u\s+["\']?([^\s"':]+:[^\s"']+)["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"curl", "-u "},
			Tags:        []string{"auth", "curl", "credentials"},
			Allowlists: []config.Allowlist{
				{
					Description: "Ignore placeholder credentials",
					StopWords:   []string{"username", "password", "user", "pass", "example", "xxx", "<"},
				},
			},
		},

		// =====================================================================
		// Generic API Key patterns (127-130)
		// =====================================================================
		{
			ID:          "generic-api-key",
			Description: "Generic API Key Assignment",
			Regex:       `(?i)(?:api[_\-]?key|apikey|api[_\-]?token|access[_\-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"api_key", "apikey", "api-key", "api_token", "access_key"},
			Tags:        []string{"generic", "api-key"},
			Allowlists: []config.Allowlist{
				{
					Description: "Ignore common placeholder values",
					StopWords:   []string{"your_api_key", "CHANGE_ME", "INSERT_", "TODO", "example", "placeholder", "xxxx", "test"},
				},
			},
		},
		{
			ID:          "generic-secret-assignment",
			Description: "Generic Secret Assignment",
			Regex:       `(?i)(?:secret|client[_\-]?secret|app[_\-]?secret|application[_\-]?secret)\s*[:=]\s*["\']([A-Za-z0-9_\-/+=]{20,})["\']`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"secret"},
			Tags:        []string{"generic", "secret"},
			Allowlists: []config.Allowlist{
				{
					Description: "Ignore common placeholder values",
					StopWords:   []string{"your_secret", "CHANGE_ME", "INSERT_", "TODO", "example", "placeholder", "xxxx", "test", "secret_here"},
				},
			},
		},
		{
			ID:          "generic-token-assignment",
			Description: "Generic Token Assignment",
			Regex:       `(?i)(?:auth[_\-]?token|access[_\-]?token|secret[_\-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-/+=.]{20,})["\']`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"auth_token", "access_token", "secret_token"},
			Tags:        []string{"generic", "token"},
			Allowlists: []config.Allowlist{
				{
					Description: "Ignore common placeholder values",
					StopWords:   []string{"your_token", "CHANGE_ME", "INSERT_", "TODO", "example", "placeholder", "xxxx", "test"},
				},
			},
		},
		{
			ID:          "generic-password-assignment",
			Description: "Generic Password Assignment",
			Regex:       `(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^\s"']{8,})["\']`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"password", "passwd", "pwd"},
			Tags:        []string{"generic", "password"},
			Allowlists: []config.Allowlist{
				{
					Description: "Ignore common placeholder values",
					StopWords:   []string{"password", "CHANGE_ME", "INSERT_", "TODO", "example", "placeholder", "xxxx", "test", "changeme", "your_password", "********"},
				},
			},
		},

		// =====================================================================
		// OAuth Client Secret (131)
		// =====================================================================
		{
			ID:          "oauth-client-secret",
			Description: "OAuth Client Secret",
			Regex:       `(?i)(?:oauth[_\-]?)?client[_\-]?secret\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"client_secret", "client-secret"},
			Tags:        []string{"oauth", "auth", "secret"},
		},

		// =====================================================================
		// SAML (132)
		// =====================================================================
		{
			ID:          "saml-private-key",
			Description: "SAML Private Key or Certificate",
			Regex:       `(?i)(?:saml[_\-]?(?:private[_\-]?)?key|saml[_\-]?cert(?:ificate)?)\s*[:=]\s*["\']([A-Za-z0-9+/=\n]{50,})["\']`,
			SecretGroup: 1,
			Keywords:    []string{"saml"},
			Tags:        []string{"saml", "auth", "key"},
		},

		// =====================================================================
		// Base64-Encoded Credentials (133)
		// =====================================================================
		{
			ID:          "base64-basic-auth",
			Description: "Base64-Encoded Basic Auth Credentials",
			Regex:       `(?i)(?:basic)\s+((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=))\b`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"basic"},
			Tags:        []string{"auth", "base64", "credentials"},
		},

		// =====================================================================
		// Hardcoded Password in Source (134)
		// =====================================================================
		{
			ID:          "hardcoded-password-source",
			Description: "Hardcoded Password in Source Code",
			Regex:       `(?i)(?:password|passwd|pwd|pass)\s*=\s*["\']([^"'\s]{8,})["\']`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"password", "passwd", "pwd"},
			Tags:        []string{"password", "hardcoded"},
			Allowlists: []config.Allowlist{
				{
					Description: "Ignore common test/placeholder passwords",
					StopWords:   []string{"password", "changeme", "CHANGE_ME", "TODO", "example", "placeholder", "xxxx", "test123", "your_password", "********", "admin", "root"},
				},
				{
					Description: "Ignore test files",
					Paths:       []string{`(?:_test|test_|spec|mock)\.`},
				},
			},
		},

		// =====================================================================
		// AI/ML Keys (135-141)
		// =====================================================================
		{
			ID:          "openai-api-key",
			Description: "OpenAI API Key",
			Regex:       `\b(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b`,
			SecretGroup: 1,
			Keywords:    []string{"sk-", "T3BlbkFJ"},
			Tags:        []string{"openai", "ai", "api-key"},
		},
		{
			ID:          "openai-api-key-v2",
			Description: "OpenAI API Key (project-scoped)",
			Regex:       `\b(sk-proj-[A-Za-z0-9_\-]{40,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"sk-proj-"},
			Tags:        []string{"openai", "ai", "api-key"},
		},
		{
			ID:          "anthropic-api-key",
			Description: "Anthropic API Key",
			Regex:       `\b(sk-ant-api03-[A-Za-z0-9_\-]{90,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"sk-ant-"},
			Tags:        []string{"anthropic", "ai", "api-key"},
		},
		{
			ID:          "google-ai-api-key",
			Description: "Google AI / Gemini API Key",
			Regex:       `(?i)(?:gemini[_\-]?api[_\-]?key|GOOGLE_AI_API_KEY)\s*[:=]\s*["\']?(AIza[A-Za-z0-9_\-]{35})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"gemini", "GOOGLE_AI", "AIza"},
			Tags:        []string{"google", "ai", "api-key"},
		},
		{
			ID:          "huggingface-token",
			Description: "Hugging Face Access Token",
			Regex:       `\b(hf_[A-Za-z0-9]{34,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"hf_"},
			Tags:        []string{"huggingface", "ai", "token"},
		},
		{
			ID:          "cohere-api-key",
			Description: "Cohere API Key",
			Regex:       `(?i)(?:cohere[_\-]?api[_\-]?key|COHERE_API_KEY)\s*[:=]\s*["\']?([A-Za-z0-9]{40})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"cohere"},
			Tags:        []string{"cohere", "ai", "api-key"},
		},
		{
			ID:          "replicate-api-token",
			Description: "Replicate API Token",
			Regex:       `\b(r8_[A-Za-z0-9]{36})\b`,
			SecretGroup: 1,
			Keywords:    []string{"r8_"},
			Tags:        []string{"replicate", "ai", "token"},
		},

		// =====================================================================
		// Cloudflare (142-144)
		// =====================================================================
		{
			ID:          "cloudflare-api-key",
			Description: "Cloudflare Global API Key",
			Regex:       `(?i)(?:cloudflare[_\-]?(?:api[_\-]?)?key|CF_API_KEY)\s*[:=]\s*["\']?([a-f0-9]{37})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"cloudflare", "CF_API_KEY"},
			Tags:        []string{"cloudflare", "cdn", "api-key"},
		},
		{
			ID:          "cloudflare-api-token",
			Description: "Cloudflare API Token",
			Regex:       `(?i)(?:cloudflare[_\-]?(?:api[_\-]?)?token|CF_API_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{40})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"cloudflare", "CF_API_TOKEN"},
			Tags:        []string{"cloudflare", "cdn", "token"},
		},
		{
			ID:          "cloudflare-origin-ca-key",
			Description: "Cloudflare Origin CA Key",
			Regex:       `\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"v1.0-"},
			Tags:        []string{"cloudflare", "cdn", "key"},
		},

		// =====================================================================
		// Fastly (145)
		// =====================================================================
		{
			ID:          "fastly-api-token",
			Description: "Fastly API Token",
			Regex:       `(?i)(?:fastly[_\-]?(?:api[_\-]?)?(?:token|key)|FASTLY_API_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{32})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"fastly"},
			Tags:        []string{"fastly", "cdn", "token"},
		},

		// =====================================================================
		// LaunchDarkly (146-147)
		// =====================================================================
		{
			ID:          "launchdarkly-sdk-key",
			Description: "LaunchDarkly SDK Key",
			Regex:       `(?i)(?:launchdarkly[_\-]?sdk[_\-]?key|LD_SDK_KEY)\s*[:=]\s*["\']?(sdk-[a-f0-9\-]{36})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"launchdarkly", "sdk-", "LD_SDK_KEY"},
			Tags:        []string{"launchdarkly", "feature-flag", "key"},
		},
		{
			ID:          "launchdarkly-api-key",
			Description: "LaunchDarkly API Access Token",
			Regex:       `(?i)(?:launchdarkly[_\-]?(?:api[_\-]?)?(?:access[_\-]?)?(?:token|key)|LD_API_KEY)\s*[:=]\s*["\']?(api-[a-f0-9\-]{36})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"launchdarkly", "api-", "LD_API_KEY"},
			Tags:        []string{"launchdarkly", "feature-flag", "key"},
		},

		// =====================================================================
		// Linear (148)
		// =====================================================================
		{
			ID:          "linear-api-key",
			Description: "Linear API Key",
			Regex:       `\b(lin_api_[A-Za-z0-9]{40})\b`,
			SecretGroup: 1,
			Keywords:    []string{"lin_api_"},
			Tags:        []string{"linear", "project-management", "api-key"},
		},

		// =====================================================================
		// Lob (149-150)
		// =====================================================================
		{
			ID:          "lob-api-key",
			Description: "Lob API Key (Live)",
			Regex:       `(?i)(?:lob[_\-]?api[_\-]?key|LOB_API_KEY)\s*[:=]\s*["\']?(live_[a-f0-9]{35})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"lob", "live_"},
			Tags:        []string{"lob", "mail", "api-key"},
		},
		{
			ID:          "lob-pub-api-key",
			Description: "Lob Publishable API Key",
			Regex:       `(?i)(?:lob[_\-]?pub[_\-]?(?:api[_\-]?)?key)\s*[:=]\s*["\']?(live_pub_[a-f0-9]{31})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"lob", "live_pub_"},
			Tags:        []string{"lob", "mail", "api-key"},
		},

		// =====================================================================
		// Mapbox (151)
		// =====================================================================
		{
			ID:          "mapbox-access-token",
			Description: "Mapbox Access Token",
			Regex:       `\b(pk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9_\-]{20,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"pk.", "mapbox"},
			Tags:        []string{"mapbox", "maps", "token"},
		},

		// =====================================================================
		// Mapbox Secret (152)
		// =====================================================================
		{
			ID:          "mapbox-secret-token",
			Description: "Mapbox Secret Token",
			Regex:       `\b(sk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9_\-]{20,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"sk.", "mapbox"},
			Tags:        []string{"mapbox", "maps", "secret"},
		},

		// =====================================================================
		// MessageBird (153)
		// =====================================================================
		{
			ID:          "messagebird-api-key",
			Description: "MessageBird API Key",
			Regex:       `(?i)(?:messagebird[_\-]?(?:api[_\-]?)?(?:key|token)|MESSAGEBIRD_API_KEY)\s*[:=]\s*["\']?([A-Za-z0-9]{25})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"messagebird"},
			Tags:        []string{"messagebird", "communication", "api-key"},
		},

		// =====================================================================
		// Netlify (154)
		// =====================================================================
		{
			ID:          "netlify-access-token",
			Description: "Netlify Access Token",
			Regex:       `(?i)(?:netlify[_\-]?(?:access[_\-]?)?(?:auth[_\-]?)?token|NETLIFY_AUTH_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{40,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"netlify"},
			Tags:        []string{"netlify", "hosting", "token"},
		},

		// =====================================================================
		// Okta (155)
		// =====================================================================
		{
			ID:          "okta-api-token",
			Description: "Okta API Token",
			Regex:       `(?i)(?:okta[_\-]?(?:api[_\-]?)?token|OKTA_TOKEN)\s*[:=]\s*["\']?(00[A-Za-z0-9_\-]{40})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"okta"},
			Tags:        []string{"okta", "auth", "token"},
		},

		// =====================================================================
		// PlanetScale (156)
		// =====================================================================
		{
			ID:          "planetscale-token",
			Description: "PlanetScale API Token",
			Regex:       `\b(pscale_tkn_[A-Za-z0-9_\-]{43})\b`,
			SecretGroup: 1,
			Keywords:    []string{"pscale_tkn_"},
			Tags:        []string{"planetscale", "database", "token"},
		},

		// =====================================================================
		// PlanetScale Password (157)
		// =====================================================================
		{
			ID:          "planetscale-password",
			Description: "PlanetScale Database Password",
			Regex:       `\b(pscale_pw_[A-Za-z0-9_\-]{43})\b`,
			SecretGroup: 1,
			Keywords:    []string{"pscale_pw_"},
			Tags:        []string{"planetscale", "database", "password"},
		},

		// =====================================================================
		// PlanetScale OAuth (158)
		// =====================================================================
		{
			ID:          "planetscale-oauth-token",
			Description: "PlanetScale OAuth Token",
			Regex:       `\b(pscale_oauth_[A-Za-z0-9_\-]{43})\b`,
			SecretGroup: 1,
			Keywords:    []string{"pscale_oauth_"},
			Tags:        []string{"planetscale", "database", "oauth"},
		},

		// =====================================================================
		// Postman (159)
		// =====================================================================
		{
			ID:          "postman-api-key",
			Description: "Postman API Key",
			Regex:       `\b(PMAK-[A-Za-z0-9]{24}-[a-f0-9]{34})\b`,
			SecretGroup: 1,
			Keywords:    []string{"PMAK-"},
			Tags:        []string{"postman", "api-testing", "key"},
		},

		// =====================================================================
		// RapidAPI (160)
		// =====================================================================
		{
			ID:          "rapidapi-key",
			Description: "RapidAPI Key",
			Regex:       `(?i)(?:rapidapi[_\-]?key|X-RapidAPI-Key)\s*[:=]\s*["\']?([a-f0-9]{50})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"rapidapi", "X-RapidAPI-Key"},
			Tags:        []string{"rapidapi", "api", "key"},
		},

		// =====================================================================
		// Supabase (161)
		// =====================================================================
		{
			ID:          "supabase-service-role-key",
			Description: "Supabase Service Role Key",
			Regex:       `\b(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b`,
			SecretGroup: 1,
			Keywords:    []string{"supabase", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
			Tags:        []string{"supabase", "database", "key"},
		},

		// =====================================================================
		// Vercel (162)
		// =====================================================================
		{
			ID:          "vercel-access-token",
			Description: "Vercel Access Token",
			Regex:       `(?i)(?:vercel[_\-]?(?:access[_\-]?)?token|VERCEL_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9]{24})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"vercel"},
			Tags:        []string{"vercel", "hosting", "token"},
		},

		// =====================================================================
		// Vonage (163-164)
		// =====================================================================
		{
			ID:          "vonage-api-key",
			Description: "Vonage API Key",
			Regex:       `(?i)(?:vonage[_\-]?api[_\-]?key|VONAGE_API_KEY)\s*[:=]\s*["\']?([a-f0-9]{8})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"vonage"},
			Tags:        []string{"vonage", "communication", "api-key"},
		},
		{
			ID:          "vonage-api-secret",
			Description: "Vonage API Secret",
			Regex:       `(?i)(?:vonage[_\-]?api[_\-]?secret|VONAGE_API_SECRET)\s*[:=]\s*["\']?([A-Za-z0-9]{16})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"vonage"},
			Tags:        []string{"vonage", "communication", "secret"},
		},

		// =====================================================================
		// Stripe Test Keys (165-166)
		// =====================================================================
		{
			ID:          "stripe-test-secret-key",
			Description: "Stripe Test Secret Key",
			Regex:       `\b(sk_test_[A-Za-z0-9]{20,99})\b`,
			SecretGroup: 1,
			Keywords:    []string{"sk_test_"},
			Tags:        []string{"stripe", "payment", "test"},
		},
		{
			ID:          "stripe-test-publishable-key",
			Description: "Stripe Test Publishable Key",
			Regex:       `\b(pk_test_[A-Za-z0-9]{20,99})\b`,
			SecretGroup: 1,
			Keywords:    []string{"pk_test_"},
			Tags:        []string{"stripe", "payment", "test"},
		},

		// =====================================================================
		// Slack Configuration Token (167)
		// =====================================================================
		{
			ID:          "slack-config-token",
			Description: "Slack Configuration/Refresh Token",
			Regex:       `\b(xoxe\.xox[bp]-[0-9]+-[A-Za-z0-9\-]+)\b`,
			SecretGroup: 1,
			Keywords:    []string{"xoxe.xox"},
			Tags:        []string{"slack", "messaging", "token"},
		},

		// =====================================================================
		// Slack Legacy Token (168)
		// =====================================================================
		{
			ID:          "slack-legacy-token",
			Description: "Slack Legacy API Token",
			Regex:       `\b(xoxs-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9\-]+)\b`,
			SecretGroup: 1,
			Keywords:    []string{"xoxs-"},
			Tags:        []string{"slack", "messaging", "token"},
		},

		// =====================================================================
		// Slack Legacy Workspace Token (169)
		// =====================================================================
		{
			ID:          "slack-workspace-token",
			Description: "Slack Legacy Workspace Token",
			Regex:       `\b(xoxa-[0-9]+-[0-9]+-[A-Za-z0-9\-]+)\b`,
			SecretGroup: 1,
			Keywords:    []string{"xoxa-"},
			Tags:        []string{"slack", "messaging", "token"},
		},

		// =====================================================================
		// Twitch (170)
		// =====================================================================
		{
			ID:          "twitch-api-token",
			Description: "Twitch API Token",
			Regex:       `(?i)(?:twitch[_\-]?(?:api[_\-]?)?(?:token|key|secret)|TWITCH_CLIENT_SECRET)\s*[:=]\s*["\']?([a-z0-9]{30})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"twitch"},
			Tags:        []string{"twitch", "streaming", "token"},
		},

		// =====================================================================
		// Twitter / X (171-172)
		// =====================================================================
		{
			ID:          "twitter-bearer-token",
			Description: "Twitter / X Bearer Token",
			Regex:       `(?i)(?:twitter[_\-]?bearer[_\-]?token|TWITTER_BEARER_TOKEN)\s*[:=]\s*["\']?(AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+)["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"twitter", "AAAAAAAAAAAAAAAAAA"},
			Tags:        []string{"twitter", "social", "token"},
		},
		{
			ID:          "twitter-api-secret",
			Description: "Twitter / X API Secret",
			Regex:       `(?i)(?:twitter[_\-]?(?:api[_\-]?)?(?:secret|consumer[_\-]?secret)|TWITTER_API_SECRET)\s*[:=]\s*["\']?([A-Za-z0-9]{35,65})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"twitter"},
			Tags:        []string{"twitter", "social", "secret"},
		},

		// =====================================================================
		// Instagram (173)
		// =====================================================================
		{
			ID:          "instagram-access-token",
			Description: "Instagram Access Token",
			Regex:       `(?i)(?:instagram[_\-]?(?:access[_\-]?)?token|IG_ACCESS_TOKEN)\s*[:=]\s*["\']?(IGQV[A-Za-z0-9_\-]+)["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"instagram", "IGQV"},
			Tags:        []string{"instagram", "social", "token"},
		},

		// =====================================================================
		// Facebook (174)
		// =====================================================================
		{
			ID:          "facebook-access-token",
			Description: "Facebook Access Token",
			Regex:       `\b(EAA[A-Za-z0-9]{100,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"EAA", "facebook"},
			Tags:        []string{"facebook", "social", "token"},
		},

		// =====================================================================
		// LinkedIn (175)
		// =====================================================================
		{
			ID:          "linkedin-client-secret",
			Description: "LinkedIn Client Secret",
			Regex:       `(?i)(?:linkedin[_\-]?client[_\-]?secret|LINKEDIN_CLIENT_SECRET)\s*[:=]\s*["\']?([A-Za-z0-9]{16})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"linkedin"},
			Tags:        []string{"linkedin", "social", "secret"},
		},

		// =====================================================================
		// Intercom (176)
		// =====================================================================
		{
			ID:          "intercom-access-token",
			Description: "Intercom Access Token",
			Regex:       `(?i)(?:intercom[_\-]?(?:access[_\-]?)?token|INTERCOM_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9=_\-]{60,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"intercom"},
			Tags:        []string{"intercom", "support", "token"},
		},

		// =====================================================================
		// Zendesk (177)
		// =====================================================================
		{
			ID:          "zendesk-api-token",
			Description: "Zendesk API Token",
			Regex:       `(?i)(?:zendesk[_\-]?(?:api[_\-]?)?token|ZENDESK_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9]{40})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"zendesk"},
			Tags:        []string{"zendesk", "support", "token"},
		},

		// =====================================================================
		// Algolia (178-179)
		// =====================================================================
		{
			ID:          "algolia-api-key",
			Description: "Algolia API Key",
			Regex:       `(?i)(?:algolia[_\-]?(?:api[_\-]?)?key|ALGOLIA_API_KEY)\s*[:=]\s*["\']?([a-f0-9]{32})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"algolia"},
			Tags:        []string{"algolia", "search", "api-key"},
		},
		{
			ID:          "algolia-admin-key",
			Description: "Algolia Admin API Key",
			Regex:       `(?i)(?:algolia[_\-]?admin[_\-]?(?:api[_\-]?)?key|ALGOLIA_ADMIN_KEY)\s*[:=]\s*["\']?([a-f0-9]{32})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"algolia", "admin"},
			Tags:        []string{"algolia", "search", "admin-key"},
		},

		// =====================================================================
		// Elasticsearch (180)
		// =====================================================================
		{
			ID:          "elasticsearch-credentials",
			Description: "Elasticsearch Credentials in URL",
			Regex:       `https?://[^\s"']+:[^\s"']+@[^\s"']*(?:elastic|es|elasticsearch)[^\s"']*(?::\d+)?`,
			Keywords:    []string{"elastic", "elasticsearch"},
			Tags:        []string{"elasticsearch", "search", "credentials"},
		},

		// =====================================================================
		// Airtable (181)
		// =====================================================================
		{
			ID:          "airtable-api-key",
			Description: "Airtable API Key",
			Regex:       `(?i)(?:airtable[_\-]?(?:api[_\-]?)?key|AIRTABLE_API_KEY)\s*[:=]\s*["\']?(key[A-Za-z0-9]{14})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"airtable", "key"},
			Tags:        []string{"airtable", "productivity", "api-key"},
		},

		// =====================================================================
		// Airtable PAT (182)
		// =====================================================================
		{
			ID:          "airtable-pat",
			Description: "Airtable Personal Access Token",
			Regex:       `\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b`,
			SecretGroup: 1,
			Keywords:    []string{"pat", "airtable"},
			Tags:        []string{"airtable", "productivity", "token"},
		},

		// =====================================================================
		// Doppler (183)
		// =====================================================================
		{
			ID:          "doppler-api-token",
			Description: "Doppler API Token",
			Regex:       `\b(dp\.pt\.[A-Za-z0-9]{43})\b`,
			SecretGroup: 1,
			Keywords:    []string{"dp.pt."},
			Tags:        []string{"doppler", "secrets-management", "token"},
		},

		// =====================================================================
		// Doppler Service Token (184)
		// =====================================================================
		{
			ID:          "doppler-service-token",
			Description: "Doppler Service Token",
			Regex:       `\b(dp\.st\.(?:[a-z0-9\-_]{2,35}\.)[A-Za-z0-9]{40,44})\b`,
			SecretGroup: 1,
			Keywords:    []string{"dp.st."},
			Tags:        []string{"doppler", "secrets-management", "token"},
		},

		// =====================================================================
		// Doppler CLI Token (185)
		// =====================================================================
		{
			ID:          "doppler-cli-token",
			Description: "Doppler CLI Auth Token",
			Regex:       `\b(dp\.ct\.[A-Za-z0-9]{40,44})\b`,
			SecretGroup: 1,
			Keywords:    []string{"dp.ct."},
			Tags:        []string{"doppler", "secrets-management", "token"},
		},

		// =====================================================================
		// Doppler SCIM Token (186)
		// =====================================================================
		{
			ID:          "doppler-scim-token",
			Description: "Doppler SCIM Token",
			Regex:       `\b(dp\.scim\.[A-Za-z0-9]{40,44})\b`,
			SecretGroup: 1,
			Keywords:    []string{"dp.scim."},
			Tags:        []string{"doppler", "secrets-management", "token"},
		},

		// =====================================================================
		// Doppler Audit Token (187)
		// =====================================================================
		{
			ID:          "doppler-audit-token",
			Description: "Doppler Audit Token",
			Regex:       `\b(dp\.audit\.[A-Za-z0-9]{40,44})\b`,
			SecretGroup: 1,
			Keywords:    []string{"dp.audit."},
			Tags:        []string{"doppler", "secrets-management", "token"},
		},

		// =====================================================================
		// 1Password (188)
		// =====================================================================
		{
			ID:          "1password-service-account-token",
			Description: "1Password Service Account Token",
			Regex:       `\b(ops_[A-Za-z0-9_\-]{80,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"ops_"},
			Tags:        []string{"1password", "secrets-management", "token"},
		},

		// =====================================================================
		// Snyk (189)
		// =====================================================================
		{
			ID:          "snyk-api-token",
			Description: "Snyk API Token",
			Regex:       `(?i)(?:snyk[_\-]?(?:api[_\-]?)?token|SNYK_TOKEN)\s*[:=]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"snyk"},
			Tags:        []string{"snyk", "security", "token"},
		},

		// =====================================================================
		// SonarQube / SonarCloud (190)
		// =====================================================================
		{
			ID:          "sonarqube-token",
			Description: "SonarQube / SonarCloud Token",
			Regex:       `\b(sqp_[a-f0-9]{40})\b`,
			SecretGroup: 1,
			Keywords:    []string{"sqp_"},
			Tags:        []string{"sonarqube", "security", "token"},
		},

		// =====================================================================
		// Contentful (191-192)
		// =====================================================================
		{
			ID:          "contentful-delivery-token",
			Description: "Contentful Delivery API Token",
			Regex:       `(?i)(?:contentful[_\-]?(?:delivery[_\-]?)?(?:api[_\-]?)?(?:token|key)|CONTENTFUL_ACCESS_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{43})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"contentful"},
			Tags:        []string{"contentful", "cms", "token"},
		},
		{
			ID:          "contentful-management-token",
			Description: "Contentful Management API Token",
			Regex:       `\b(CFPAT-[A-Za-z0-9_\-]{43})\b`,
			SecretGroup: 1,
			Keywords:    []string{"CFPAT-"},
			Tags:        []string{"contentful", "cms", "token"},
		},

		// =====================================================================
		// Figma (193)
		// =====================================================================
		{
			ID:          "figma-pat",
			Description: "Figma Personal Access Token",
			Regex:       `\b(figd_[A-Za-z0-9_\-]{40,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"figd_"},
			Tags:        []string{"figma", "design", "token"},
		},

		// =====================================================================
		// Finicity (194)
		// =====================================================================
		{
			ID:          "finicity-api-token",
			Description: "Finicity API Token",
			Regex:       `(?i)(?:finicity[_\-]?(?:api[_\-]?)?(?:token|key|secret))\s*[:=]\s*["\']?([a-f0-9]{32})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"finicity"},
			Tags:        []string{"finicity", "finance", "token"},
		},

		// =====================================================================
		// Flutterwave (195)
		// =====================================================================
		{
			ID:          "flutterwave-secret-key",
			Description: "Flutterwave Secret Key",
			Regex:       `\b(FLWSECK-[a-f0-9]{32}-X)\b`,
			SecretGroup: 1,
			Keywords:    []string{"FLWSECK-"},
			Tags:        []string{"flutterwave", "payment", "secret"},
		},

		// =====================================================================
		// Flutterwave Pub (196)
		// =====================================================================
		{
			ID:          "flutterwave-public-key",
			Description: "Flutterwave Public Key",
			Regex:       `\b(FLWPUBK-[a-f0-9]{32}-X)\b`,
			SecretGroup: 1,
			Keywords:    []string{"FLWPUBK-"},
			Tags:        []string{"flutterwave", "payment", "key"},
		},

		// =====================================================================
		// Flutterwave Enc (197)
		// =====================================================================
		{
			ID:          "flutterwave-encryption-key",
			Description: "Flutterwave Encryption Key",
			Regex:       `\b(FLWSECK_TEST-[a-f0-9]{12})\b`,
			SecretGroup: 1,
			Keywords:    []string{"FLWSECK_TEST-"},
			Tags:        []string{"flutterwave", "payment", "key"},
		},

		// =====================================================================
		// FrameIO (198)
		// =====================================================================
		{
			ID:          "frameio-api-token",
			Description: "Frame.io API Token",
			Regex:       `\b(fio-u-[A-Za-z0-9_\-]{64,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"fio-u-"},
			Tags:        []string{"frameio", "video", "token"},
		},

		// =====================================================================
		// GoCardless (199)
		// =====================================================================
		{
			ID:          "gocardless-api-token",
			Description: "GoCardless Live Access Token",
			Regex:       `\b(live_[A-Za-z0-9_\-]{40,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"gocardless", "live_"},
			Tags:        []string{"gocardless", "payment", "token"},
		},

		// =====================================================================
		// Prefect (200)
		// =====================================================================
		{
			ID:          "prefect-api-token",
			Description: "Prefect API Token",
			Regex:       `\b(pnu_[A-Za-z0-9]{36})\b`,
			SecretGroup: 1,
			Keywords:    []string{"pnu_"},
			Tags:        []string{"prefect", "orchestration", "token"},
		},

		// =====================================================================
		// Duffel (201)
		// =====================================================================
		{
			ID:          "duffel-api-token",
			Description: "Duffel Live API Token",
			Regex:       `\b(duffel_live_[A-Za-z0-9_\-]{43})\b`,
			SecretGroup: 1,
			Keywords:    []string{"duffel_live_"},
			Tags:        []string{"duffel", "travel", "token"},
		},

		// =====================================================================
		// Duffel Test (202)
		// =====================================================================
		{
			ID:          "duffel-test-token",
			Description: "Duffel Test API Token",
			Regex:       `\b(duffel_test_[A-Za-z0-9_\-]{43})\b`,
			SecretGroup: 1,
			Keywords:    []string{"duffel_test_"},
			Tags:        []string{"duffel", "travel", "token"},
		},

		// =====================================================================
		// Dynatrace (203)
		// =====================================================================
		{
			ID:          "dynatrace-api-token",
			Description: "Dynatrace API Token",
			Regex:       `\b(dt0c01\.[A-Z0-9]{24}\.[A-Za-z0-9]{64})\b`,
			SecretGroup: 1,
			Keywords:    []string{"dt0c01."},
			Tags:        []string{"dynatrace", "monitoring", "token"},
		},

		// =====================================================================
		// EasyPost (204-205)
		// =====================================================================
		{
			ID:          "easypost-api-token",
			Description: "EasyPost API Token",
			Regex:       `\b(EZAK[a-f0-9]{54})\b`,
			SecretGroup: 1,
			Keywords:    []string{"EZAK"},
			Tags:        []string{"easypost", "shipping", "token"},
		},
		{
			ID:          "easypost-test-api-token",
			Description: "EasyPost Test API Token",
			Regex:       `\b(EZTK[a-f0-9]{54})\b`,
			SecretGroup: 1,
			Keywords:    []string{"EZTK"},
			Tags:        []string{"easypost", "shipping", "token"},
		},

		// =====================================================================
		// Vault Service Token (206)
		// =====================================================================
		{
			ID:          "vault-service-token",
			Description: "HashiCorp Vault Service Token (legacy)",
			Regex:       `(?i)(?:VAULT_TOKEN|vault[_\-]?token)\s*[:=]\s*["\']?(s\.[A-Za-z0-9]{24,})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"vault", "s."},
			Tags:        []string{"vault", "infrastructure", "token"},
		},

		// =====================================================================
		// GitHub Actions Secret Ref (207)
		// =====================================================================
		{
			ID:          "github-actions-secret-in-output",
			Description: "GitHub Actions Secret Set as Output",
			Regex:       `::set-output\s+name=[^:]+::\$\{\{\s*secrets\.[A-Z_]+\s*\}\}`,
			Keywords:    []string{"::set-output", "secrets."},
			Tags:        []string{"github", "ci", "secret"},
		},

		// =====================================================================
		// Env File (208)
		// =====================================================================
		{
			ID:          "dotenv-secret",
			Description: "Secret in .env File",
			Regex:       `(?i)^(?:export\s+)?(?:[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH)[A-Z_]*)\s*=\s*["\']?([^\s"'#]{8,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"SECRET", "KEY", "TOKEN", "PASSWORD", "CREDENTIAL", "AUTH"},
			Path:        `(?:\.env|\.env\..+)$`,
			Tags:        []string{"env", "config", "secret"},
			Allowlists: []config.Allowlist{
				{
					Description: "Ignore placeholder values",
					StopWords:   []string{"your_", "CHANGE_ME", "INSERT_", "TODO", "example", "placeholder", "xxxx", "changeme", "<", "${"},
				},
			},
		},

		// =====================================================================
		// Generic Webhook URL (209)
		// =====================================================================
		{
			ID:          "generic-webhook-secret",
			Description: "Webhook URL with Secret/Token",
			Regex:       `https?://[^\s"']+(?:webhook|hook)[^\s"']*(?:token|key|secret|auth)=[^\s"'&]+`,
			Keywords:    []string{"webhook", "hook", "token"},
			Tags:        []string{"webhook", "generic"},
		},

		// =====================================================================
		// Plaid (210-211)
		// =====================================================================
		{
			ID:          "plaid-client-id",
			Description: "Plaid Client ID",
			Regex:       `(?i)(?:plaid[_\-]?client[_\-]?id|PLAID_CLIENT_ID)\s*[:=]\s*["\']?([a-f0-9]{24})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"plaid", "client_id"},
			Tags:        []string{"plaid", "finance", "id"},
		},
		{
			ID:          "plaid-secret",
			Description: "Plaid Secret Key",
			Regex:       `(?i)(?:plaid[_\-]?secret|PLAID_SECRET)\s*[:=]\s*["\']?([a-f0-9]{30})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"plaid"},
			Tags:        []string{"plaid", "finance", "secret"},
		},

		// =====================================================================
		// Segment (212)
		// =====================================================================
		{
			ID:          "segment-write-key",
			Description: "Segment Write Key",
			Regex:       `(?i)(?:segment[_\-]?write[_\-]?key|SEGMENT_WRITE_KEY)\s*[:=]\s*["\']?([A-Za-z0-9]{32})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"segment", "write_key"},
			Tags:        []string{"segment", "analytics", "key"},
		},

		// =====================================================================
		// Amplitude (213)
		// =====================================================================
		{
			ID:          "amplitude-api-key",
			Description: "Amplitude API Key",
			Regex:       `(?i)(?:amplitude[_\-]?(?:api[_\-]?)?key|AMPLITUDE_API_KEY)\s*[:=]\s*["\']?([a-f0-9]{32})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"amplitude"},
			Tags:        []string{"amplitude", "analytics", "key"},
		},

		// =====================================================================
		// Mixpanel (214)
		// =====================================================================
		{
			ID:          "mixpanel-api-secret",
			Description: "Mixpanel API Secret",
			Regex:       `(?i)(?:mixpanel[_\-]?(?:api[_\-]?)?secret|MIXPANEL_SECRET)\s*[:=]\s*["\']?([a-f0-9]{32})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"mixpanel"},
			Tags:        []string{"mixpanel", "analytics", "secret"},
		},

		// =====================================================================
		// Braintree (215)
		// =====================================================================
		{
			ID:          "braintree-access-token",
			Description: "Braintree Access Token",
			Regex:       `access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}`,
			Keywords:    []string{"access_token$"},
			Tags:        []string{"braintree", "payment", "token"},
		},

		// =====================================================================
		// CircleCI v2 (216)
		// =====================================================================
		{
			ID:          "circleci-v2-token",
			Description: "CircleCI v2 API Token (CIRCLE prefix)",
			Regex:       `(?i)(?:CIRCLE_TOKEN|CIRCLECI_TOKEN)\s*[:=]\s*["\']?([a-f0-9]{40})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"CIRCLE_TOKEN", "CIRCLECI_TOKEN"},
			Tags:        []string{"circleci", "ci", "token"},
		},

		// =====================================================================
		// Jenkins (217)
		// =====================================================================
		{
			ID:          "jenkins-api-token",
			Description: "Jenkins API Token",
			Regex:       `(?i)(?:jenkins[_\-]?(?:api[_\-]?)?token|JENKINS_TOKEN)\s*[:=]\s*["\']?([a-f0-9]{34})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"jenkins"},
			Tags:        []string{"jenkins", "ci", "token"},
		},

		// =====================================================================
		// Buildkite (218)
		// =====================================================================
		{
			ID:          "buildkite-agent-token",
			Description: "Buildkite Agent Token",
			Regex:       `(?i)(?:buildkite[_\-]?agent[_\-]?token|BUILDKITE_AGENT_TOKEN)\s*[:=]\s*["\']?([a-f0-9]{40,})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"buildkite"},
			Tags:        []string{"buildkite", "ci", "token"},
		},

		// =====================================================================
		// Codecov (219)
		// =====================================================================
		{
			ID:          "codecov-token",
			Description: "Codecov Upload Token",
			Regex:       `(?i)(?:codecov[_\-]?token|CODECOV_TOKEN)\s*[:=]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"codecov"},
			Tags:        []string{"codecov", "ci", "token"},
		},

		// =====================================================================
		// Shippo (220)
		// =====================================================================
		{
			ID:          "shippo-api-token",
			Description: "Shippo API Token",
			Regex:       `\b(shippo_live_[a-f0-9]{40})\b`,
			SecretGroup: 1,
			Keywords:    []string{"shippo_live_"},
			Tags:        []string{"shippo", "shipping", "token"},
		},

		// =====================================================================
		// Shippo Test (221)
		// =====================================================================
		{
			ID:          "shippo-test-token",
			Description: "Shippo Test API Token",
			Regex:       `\b(shippo_test_[a-f0-9]{40})\b`,
			SecretGroup: 1,
			Keywords:    []string{"shippo_test_"},
			Tags:        []string{"shippo", "shipping", "token"},
		},

		// =====================================================================
		// Typeform (222)
		// =====================================================================
		{
			ID:          "typeform-api-token",
			Description: "Typeform Personal Access Token",
			Regex:       `\b(tfp_[A-Za-z0-9_\-]{40,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"tfp_"},
			Tags:        []string{"typeform", "forms", "token"},
		},

		// =====================================================================
		// Yandex (223)
		// =====================================================================
		{
			ID:          "yandex-api-key",
			Description: "Yandex API Key",
			Regex:       `\b(AQVN[A-Za-z0-9_\-]{35,38})\b`,
			SecretGroup: 1,
			Keywords:    []string{"AQVN"},
			Tags:        []string{"yandex", "cloud", "api-key"},
		},

		// =====================================================================
		// Yandex OAuth (224)
		// =====================================================================
		{
			ID:          "yandex-oauth-token",
			Description: "Yandex OAuth Token",
			Regex:       `\b(y[0-3]_[A-Za-z0-9_\-]{35,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"y0_", "y1_", "y2_", "y3_"},
			Tags:        []string{"yandex", "cloud", "oauth"},
		},

		// =====================================================================
		// Yandex IAM (225)
		// =====================================================================
		{
			ID:          "yandex-iam-token",
			Description: "Yandex IAM Token",
			Regex:       `\b(t1\.[A-Za-z0-9_\-]{84,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"t1.", "yandex"},
			Tags:        []string{"yandex", "cloud", "iam"},
		},

		// =====================================================================
		// Sumologic (226)
		// =====================================================================
		{
			ID:          "sumologic-access-key",
			Description: "Sumo Logic Access Key",
			Regex:       `(?i)(?:sumo[_\-]?(?:logic[_\-]?)?access[_\-]?(?:key|id)|SUMOLOGIC_ACCESSID)\s*[:=]\s*["\']?(su[A-Za-z0-9]{12})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"sumo", "sumologic", "SUMOLOGIC"},
			Tags:        []string{"sumologic", "monitoring", "key"},
		},

		// =====================================================================
		// Scalr (227)
		// =====================================================================
		{
			ID:          "scalr-token",
			Description: "Scalr API Token",
			Regex:       `(?i)(?:scalr[_\-]?token|SCALR_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9\-_]{136,})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"scalr"},
			Tags:        []string{"scalr", "infrastructure", "token"},
		},

		// =====================================================================
		// ReadMe (228)
		// =====================================================================
		{
			ID:          "readme-api-key",
			Description: "ReadMe API Key",
			Regex:       `\b(rdme_[a-z0-9]{70})\b`,
			SecretGroup: 1,
			Keywords:    []string{"rdme_"},
			Tags:        []string{"readme", "documentation", "key"},
		},

		// =====================================================================
		// Clojars (229)
		// =====================================================================
		{
			ID:          "clojars-deploy-token",
			Description: "Clojars Deploy Token",
			Regex:       `\b(CLOJARS_[a-z0-9]{60})\b`,
			SecretGroup: 1,
			Keywords:    []string{"CLOJARS_"},
			Tags:        []string{"clojars", "package-registry", "token"},
		},

		// =====================================================================
		// HashiCorp TF (230)
		// =====================================================================
		{
			ID:          "hashicorp-tf-api-token",
			Description: "HashiCorp Terraform/HCP API Token",
			Regex:       `(?i)(?:credentials\s+"app\.terraform\.io"\s*\{[^}]*token\s*=\s*")["\']?([A-Za-z0-9.]{14,170})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"app.terraform.io", "credentials"},
			Tags:        []string{"terraform", "infrastructure", "token"},
		},

		// =====================================================================
		// Databricks v2 (231)
		// =====================================================================
		{
			ID:          "databricks-pat",
			Description: "Databricks Personal Access Token (dapi prefix)",
			Regex:       `\b(dapi[a-f0-9]{32,40})\b`,
			SecretGroup: 1,
			Keywords:    []string{"dapi"},
			Tags:        []string{"databricks", "database", "token"},
		},

		// =====================================================================
		// NPM Registry Auth (232)
		// =====================================================================
		{
			ID:          "npmrc-auth",
			Description: "NPM Registry Authentication in .npmrc",
			Regex:       `//[^\s]+/:_authToken=([A-Za-z0-9\-_.]{36,})`,
			SecretGroup: 1,
			Keywords:    []string{"_authToken="},
			Path:        `\.npmrc$`,
			Tags:        []string{"npm", "package-registry", "token"},
		},

		// =====================================================================
		// Private key in variable (233)
		// =====================================================================
		{
			ID:          "private-key-variable",
			Description: "Private Key Assigned to Variable",
			Regex:       `(?i)(?:private[_\-]?key|PRIVATE_KEY|signing[_\-]?key)\s*[:=]\s*["\']?(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)`,
			SecretGroup: 1,
			Keywords:    []string{"PRIVATE_KEY", "private_key", "signing_key", "BEGIN"},
			Tags:        []string{"crypto", "private-key"},
		},

		// =====================================================================
		// SSH Password (234)
		// =====================================================================
		{
			ID:          "ssh-password",
			Description: "SSH Password in sshpass or expect Script",
			Regex:       `(?i)sshpass\s+-p\s+["\']?([^\s"']+)["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"sshpass"},
			Tags:        []string{"ssh", "password"},
		},

		// =====================================================================
		// Additional Cloud/SaaS rules (235-250)
		// =====================================================================
		{
			ID:          "openai-org-id",
			Description: "OpenAI Organization ID",
			Regex:       `\b(org-[A-Za-z0-9]{24})\b`,
			SecretGroup: 1,
			Keywords:    []string{"org-", "openai"},
			Tags:        []string{"openai", "ai", "org"},
		},
		{
			ID:          "anthropic-api-key-v2",
			Description: "Anthropic API Key (generic sk-ant pattern)",
			Regex:       `\b(sk-ant-[A-Za-z0-9_\-]{20,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"sk-ant-"},
			Tags:        []string{"anthropic", "ai", "api-key"},
		},
		{
			ID:          "fly-io-token",
			Description: "Fly.io Access Token",
			Regex:       `\b(fo1_[A-Za-z0-9_\-]{39})\b`,
			SecretGroup: 1,
			Keywords:    []string{"fo1_"},
			Tags:        []string{"flyio", "hosting", "token"},
		},
		{
			ID:          "railway-api-token",
			Description: "Railway API Token",
			Regex:       `(?i)(?:railway[_\-]?token|RAILWAY_TOKEN)\s*[:=]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"railway"},
			Tags:        []string{"railway", "hosting", "token"},
		},
		{
			ID:          "render-api-key",
			Description: "Render API Key",
			Regex:       `\b(rnd_[A-Za-z0-9]{32,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"rnd_"},
			Tags:        []string{"render", "hosting", "key"},
		},
		{
			ID:          "tencent-cloud-secret-id",
			Description: "Tencent Cloud Secret ID",
			Regex:       `\b(AKID[A-Za-z0-9]{32})\b`,
			SecretGroup: 1,
			Keywords:    []string{"AKID"},
			Tags:        []string{"tencent", "cloud", "key"},
		},
		{
			ID:          "tencent-cloud-secret-key",
			Description: "Tencent Cloud Secret Key",
			Regex:       `(?i)(?:tencent[_\-]?(?:cloud[_\-]?)?secret[_\-]?key|TENCENTCLOUD_SECRET_KEY)\s*[:=]\s*["\']?([A-Za-z0-9]{32})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"tencent", "TENCENTCLOUD"},
			Tags:        []string{"tencent", "cloud", "secret"},
		},
		{
			ID:          "naver-cloud-access-key",
			Description: "Naver Cloud Access Key",
			Regex:       `(?i)(?:naver[_\-]?(?:cloud[_\-]?)?access[_\-]?key|NCP_ACCESS_KEY)\s*[:=]\s*["\']?([A-Za-z0-9]{20})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"naver", "NCP_ACCESS"},
			Tags:        []string{"naver", "cloud", "key"},
		},
		{
			ID:          "upstash-redis-token",
			Description: "Upstash Redis REST Token",
			Regex:       `(?i)(?:upstash[_\-]?redis[_\-]?rest[_\-]?token|UPSTASH_REDIS_REST_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9=]{30,})["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"upstash"},
			Tags:        []string{"upstash", "database", "token"},
		},
		{
			ID:          "fauna-secret",
			Description: "Fauna Secret Key",
			Regex:       `\b(fnAE[A-Za-z0-9_\-]{36,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"fnAE"},
			Tags:        []string{"fauna", "database", "secret"},
		},
		{
			ID:          "hasura-admin-secret",
			Description: "Hasura Admin Secret",
			Regex:       `(?i)(?:hasura[_\-]?(?:graphql[_\-]?)?admin[_\-]?secret|HASURA_ADMIN_SECRET)\s*[:=]\s*["\']?([^\s"']{8,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"hasura", "admin_secret"},
			Tags:        []string{"hasura", "database", "secret"},
		},
		{
			ID:          "neon-api-key",
			Description: "Neon Database API Key",
			Regex:       `(?i)(?:neon[_\-]?api[_\-]?key|NEON_API_KEY)\s*[:=]\s*["\']?([A-Za-z0-9]{48,})["\']?`,
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"neon"},
			Tags:        []string{"neon", "database", "key"},
		},
		{
			ID:          "turso-auth-token",
			Description: "Turso Database Auth Token",
			Regex:       `(?i)(?:turso[_\-]?(?:auth[_\-]?)?token|TURSO_AUTH_TOKEN)\s*[:=]\s*["\']?(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)["\']?`,
			SecretGroup: 1,
			Keywords:    []string{"turso"},
			Tags:        []string{"turso", "database", "token"},
		},
		{
			ID:          "convex-deploy-key",
			Description: "Convex Deploy Key",
			Regex:       `\b(prod:[a-z0-9\-]+:[a-z0-9]{32,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"convex", "prod:"},
			Tags:        []string{"convex", "database", "key"},
		},
		{
			ID:          "clerk-secret-key",
			Description: "Clerk Secret Key",
			Regex:       `\b(sk_live_[A-Za-z0-9]{24,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"sk_live_", "clerk"},
			Tags:        []string{"clerk", "auth", "key"},
		},
		{
			ID:          "clerk-publishable-key",
			Description: "Clerk Publishable Key",
			Regex:       `\b(pk_live_[A-Za-z0-9]{24,})\b`,
			SecretGroup: 1,
			Keywords:    []string{"pk_live_", "clerk"},
			Tags:        []string{"clerk", "auth", "key"},
		},
	}
}

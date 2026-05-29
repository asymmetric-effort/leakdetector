# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | Yes                |

## Reporting a Vulnerability

If you discover a security vulnerability in leakdetector, please report it
responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email: **security@asymmetric-effort.com**

Include the following in your report:
- Description of the vulnerability.
- Steps to reproduce.
- Potential impact.
- Suggested fix (if any).

## Response SLAs

| Severity | Response Time |
|----------|---------------|
| Critical | 24 hours      |
| High     | 72 hours      |
| Medium   | 30 days       |
| Low      | 90 days       |

## Disclosure Policy

We follow coordinated disclosure. We will:
1. Acknowledge your report within 48 hours.
2. Provide an estimated timeline for a fix.
3. Notify you when the fix is released.
4. Credit you in the release notes (unless you prefer anonymity).

## Security Best Practices

This project follows the
[Asymmetric Effort Security Standards](https://coding-standards.asymmetric-effort.com/security-standards):

- No hardcoded secrets, credentials, or API keys.
- Minimal runtime dependencies to reduce supply chain attack surface.
- CodeQL and static analysis enabled in CI.
- All dependencies pinned to specific versions.
- GitHub Actions pinned to commit SHAs.

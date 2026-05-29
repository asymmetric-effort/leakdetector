# Output Formats

leakdetector supports multiple output formats for integration with different
tools and workflows.

## JSON (Default)

```bash
leakdetector --format json
```

Produces a JSON array of findings:

```json
[
  {
    "rule_id": "aws-access-key-id",
    "description": "AWS Access Key ID",
    "start_line": 10,
    "end_line": 10,
    "start_column": 15,
    "end_column": 35,
    "match": "AKIAIOSFODNN7EXAMPLE",
    "secret": "AKIAIOSFODNN7EXAMPLE",
    "file": "config/aws.go",
    "commit": "abc1234def5678",
    "author": "John Doe",
    "email": "john@example.com",
    "date": "2026-01-15T10:30:00Z",
    "message": "add AWS config",
    "tags": ["aws", "cloud"],
    "entropy": 3.68,
    "fingerprint": "abc1234def5678:config/aws.go:aws-access-key-id:10"
  }
]
```

## CSV

```bash
leakdetector --format csv
```

Produces a CSV file with a header row:

```
RuleID,Description,File,StartLine,Secret,Commit,Author,Fingerprint
aws-access-key-id,AWS Access Key ID,config/aws.go,10,AKIAIOSFODNN7EXAMPLE,abc1234,John Doe,abc1234:config/aws.go:aws-access-key-id:10
```

## JUnit XML

```bash
leakdetector --format junit
```

Produces JUnit XML for CI/CD integration:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="aws-access-key-id" tests="1" failures="1">
    <testcase name="config/aws.go:10" classname="aws-access-key-id">
      <failure message="AWS Access Key ID">
        Secret found in config/aws.go at line 10
      </failure>
    </testcase>
  </testsuite>
</testsuites>
```

## SARIF 2.1.0

```bash
leakdetector --format sarif
```

Produces [SARIF](https://sarifweb.azurewebsites.net/) output for GitHub
Security tab integration:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "leakdetector",
          "rules": [
            {
              "id": "aws-access-key-id",
              "shortDescription": {
                "text": "AWS Access Key ID"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "aws-access-key-id",
          "message": {
            "text": "AWS Access Key ID"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "config/aws.go"
                },
                "region": {
                  "startLine": 10,
                  "startColumn": 15,
                  "endLine": 10,
                  "endColumn": 35
                }
              }
            }
          ],
          "fingerprints": {
            "leakdetector": "abc1234:config/aws.go:aws-access-key-id:10"
          }
        }
      ]
    }
  ]
}
```

## Redaction

Use `--redact` with any format to mask secrets:

```bash
leakdetector --redact --format json
```

Secrets are replaced: `AKIAIOSFODNN7EXAMPLE` becomes `AK...LE`.
Secrets of 4 characters or fewer are fully replaced with `REDACTED`.

## Writing to a File

Use `--report` to write output to a file instead of stdout:

```bash
leakdetector --format sarif --report findings.sarif
```

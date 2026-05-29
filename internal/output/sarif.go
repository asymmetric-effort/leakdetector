package output

import (
	"encoding/json"
	"io"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
)

// SARIF 2.1.0 structures.

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	ShortDescription sarifMultiFormat `json:"shortDescription"`
}

type sarifMultiFormat struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	Message      sarifMultiFormat   `json:"message"`
	Locations    []sarifLocation    `json:"locations"`
	Fingerprints map[string]string  `json:"fingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartColumn int `json:"startColumn"`
	EndColumn   int `json:"endColumn"`
}

// writeSARIF writes findings in SARIF v2.1.0 JSON format.
func writeSARIF(dest io.Writer, findings []finding.Finding) error {
	// Collect unique rules preserving order.
	ruleIndex := make(map[string]int)
	var rules []sarifRule
	for i := range findings {
		if _, exists := ruleIndex[findings[i].RuleID]; !exists {
			ruleIndex[findings[i].RuleID] = len(rules)
			rules = append(rules, sarifRule{
				ID: findings[i].RuleID,
				ShortDescription: sarifMultiFormat{
					Text: findings[i].Description,
				},
			})
		}
	}

	// Build results.
	results := make([]sarifResult, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		result := sarifResult{
			RuleID: f.RuleID,
			Message: sarifMultiFormat{
				Text: f.Description,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.File,
						},
						Region: sarifRegion{
							StartLine:   f.StartLine,
							EndLine:     f.EndLine,
							StartColumn: f.StartColumn,
							EndColumn:   f.EndColumn,
						},
					},
				},
			},
			Fingerprints: map[string]string{
				"leakdetector": f.Fingerprint,
			},
		}
		results = append(results, result)
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            "leakdetector",
						SemanticVersion: "1.0.0",
						Rules:           rules,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(dest)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

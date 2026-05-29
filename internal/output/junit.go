package output

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
)

// junitTestSuites is the top-level JUnit XML element.
type junitTestSuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	TestSuites []junitTestSuite `xml:"testsuite"`
}

// junitTestSuite groups test cases by rule ID.
type junitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

// junitTestCase represents a single finding as a failed test.
type junitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

// junitFailure contains the failure details.
type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// writeJUnit writes findings in JUnit XML format, grouped by rule ID.
func writeJUnit(dest io.Writer, findings []finding.Finding) error {
	// Group findings by rule ID.
	grouped := make(map[string][]finding.Finding)
	var order []string
	for i := range findings {
		rid := findings[i].RuleID
		if _, exists := grouped[rid]; !exists {
			order = append(order, rid)
		}
		grouped[rid] = append(grouped[rid], findings[i])
	}

	var suites junitTestSuites
	for _, ruleID := range order {
		group := grouped[ruleID]
		suite := junitTestSuite{
			Name:     ruleID,
			Tests:    len(group),
			Failures: len(group),
		}
		for j := range group {
			f := &group[j]
			tc := junitTestCase{
				Name:      fmt.Sprintf("%s:%d", f.File, f.StartLine),
				ClassName: f.RuleID,
				Failure: &junitFailure{
					Message: f.Description,
					Type:    f.RuleID,
					Text:    fmt.Sprintf("Secret detected in %s at line %d: %s", f.File, f.StartLine, f.Secret),
				},
			}
			suite.TestCases = append(suite.TestCases, tc)
		}
		suites.TestSuites = append(suites.TestSuites, suite)
	}

	if _, err := io.WriteString(dest, xml.Header); err != nil {
		return err
	}
	encoder := xml.NewEncoder(dest)
	encoder.Indent("", "  ")
	return encoder.Encode(suites)
}

package rules

import "fmt"

// RuleCompileError is returned when a rule regex fails to compile.
type RuleCompileError struct {
	RuleID string
	Field  string
	Err    error
}

func (e *RuleCompileError) Error() string {
	return fmt.Sprintf("rule %q: invalid %s: %v", e.RuleID, e.Field, e.Err)
}

func (e *RuleCompileError) Unwrap() error {
	return e.Err
}

// AllowlistCompileError is returned when an allowlist regex fails to compile.
type AllowlistCompileError struct {
	Field   string
	Pattern string
	Err     error
}

func (e *AllowlistCompileError) Error() string {
	return fmt.Sprintf("allowlist: invalid %s pattern %q: %v", e.Field, e.Pattern, e.Err)
}

func (e *AllowlistCompileError) Unwrap() error {
	return e.Err
}

package rules

import (
	"errors"
	"fmt"
	"testing"
)

func TestRuleCompileError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *RuleCompileError
		wantMsg  string
	}{
		{
			name: "regex field error",
			err: &RuleCompileError{
				RuleID: "my-rule",
				Field:  "regex",
				Err:    fmt.Errorf("invalid syntax"),
			},
			wantMsg: `rule "my-rule": invalid regex: invalid syntax`,
		},
		{
			name: "path field error",
			err: &RuleCompileError{
				RuleID: "test-rule",
				Field:  "path",
				Err:    fmt.Errorf("bad pattern"),
			},
			wantMsg: `rule "test-rule": invalid path: bad pattern`,
		},
		{
			name: "empty rule ID",
			err: &RuleCompileError{
				RuleID: "",
				Field:  "regex",
				Err:    fmt.Errorf("oops"),
			},
			wantMsg: `rule "": invalid regex: oops`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.err.Error()
			if got != tc.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tc.wantMsg)
			}
		})
	}
}

func TestRuleCompileError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("inner error")
	err := &RuleCompileError{
		RuleID: "r1",
		Field:  "regex",
		Err:    inner,
	}

	if unwrapped := err.Unwrap(); unwrapped != inner {
		t.Errorf("Unwrap() returned %v, want %v", unwrapped, inner)
	}

	if !errors.Is(err, inner) {
		t.Error("errors.Is should find the inner error")
	}
}

func TestAllowlistCompileError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *AllowlistCompileError
		wantMsg string
	}{
		{
			name: "path pattern error",
			err: &AllowlistCompileError{
				Field:   "path",
				Pattern: `[invalid`,
				Err:     fmt.Errorf("unclosed bracket"),
			},
			wantMsg: `allowlist: invalid path pattern "[invalid": unclosed bracket`,
		},
		{
			name: "regex pattern error",
			err: &AllowlistCompileError{
				Field:   "regex",
				Pattern: `(bad`,
				Err:     fmt.Errorf("unclosed group"),
			},
			wantMsg: `allowlist: invalid regex pattern "(bad": unclosed group`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.err.Error()
			if got != tc.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tc.wantMsg)
			}
		})
	}
}

func TestAllowlistCompileError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("inner allowlist error")
	err := &AllowlistCompileError{
		Field:   "regex",
		Pattern: "abc",
		Err:     inner,
	}

	if unwrapped := err.Unwrap(); unwrapped != inner {
		t.Errorf("Unwrap() returned %v, want %v", unwrapped, inner)
	}

	if !errors.Is(err, inner) {
		t.Error("errors.Is should find the inner error")
	}
}

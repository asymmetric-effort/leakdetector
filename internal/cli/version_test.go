package cli

import "testing"

func TestVersionDefault(t *testing.T) {
	if Version == "" {
		t.Error("expected Version to have a non-empty default value")
	}
	if Version != "0.0.0-dev" {
		t.Errorf("expected default Version to be '0.0.0-dev', got %q", Version)
	}
}

package config

import (
	"github.com/asymmetric-effort/leakdetector/internal/safefile"
)

// Config represents the .leakdetector.yml configuration.
// Config represents the .leakdetector.yml configuration.
type Config struct {
	ExcludeCommits []string       `yaml:"exclude_commits"`
	ExcludePaths   []string       `yaml:"exclude_paths"`
	Rules          []RuleConfig   `yaml:"rules"`
	Allowlists     []Allowlist    `yaml:"allowlists"`
	Extend         *ExtendConfig  `yaml:"extend"`
	Warnings       []string       `yaml:"-"` // parse warnings (not serialized)
}

// RuleConfig defines a single detection rule in the config file.
type RuleConfig struct {
	ID          string       `yaml:"id"`
	Description string       `yaml:"description"`
	Regex       string       `yaml:"regex"`
	SecretGroup int          `yaml:"secret_group"`
	Entropy     float64      `yaml:"entropy"`
	Path        string       `yaml:"path"`
	Keywords    []string     `yaml:"keywords"`
	Tags        []string     `yaml:"tags"`
	Allowlists  []Allowlist  `yaml:"allowlists"`
	Required    []RequiredRule `yaml:"required"`
}

// RequiredRule defines an auxiliary pattern for composite/proximity rules.
type RequiredRule struct {
	ID            string `yaml:"id"`
	Regex         string `yaml:"regex"`
	WithinLines   int    `yaml:"within_lines"`
	WithinColumns int    `yaml:"within_columns"`
}

// Allowlist defines criteria for ignoring findings.
type Allowlist struct {
	Description string   `yaml:"description"`
	Paths       []string `yaml:"paths"`
	Regexes     []string `yaml:"regexes"`
	Commits     []string `yaml:"commits"`
	StopWords   []string `yaml:"stop_words"`
	RegexTarget string   `yaml:"regex_target"`
	Condition   string   `yaml:"condition"`
}

// ExtendConfig specifies configuration inheritance.
type ExtendConfig struct {
	UseDefault    bool     `yaml:"use_default"`
	Path          string   `yaml:"path"`
	DisabledRules []string `yaml:"disabled_rules"`
}

// Default returns a default configuration with no custom rules or exclusions.
func Default() *Config {
	return &Config{
		Extend: &ExtendConfig{
			UseDefault: true,
		},
	}
}

// Load reads and parses a configuration file at the given path.
func Load(path string) (*Config, error) {
	data, err := safefile.Read(path)
	if err != nil {
		return nil, err
	}
	return parse(data)
}

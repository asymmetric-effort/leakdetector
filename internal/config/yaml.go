package config

import (
	"fmt"
	"strconv"
	"strings"
)

// parse parses YAML data into a Config struct.
// Returns an error if the configuration contains invalid syntax or values.
func parse(data []byte) (*Config, error) {
	cfg := &Config{}
	lines := strings.Split(string(data), "\n")
	p := &parser{lines: lines, pos: 0}
	p.parseConfig(cfg)
	if len(p.errors) > 0 {
		return nil, fmt.Errorf("configuration errors:\n  %s", strings.Join(p.errors, "\n  "))
	}
	if len(p.warnings) > 0 {
		cfg.Warnings = p.warnings
	}
	return cfg, nil
}

type parser struct {
	lines    []string
	pos      int
	errors   []string
	warnings []string
}

// errorf records a hard error that will cause parse to fail.
func (p *parser) errorf(format string, args ...interface{}) {
	msg := fmt.Sprintf("line %d: %s", p.pos+1, fmt.Sprintf(format, args...))
	p.errors = append(p.errors, msg)
}

// warnf records a warning that does not cause parse to fail.
func (p *parser) warnf(format string, args ...interface{}) {
	msg := fmt.Sprintf("line %d: %s", p.pos+1, fmt.Sprintf(format, args...))
	p.warnings = append(p.warnings, msg)
}

var validTopLevelKeys = map[string]bool{
	"exclude_commits": true,
	"exclude_paths":   true,
	"rules":           true,
	"allowlists":      true,
	"extend":          true,
}

var validRuleFields = map[string]bool{
	"id": true, "description": true, "regex": true,
	"secret_group": true, "entropy": true, "path": true,
	"keywords": true, "tags": true, "allowlists": true,
	"required": true,
}

var validAllowlistFields = map[string]bool{
	"description": true, "paths": true, "regexes": true,
	"commits": true, "stop_words": true, "regex_target": true,
	"condition": true,
}

var validExtendFields = map[string]bool{
	"use_default": true, "path": true, "disabled_rules": true,
}

func (p *parser) parseConfig(cfg *Config) {
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}

		indent := countIndent(line)
		if indent > 0 {
			p.warnf("unexpected indented line at top level: %q", trimmed)
			p.pos++
			continue
		}

		key, _ := splitKeyValue(trimmed)
		if !validTopLevelKeys[key] {
			p.warnf("unknown configuration key %q (expected: exclude_commits, exclude_paths, rules, allowlists, extend)", key)
			p.pos++
			continue
		}

		switch key {
		case "exclude_commits":
			cfg.ExcludeCommits = p.parseStringList(indent)
		case "exclude_paths":
			cfg.ExcludePaths = p.parseStringList(indent)
		case "rules":
			cfg.Rules = p.parseRuleList(indent)
		case "allowlists":
			cfg.Allowlists = p.parseAllowlistList(indent)
		case "extend":
			cfg.Extend = p.parseExtend(indent)
		}
	}
}

func (p *parser) parseStringList(parentIndent int) []string {
	p.pos++
	var items []string
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}

		indent := countIndent(line)
		if indent <= parentIndent {
			break
		}

		if strings.HasPrefix(trimmed, "- ") {
			val := strings.TrimPrefix(trimmed, "- ")
			val = unquoteYAML(val)
			items = append(items, val)
		} else {
			p.warnf("expected list item starting with '- ', got: %q", trimmed)
		}
		p.pos++
	}
	return items
}

func (p *parser) parseRuleList(parentIndent int) []RuleConfig {
	p.pos++
	var rules []RuleConfig
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}

		indent := countIndent(line)
		if indent <= parentIndent {
			break
		}

		if strings.HasPrefix(trimmed, "- ") {
			rule := p.parseRule(indent)
			// Validate required fields.
			if rule.ID == "" {
				p.errorf("rule is missing required 'id' field")
			}
			if rule.Regex == "" {
				p.errorf("rule %q is missing required 'regex' field", rule.ID)
			}
			rules = append(rules, rule)
		} else {
			p.warnf("expected rule list item starting with '- ', got: %q", trimmed)
			p.pos++
		}
	}
	return rules
}

func (p *parser) parseRule(listItemIndent int) RuleConfig {
	var rule RuleConfig
	line := p.lines[p.pos]
	trimmed := strings.TrimSpace(line)

	first := strings.TrimPrefix(trimmed, "- ")
	key, val := splitKeyValue(first)
	p.setRuleFieldChecked(&rule, key, val)
	p.pos++

	for p.pos < len(p.lines) {
		line = p.lines[p.pos]
		trimmed = strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}

		indent := countIndent(line)
		if indent <= listItemIndent {
			break
		}

		if strings.HasPrefix(trimmed, "- ") {
			break
		}

		key, val = splitKeyValue(trimmed)
		switch key {
		case "keywords", "tags":
			items := p.parseStringListOrInline(val, indent)
			if key == "keywords" {
				rule.Keywords = items
			} else {
				rule.Tags = items
			}
			continue
		case "allowlists":
			rule.Allowlists = p.parseAllowlistList(indent)
			continue
		default:
			p.setRuleFieldChecked(&rule, key, val)
		}
		p.pos++
	}
	return rule
}

func (p *parser) parseAllowlistList(parentIndent int) []Allowlist {
	p.pos++
	var lists []Allowlist
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}

		indent := countIndent(line)
		if indent <= parentIndent {
			break
		}

		if strings.HasPrefix(trimmed, "- ") {
			al := p.parseAllowlist(indent)
			lists = append(lists, al)
		} else {
			p.warnf("expected allowlist item starting with '- ', got: %q", trimmed)
			p.pos++
		}
	}
	return lists
}

func (p *parser) parseAllowlist(listItemIndent int) Allowlist {
	var al Allowlist
	line := p.lines[p.pos]
	trimmed := strings.TrimSpace(line)

	first := strings.TrimPrefix(trimmed, "- ")
	key, val := splitKeyValue(first)
	p.setAllowlistFieldChecked(&al, key, val)
	p.pos++

	for p.pos < len(p.lines) {
		line = p.lines[p.pos]
		trimmed = strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}

		indent := countIndent(line)
		if indent <= listItemIndent {
			break
		}

		if strings.HasPrefix(trimmed, "- ") && !strings.Contains(trimmed, ":") {
			break
		}

		key, val = splitKeyValue(trimmed)
		switch key {
		case "paths", "regexes", "commits", "stop_words":
			items := p.parseStringListOrInline(val, indent)
			switch key {
			case "paths":
				al.Paths = items
			case "regexes":
				al.Regexes = items
			case "commits":
				al.Commits = items
			case "stop_words":
				al.StopWords = items
			}
			continue
		default:
			p.setAllowlistFieldChecked(&al, key, val)
		}
		p.pos++
	}
	return al
}

func (p *parser) parseExtend(parentIndent int) *ExtendConfig {
	p.pos++
	ext := &ExtendConfig{}
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}

		indent := countIndent(line)
		if indent <= parentIndent {
			break
		}

		key, val := splitKeyValue(trimmed)
		if !validExtendFields[key] {
			p.warnf("unknown extend field %q (expected: use_default, path, disabled_rules)", key)
			p.pos++
			continue
		}
		switch key {
		case "use_default":
			if val != "true" && val != "false" {
				p.errorf("extend.use_default must be 'true' or 'false', got %q", val)
			}
			ext.UseDefault = val == "true"
		case "path":
			ext.Path = unquoteYAML(val)
		case "disabled_rules":
			ext.DisabledRules = p.parseStringListOrInline(val, indent)
			continue
		}
		p.pos++
	}
	return ext
}

func (p *parser) parseStringListOrInline(val string, indent int) []string {
	if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
		inner := val[1 : len(val)-1]
		parts := strings.Split(inner, ",")
		var items []string
		for _, part := range parts {
			part = strings.TrimSpace(part)
			part = unquoteYAML(part)
			if part != "" {
				items = append(items, part)
			}
		}
		p.pos++
		return items
	}

	if val == "" {
		return p.parseStringList2(indent)
	}

	p.pos++
	return []string{unquoteYAML(val)}
}

func (p *parser) parseStringList2(parentIndent int) []string {
	p.pos++
	var items []string
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}

		indent := countIndent(line)
		if indent <= parentIndent {
			break
		}

		if strings.HasPrefix(trimmed, "- ") {
			val := strings.TrimPrefix(trimmed, "- ")
			val = unquoteYAML(val)
			items = append(items, val)
		} else {
			p.warnf("expected list item starting with '- ', got: %q", trimmed)
		}
		p.pos++
	}
	return items
}

// setRuleFieldChecked sets a rule field and warns on unknown keys or invalid values.
func (p *parser) setRuleFieldChecked(rule *RuleConfig, key, val string) {
	if !validRuleFields[key] {
		p.warnf("unknown rule field %q (expected: id, description, regex, secret_group, entropy, path, keywords, tags, allowlists, required)", key)
		return
	}
	val = unquoteYAML(val)
	switch key {
	case "id":
		rule.ID = val
	case "description":
		rule.Description = val
	case "regex":
		rule.Regex = val
	case "secret_group":
		n, err := strconv.Atoi(val)
		if err != nil {
			p.errorf("rule %q: secret_group must be an integer, got %q", rule.ID, val)
			return
		}
		rule.SecretGroup = n
	case "entropy":
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			p.errorf("rule %q: entropy must be a number, got %q", rule.ID, val)
			return
		}
		rule.Entropy = f
	case "path":
		rule.Path = val
	}
}

// setAllowlistFieldChecked sets an allowlist field and warns on unknown keys.
func (p *parser) setAllowlistFieldChecked(al *Allowlist, key, val string) {
	if !validAllowlistFields[key] {
		p.warnf("unknown allowlist field %q (expected: description, paths, regexes, commits, stop_words, regex_target, condition)", key)
		return
	}
	val = unquoteYAML(val)
	switch key {
	case "description":
		al.Description = val
	case "regex_target":
		target := strings.ToLower(val)
		if target != "secret" && target != "match" && target != "line" {
			p.errorf("allowlist regex_target must be 'secret', 'match', or 'line', got %q", val)
			return
		}
		al.RegexTarget = val
	case "condition":
		cond := strings.ToUpper(val)
		if cond != "OR" && cond != "AND" {
			p.errorf("allowlist condition must be 'OR' or 'AND', got %q", val)
			return
		}
		al.Condition = val
	}
}

// Helper functions

func countIndent(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' {
			count++
		} else if ch == '\t' {
			count += 2
		} else {
			break
		}
	}
	return count
}

func splitKeyValue(s string) (string, string) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return s, ""
	}
	key := strings.TrimSpace(s[:idx])
	val := strings.TrimSpace(s[idx+1:])
	return key, val
}

func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') {
			unq, err := strconv.Unquote(s)
			if err == nil {
				return unq
			}
			return s[1 : len(s)-1]
		}
	}
	return s
}

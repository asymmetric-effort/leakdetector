package config

import (
	"strconv"
	"strings"
)

// parse parses YAML data into a Config struct.
// This is a minimal YAML parser that handles the subset of YAML used by
// .leakdetector.yml configuration files. It avoids third-party dependencies.
func parse(data []byte) (*Config, error) {
	cfg := &Config{}
	lines := strings.Split(string(data), "\n")
	p := &parser{lines: lines, pos: 0}
	p.parseConfig(cfg)
	return cfg, nil
}

type parser struct {
	lines []string
	pos   int
}

func (p *parser) parseConfig(cfg *Config) {
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}

		indent := countIndent(line)
		if indent > 0 {
			p.pos++
			continue
		}

		key, _ := splitKeyValue(trimmed)
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
		default:
			p.pos++
		}
	}
}

func (p *parser) parseStringList(parentIndent int) []string {
	p.pos++ // skip the key line
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
		}
		p.pos++
	}
	return items
}

func (p *parser) parseRuleList(parentIndent int) []RuleConfig {
	p.pos++ // skip "rules:" line
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
			rules = append(rules, rule)
		} else {
			p.pos++
		}
	}
	return rules
}

func (p *parser) parseRule(listItemIndent int) RuleConfig {
	var rule RuleConfig
	line := p.lines[p.pos]
	trimmed := strings.TrimSpace(line)

	// Parse first line (starts with "- key: val")
	first := strings.TrimPrefix(trimmed, "- ")
	key, val := splitKeyValue(first)
	setRuleField(&rule, key, val)
	p.pos++

	// Parse subsequent lines at deeper indent
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
			setRuleField(&rule, key, val)
		}
		p.pos++
	}
	return rule
}

func (p *parser) parseAllowlistList(parentIndent int) []Allowlist {
	p.pos++ // skip key line
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
	setAllowlistField(&al, key, val)
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
			setAllowlistField(&al, key, val)
		}
		p.pos++
	}
	return al
}

func (p *parser) parseExtend(parentIndent int) *ExtendConfig {
	p.pos++ // skip "extend:" line
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
		switch key {
		case "use_default":
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
	// Check for inline list: [a, b, c]
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

	// Block list (val is empty, items follow as "- val")
	if val == "" {
		return p.parseStringList2(indent)
	}

	// Single value
	p.pos++
	return []string{unquoteYAML(val)}
}

func (p *parser) parseStringList2(parentIndent int) []string {
	p.pos++ // skip key line
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
		}
		p.pos++
	}
	return items
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
			// For single-quoted strings, just strip quotes
			return s[1 : len(s)-1]
		}
	}
	return s
}

func setRuleField(rule *RuleConfig, key, val string) {
	val = unquoteYAML(val)
	switch key {
	case "id":
		rule.ID = val
	case "description":
		rule.Description = val
	case "regex":
		rule.Regex = val
	case "secret_group":
		n, _ := strconv.Atoi(val)
		rule.SecretGroup = n
	case "entropy":
		f, _ := strconv.ParseFloat(val, 64)
		rule.Entropy = f
	case "path":
		rule.Path = val
	}
}

func setAllowlistField(al *Allowlist, key, val string) {
	val = unquoteYAML(val)
	switch key {
	case "description":
		al.Description = val
	case "regex_target":
		al.RegexTarget = val
	case "condition":
		al.Condition = val
	}
}

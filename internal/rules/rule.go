package rules

import (
	"regexp"
	"strings"

	"github.com/asymmetric-effort/leakdetector/internal/config"
	"github.com/asymmetric-effort/leakdetector/internal/entropy"
)

// CompiledRule is a rule with pre-compiled regex patterns.
type CompiledRule struct {
	ID          string
	Description string
	Regex       *regexp.Regexp
	SecretGroup int
	Entropy     float64
	Path        *regexp.Regexp
	Keywords    []string
	Tags        []string
	Allowlists  []CompiledAllowlist
	Required    []CompiledRequired
}

// CompiledRequired is a compiled auxiliary pattern for composite rules.
type CompiledRequired struct {
	ID            string
	Regex         *regexp.Regexp
	WithinLines   int
	WithinColumns int
}

// CompiledAllowlist is an allowlist with pre-compiled regex patterns.
type CompiledAllowlist struct {
	Description string
	Paths       []*regexp.Regexp
	Regexes     []*regexp.Regexp
	Commits     map[string]struct{}
	StopWords   []string
	RegexTarget string
	Condition   string
}

// RuleSet holds all compiled rules and global allowlists.
type RuleSet struct {
	Rules      []CompiledRule
	Allowlists []CompiledAllowlist
}

// Compile compiles user-provided rule configs merged with built-in defaults
// and returns a RuleSet ready for scanning.
// CompileOptions controls rule compilation behavior.
type CompileOptions struct {
	UseDefault    bool
	DisabledRules []string
	EnabledRules  []string
}

// Compile compiles user-provided rule configs merged with built-in defaults
// and returns a RuleSet ready for scanning.
func Compile(userRules []config.RuleConfig, globalAllowlists []config.Allowlist) (*RuleSet, error) {
	return CompileWithOptions(userRules, globalAllowlists, CompileOptions{UseDefault: true})
}

// CompileWithOptions compiles rules with extended options for controlling
// which built-in rules are included.
func CompileWithOptions(userRules []config.RuleConfig, globalAllowlists []config.Allowlist, opts CompileOptions) (*RuleSet, error) {
	rs := &RuleSet{}

	// Build disabled rules set for fast lookup.
	disabled := make(map[string]struct{}, len(opts.DisabledRules))
	for _, id := range opts.DisabledRules {
		disabled[id] = struct{}{}
	}

	// Build enabled rules set for fast lookup.
	var enabled map[string]struct{}
	if len(opts.EnabledRules) > 0 {
		enabled = make(map[string]struct{}, len(opts.EnabledRules))
		for _, id := range opts.EnabledRules {
			enabled[id] = struct{}{}
		}
	}

	// Start with built-in rules if use_default is true.
	if opts.UseDefault {
		builtinRules := BuiltinRules()
		for i := range builtinRules {
			if _, ok := disabled[builtinRules[i].ID]; ok {
				continue
			}
			compiled, err := compileRule(&builtinRules[i])
			if err != nil {
				return nil, err
			}
			rs.Rules = append(rs.Rules, compiled)
		}
	}

	// Compile user rules (override built-in if same ID)
	for i := range userRules {
		if _, ok := disabled[userRules[i].ID]; ok {
			continue
		}
		compiled, err := compileRule(&userRules[i])
		if err != nil {
			return nil, err
		}

		// Check for override
		found := false
		for j := range rs.Rules {
			if rs.Rules[j].ID == compiled.ID {
				rs.Rules[j] = compiled
				found = true
				break
			}
		}
		if !found {
			rs.Rules = append(rs.Rules, compiled)
		}
	}

	// Filter to only enabled rules if specified.
	if enabled != nil {
		var filtered []CompiledRule
		for i := range rs.Rules {
			if _, ok := enabled[rs.Rules[i].ID]; ok {
				filtered = append(filtered, rs.Rules[i])
			}
		}
		rs.Rules = filtered
	}

	// Compile global allowlists
	for i := range globalAllowlists {
		compiled, err := compileAllowlist(&globalAllowlists[i])
		if err != nil {
			return nil, err
		}
		rs.Allowlists = append(rs.Allowlists, compiled)
	}

	return rs, nil
}

func compileRule(rc *config.RuleConfig) (CompiledRule, error) {
	cr := CompiledRule{
		ID:          rc.ID,
		Description: rc.Description,
		SecretGroup: rc.SecretGroup,
		Entropy:     rc.Entropy,
		Keywords:    rc.Keywords,
		Tags:        rc.Tags,
	}

	if rc.Regex != "" {
		re, err := regexp.Compile(rc.Regex)
		if err != nil {
			return cr, &RuleCompileError{RuleID: rc.ID, Field: "regex", Err: err}
		}
		cr.Regex = re
	}

	if rc.Path != "" {
		re, err := regexp.Compile(rc.Path)
		if err != nil {
			return cr, &RuleCompileError{RuleID: rc.ID, Field: "path", Err: err}
		}
		cr.Path = re
	}

	for i := range rc.Allowlists {
		compiled, err := compileAllowlist(&rc.Allowlists[i])
		if err != nil {
			return cr, err
		}
		cr.Allowlists = append(cr.Allowlists, compiled)
	}

	// Compile required/proximity rules.
	for i := range rc.Required {
		req := rc.Required[i]
		re, err := regexp.Compile(req.Regex)
		if err != nil {
			return cr, &RuleCompileError{RuleID: rc.ID, Field: "required.regex", Err: err}
		}
		cr.Required = append(cr.Required, CompiledRequired{
			ID:            req.ID,
			Regex:         re,
			WithinLines:   req.WithinLines,
			WithinColumns: req.WithinColumns,
		})
	}

	return cr, nil
}

func compileAllowlist(al *config.Allowlist) (CompiledAllowlist, error) {
	cal := CompiledAllowlist{
		Description: al.Description,
		StopWords:   al.StopWords,
		RegexTarget: al.RegexTarget,
		Condition:   al.Condition,
	}

	if len(al.Commits) > 0 {
		cal.Commits = make(map[string]struct{}, len(al.Commits))
		for _, c := range al.Commits {
			cal.Commits[c] = struct{}{}
		}
	}

	for _, p := range al.Paths {
		re, err := regexp.Compile(p)
		if err != nil {
			return cal, &AllowlistCompileError{Field: "path", Pattern: p, Err: err}
		}
		cal.Paths = append(cal.Paths, re)
	}

	for _, r := range al.Regexes {
		re, err := regexp.Compile(r)
		if err != nil {
			return cal, &AllowlistCompileError{Field: "regex", Pattern: r, Err: err}
		}
		cal.Regexes = append(cal.Regexes, re)
	}

	return cal, nil
}

// MatchResult holds the result of a rule match.
type MatchResult struct {
	FullMatch string
	Secret    string
	Entropy   float64
	Found     bool
}

// Match checks a line of content against a compiled rule.
func (r *CompiledRule) Match(line, filePath, commit string) MatchResult {
	// Path filter
	if r.Path != nil && !r.Path.MatchString(filePath) {
		return MatchResult{}
	}

	// Keyword pre-filter
	if len(r.Keywords) > 0 {
		lower := strings.ToLower(line)
		found := false
		for _, kw := range r.Keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				found = true
				break
			}
		}
		if !found {
			return MatchResult{}
		}
	}

	// Regex match
	if r.Regex == nil {
		return MatchResult{}
	}

	matches := r.Regex.FindStringSubmatch(line)
	if matches == nil {
		return MatchResult{}
	}

	fullMatch := matches[0]
	secret := fullMatch
	if r.SecretGroup > 0 && r.SecretGroup < len(matches) {
		secret = matches[r.SecretGroup]
	}

	// Compute entropy
	e := entropy.Shannon(secret)

	// Entropy filter
	if r.Entropy > 0 && e < r.Entropy {
		return MatchResult{}
	}

	// Check rule-level allowlists
	for i := range r.Allowlists {
		if r.Allowlists[i].IsAllowed(secret, fullMatch, line, filePath, commit) {
			return MatchResult{}
		}
	}

	return MatchResult{
		FullMatch: fullMatch,
		Secret:    secret,
		Entropy:   e,
		Found:     true,
	}
}

// MatchContent checks pre-extracted match and secret strings against entropy
// thresholds and allowlists. Used by the buffer scanner where regex matching
// is done externally.
func (r *CompiledRule) MatchContent(fullMatch, secret, filePath, commit string) MatchResult {
	e := entropy.Shannon(secret)
	if r.Entropy > 0 && e < r.Entropy {
		return MatchResult{}
	}

	for i := range r.Allowlists {
		if r.Allowlists[i].IsAllowed(secret, fullMatch, fullMatch, filePath, commit) {
			return MatchResult{}
		}
	}

	return MatchResult{
		FullMatch: fullMatch,
		Secret:    secret,
		Entropy:   e,
		Found:     true,
	}
}

// IsAllowed returns true if a finding should be ignored based on this allowlist.
func (al *CompiledAllowlist) IsAllowed(secret, match, line, filePath, commit string) bool {
	isAnd := strings.EqualFold(al.Condition, "AND")

	// Determine target for regex matching
	target := secret
	switch strings.ToLower(al.RegexTarget) {
	case "match":
		target = match
	case "line":
		target = line
	}

	checks := 0
	passed := 0

	// Check commits
	if len(al.Commits) > 0 {
		checks++
		if _, ok := al.Commits[commit]; ok {
			passed++
		}
		// Also check short hash
		if len(commit) >= 7 {
			if _, ok := al.Commits[commit[:7]]; ok {
				passed++
				if passed > checks {
					passed = checks
				}
			}
		}
	}

	// Check paths
	if len(al.Paths) > 0 {
		checks++
		for _, re := range al.Paths {
			if re.MatchString(filePath) {
				passed++
				break
			}
		}
	}

	// Check regexes
	if len(al.Regexes) > 0 {
		checks++
		for _, re := range al.Regexes {
			if re.MatchString(target) {
				passed++
				break
			}
		}
	}

	// Check stop words
	if len(al.StopWords) > 0 {
		checks++
		lowerSecret := strings.ToLower(secret)
		for _, sw := range al.StopWords {
			if strings.Contains(lowerSecret, strings.ToLower(sw)) {
				passed++
				break
			}
		}
	}

	if checks == 0 {
		return false
	}

	if isAnd {
		return passed == checks
	}
	return passed > 0
}

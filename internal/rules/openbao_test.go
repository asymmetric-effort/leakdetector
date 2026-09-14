package rules

import (
	"strings"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/config"
)

// Tests for the OpenBao/Vault unseal-key, cleartext ansible-vault, and bare
// hvs. token rules.
//
// Motivating incident: an `ansible/group_vars/all/vault_openbao.yml` containing
// five Shamir unseal shares and a root token was committed in cleartext and sat
// in a repository for weeks. Scanning it with the then-current ruleset returned
// ZERO findings -- the shares are bare base64 list items with no assignment
// keyword, so no key-name or entropy rule fired.

// scanFixture compiles the built-in ruleset and returns the IDs of rules that
// fire against content at the given path. It mirrors what the scanner does:
// match line by line, then apply the proximity constraint for composite rules.
func scanFixture(t *testing.T, path, content string) map[string]bool {
	t.Helper()
	rs, err := Compile(nil, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	lines := strings.Split(content, "\n")
	got := make(map[string]bool)
	for i := range rs.Rules {
		rule := &rs.Rules[i]
		for idx, line := range lines {
			mr := rule.Match(line, path, "")
			if !mr.Found {
				continue
			}
			col := strings.Index(line, mr.Secret)
			if col < 0 {
				col = 0
			}
			if !rule.CheckProximity(lines, idx, col) {
				continue
			}
			got[rule.ID] = true
		}
	}
	return got
}

// realWorldLeak reproduces the shape of the committed file that motivated
// these rules. Values are randomly generated, not the real shares.
const realWorldLeak = `---
# OpenBao unseal material — ansible-vault encrypted.
# Written by server_openbao on first init. DO NOT store unencrypted.
vault_openbao_unseal_keys:
  - "LtM0vevPx20ObLq4XKdnIplzgPAzwLPnNYrRQ8O7nJ1T"
  - "0ArjPWStywEF3UpuUmACIR2ytWH4cEsc8k1EQ93KLsg6"
  - "8sMzjye7UrS77jQfr7M3034Ukj9Gpus1SJGNMw9nxqra"
  - "x3yFbf5d5CMiZAsjIJDO7JNSlpV3VhldmoRYQRkeEH1O"
  - "uqkXu4J8kB4Ct8a1PkyuBPzdPdTr1fXkeHNtbf9FQILB"
vault_openbao_root_token: "hvs.CAESIJx8kQm2N4pLvRtYwZbHqKdMnXcVfTgUoPaEiSrLwBnZ"
`

// The structural rule must fire on the cleartext file. This is the check that
// is deterministic rather than probabilistic: it does not depend on the shape
// of any secret value.
func TestAnsibleVaultCleartext_FiresOnRealWorldLeak(t *testing.T) {
	got := scanFixture(t, "ansible/group_vars/all/vault_openbao.yml", realWorldLeak)
	if !got["ansible-vault-cleartext"] {
		t.Error("ansible-vault-cleartext must fire on an unencrypted vault_*.yml; " +
			"this is the rule that makes the detection deterministic")
	}
}

// An ansible-vault ENCRYPTED file must not fire: its content is a header plus
// hex, so no vault_* key is visible. A false positive here would make the rule
// unusable, since every correctly-encrypted file would trip it.
func TestAnsibleVaultCleartext_SilentOnEncryptedFile(t *testing.T) {
	encrypted := `$ANSIBLE_VAULT;1.1;AES256
38356265623838356533616534306665343831353732313438323161653061346430386262363562
6534363264653933356362373263363735616139383331360a363334393234393638623461323865
`
	got := scanFixture(t, "ansible/group_vars/all/vault_openbao.yml", encrypted)
	if got["ansible-vault-cleartext"] {
		t.Error("ansible-vault-cleartext must not fire on a properly encrypted file")
	}
}

// A Jinja reference to a vault variable is not a secret. group_vars/main.yml
// routinely contains lines like:
//
//	cloudflared_tunnel_token: "{{ vault_cloudflared_tunnel_token | default('') }}"
//
// The rule is anchored to line start specifically so these do not match.
func TestAnsibleVaultCleartext_SilentOnJinjaReference(t *testing.T) {
	refs := `---
cloudflared_tunnel_token: "{{ vault_cloudflared_tunnel_token | default('') }}"
registry_token: "{{ vault_registry_token | default('') }}"
`
	got := scanFixture(t, "ansible/group_vars/all/vault_main.yml", refs)
	if got["ansible-vault-cleartext"] {
		t.Error("a Jinja reference to a vault_ variable is not a cleartext secret")
	}
}

// Path scoping: an ordinary playbook that happens to name a vault_ variable is
// not a vault file and must not fire.
func TestAnsibleVaultCleartext_PathScoped(t *testing.T) {
	got := scanFixture(t, "ansible/roles/server_openbao/tasks/init.yml",
		"vault_openbao_root_token: \"{{ init.json.root_token }}\"\n")
	if got["ansible-vault-cleartext"] {
		t.Error("rule must be scoped to vault-named files, not every playbook")
	}
}

// The composite unseal rule must fire when shares appear near an unseal context.
func TestOpenBaoUnsealKey_FiresNearUnsealContext(t *testing.T) {
	got := scanFixture(t, "ansible/group_vars/all/vault_openbao.yml", realWorldLeak)
	if !got["openbao-unseal-key"] {
		t.Error("openbao-unseal-key must fire on Shamir shares near an unseal context")
	}
}

// keys_base64 as emitted verbatim by `bao operator init -format=json`.
func TestOpenBaoUnsealKey_FiresOnInitJSONOutput(t *testing.T) {
	initOutput := `{
  "keys_base64": [
    "LtM0vevPx20ObLq4XKdnIplzgPAzwLPnNYrRQ8O7nJ1T",
    "0ArjPWStywEF3UpuUmACIR2ytWH4cEsc8k1EQ93KLsg6"
  ]
}`
	got := scanFixture(t, "bootstrap/init-output.json", initOutput)
	if !got["openbao-unseal-key"] {
		t.Error("openbao-unseal-key must fire on `operator init` JSON output")
	}
}

// Without the unseal context, a lone base64 value is just data. The Required
// proximity constraint is what keeps this rule from flagging every base64 blob
// in the repository.
func TestOpenBaoUnsealKey_SilentWithoutUnsealContext(t *testing.T) {
	unrelated := `---
image_digest: "sha256AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
asset_hash: "LtM0vevPx20ObLq4XKdnIplzgPAzwLPnNYrRQ8O7nJ1T"
`
	got := scanFixture(t, "config/assets.yml", unrelated)
	if got["openbao-unseal-key"] {
		t.Error("openbao-unseal-key must require an unseal/recovery context; " +
			"otherwise it flags every 44-char base64 value")
	}
}

// A bare hvs. token must be caught regardless of the key name. The pre-existing
// vault-token rule requires a literal `vault_token` key, so it misses the
// common real-world spellings.
func TestVaultHVSToken_FiresRegardlessOfKeyName(t *testing.T) {
	for _, line := range []string{
		`vault_openbao_root_token: "hvs.CAESIJx8kQm2N4pLvRtYwZbHqKdMnXcVfTgUoPaEiSrLwBnZ"`,
		`bao_root_token = hvs.CAESIJx8kQm2N4pLvRtYwZbHqKdMnXcVfTgUoPaEiSrLwBnZ`,
		`export ROOT=hvs.CAESIJx8kQm2N4pLvRtYwZbHqKdMnXcVfTgUoPaEiSrLwBnZ`,
		`curl -H "X-Vault-Token: hvs.CAESIJx8kQm2N4pLvRtYwZbHqKdMnXcVfTgUoPaEiSrLwBnZ" ...`,
	} {
		got := scanFixture(t, "scripts/bootstrap.sh", line)
		if !got["vault-hvs-token"] {
			t.Errorf("vault-hvs-token must fire on: %s", strings.TrimSpace(line))
		}
	}
}

// Every new rule must be registered exactly once and compile.
func TestOpenBaoRules_Registered(t *testing.T) {
	want := []string{"openbao-unseal-key", "ansible-vault-cleartext", "vault-hvs-token"}
	byID := make(map[string]config.RuleConfig)
	for _, r := range BuiltinRules() {
		byID[r.ID] = r
	}
	for _, id := range want {
		r, ok := byID[id]
		if !ok {
			t.Errorf("rule %q is not registered in BuiltinRules()", id)
			continue
		}
		if r.Description == "" {
			t.Errorf("rule %q has no description", id)
		}
		if len(r.Tags) == 0 {
			t.Errorf("rule %q has no tags", id)
		}
	}
}

// The buffer scanner matches against a multi-line window, not line by line, so
// openbao-unseal-key's regex must carry (?m). Without it `$` anchors to the end
// of the whole window and only the final entry of a key list is ever reported.
//
// This is deliberately tested against the raw compiled regex rather than
// through scanFixture: that helper splits into lines first, which makes `$`
// behave per-line and hides the bug entirely. Caught end-to-end, not by unit
// tests -- a five-share list yielded one finding instead of five.
func TestOpenBaoUnsealKey_MatchesEveryShareInMultilineBuffer(t *testing.T) {
	rs, err := Compile(nil, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var rule *CompiledRule
	for i := range rs.Rules {
		if rs.Rules[i].ID == "openbao-unseal-key" {
			rule = &rs.Rules[i]
			break
		}
	}
	if rule == nil {
		t.Fatal("openbao-unseal-key not found in the compiled ruleset")
	}

	const shares = `vault_openbao_unseal_keys:
  - "LtM0vevPx20ObLq4XKdnIplzgPAzwLPnNYrRQ8O7nJ1T"
  - "0ArjPWStywEF3UpuUmACIR2ytWH4cEsc8k1EQ93KLsg6"
  - "8sMzjye7UrS77jQfr7M3034Ukj9Gpus1SJGNMw9nxqra"
  - "x3yFbf5d5CMiZAsjIJDO7JNSlpV3VhldmoRYQRkeEH1O"
  - "uqkXu4J8kB4Ct8a1PkyuBPzdPdTr1fXkeHNtbf9FQILB"
`
	got := len(rule.Regex.FindAllStringSubmatch(shares, -1))
	if got != 5 {
		t.Errorf("expected all 5 shares to match in a multi-line buffer, got %d; "+
			"is (?m) still present on the regex?", got)
	}
}

// Composite rules must not set Keywords: CompiledRule.Match applies the keyword
// pre-filter to the matched line, while Required matches context on OTHER
// lines. Setting both makes a rule silently never fire.
func TestCompositeRules_DoNotSetKeywords(t *testing.T) {
	for _, r := range BuiltinRules() {
		if len(r.Required) > 0 && len(r.Keywords) > 0 {
			t.Errorf("rule %q sets both Required and Keywords; the per-line keyword "+
				"pre-filter will reject matches whose context is on another line", r.ID)
		}
	}
}

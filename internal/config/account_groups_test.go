package config

import "testing"

func TestNormalizeAccountGroups(t *testing.T) {
	keyHash := HashAPIKeyForGroupPolicy("key-a")
	cfg := &Config{SDKConfig: SDKConfig{
		AccountGroups: []AccountGroup{
			{ID: 2, Name: " Beta ", Color: "#ABCDEF", SortOrder: 20},
			{ID: 2, Name: "Alpha", Color: "invalid", SortOrder: 10},
			{ID: 9, Name: "alpha"},
			{ID: 10, Name: "   "},
		},
		APIKeyGroupPolicies: []APIKeyGroupPolicy{
			{APIKeyHash: keyHash, AllowedGroupIDs: []int64{2, 2, -1, 7}},
			{APIKeyHash: "invalid", AllowedGroupIDs: []int64{2}},
		},
	}}

	cfg.NormalizeAccountGroups()

	if len(cfg.AccountGroups) != 2 {
		t.Fatalf("AccountGroups length = %d, want 2", len(cfg.AccountGroups))
	}
	if cfg.AccountGroups[0].Name != "Alpha" || cfg.AccountGroups[0].ID == 2 {
		t.Fatalf("first group = %#v, want normalized unique Alpha group", cfg.AccountGroups[0])
	}
	if cfg.AccountGroups[0].Color != DefaultAccountGroupColor {
		t.Fatalf("Alpha color = %q, want %q", cfg.AccountGroups[0].Color, DefaultAccountGroupColor)
	}
	if cfg.AccountGroups[1].Name != "Beta" || cfg.AccountGroups[1].Color != "#abcdef" {
		t.Fatalf("second group = %#v", cfg.AccountGroups[1])
	}
	if len(cfg.APIKeyGroupPolicies) != 1 {
		t.Fatalf("APIKeyGroupPolicies length = %d, want 1", len(cfg.APIKeyGroupPolicies))
	}
	gotIDs := cfg.APIKeyGroupPolicies[0].AllowedGroupIDs
	if len(gotIDs) != 2 || gotIDs[0] != 2 || gotIDs[1] != 7 {
		t.Fatalf("AllowedGroupIDs = %v, want [2 7]", gotIDs)
	}
}

func TestNormalizeAccountGroupsDoesNotReuseReservedPolicyIDs(t *testing.T) {
	cfg := &Config{SDKConfig: SDKConfig{
		AccountGroups: []AccountGroup{{Name: "Replacement"}},
		APIKeyGroupPolicies: []APIKeyGroupPolicy{{
			APIKeyHash:      HashAPIKeyForGroupPolicy("restricted-key"),
			AllowedGroupIDs: []int64{7},
		}},
	}}

	cfg.NormalizeAccountGroups()

	if len(cfg.AccountGroups) != 1 || cfg.AccountGroups[0].ID != 8 {
		t.Fatalf("normalized groups = %#v, want generated id 8", cfg.AccountGroups)
	}
}

func TestHashAPIKeyForGroupPolicyTrimsInput(t *testing.T) {
	if got, want := HashAPIKeyForGroupPolicy(" key-a "), HashAPIKeyForGroupPolicy("key-a"); got != want {
		t.Fatalf("hash mismatch: %q != %q", got, want)
	}
	if got := HashAPIKeyForGroupPolicy("   "); got != "" {
		t.Fatalf("empty hash = %q, want empty", got)
	}
}

func TestNormalizeAccountGroupsNormalizesCredentialMemberships(t *testing.T) {
	cfg := &Config{
		GeminiKey:       []GeminiKey{{GroupIDs: []int64{3, 1, 3, -1}}},
		InteractionsKey: []GeminiKey{{GroupIDs: []int64{4, 2}}},
		ClaudeKey:       []ClaudeKey{{GroupIDs: []int64{5, 5}}},
		CodexKey:        []CodexKey{{GroupIDs: []int64{7, 6}}},
		XAIKey:          []CodexKey{{GroupIDs: []int64{9, 8}}},
		OpenAICompatibility: []OpenAICompatibility{{
			GroupIDs:      []int64{11, 10},
			APIKeyEntries: []OpenAICompatibilityAPIKey{{GroupIDs: []int64{13, 12, 13}}},
		}},
		VertexCompatAPIKey: []VertexCompatKey{{GroupIDs: []int64{15, 14}}},
	}

	cfg.NormalizeAccountGroups()

	checks := []struct {
		name string
		got  []int64
		want []int64
	}{
		{name: "gemini", got: cfg.GeminiKey[0].GroupIDs, want: []int64{1, 3}},
		{name: "interactions", got: cfg.InteractionsKey[0].GroupIDs, want: []int64{2, 4}},
		{name: "claude", got: cfg.ClaudeKey[0].GroupIDs, want: []int64{5}},
		{name: "codex", got: cfg.CodexKey[0].GroupIDs, want: []int64{6, 7}},
		{name: "xai", got: cfg.XAIKey[0].GroupIDs, want: []int64{8, 9}},
		{name: "openai provider", got: cfg.OpenAICompatibility[0].GroupIDs, want: []int64{10, 11}},
		{name: "openai key", got: cfg.OpenAICompatibility[0].APIKeyEntries[0].GroupIDs, want: []int64{12, 13}},
		{name: "vertex", got: cfg.VertexCompatAPIKey[0].GroupIDs, want: []int64{14, 15}},
	}
	for _, check := range checks {
		if len(check.got) != len(check.want) {
			t.Fatalf("%s group ids = %v, want %v", check.name, check.got, check.want)
		}
		for index := range check.want {
			if check.got[index] != check.want[index] {
				t.Fatalf("%s group ids = %v, want %v", check.name, check.got, check.want)
			}
		}
	}
}

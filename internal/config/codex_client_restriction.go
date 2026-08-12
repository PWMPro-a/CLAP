package config

import (
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/codexclientpolicy"
)

func (c CodexClientRestrictionConfig) Validate() error {
	policy := codexclientpolicy.Policy{
		ForceAllow:               c.ForceAllow,
		MinCodexVersion:          c.MinCodexVersion,
		MaxCodexVersion:          c.MaxCodexVersion,
		AllowAppServerClients:    c.AllowAppServerClients,
		Whitelist:                make([]codexclientpolicy.ClientEntry, 0, len(c.Whitelist)),
		Blacklist:                make([]codexclientpolicy.ClientEntry, 0, len(c.Blacklist)),
		EngineFingerprintSignals: make([]codexclientpolicy.EngineFingerprintSignal, 0, len(c.EngineFingerprintSignals)),
	}
	for _, entry := range c.Whitelist {
		policy.Whitelist = append(policy.Whitelist, codexclientpolicy.ClientEntry{
			Originator: entry.Originator, UAContains: entry.UAContains, SkipEngineFingerprint: entry.SkipEngineFingerprint,
		})
	}
	for _, entry := range c.Blacklist {
		policy.Blacklist = append(policy.Blacklist, codexclientpolicy.ClientEntry{
			Originator: entry.Originator, UAContains: entry.UAContains,
		})
	}
	for _, signal := range c.EngineFingerprintSignals {
		policy.EngineFingerprintSignals = append(policy.EngineFingerprintSignals, codexclientpolicy.EngineFingerprintSignal{
			Type: signal.Type, Match: signal.Match, Required: signal.Required,
		})
	}
	return codexclientpolicy.ValidatePolicy(policy)
}

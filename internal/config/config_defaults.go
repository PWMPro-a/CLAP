package config

const (
	DefaultPanelGitHubRepository = "https://github.com/router-for-me/Cli-Proxy-API-Management-Center"
	DefaultPprofAddr             = "127.0.0.1:8316"
	DefaultAuthDir               = "~/.cli-proxy-api"

	DefaultAgentIdentityRecoveryConcurrency = 6
	MaxAgentIdentityRecoveryConcurrency     = 64
	DefaultAgentIdentityRecoveryHistory     = 2000
	MaxAgentIdentityRecoveryHistory         = 10000
)

// AgentIdentityRecoveryConfig controls Agent Identity task registration and recovery.
type AgentIdentityRecoveryConfig struct {
	Concurrency  int `yaml:"concurrency,omitempty" json:"concurrency"`
	HistoryLimit int `yaml:"history-limit,omitempty" json:"history-limit"`
}

// Normalize clamps Agent Identity recovery settings and fills defaults.
func (c *AgentIdentityRecoveryConfig) Normalize() {
	if c == nil {
		return
	}
	if c.Concurrency <= 0 {
		c.Concurrency = DefaultAgentIdentityRecoveryConcurrency
	} else if c.Concurrency > MaxAgentIdentityRecoveryConcurrency {
		c.Concurrency = MaxAgentIdentityRecoveryConcurrency
	}
	if c.HistoryLimit <= 0 {
		c.HistoryLimit = DefaultAgentIdentityRecoveryHistory
	} else if c.HistoryLimit > MaxAgentIdentityRecoveryHistory {
		c.HistoryLimit = MaxAgentIdentityRecoveryHistory
	}
}

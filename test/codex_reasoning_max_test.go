package test

import (
	"fmt"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/tidwall/gjson"
)

func TestCodexReasoningMaxSupport(t *testing.T) {
	registryRef := registry.GetGlobalRegistry()
	clientID := fmt.Sprintf("codex-max-reasoning-%d", time.Now().UnixNano())
	registryRef.RegisterClient(clientID, "codex", registry.GetCodexProModels())
	t.Cleanup(func() {
		registryRef.UnregisterClient(clientID)
	})

	cases := []struct {
		name  string
		model string
		body  []byte
	}{
		{
			name:  "request body",
			model: "gpt-5.5",
			body:  []byte(`{"model":"gpt-5.5","reasoning":{"effort":"max"}}`),
		},
		{
			name:  "model suffix",
			model: "gpt-5.5(max)",
			body:  []byte(`{"model":"gpt-5.5","reasoning":{"effort":"low"}}`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := thinking.ApplyThinking(tc.body, tc.model, "codex", "codex", "codex")
			if err != nil {
				t.Fatalf("ApplyThinking() error = %v", err)
			}
			if got := gjson.GetBytes(output, "reasoning.effort").String(); got != "max" {
				t.Fatalf("reasoning.effort = %q, want max; body=%s", got, output)
			}
		})
	}
}

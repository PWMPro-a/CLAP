package auth

import (
	"bytes"
	"context"
	"strings"

	"github.com/tidwall/gjson"
)

type sessionAffinityBinder interface {
	BindAuthSession(provider, model, sessionID, authID string)
}

func (m *Manager) bindSessionAffinityFromResponsePayload(_ context.Context, provider, model, authID string, payload []byte) {
	if m == nil || len(payload) == 0 || strings.TrimSpace(authID) == "" {
		return
	}
	binder, ok := m.selector.(sessionAffinityBinder)
	if !ok || binder == nil {
		return
	}
	for _, responseID := range responseSessionAffinityIDs(payload) {
		binder.BindAuthSession(provider, model, "response:"+responseID, authID)
	}
}

func responseSessionAffinityIDs(payload []byte) []string {
	if len(payload) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, 2)
	out := make([]string, 0, 2)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	collectJSON := func(data []byte) {
		data = bytes.TrimSpace(data)
		if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
			return
		}
		add(gjson.GetBytes(data, "id").String())
		add(gjson.GetBytes(data, "response.id").String())
	}
	collectJSON(payload)
	for _, line := range bytes.Split(payload, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("data:")) {
			collectJSON(bytes.TrimSpace(line[len("data:"):]))
		}
	}
	return out
}

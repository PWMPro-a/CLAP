package helps

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestNewProxyAwareHTTPClientDirectBypassesGlobalProxy(t *testing.T) {
	t.Parallel()

	client := NewProxyAwareHTTPClient(
		context.Background(),
		&config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"}},
		&cliproxyauth.Auth{ProxyURL: "direct"},
		0,
	)

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("expected direct transport to disable proxy function")
	}
}

func TestCachedCodexChromeRoundTripperReusesPerAuthTransport(t *testing.T) {
	t.Parallel()

	firstAuth := &cliproxyauth.Auth{ID: "auth-1"}
	first := cachedCodexChromeRoundTripperWithSourceIP("", "", firstAuth)
	second := cachedCodexChromeRoundTripperWithSourceIP("", "", firstAuth)
	if first != second {
		t.Fatal("cached codex chrome transport returned different instances for one auth")
	}

	other := cachedCodexChromeRoundTripperWithSourceIP("", "", &cliproxyauth.Auth{ID: "auth-2"})
	if other == first {
		t.Fatal("different auths reused the same codex chrome transport")
	}
}

func TestResolveEgressSettingsAuthSourceIPBypassesGlobalProxy(t *testing.T) {
	t.Parallel()

	proxyURL, sourceIP := ResolveEgressSettings(
		&config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"}},
		&cliproxyauth.Auth{SourceIP: "127.0.0.2"},
	)

	if proxyURL != "" {
		t.Fatalf("proxyURL = %q, want empty direct source route", proxyURL)
	}
	if sourceIP != "127.0.0.2" {
		t.Fatalf("sourceIP = %q, want 127.0.0.2", sourceIP)
	}
}

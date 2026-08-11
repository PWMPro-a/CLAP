package helps

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

// NewProxyAwareHTTPClient creates an HTTP client with proper egress configuration priority:
// 1. Use auth.ProxyURL if configured.
// 2. Use auth.SourceIP if configured, bypassing the global proxy.
// 3. Use cfg.ProxyURL/cfg.SourceIP.
// 4. Use RoundTripper from context if neither are configured.
//
// Parameters:
//   - ctx: The context containing optional RoundTripper
//   - cfg: The application configuration
//   - auth: The authentication information
//   - timeout: The client timeout (0 means no timeout)
//
// Returns:
//   - *http.Client: An HTTP client with configured proxy or transport
func NewProxyAwareHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	httpClient := &http.Client{}
	if timeout > 0 {
		httpClient.Timeout = timeout
	}

	proxyURL, sourceIP := ResolveEgressSettings(cfg, auth)

	// If we have an egress override configured, set up the transport.
	if proxyURL != "" || sourceIP != "" {
		transport := buildProxyTransport(proxyURL, sourceIP)
		if transport != nil {
			httpClient.Transport = transport
			return httpClient
		}
		// If proxy setup failed, log and fall through to context RoundTripper
		log.Debugf("failed to setup egress from proxy URL %s and source IP %q, falling back to context transport", proxyutil.Redact(proxyURL), sourceIP)
	}

	// Priority 3: Use RoundTripper from context (typically from RoundTripperFor)
	if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
		httpClient.Transport = rt
	}

	return httpClient
}

// ResolveEgressSettings returns the effective proxy URL and source IP for an auth.
func ResolveEgressSettings(cfg *config.Config, auth *cliproxyauth.Auth) (string, string) {
	authProxyURL := ""
	authSourceIP := ""
	if auth != nil {
		authProxyURL = strings.TrimSpace(auth.ProxyURL)
		authSourceIP = strings.TrimSpace(auth.SourceIP)
	}
	if authProxyURL != "" {
		if authSourceIP == "" && cfg != nil {
			authSourceIP = strings.TrimSpace(cfg.SourceIP)
		}
		return authProxyURL, authSourceIP
	}
	if authSourceIP != "" {
		return "", authSourceIP
	}
	if cfg == nil {
		return "", ""
	}
	return strings.TrimSpace(cfg.ProxyURL), strings.TrimSpace(cfg.SourceIP)
}

// buildProxyTransport creates an HTTP transport configured for the given egress settings.
func buildProxyTransport(proxyURL string, sourceIP string) *http.Transport {
	transport, _, errBuild := proxyutil.BuildHTTPTransportWithSourceIP(proxyURL, sourceIP)
	if errBuild != nil {
		log.Errorf("%v", errBuild)
		return nil
	}
	return transport
}

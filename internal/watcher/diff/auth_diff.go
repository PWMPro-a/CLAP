// auth_diff.go computes human-readable diffs for auth file field changes.
package diff

import (
	"fmt"
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// BuildAuthChangeDetails computes a redacted, human-readable list of auth field changes.
// Only prefix, proxy_url, source_ip, and disabled fields are tracked; sensitive data is never printed.
func BuildAuthChangeDetails(oldAuth, newAuth *coreauth.Auth) []string {
	changes := make([]string, 0, 4)

	// Handle nil cases by using empty Auth as default
	if oldAuth == nil {
		oldAuth = &coreauth.Auth{}
	}
	if newAuth == nil {
		return changes
	}

	// Compare prefix
	oldPrefix := strings.TrimSpace(oldAuth.Prefix)
	newPrefix := strings.TrimSpace(newAuth.Prefix)
	if oldPrefix != newPrefix {
		changes = append(changes, fmt.Sprintf("prefix: %s -> %s", oldPrefix, newPrefix))
	}

	// Compare proxy_url (redacted)
	oldProxy := strings.TrimSpace(oldAuth.ProxyURL)
	newProxy := strings.TrimSpace(newAuth.ProxyURL)
	if oldProxy != newProxy {
		changes = append(changes, fmt.Sprintf("proxy_url: %s -> %s", formatProxyURL(oldProxy), formatProxyURL(newProxy)))
	}

	oldSourceIP := strings.TrimSpace(oldAuth.SourceIP)
	newSourceIP := strings.TrimSpace(newAuth.SourceIP)
	if oldSourceIP != newSourceIP {
		changes = append(changes, fmt.Sprintf("source_ip: %s -> %s", oldSourceIP, newSourceIP))
	}

	// Compare disabled
	if oldAuth.Disabled != newAuth.Disabled {
		changes = append(changes, fmt.Sprintf("disabled: %t -> %t", oldAuth.Disabled, newAuth.Disabled))
	}

	return changes
}

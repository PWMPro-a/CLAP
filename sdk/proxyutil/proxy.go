package proxyutil

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Mode describes how a proxy setting should be interpreted.
type Mode int

const (
	// ModeInherit means no explicit proxy behavior was configured.
	ModeInherit Mode = iota
	// ModeDirect means outbound requests must bypass proxies explicitly.
	ModeDirect
	// ModeProxy means a concrete proxy URL was configured.
	ModeProxy
	// ModeInvalid means the proxy setting is present but malformed or unsupported.
	ModeInvalid
)

// Setting is the normalized interpretation of a proxy configuration value.
type Setting struct {
	Raw  string
	Mode Mode
	URL  *url.URL
}

// Parse normalizes a proxy configuration value into inherit, direct, or proxy modes.
func Parse(raw string) (Setting, error) {
	trimmed := strings.TrimSpace(raw)
	setting := Setting{Raw: trimmed}

	if trimmed == "" {
		setting.Mode = ModeInherit
		return setting, nil
	}

	if strings.EqualFold(trimmed, "direct") || strings.EqualFold(trimmed, "none") {
		setting.Mode = ModeDirect
		return setting, nil
	}

	parsedURL, errParse := url.Parse(trimmed)
	if errParse != nil {
		setting.Mode = ModeInvalid
		return setting, fmt.Errorf("parse proxy URL failed")
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		setting.Mode = ModeInvalid
		return setting, fmt.Errorf("proxy URL missing scheme/host")
	}

	switch parsedURL.Scheme {
	case "socks5", "socks5h", "http", "https":
		setting.Mode = ModeProxy
		setting.URL = parsedURL
		return setting, nil
	default:
		setting.Mode = ModeInvalid
		return setting, fmt.Errorf("unsupported proxy scheme: %s", parsedURL.Scheme)
	}
}

func cloneDefaultTransport() *http.Transport {
	if transport, ok := http.DefaultTransport.(*http.Transport); ok && transport != nil {
		return transport.Clone()
	}
	return &http.Transport{}
}

// NewDirectTransport returns a transport that bypasses environment proxies.
func NewDirectTransport() *http.Transport {
	clone := cloneDefaultTransport()
	clone.Proxy = nil
	return clone
}

// NewSourceIPTransport returns a direct transport bound to the provided local source IP.
func NewSourceIPTransport(sourceIP string) (*http.Transport, error) {
	ip, errParse := parseSourceIP(sourceIP)
	if errParse != nil {
		return nil, errParse
	}
	clone := NewDirectTransport()
	dialer := sourceIPNetDialer(ip)
	clone.DialContext = dialer.DialContext
	return clone, nil
}

// BuildHTTPTransport constructs an HTTP transport for the provided proxy setting.
func BuildHTTPTransport(raw string) (*http.Transport, Mode, error) {
	return BuildHTTPTransportWithSourceIP(raw, "")
}

// BuildHTTPTransportWithSourceIP constructs an HTTP transport for proxy and source IP settings.
// Concrete proxy URLs keep proxy behavior and do not bind source IP on the proxy socket.
func BuildHTTPTransportWithSourceIP(raw string, sourceIP string) (*http.Transport, Mode, error) {
	setting, errParse := Parse(raw)
	if errParse != nil {
		return nil, setting.Mode, errParse
	}
	sourceIP = strings.TrimSpace(sourceIP)

	switch setting.Mode {
	case ModeInherit:
		if sourceIP != "" {
			transport, errSource := NewSourceIPTransport(sourceIP)
			if errSource != nil {
				return nil, setting.Mode, errSource
			}
			return transport, ModeDirect, nil
		}
		return nil, setting.Mode, nil
	case ModeDirect:
		if sourceIP != "" {
			transport, errSource := NewSourceIPTransport(sourceIP)
			if errSource != nil {
				return nil, setting.Mode, errSource
			}
			return transport, setting.Mode, nil
		}
		return NewDirectTransport(), setting.Mode, nil
	case ModeProxy:
		if setting.URL.Scheme == "socks5" || setting.URL.Scheme == "socks5h" {
			var proxyAuth *proxy.Auth
			if setting.URL.User != nil {
				username := setting.URL.User.Username()
				password, _ := setting.URL.User.Password()
				proxyAuth = &proxy.Auth{User: username, Password: password}
			}
			dialer, errSOCKS5 := proxy.SOCKS5("tcp", setting.URL.Host, proxyAuth, proxy.Direct)
			if errSOCKS5 != nil {
				return nil, setting.Mode, fmt.Errorf("create SOCKS5 dialer failed: %w", errSOCKS5)
			}
			transport := cloneDefaultTransport()
			transport.Proxy = nil
			transport.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
			return transport, setting.Mode, nil
		}
		transport := cloneDefaultTransport()
		transport.Proxy = http.ProxyURL(setting.URL)
		return transport, setting.Mode, nil
	default:
		return nil, setting.Mode, nil
	}
}

// BuildDialer constructs a proxy dialer for settings that operate at the connection layer.
func BuildDialer(raw string) (proxy.Dialer, Mode, error) {
	return BuildDialerWithSourceIP(raw, "")
}

// BuildDialerWithSourceIP constructs a connection-layer dialer for proxy and source IP settings.
// Concrete proxy URLs keep proxy behavior and do not bind source IP on the proxy socket.
func BuildDialerWithSourceIP(raw string, sourceIP string) (proxy.Dialer, Mode, error) {
	setting, errParse := Parse(raw)
	if errParse != nil {
		return nil, setting.Mode, errParse
	}
	sourceIP = strings.TrimSpace(sourceIP)

	switch setting.Mode {
	case ModeInherit:
		if sourceIP != "" {
			dialer, _, errSource := NewSourceIPDialer(sourceIP)
			return dialer, ModeDirect, errSource
		}
		return nil, setting.Mode, nil
	case ModeDirect:
		if sourceIP != "" {
			return NewSourceIPDialer(sourceIP)
		}
		return proxy.Direct, setting.Mode, nil
	case ModeProxy:
		if setting.URL.Scheme == "http" || setting.URL.Scheme == "https" {
			return &httpConnectDialer{proxyURL: setting.URL, dialer: proxy.Direct}, setting.Mode, nil
		}
		dialer, errDialer := proxy.FromURL(setting.URL, proxy.Direct)
		if errDialer != nil {
			return nil, setting.Mode, fmt.Errorf("create proxy dialer failed: %w", errDialer)
		}
		return dialer, setting.Mode, nil
	default:
		return nil, setting.Mode, nil
	}
}

// NewSourceIPDialer returns a direct proxy.Dialer bound to the provided local source IP.
func NewSourceIPDialer(sourceIP string) (proxy.Dialer, Mode, error) {
	ip, errParse := parseSourceIP(sourceIP)
	if errParse != nil {
		return nil, ModeDirect, errParse
	}
	return &sourceIPDialer{dialer: sourceIPNetDialer(ip)}, ModeDirect, nil
}

type sourceIPDialer struct {
	dialer net.Dialer
}

func (d *sourceIPDialer) Dial(network, addr string) (net.Conn, error) {
	return d.dialer.Dial(network, addr)
}

func parseSourceIP(sourceIP string) (net.IP, error) {
	trimmed := strings.TrimSpace(sourceIP)
	if trimmed == "" {
		return nil, fmt.Errorf("source IP is empty")
	}
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return nil, fmt.Errorf("invalid source IP: %s", trimmed)
	}
	return ip, nil
}

func sourceIPNetDialer(ip net.IP) net.Dialer {
	return net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: &net.TCPAddr{IP: ip},
	}
}

type httpConnectDialer struct {
	proxyURL *url.URL
	dialer   proxy.Dialer
}

func (d *httpConnectDialer) Dial(network, addr string) (net.Conn, error) {
	proxyConn, errDial := d.dialer.Dial(network, proxyDialAddr(d.proxyURL))
	if errDial != nil {
		return nil, fmt.Errorf("dial HTTP proxy failed: %w", errDial)
	}

	conn := proxyConn
	if d.proxyURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: d.proxyURL.Hostname()})
		if errHandshake := tlsConn.Handshake(); errHandshake != nil {
			if errClose := conn.Close(); errClose != nil {
				return nil, fmt.Errorf("HTTPS proxy TLS handshake failed: %w; close failed: %v", errHandshake, errClose)
			}
			return nil, fmt.Errorf("HTTPS proxy TLS handshake failed: %w", errHandshake)
		}
		conn = tlsConn
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if d.proxyURL.User != nil {
		req.Header.Set("Proxy-Authorization", proxyAuthorization(d.proxyURL.User))
	}
	if errWrite := req.Write(conn); errWrite != nil {
		if errClose := conn.Close(); errClose != nil {
			return nil, fmt.Errorf("write CONNECT request failed: %w; close failed: %v", errWrite, errClose)
		}
		return nil, fmt.Errorf("write CONNECT request failed: %w", errWrite)
	}

	reader := bufio.NewReader(conn)
	resp, errRead := http.ReadResponse(reader, req)
	if errRead != nil {
		if errClose := conn.Close(); errClose != nil {
			return nil, fmt.Errorf("read CONNECT response failed: %w; close failed: %v", errRead, errClose)
		}
		return nil, fmt.Errorf("read CONNECT response failed: %w", errRead)
	}
	if resp.StatusCode != http.StatusOK {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		if errClose := conn.Close(); errClose != nil {
			return nil, fmt.Errorf("proxy CONNECT returned status %s; close failed: %v", resp.Status, errClose)
		}
		return nil, fmt.Errorf("proxy CONNECT returned status %s", resp.Status)
	}

	if reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: reader}, nil
	}
	return conn, nil
}

func proxyDialAddr(proxyURL *url.URL) string {
	port := proxyURL.Port()
	if port == "" {
		port = "80"
		if proxyURL.Scheme == "https" {
			port = "443"
		}
	}
	return net.JoinHostPort(proxyURL.Hostname(), port)
}

func proxyAuthorization(user *url.Userinfo) string {
	username := user.Username()
	password, _ := user.Password()
	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return "Basic " + encoded
}

// Redact returns a log-safe proxy URL with credentials and path-like data removed.
func Redact(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	parsedURL, errParse := url.Parse(trimmed)
	if errParse != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return "<invalid proxy URL>"
	}

	redacted := &url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
	}
	if parsedURL.User != nil {
		redacted.User = url.User("redacted")
	}
	return redacted.String()
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.reader.Buffered() > 0 {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}

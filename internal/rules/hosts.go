package rules

import (
	"net"
	"net/url"
	"strings"
)

// isLoopback reports whether host only refers to the local machine.
func isLoopback(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// internalSuffixes are DNS suffixes that only resolve inside a private
// network: Kubernetes service names, Docker Desktop's host alias, mDNS and
// the reserved ".internal" TLD.
var internalSuffixes = []string{
	".svc", ".svc.cluster.local", ".cluster.local", ".internal", ".local", ".lan", ".home.arpa",
}

// isInternalHost reports whether traffic to host stays on the local machine
// or a private network: loopback, private/link-local IP ranges, single-label
// names (Docker Compose and Kubernetes service names such as "postgres") and
// internal DNS suffixes.
//
// Rules about plaintext transport skip these hosts. Unencrypted traffic inside
// a private network is still a (smaller) risk; the trade-off is documented in
// the rule docs and in the README limitations.
func isInternalHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || isLoopback(host) {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	if !strings.Contains(host, ".") {
		return true
	}
	for _, suffix := range internalSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// parseURL parses raw and reports whether it has a scheme and host.
func parseURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, false
	}
	return u, true
}

// endpointHost extracts the host from an endpoint written either as a URL
// ("https://collector:4317") or as "host:port" (the OTEL collector format).
func endpointHost(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if strings.Contains(endpoint, "://") {
		if u, ok := parseURL(endpoint); ok {
			return u.Hostname()
		}
		return ""
	}
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return host
	}
	return strings.Trim(strings.SplitN(endpoint, "/", 2)[0], "[]")
}

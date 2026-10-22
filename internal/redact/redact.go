// Package redact masks secret values before anything is printed.
//
// oraclint reads files full of credentials. The invariant is: no secret value
// from a scanned file ever appears in any output (text, JSON, SARIF, logs).
// Rules are written to never put values in messages; this package is the
// second line of defense, applied to every message by the engine.
//
// Two layers:
//  1. Known secrets: the engine registers every secret value it can find in
//     the scanned files (see Collect). Any exact occurrence is masked.
//  2. Patterns: URL credentials, sensitive query parameters, key-like URL path
//     segments and "password=value" style text are masked even if the value
//     was never registered.
package redact

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Mask replaces every secret. It has a fixed length so the output does not
// reveal how long the secret was.
const Mask = "****"

// minSecretLen is the shortest value tracked as a known secret. Masking very
// short strings would mangle ordinary text (for example "1" in "line 1").
// The node itself requires passwords of at least 16 characters.
const minSecretLen = 4

// Redactor masks known secret values and secret-looking patterns.
// The zero value is ready to use.
type Redactor struct {
	secrets []string
	sorted  bool
}

// Add registers a secret value. Short and empty values are ignored.
func (r *Redactor) Add(secret string) {
	secret = strings.TrimSpace(secret)
	if len(secret) < minSecretLen {
		return
	}
	r.secrets = append(r.secrets, secret)
	r.sorted = false
}

// Apply returns s with every known secret and secret-looking pattern masked.
func (r *Redactor) Apply(s string) string {
	if !r.sorted {
		// Longest first, so a secret that contains another one is masked
		// as a whole; ties broken lexically so the result never depends on
		// registration order (which can come from map iteration).
		sort.Slice(r.secrets, func(i, j int) bool {
			a, b := r.secrets[i], r.secrets[j]
			if len(a) != len(b) {
				return len(a) > len(b)
			}
			return a < b
		})
		r.sorted = true
	}
	for _, secret := range r.secrets {
		if len(secret) < wordBoundaryLen {
			s = replaceToken(s, secret)
		} else {
			s = strings.ReplaceAll(s, secret, Mask)
		}
	}
	return Text(s)
}

// wordBoundaryLen: secrets shorter than this are only masked as whole tokens.
// A weak password such as "short" or "pass" would otherwise be masked inside
// ordinary words ("shorter", "Password.Keystore") and garble the message.
// Long secrets are masked anywhere, since they never occur by accident.
const wordBoundaryLen = 8

// replaceToken masks occurrences of secret that are not part of a longer run
// of letters and digits.
func replaceToken(s, secret string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, secret)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		end := i + len(secret)
		bounded := (i == 0 || !isAlnum(s[i-1])) && (end == len(s) || !isAlnum(s[end]))
		b.WriteString(s[:i])
		if bounded {
			b.WriteString(Mask)
		} else {
			b.WriteString(secret)
		}
		s = s[end:]
	}
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

var (
	urlInText = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s'"<>]+`)
	// key=value or key: value where key names a secret.
	assignment = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|apikey|api_key|api-key|credential)[A-Za-z0-9_.-]*)(\s*[=:]\s*)([^\s,;'"&]+)`)
)

// Text masks secret-looking patterns in free text: credentials inside URLs
// and "password=..." style assignments.
func Text(s string) string {
	s = urlInText.ReplaceAllStringFunc(s, URL)
	return assignment.ReplaceAllStringFunc(s, func(m string) string {
		parts := assignment.FindStringSubmatch(m)
		if parts[3] == Mask || isKeyword(parts[3]) {
			return m // already masked, or a boolean such as AllowSimplePasswords = true
		}
		return parts[1] + parts[2] + Mask
	})
}

// isKeyword reports whether s is a boolean or null keyword. Such values are
// never secrets, and masking them would only make messages unreadable.
func isKeyword(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "true", "false", "yes", "no", "on", "off", "null", "none":
		return true
	}
	return false
}

// sensitiveParams are query parameter names whose values are masked.
var sensitiveParams = []string{"password", "passwd", "pwd", "secret", "token", "key", "apikey", "api_key", "api-key", "auth", "sig", "signature", "access_token", "credential"}

// URL masks the password in the userinfo, sensitive query parameter values,
// and path segments that look like API keys (as used by RPC providers that
// put the key in the path, e.g. /v3/<key>).
//
// The URL is rebuilt by hand rather than with url.URL.String so that the rest
// of it is reproduced exactly (url.URL would re-encode characters).
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return maskUserinfo(raw)
	}

	var b strings.Builder
	b.WriteString(u.Scheme)
	b.WriteString("://")
	if u.User != nil {
		b.WriteString(u.User.Username())
		if _, hasPassword := u.User.Password(); hasPassword {
			b.WriteString(":" + Mask)
		}
		b.WriteString("@")
	}
	b.WriteString(u.Host)
	b.WriteString(maskPath(u.EscapedPath()))
	if u.RawQuery != "" {
		b.WriteString("?" + maskQuery(u.RawQuery))
	}
	if u.Fragment != "" {
		b.WriteString("#" + Mask)
	}
	return b.String()
}

var userinfo = regexp.MustCompile(`://([^/@\s:]*):[^/@\s]*@`)

// maskUserinfo is the fallback for strings url.Parse rejects.
func maskUserinfo(raw string) string {
	return userinfo.ReplaceAllString(raw, "://$1:"+Mask+"@")
}

var keyLike = regexp.MustCompile(`^[A-Za-z0-9_-]{20,}$`)

// KeyLikeSegment reports whether a URL path segment looks like an API key:
// at least 20 characters of [A-Za-z0-9_-] including a digit, which matches
// the key formats of common RPC providers (Infura, Alchemy, QuickNode).
func KeyLikeSegment(seg string) bool {
	return keyLike.MatchString(seg) && strings.ContainsAny(seg, "0123456789")
}

func maskPath(path string) string {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if KeyLikeSegment(seg) {
			segments[i] = Mask
		}
	}
	return strings.Join(segments, "/")
}

func maskQuery(rawQuery string) string {
	pairs := strings.Split(rawQuery, "&")
	for i, pair := range pairs {
		name, _, hasValue := strings.Cut(pair, "=")
		if hasValue && SensitiveParam(name) {
			pairs[i] = name + "=" + Mask
		}
	}
	return strings.Join(pairs, "&")
}

// SensitiveParam reports whether a URL query parameter name usually carries
// a credential (key, token, password, signature, ...).
func SensitiveParam(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range sensitiveParams {
		if lower == p || strings.HasSuffix(lower, "_"+p) || strings.HasSuffix(lower, "-"+p) {
			return true
		}
	}
	return false
}

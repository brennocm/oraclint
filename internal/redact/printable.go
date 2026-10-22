package redact

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Printable makes text from scanned files safe to show. Control characters
// (including ESC, which starts terminal escape sequences) and Unicode
// bidirectional overrides ("Trojan Source") are replaced by visible escapes,
// so a malicious file cannot rewrite the terminal, hide output, or make a
// message read differently from what it says.
//
// Bytes that are not valid UTF-8 are escaped too: on 8-bit terminals a lone
// 0x9b byte is a CSI and starts an escape sequence.
func Printable(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, unsafeRune) {
		return s
	}
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[0])
		case unsafeRune(r) && r < 0x80:
			fmt.Fprintf(&b, `\x%02x`, r)
		case unsafeRune(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
		s = s[size:]
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	if unicode.IsControl(r) {
		return true
	}
	switch {
	case r >= 0x202A && r <= 0x202E, // LRE, RLE, PDF, LRO, RLO
		r >= 0x2066 && r <= 0x2069,            // LRI, RLI, FSI, PDI
		r == 0x200E, r == 0x200F, r == 0x061C: // LRM, RLM, ALM
		return true
	}
	return false
}

package redact

import "testing"

func TestPrintable(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain text, \u00fcn\u00efcode ok", "plain text, \u00fcn\u00efcode ok"},
		{"\x1b[2J\x1b[31mPWNED", `\x1b[2J\x1b[31mPWNED`},
		{"line\nbreak\ttab\r", `line\x0abreak\x09tab\x0d`},
		{"admin\u202etxt.exe", `admin\u202etxt.exe`},
		{"next\u0085line", `next\u0085line`},
		{"csi\x9b31m and \xff", `csi\x9b31m and \xff`},
	}
	for _, tc := range tests {
		if got := Printable(tc.in); got != tc.want {
			t.Errorf("Printable(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func FuzzPrintable(f *testing.F) {
	f.Add("\x1b[31mred\u202e")
	f.Fuzz(func(t *testing.T, s string) {
		out := Printable(s)
		for _, r := range out {
			if unsafeRune(r) || r == 0xfffd && !containsRune(s, 0xfffd) {
				t.Fatalf("unsafe rune %U left in %q", r, out)
			}
		}
	})
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

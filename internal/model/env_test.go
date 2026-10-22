package model

import (
	"strings"
	"testing"
)

func TestParseEnv(t *testing.T) {
	src := "# comment\n" +
		"\n" +
		"CL_DATABASE_URL=postgresql://u:p@db:5432/cl\n" +
		"export CL_PASSWORD_KEYSTORE='quoted value' # trailing\n" +
		"EMPTY=\n" +
		"SPACED = \"double\"\n" +
		"INLINE=abc #comment\n" +
		"not an assignment\n" +
		"1BAD=x\n" +
		"HASH=abc#notcomment\n"

	vars, err := ParseEnv(".env", []byte(src))
	if err != nil {
		t.Fatalf("ParseEnv: %v", err)
	}
	want := []EnvVar{
		{Name: "CL_DATABASE_URL", Value: "postgresql://u:p@db:5432/cl", Loc: Location{File: ".env", Line: 3, Column: 1}},
		{Name: "CL_PASSWORD_KEYSTORE", Value: "quoted value", Loc: Location{File: ".env", Line: 4, Column: 1}},
		{Name: "EMPTY", Value: "", Loc: Location{File: ".env", Line: 5, Column: 1}},
		{Name: "SPACED", Value: "double", Loc: Location{File: ".env", Line: 6, Column: 1}},
		{Name: "INLINE", Value: "abc", Loc: Location{File: ".env", Line: 7, Column: 1}},
		{Name: "HASH", Value: "abc#notcomment", Loc: Location{File: ".env", Line: 10, Column: 1}},
	}
	if len(vars) != len(want) {
		t.Fatalf("got %d vars, want %d: %+v", len(vars), len(want), vars)
	}
	for i := range want {
		if vars[i] != want[i] {
			t.Errorf("var %d = %+v, want %+v", i, vars[i], want[i])
		}
	}
}

func TestParseEnvEdgeCases(t *testing.T) {
	if vars, err := ParseEnv(".env", nil); err != nil || len(vars) != 0 {
		t.Errorf("empty file: %v %v", vars, err)
	}
	vars, err := ParseEnv(".env", []byte("\xEF\xBB\xBFA='unterminated\r\n"))
	if err != nil || len(vars) != 1 || vars[0].Name != "A" || vars[0].Value != "unterminated\r" && vars[0].Value != "unterminated" {
		t.Errorf("BOM/unterminated: %+v %v", vars, err)
	}
	long := "A=" + strings.Repeat("x", maxEnvLine+10)
	if _, err := ParseEnv(".env", []byte(long)); err == nil {
		t.Error("expected error for over-long line")
	}
}

func FuzzParseEnv(f *testing.F) {
	f.Add([]byte("A=1\nexport B='x'\n#c\nC=\"y\" # z\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		vars, err := ParseEnv(".env", data)
		if err != nil {
			return
		}
		for _, v := range vars {
			if v.Name == "" || v.Loc.Line < 1 {
				t.Fatalf("invalid var %+v", v)
			}
		}
	})
}

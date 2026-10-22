package model

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// MatchPath reports whether file matches pattern, as used by .oraclint.yaml
// "ignore" and "exclude" entries and the --exclude flag. Supported patterns:
// an exact path, a path.Match glob ("*" stays within one directory), and
// "dir/**" for dir and everything below it.
//
// Patterns are relative to the working directory. An absolute file path is
// also tried relative to the working directory, so "oraclint scan $PWD"
// honors the same patterns as "oraclint scan .".
func MatchPath(pattern, file string) bool {
	pattern = path.Clean(filepath.ToSlash(pattern))
	for _, candidate := range pathForms(file) {
		if matchOne(pattern, candidate) {
			return true
		}
	}
	return false
}

func matchOne(pattern, file string) bool {
	if dir, ok := strings.CutSuffix(pattern, "/**"); ok {
		return dir == "**" || file == dir || strings.HasPrefix(file, dir+"/")
	}
	ok, err := path.Match(pattern, file)
	return err == nil && ok
}

// pathForms returns file cleaned with forward slashes and, when it is
// absolute and below the working directory, also relative to it.
func pathForms(file string) []string {
	forms := []string{path.Clean(filepath.ToSlash(file))}
	if !filepath.IsAbs(file) {
		return forms
	}
	cwd, err := os.Getwd()
	if err != nil {
		return forms
	}
	rel, err := filepath.Rel(cwd, file)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return forms
	}
	return append(forms, filepath.ToSlash(rel))
}

// ValidPattern reports whether pattern is a usable path pattern.
func ValidPattern(pattern string) bool {
	_, err := path.Match(strings.TrimSuffix(pattern, "/**"), "")
	return err == nil && strings.TrimSpace(pattern) != ""
}

// Package loader finds the files to scan, decides what kind of file each one
// is, and parses them into model.Targets.
package loader

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// DefaultMaxFileSize is the largest file oraclint reads. Node configuration
// files are a few kilobytes; anything bigger is almost certainly not one, and
// the limit bounds memory use on hostile input.
const DefaultMaxFileSize = 5 << 20 // 5 MiB

// Options control discovery. The Config/Secrets/Compose/K8s/Env lists force a
// file's kind when the name-based heuristics are not enough.
type Options struct {
	MaxFileSize int64
	Config      []string // merged in order, like `chainlink node -config a -config b`
	Secrets     []string
	Compose     []string
	K8s         []string
	Env         []string
	Logger      *slog.Logger
}

// Result is everything the loader produced.
type Result struct {
	Targets []*model.Target
	// Problems are files that look relevant but could not be scanned (parse
	// errors, size limit). They are reported as findings, never dropped
	// silently: a skipped file would be a silent false negative.
	Problems []*model.ParseError
}

// Load scans the given paths (files or directories) plus any forced files.
// It returns an error only for problems with the invocation itself, such as a
// path that does not exist.
func Load(paths []string, opts Options) (*Result, error) {
	l := &loader{opts: opts, seen: map[string]bool{}, res: &Result{}}
	if l.opts.MaxFileSize <= 0 {
		l.opts.MaxFileSize = DefaultMaxFileSize
	}
	if l.opts.Logger == nil {
		l.opts.Logger = slog.New(slog.DiscardHandler)
	}

	if err := l.loadForced(); err != nil {
		return nil, err
	}
	for _, p := range paths {
		if err := l.loadPath(p); err != nil {
			return nil, err
		}
	}

	sort.SliceStable(l.res.Targets, func(i, j int) bool { return l.res.Targets[i].Path < l.res.Targets[j].Path })
	sort.SliceStable(l.res.Problems, func(i, j int) bool { return l.res.Problems[i].Loc.File < l.res.Problems[j].Loc.File })
	return l.res, nil
}

type loader struct {
	opts Options
	seen map[string]bool // absolute paths already handled
	res  *Result
}

func (l *loader) loadForced() error {
	if len(l.opts.Config) > 0 {
		if err := l.loadMergedConfig(l.opts.Config); err != nil {
			return err
		}
	}
	forced := []struct {
		kind  model.Kind
		files []string
	}{
		{model.KindSecrets, l.opts.Secrets},
		{model.KindCompose, l.opts.Compose},
		{model.KindK8s, l.opts.K8s},
		{model.KindEnv, l.opts.Env},
	}
	for _, f := range forced {
		for _, path := range f.files {
			if err := l.requireRegularFile(path); err != nil {
				return err
			}
			l.markSeen(path)
			l.loadFile(path, forcedClass(f.kind))
		}
	}
	return nil
}

// loadMergedConfig parses several config files and merges them into a single
// target, mirroring the node's override semantics (see model.Merge).
func (l *loader) loadMergedConfig(paths []string) error {
	var roots []*model.Value
	var files []string
	for _, path := range paths {
		if err := l.requireRegularFile(path); err != nil {
			return err
		}
		l.markSeen(path)
		display := displayPath(path)
		data, ok := l.read(path, display, true)
		if !ok {
			continue
		}
		root, err := model.ParseTOML(display, data)
		if err != nil {
			l.problem(err, display)
			continue
		}
		roots = append(roots, root)
		files = append(files, display)
	}
	if len(roots) == 0 {
		return nil
	}
	t := &model.Target{
		Kind:  model.KindConfig,
		Path:  files[0],
		Files: files,
		TOML:  &model.TOMLDoc{Kind: model.KindConfig, Root: model.Merge(roots...)},
	}
	if len(files) == 1 {
		t.Mode = l.mode(paths[0])
	}
	l.res.Targets = append(l.res.Targets, t)
	return nil
}

func (l *loader) loadPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot scan %s: %w", path, err)
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("cannot scan %s: not a regular file", path)
		}
		if l.markSeen(path) {
			l.loadFile(path, classifyByName(filepath.Base(path)))
		}
		return nil
	}
	return l.walk(path)
}

func (l *loader) walk(root string) error {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("cannot resolve %s: %w", root, err)
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			l.opts.Logger.Warn("skipping unreadable path", "path", path, "error", walkErr)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		c := classifyByName(d.Name())
		if c.format == formatNone {
			return nil // not a file type oraclint looks at
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if !l.symlinkInside(path, realRoot) {
				return nil
			}
		} else if !d.Type().IsRegular() {
			return nil
		}
		if l.markSeen(path) {
			l.loadFile(path, c)
		}
		return nil
	})
}

// symlinkInside reports whether a symlink resolves to a regular file inside
// the scan root. Links that escape the root are skipped so a malicious
// repository cannot make oraclint read (and possibly echo) files such as
// ~/.ssh/id_rsa or /etc/shadow.
func (l *loader) symlinkInside(path, realRoot string) bool {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		l.opts.Logger.Debug("skipping broken symlink", "path", path)
		return false
	}
	rel, err := filepath.Rel(realRoot, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		l.opts.Logger.Warn("skipping symlink that points outside the scan root", "path", path)
		return false
	}
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return true
}

// loadFile parses one file according to its class. For strong classes (file
// name or flag) parse errors are reported. For files picked only by extension
// (any *.toml, *.yaml) they are logged and ignored, because such files are
// usually not node files at all (for example Helm templates).
func (l *loader) loadFile(path string, c class) {
	if c.format == formatNone {
		l.opts.Logger.Debug("skipping file of unknown type", "path", path)
		return
	}
	display := displayPath(path)
	data, ok := l.read(path, display, c.strong)
	if !ok {
		return
	}
	t := &model.Target{Kind: c.kind, Path: display, Files: []string{display}, Mode: l.mode(path)}

	switch c.format {
	case formatTOML:
		root, err := model.ParseTOML(display, data)
		if err != nil {
			l.parseFailed(err, display, c.strong)
			return
		}
		if t.Kind == 0 {
			t.Kind = classifyTOML(filepath.Base(path), root)
		}
		if t.Kind == 0 {
			l.opts.Logger.Debug("skipping TOML file that is not a node config", "path", display)
			return
		}
		t.TOML = &model.TOMLDoc{Kind: t.Kind, Root: root}

	case formatYAML:
		// Helm/Go templates are not supported in v1: their YAML is only
		// meaningful after rendering, so a weakly classified file containing
		// template actions is skipped instead of being misread.
		if !c.strong && bytes.Contains(data, []byte("{{")) {
			l.opts.Logger.Debug("skipping templated YAML file", "path", display)
			return
		}
		docs, err := model.ParseYAML(display, data)
		if err != nil {
			l.parseFailed(err, display, c.strong)
			return
		}
		if t.Kind == 0 && looksLikeK8s(docs) {
			t.Kind = model.KindK8s
		}
		if t.Kind == 0 {
			l.opts.Logger.Debug("skipping YAML file that is not a Kubernetes manifest", "path", display)
			return
		}
		t.YAML = docs

	case formatEnv:
		vars, err := model.ParseEnv(display, data)
		if err != nil {
			l.parseFailed(err, display, c.strong)
			return
		}
		t.Env = vars
	}
	l.res.Targets = append(l.res.Targets, t)
}

// read returns the file content, enforcing the size limit. Oversized files
// that look relevant are reported as problems.
func (l *loader) read(path, display string, report bool) ([]byte, bool) {
	f, err := os.Open(path) //nolint:gosec // reading user-selected files is the purpose of this tool
	if err != nil {
		l.problem(&model.ParseError{Loc: model.Location{File: display}, Msg: "cannot read file"}, display)
		return nil, false
	}
	defer f.Close() //nolint:errcheck // read-only file; Close cannot lose data

	// Read at most one byte more than the limit, so we can tell "exactly at
	// the limit" from "too big" without trusting Stat (the file may change).
	data, err := io.ReadAll(io.LimitReader(f, l.opts.MaxFileSize+1))
	if err != nil {
		l.problem(&model.ParseError{Loc: model.Location{File: display}, Msg: "cannot read file"}, display)
		return nil, false
	}
	if int64(len(data)) > l.opts.MaxFileSize {
		msg := fmt.Sprintf("file is larger than %d bytes and was not scanned", l.opts.MaxFileSize)
		if report {
			l.problem(&model.ParseError{Loc: model.Location{File: display}, Msg: msg}, display)
		} else {
			l.opts.Logger.Warn("skipping large file", "path", display)
		}
		return nil, false
	}
	return data, true
}

func (l *loader) parseFailed(err error, display string, report bool) {
	if report {
		l.problem(err, display)
		return
	}
	l.opts.Logger.Debug("skipping unparsable file", "path", display)
}

func (l *loader) problem(err error, display string) {
	var pe *model.ParseError
	if !errors.As(err, &pe) {
		pe = &model.ParseError{Loc: model.Location{File: display}, Msg: "cannot parse file"}
	}
	l.res.Problems = append(l.res.Problems, pe)
}

func (l *loader) mode(path string) fs.FileMode {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Mode().Perm()
}

// markSeen records path and reports whether it was new.
func (l *loader) markSeen(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if l.seen[abs] {
		return false
	}
	l.seen[abs] = true
	return true
}

func (l *loader) requireRegularFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("cannot read %s: not a regular file", path)
	}
	return nil
}

// displayPath is the path shown in findings: cleaned, with forward slashes,
// as the user wrote it (relative paths stay relative).
func displayPath(path string) string {
	return filepath.ToSlash(filepath.Clean(path))
}

func skipDir(name string) bool {
	return name == ".git" || name == "node_modules"
}

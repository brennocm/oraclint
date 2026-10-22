// Package loader finds the files to scan, decides what kind of file each one
// is, and parses them into model.Targets.
package loader

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"

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
			l.loadFile(openPath(path), displayPath(path), forcedClass(f.kind))
		}
	}
	return nil
}

// loadMergedConfig parses several config files and merges them into a single
// target, mirroring the node's override semantics (see model.Merge).
func (l *loader) loadMergedConfig(paths []string) error {
	var roots []*model.Value
	var files []string
	var directives []model.Directive
	var modes []fs.FileMode
	for _, path := range paths {
		if err := l.requireRegularFile(path); err != nil {
			return err
		}
		l.markSeen(path)
		display := displayPath(path)
		data, mode, ok := l.read(openPath(path), display, true)
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
		modes = append(modes, mode)
		directives = append(directives, model.ParseDirectives(display, data)...)
	}
	if len(roots) == 0 {
		return nil
	}
	t := &model.Target{
		Kind:       model.KindConfig,
		Path:       files[0],
		Files:      files,
		TOML:       &model.TOMLDoc{Kind: model.KindConfig, Root: model.Merge(roots...)},
		Directives: directives,
	}
	if len(files) == 1 {
		t.Mode = modes[0]
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
			c := classifyByName(filepath.Base(path))
			c.strong, c.explicit = true, true
			l.loadFile(openPath(path), displayPath(path), c)
		}
		return nil
	}
	return l.walk(path)
}

// walk scans a directory through an os.Root. Every open is resolved by the
// kernel relative to the root and may not leave it, even through symlinks or
// ".." components, and even if the tree changes during the scan (no
// check-then-open race). A malicious repository therefore cannot make
// oraclint read files such as ~/.ssh/id_rsa or /etc/shadow.
func (l *loader) walk(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("cannot scan %s: %w", dir, err)
	}
	defer root.Close() //nolint:errcheck // read-only directory handle

	return fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, walkErr error) error {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if walkErr != nil {
			l.opts.Logger.Warn("skipping unreadable path", "path", path, "error", walkErr)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if rel != "." && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		c := classifyByName(d.Name())
		if c.format == formatNone {
			return nil // not a file type oraclint looks at
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// Root.Stat follows the link but fails if it leaves the root.
			info, err := root.Stat(rel)
			if err != nil {
				l.opts.Logger.Warn("skipping symlink that is broken or points outside the scan root", "path", path)
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
		} else if !d.Type().IsRegular() {
			return nil // sockets, FIFOs, devices
		}
		if l.markSeen(path) {
			l.loadFile(func() (*os.File, error) { return root.Open(rel) }, displayPath(path), c)
		}
		return nil
	})
}

// opener opens the file to read. It abstracts over plain paths (files named
// on the command line) and os.Root-relative paths (files found by walk).
type opener func() (*os.File, error)

func openPath(path string) opener {
	return func() (*os.File, error) {
		return os.Open(path) //nolint:gosec // reading user-selected files is the purpose of this tool
	}
}

// loadFile parses one file according to its class. For strong classes (file
// name or flag) parse errors are reported. For files picked only by extension
// (any *.toml, *.yaml) they are logged and ignored, because such files are
// usually not node files at all (for example Helm templates).
func (l *loader) loadFile(open opener, display string, c class) {
	if c.format == formatNone {
		l.notRecognized(display, c)
		return
	}
	data, mode, ok := l.read(open, display, c.strong)
	if !ok {
		return
	}
	t := &model.Target{
		Kind: c.kind, Path: display, Files: []string{display}, Mode: mode,
		Directives: model.ParseDirectives(display, data),
	}

	switch c.format {
	case formatTOML:
		root, err := model.ParseTOML(display, data)
		if err != nil {
			l.parseFailed(err, display, c.strong)
			return
		}
		if t.Kind == 0 {
			t.Kind = classifyTOML(path.Base(display), root)
		}
		if t.Kind == 0 {
			l.notRecognized(display, c)
			return
		}
		t.TOML = &model.TOMLDoc{Kind: t.Kind, Root: root}

	case formatYAML:
		// Helm/Go templates are not supported in v1: their YAML is only
		// meaningful after rendering, so a weakly classified template is
		// skipped instead of being misread.
		if !c.strong && isGoTemplate(data) {
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
			l.notRecognized(display, c)
			return
		}
		t.YAML = docs
		// Reported even for weakly classified files: once a file is known to
		// be a compose file or manifest, an ambiguous value is an evasion risk.
		l.res.Problems = append(l.res.Problems, model.DuplicateKeys(display, docs)...)

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

// read returns the file content and permission bits, enforcing the size
// limit. Oversized files that look relevant are reported as problems. The
// mode comes from the open descriptor, so it describes the file actually read.
func (l *loader) read(open opener, display string, report bool) ([]byte, fs.FileMode, bool) {
	cannotRead := &model.ParseError{Loc: model.Location{File: display}, Msg: "cannot read file"}
	f, err := open()
	if err != nil {
		l.problem(cannotRead, display)
		return nil, 0, false
	}
	defer f.Close() //nolint:errcheck // read-only file; Close cannot lose data

	var mode fs.FileMode
	if info, err := f.Stat(); err == nil {
		mode = info.Mode().Perm()
	}

	// Read at most one byte more than the limit, so we can tell "exactly at
	// the limit" from "too big" without trusting Stat (the file may change).
	data, err := io.ReadAll(io.LimitReader(f, l.opts.MaxFileSize+1))
	if err != nil {
		l.problem(cannotRead, display)
		return nil, 0, false
	}
	if int64(len(data)) > l.opts.MaxFileSize {
		msg := fmt.Sprintf("file is larger than %d bytes and was not scanned", l.opts.MaxFileSize)
		if report {
			l.problem(&model.ParseError{Loc: model.Location{File: display}, Msg: msg}, display)
		} else {
			l.opts.Logger.Warn("skipping large file", "path", display)
		}
		return nil, 0, false
	}
	return data, mode, true
}

// templateAction matches Go template actions where Helm puts them: at the
// start of a line ("{{- if ...}}") or as an unquoted YAML value or list item
// ("image: {{ .Values.image }}", "- {{ .Values.x }}"). "{{" inside quoted
// strings or block text, as in Prometheus or Alertmanager rules stored in a
// ConfigMap, does not count: those files are real manifests.
var templateAction = regexp.MustCompile(`(?m)^\s*(?:-\s+)?(?:[^\s:#'"]+:\s+)?\{\{`)

func isGoTemplate(data []byte) bool {
	return templateAction.Match(data)
}

// notRecognized handles a file that turned out not to be a node file. Files
// found while walking are skipped quietly; a file the user named explicitly
// is reported, because skipping it would look like a clean result.
func (l *loader) notRecognized(display string, c class) {
	if !c.explicit {
		l.opts.Logger.Debug("skipping file that is not a node file", "path", display)
		return
	}
	l.res.Problems = append(l.res.Problems, &model.ParseError{
		Loc: model.Location{File: display},
		Msg: "not recognized as a node config, secrets, compose, Kubernetes or dotenv file; pass it with --config, --secrets, --compose, --k8s or --env",
	})
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

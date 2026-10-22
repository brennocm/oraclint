package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/brennocm/oraclint/internal/engine"
	"github.com/brennocm/oraclint/internal/loader"
	"github.com/brennocm/oraclint/internal/report"
	"github.com/brennocm/oraclint/internal/rules"
	"github.com/brennocm/oraclint/internal/suppress"
)

type scanFlags struct {
	format       string
	output       string
	minSeverity  string
	failOn       string
	enable       []string
	disable      []string
	experimental bool
	noColor      bool
	configFile   string
	quiet        bool
	verbose      bool

	config  []string
	secrets []string
	compose []string
	k8s     []string
	env     []string
}

func newScanCommand(info BuildInfo) *cobra.Command {
	var f scanFlags
	cmd := &cobra.Command{
		Use:   "scan [paths...]",
		Short: "Scan files and directories for insecure node configuration",
		Long: "Scan files and directories (default: the current directory) for insecure\n" +
			"Chainlink node configuration.\n\n" +
			"Exit codes: 0 no findings at or above --fail-on, 1 findings at or above\n" +
			"--fail-on, 2 usage or runtime error.",
		Example: "  oraclint scan .\n" +
			"  oraclint scan --format sarif --output oraclint.sarif deploy/\n" +
			"  oraclint scan --config base.toml --config prod.toml --secrets secrets.toml",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, info, f, args)
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.format, "format", "f", report.FormatText, "output format: text, json or sarif")
	fl.StringVarP(&f.output, "output", "o", "", "write the report to this file instead of stdout")
	fl.StringVar(&f.minSeverity, "min-severity", "info", "hide findings below this severity")
	fl.StringVar(&f.failOn, "fail-on", "low", "exit 1 if a finding has at least this severity (or \"none\")")
	fl.StringSliceVar(&f.enable, "enable", nil, "rule IDs to run even if experimental (comma-separated)")
	fl.StringSliceVar(&f.disable, "disable", nil, "rule IDs not to run (comma-separated)")
	fl.BoolVar(&f.experimental, "experimental", false, "also run experimental rules")
	fl.BoolVar(&f.noColor, "no-color", false, "disable colored output (also honored: NO_COLOR)")
	fl.StringVar(&f.configFile, "config-file", "", "oraclint configuration file (default: ./"+suppress.DefaultConfigFile+" if present)")
	fl.BoolVarP(&f.quiet, "quiet", "q", false, "print findings only, no summary or warnings")
	fl.BoolVarP(&f.verbose, "verbose", "v", false, "log debug information to stderr")
	fl.StringArrayVar(&f.config, "config", nil, "node config file; repeat to merge several in order, like the node")
	fl.StringArrayVar(&f.secrets, "secrets", nil, "treat this file as a node secrets.toml")
	fl.StringArrayVar(&f.compose, "compose", nil, "treat this file as a docker-compose file")
	fl.StringArrayVar(&f.k8s, "k8s", nil, "treat this file as Kubernetes manifests")
	fl.StringArrayVar(&f.env, "env", nil, "treat this file as a dotenv file")
	return cmd
}

func runScan(cmd *cobra.Command, info BuildInfo, f scanFlags, paths []string) error {
	opts, failOn, err := engineOptions(f)
	if err != nil {
		return err
	}
	if !isFormat(f.format) {
		return fmt.Errorf("unknown format %q (want text, json or sarif)", f.format)
	}

	logger := newLogger(cmd.ErrOrStderr(), f)
	if len(paths) == 0 && len(f.config)+len(f.secrets)+len(f.compose)+len(f.k8s)+len(f.env) == 0 {
		paths = []string{"."}
	}
	res, err := loader.Load(paths, loader.Options{
		Config: f.config, Secrets: f.secrets, Compose: f.compose, K8s: f.k8s, Env: f.env,
		Logger: logger,
	})
	if err != nil {
		return err
	}

	all := rules.All()
	findings := engine.Run(res.Targets, res.Problems, all, opts)

	var ran []rules.Metadata
	for _, r := range engine.Select(all, opts) {
		ran = append(ran, r.Metadata())
	}
	files := 0
	for _, t := range res.Targets {
		files += len(t.Files)
	}
	cwd, err := os.Getwd()
	if err != nil {
		cwd = ""
	}
	rep := report.Report{ToolVersion: info.Version, Rules: ran, Findings: findings, FilesScanned: files, BaseDir: cwd}
	if err := writeReport(cmd, f, rep); err != nil {
		return err
	}

	if failOn != 0 {
		for _, fd := range findings {
			if fd.Suppression == nil && fd.Severity >= failOn {
				return errFindings
			}
		}
	}
	return nil
}

// engineOptions turns flags and the config file into engine options and the
// --fail-on threshold (0 means never fail).
func engineOptions(f scanFlags) (engine.Options, rules.Severity, error) {
	var opts engine.Options
	minSev, err := rules.ParseSeverity(f.minSeverity)
	if err != nil {
		return opts, 0, fmt.Errorf("--min-severity: %w", err)
	}
	var failOn rules.Severity
	if !strings.EqualFold(f.failOn, "none") {
		if failOn, err = rules.ParseSeverity(f.failOn); err != nil {
			return opts, 0, fmt.Errorf("--fail-on: %w", err)
		}
	}

	known := func(id string) bool { _, ok := rules.ByID(id); return ok }
	cfg, err := loadConfigFile(f.configFile, known)
	if err != nil {
		return opts, 0, err
	}

	opts = engine.Options{
		MinSeverity:  minSev,
		Experimental: f.experimental,
		Enable:       map[string]bool{},
		Disable:      cfg.DisabledRules(),
		Suppressions: cfg,
	}
	for _, flag := range []struct {
		name string
		ids  []string
		set  map[string]bool
	}{{"--enable", f.enable, opts.Enable}, {"--disable", f.disable, opts.Disable}} {
		for _, id := range flag.ids {
			id = strings.ToUpper(strings.TrimSpace(id))
			if !known(id) {
				return opts, 0, fmt.Errorf("%s: unknown rule %q (see `oraclint rules list`)", flag.name, id)
			}
			flag.set[id] = true
		}
	}
	return opts, failOn, nil
}

// loadConfigFile reads --config-file, or ./.oraclint.yaml when it exists.
// It returns nil when there is no config.
func loadConfigFile(path string, known func(string) bool) (*suppress.Config, error) {
	if path == "" {
		if _, err := os.Stat(suppress.DefaultConfigFile); errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		path = suppress.DefaultConfigFile
	}
	return suppress.LoadConfig(path, known)
}

// writeReport renders into memory first, so a failure never leaves a
// half-written output file behind.
func writeReport(cmd *cobra.Command, f scanFlags, rep report.Report) error {
	var buf bytes.Buffer
	out := cmd.OutOrStdout()
	color := f.output == "" && useColor(out, f.noColor)
	if err := report.Write(&buf, f.format, rep, report.Options{Color: color, Quiet: f.quiet}); err != nil {
		return err
	}
	if f.output != "" {
		// 0600: a findings report maps the weak spots of the deployment.
		if err := os.WriteFile(f.output, buf.Bytes(), 0o600); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
		return nil
	}
	_, err := out.Write(buf.Bytes())
	return err
}

func isFormat(s string) bool {
	return s == report.FormatText || s == report.FormatJSON || s == report.FormatSARIF
}

// useColor enables ANSI colors only for a terminal, unless disabled by flag
// or by the NO_COLOR convention (https://no-color.org).
func useColor(w io.Writer, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func newLogger(w io.Writer, f scanFlags) *slog.Logger {
	level := slog.LevelWarn
	switch {
	case f.verbose:
		level = slog.LevelDebug
	case f.quiet:
		level = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

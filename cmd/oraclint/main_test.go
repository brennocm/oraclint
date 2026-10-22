package main

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/brennocm/oraclint/internal/cli"
)

// TestMain lets testscript run the oraclint CLI in-process as the "oraclint"
// command, without building a separate binary.
func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"oraclint": func() {
			os.Exit(cli.Execute(cli.BuildInfo{Version: "v0.0.0-test", Commit: "abc1234", Date: "2026-01-01"}))
		},
	})
}

// TestScripts runs the end-to-end scenarios in testdata/script/*.txtar.
func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "../../testdata/script",
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"exitcode": exitCode,
		},
	})
}

// exitCode runs a command and asserts its exact exit code:
//
//	exitcode 1 oraclint scan .
//
// testscript's own "! exec" only checks for failure, but the difference
// between 1 (findings) and 2 (error) is part of oraclint's contract.
func exitCode(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) < 2 {
		ts.Fatalf("usage: exitcode <code> <command> [args...]")
	}
	want, err := strconv.Atoi(args[0])
	if err != nil {
		ts.Fatalf("invalid exit code %q", args[0])
	}
	got := 0
	if err := ts.Exec(args[1], args[2:]...); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			ts.Fatalf("running %s: %v", args[1], err)
		}
		got = exitErr.ExitCode()
	}
	if got != want {
		ts.Fatalf("exit code = %d, want %d", got, want)
	}
}

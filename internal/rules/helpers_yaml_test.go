package rules

import (
	"testing"

	"github.com/brennocm/oraclint/internal/model"
)

func yamlTarget(t *testing.T, kind model.Kind, src string) *model.Target {
	t.Helper()
	file := kind.String() + ".yaml"
	docs, err := model.ParseYAML(file, []byte(src))
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return &model.Target{Kind: kind, Path: file, Files: []string{file}, YAML: docs}
}

func compose(src string) func(t *testing.T) *model.Target {
	return func(t *testing.T) *model.Target { t.Helper(); return yamlTarget(t, model.KindCompose, src) }
}

func k8s(src string) func(t *testing.T) *model.Target {
	return func(t *testing.T) *model.Target { t.Helper(); return yamlTarget(t, model.KindK8s, src) }
}

func dotenv(src string) func(t *testing.T) *model.Target {
	return func(t *testing.T) *model.Target {
		t.Helper()
		vars, err := model.ParseEnv(".env", []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		return &model.Target{Kind: model.KindEnv, Path: ".env", Files: []string{".env"}, Env: vars}
	}
}

func TestEnvAssignments(t *testing.T) {
	src := `services:
  node:
    environment:
      CL_PASSWORD_KEYSTORE: literal-value-1
      CL_DATABASE_URL: ${DATABASE_URL}
      PASS_THROUGH:
  db:
    environment:
      - POSTGRES_PASSWORD=literal-2
      - POSTGRES_USER
      - TOKEN=$OTHER
`
	got := envAssignments(yamlTarget(t, model.KindCompose, src))
	want := []struct {
		name    string
		literal bool
		line    int
	}{
		{"CL_PASSWORD_KEYSTORE", true, 4},
		{"CL_DATABASE_URL", false, 5},
		{"PASS_THROUGH", false, 6},
		{"POSTGRES_PASSWORD", true, 9},
		{"POSTGRES_USER", false, 10},
		{"TOKEN", false, 11},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d assignments: %+v", len(got), got)
	}
	for i, w := range want {
		if got[i].Name != w.name || got[i].Literal != w.literal || got[i].Loc.Line != w.line {
			t.Errorf("assignment %d = %+v, want %+v", i, got[i], w)
		}
	}

	k := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: node
spec:
  template:
    spec:
      initContainers:
      - name: init
        env:
        - name: A
          value: x
      containers:
      - name: node
        env:
        - name: CL_PASSWORD_KEYSTORE
          valueFrom:
            secretKeyRef: {name: s, key: k}
        - name: B
          value: "y"
`
	got = envAssignments(yamlTarget(t, model.KindK8s, k))
	if len(got) != 3 || !got[0].Literal || got[1].Literal || got[1].Name != "CL_PASSWORD_KEYSTORE" || !got[2].Literal {
		t.Errorf("k8s assignments = %+v", got)
	}
	if envAssignments(&model.Target{Kind: model.KindConfig}) != nil {
		t.Error("config targets have no env assignments")
	}
	if !envTrue("TRUE") || envTrue("1") || envTrue("yes") {
		t.Error("envTrue must match the node: only \"true\", case-insensitive")
	}
}

func TestComposeValue(t *testing.T) {
	tests := []struct {
		raw, value string
		literal    bool
	}{
		{"plain", "plain", true},
		{"pa$$word", "pa$word", true},
		{"${KS}", "${KS}", false},
		{"$KS", "$KS", false},
		{"${KS:-changeme}", "changeme", true},
		{"${KS-changeme}", "changeme", true},
		{"${KS:-}", "${KS:-}", false},
		{"${KS:?required}", "${KS:?required}", false},
		{"${KS:-${OTHER}}", "${KS:-${OTHER}}", false},
		{"postgresql://u:${PG}@db/x", "postgresql://u:${PG}@db/x", false},
	}
	for _, tc := range tests {
		value, literal := composeValue(tc.raw)
		if value != tc.value || literal != tc.literal {
			t.Errorf("composeValue(%q) = %q, %v; want %q, %v", tc.raw, value, literal, tc.value, tc.literal)
		}
	}
}

func TestPodSpecs(t *testing.T) {
	src := `apiVersion: v1
kind: Pod
metadata: {name: p}
spec: {containers: [{name: a}]}
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: c}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers: [{name: b}]
---
apiVersion: v1
kind: ConfigMap
metadata: {name: cm}
`
	pods := podSpecs(yamlTarget(t, model.KindK8s, src))
	if len(pods) != 2 || pods[1].Kind != "CronJob" || pods[1].containers()[0].Name != "b" {
		t.Errorf("podSpecs = %+v", pods)
	}
}

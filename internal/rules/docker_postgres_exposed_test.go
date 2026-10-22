package rules

import "testing"

func TestDockerPostgresExposed(t *testing.T) {
	runRuleCases(t, dockerPostgresExposed{}, []ruleCase{
		{"published", compose("services:\n  db:\n    image: postgres:16\n    ports:\n      - \"5432:5432\"\n"), []int{5}},
		{"different host port", compose("services:\n  db:\n    image: docker.io/library/postgres:16\n    ports: ['15432:5432']\n"), []int{4}},
		{"loopback", compose("services:\n  db:\n    image: postgres:16\n    ports: ['127.0.0.1:5432:5432']\n"), nil},
		{"not published", compose("services:\n  db:\n    image: postgres:16\n    expose: ['5432']\n"), nil},
		{"not postgres", compose("services:\n  redis:\n    image: redis:7\n    ports: ['5432:6379']\n"), nil},
	})
}

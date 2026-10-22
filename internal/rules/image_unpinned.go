package rules

import (
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/brennocm/oraclint/internal/model"
)

// imageUnpinned flags images without a fixed version: no tag (which means
// latest) or the latest tag, and no digest. Every pull may then run different
// code, including an untested node release or a compromised image. The node
// docs also state that the latest tag "does not work" for the node image.
type imageUnpinned struct{}

func (imageUnpinned) Metadata() Metadata {
	return Metadata{
		ID:          "NS-IMG-001",
		Title:       "Container image not pinned",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindCompose, model.KindK8s},
		Status:      Stable,
		Remediation: "Pin an explicit version tag, ideally with a digest: smartcontract/chainlink:2.69.0@sha256:<digest>.",
		References:  []string{refRunningNode},
		CWE:         []string{"CWE-1357", "CWE-494"},
	}
}

func (r imageUnpinned) Check(t *model.Target) []Finding {
	var out []Finding
	check := func(owner string, node *yaml.Node) {
		ref, ok := model.ScalarString(node)
		if !ok || ref == "" || strings.Contains(ref, "$") {
			return // missing, or interpolated: cannot judge
		}
		tag, digest := imageTag(ref)
		if digest || (tag != "" && tag != "latest") {
			return
		}
		out = append(out, newFinding(r.Metadata(), model.YAMLLocation(t.Path, node),
			"%s uses image %q without a fixed version", owner, ref))
	}

	switch t.Kind {
	case model.KindCompose:
		for _, svc := range composeServices(t) {
			check("service \""+svc.Name+"\"", model.MapValue(svc.Node, "image"))
		}
	case model.KindK8s:
		for _, pod := range podSpecs(t) {
			for _, c := range pod.containers() {
				check(pod.Kind+" \""+pod.Name+"\" container \""+c.Name+"\"", model.MapValue(c.Node, "image"))
			}
		}
	}
	return out
}

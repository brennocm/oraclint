package rules

import (
	"go.yaml.in/yaml/v3"

	"github.com/brennocm/oraclint/internal/model"
)

// podSpec is the pod template of a Kubernetes workload, with the workload's
// kind and name for messages.
type podSpec struct {
	Kind string
	Name string
	Spec *yaml.Node
}

// podSpecs returns the pod spec of every workload in a manifest stream.
func podSpecs(t *model.Target) []podSpec {
	var out []podSpec
	for _, doc := range t.YAML {
		kind, _ := model.ScalarString(model.MapValue(doc, "kind"))
		name, _ := model.ScalarString(model.MapValue(model.MapValue(doc, "metadata"), "name"))
		spec := model.MapValue(doc, "spec")
		var pod *yaml.Node
		switch kind {
		case "Pod":
			pod = spec
		case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController":
			pod = model.MapValue(model.MapValue(spec, "template"), "spec")
		case "CronJob":
			job := model.MapValue(model.MapValue(spec, "jobTemplate"), "spec")
			pod = model.MapValue(model.MapValue(job, "template"), "spec")
		}
		if pod != nil {
			out = append(out, podSpec{Kind: kind, Name: name, Spec: pod})
		}
	}
	return out
}

// k8sContainer is one entry of containers or initContainers.
type k8sContainer struct {
	Name string
	Node *yaml.Node
}

func (p podSpec) containers() []k8sContainer {
	var out []k8sContainer
	for _, field := range []string{"initContainers", "containers"} {
		for _, c := range model.SeqItems(model.MapValue(p.Spec, field)) {
			name, _ := model.ScalarString(model.MapValue(c, "name"))
			out = append(out, k8sContainer{Name: name, Node: c})
		}
	}
	return out
}

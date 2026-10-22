package rules

import (
	"path"
	"strings"

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

// k8sObjects returns every object of a manifest stream, expanding
// "kind: List" documents (the format of `kubectl get -o yaml` and of many
// generated manifests) into their items.
func k8sObjects(t *model.Target) []*yaml.Node {
	var out []*yaml.Node
	for _, doc := range t.YAML {
		if kind, _ := model.ScalarString(model.MapValue(doc, "kind")); strings.HasSuffix(kind, "List") {
			out = append(out, model.SeqItems(model.MapValue(doc, "items"))...)
			continue
		}
		out = append(out, doc)
	}
	return out
}

// podSpecs returns the pod spec of every workload in a manifest stream.
func podSpecs(t *model.Target) []podSpec {
	var out []podSpec
	for _, doc := range k8sObjects(t) {
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

// dangerousHostPaths are host paths whose mount gives a container control of,
// or broad visibility into, the host: the container runtime sockets (which
// let a process start privileged containers) and system directories.
var dangerousHostPaths = []string{
	"/var/run/docker.sock", "/run/docker.sock",
	"/var/run/containerd/containerd.sock", "/run/containerd/containerd.sock",
	"/var/run/crio/crio.sock", "/run/crio/crio.sock",
	"/", "/proc", "/sys", "/etc", "/root", "/dev", "/boot", "/var/lib/docker", "/var/lib/kubelet",
}

// isDangerousHostPath reports whether mounting host path p is equivalent to
// giving the container the host.
func isDangerousHostPath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	p = path.Clean(p)
	for _, d := range dangerousHostPaths {
		if p == d {
			return true
		}
	}
	return false
}

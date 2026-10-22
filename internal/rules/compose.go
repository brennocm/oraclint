package rules

import (
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/brennocm/oraclint/internal/model"
)

// composeService is one entry under the top-level "services:" key of a
// docker-compose file.
type composeService struct {
	Name    string
	NameKey *yaml.Node // the key node, for locations
	Node    *yaml.Node // the service mapping
}

func composeServices(t *model.Target) []composeService {
	var out []composeService
	for _, doc := range t.YAML {
		keys, values := model.MapPairs(model.MapValue(doc, "services"))
		for i := range keys {
			out = append(out, composeService{Name: keys[i].Value, NameKey: keys[i], Node: values[i]})
		}
	}
	return out
}

// image returns the service's image reference, or "".
func (s composeService) image() string {
	img, _ := model.ScalarString(model.MapValue(s.Node, "image"))
	return img
}

// isNodeService reports whether a service runs the Chainlink node, judged by
// its image or name.
func (s composeService) isNodeService() bool {
	return strings.Contains(strings.ToLower(s.image()), "chainlink") ||
		strings.Contains(strings.ToLower(s.Name), "chainlink")
}

// isPostgresService reports whether a service runs a Postgres image.
func (s composeService) isPostgresService() bool {
	name := imageName(s.image())
	return strings.HasPrefix(name, "postgres") || strings.Contains(name, "postgis") || strings.Contains(name, "timescaledb")
}

// publishedPort is one entry of a service's "ports:" list.
type publishedPort struct {
	HostIP        string // "" means all interfaces
	ContainerFrom int
	ContainerTo   int // equal to ContainerFrom unless a range was given
	Node          *yaml.Node
}

// exposes reports whether the entry publishes container port p.
func (pp publishedPort) exposes(p int) bool {
	return p >= pp.ContainerFrom && p <= pp.ContainerTo
}

// onAllInterfaces reports whether the port is reachable on every host
// interface (no host IP, 0.0.0.0 or ::).
func (pp publishedPort) onAllInterfaces() bool {
	return pp.HostIP == "" || pp.HostIP == "0.0.0.0" || pp.HostIP == "::"
}

// ports parses both compose port syntaxes:
//
//	short: "6688", "6688:6688", "127.0.0.1:6688:6688", "[::1]:6688:6688/tcp", "6688-6690:6688-6690"
//	long:  {target: 6688, published: "6688", host_ip: 127.0.0.1}
func (s composeService) ports() []publishedPort {
	var out []publishedPort
	for _, item := range model.SeqItems(model.MapValue(s.Node, "ports")) {
		if item.Kind == yaml.MappingNode {
			target, _ := model.ScalarString(model.MapValue(item, "target"))
			hostIP, _ := model.ScalarString(model.MapValue(item, "host_ip"))
			if from, to, ok := portRange(target); ok {
				out = append(out, publishedPort{HostIP: hostIP, ContainerFrom: from, ContainerTo: to, Node: item})
			}
			continue
		}
		spec, ok := model.ScalarString(item)
		if !ok {
			continue
		}
		if pp, ok := parseShortPort(spec); ok {
			pp.Node = item
			out = append(out, pp)
		}
	}
	return out
}

func parseShortPort(spec string) (publishedPort, bool) {
	spec, _, _ = strings.Cut(strings.TrimSpace(spec), "/") // drop "/tcp"
	var hostIP string
	if strings.HasPrefix(spec, "[") { // bracketed IPv6 host IP
		end := strings.Index(spec, "]:")
		if end < 0 {
			return publishedPort{}, false
		}
		hostIP, spec = spec[1:end], spec[end+2:]
	}
	parts := strings.Split(spec, ":")
	container := parts[len(parts)-1]
	if hostIP == "" && len(parts) >= 3 {
		hostIP = strings.Join(parts[:len(parts)-2], ":")
	}
	from, to, ok := portRange(container)
	if !ok {
		return publishedPort{}, false
	}
	return publishedPort{HostIP: hostIP, ContainerFrom: from, ContainerTo: to}, true
}

// portRange parses "6688" or "6688-6690".
func portRange(s string) (from, to int, ok bool) {
	lo, hi, isRange := strings.Cut(strings.TrimSpace(s), "-")
	from, err := strconv.Atoi(lo)
	if err != nil {
		return 0, 0, false
	}
	to = from
	if isRange {
		if to, err = strconv.Atoi(hi); err != nil || to < from {
			return 0, 0, false
		}
	}
	return from, to, true
}

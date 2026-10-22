package rules

import (
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

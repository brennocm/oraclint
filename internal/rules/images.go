package rules

import "strings"

// imageName returns the repository name of an image reference without
// registry, tag or digest, lowercased: "docker.io/library/postgres:16" -> "postgres".
func imageName(ref string) string {
	ref, _, _ = strings.Cut(strings.ToLower(ref), "@")
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	name, _, _ := strings.Cut(ref, ":")
	return name
}

// imageTag returns the tag of an image reference ("" when there is none) and
// whether it is pinned by digest.
func imageTag(ref string) (tag string, digest bool) {
	ref, _, digest = strings.Cut(ref, "@")
	last := ref
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		last = ref[i+1:] // a ":" before the last "/" is a registry port
	}
	_, tag, _ = strings.Cut(last, ":")
	return tag, digest
}

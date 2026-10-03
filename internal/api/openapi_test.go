package api

import (
	"bufio"
	"bytes"
	"regexp"
	"slices"
	"strings"
	"testing"

	delilapi "github.com/serxan22/delil/api"
	"github.com/serxan22/delil/internal/config"
	"github.com/serxan22/delil/internal/metrics"
)

var (
	specPath   = regexp.MustCompile(`^  (/\S*):\s*$`)
	specMethod = regexp.MustCompile(`^    (get|put|post|patch|delete):`)
)

// specOperations lists "METHOD /path" for every operation in api/openapi.yaml.
// The document keeps paths at two and methods at four spaces of indentation.
func specOperations(t *testing.T) []string {
	t.Helper()
	var ops []string
	path := ""
	sc := bufio.NewScanner(bytes.NewReader(delilapi.OpenAPI))
	inPaths := false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "paths:":
			inPaths = true
		case inPaths && len(line) > 0 && line[0] != ' ' && line[0] != '#':
			inPaths = false
		case !inPaths:
		case specPath.MatchString(line):
			path = specPath.FindStringSubmatch(line)[1]
		case specMethod.MatchString(line):
			ops = append(ops, strings.ToUpper(specMethod.FindStringSubmatch(line)[1])+" "+path)
		}
	}
	if len(ops) == 0 {
		t.Fatal("no operations found in the OpenAPI document")
	}
	return ops
}

// TestOpenAPICoversRoutes fails when a route is added without documenting it,
// or when the document describes a route that does not exist.
func TestOpenAPICoversRoutes(t *testing.T) {
	s := New(Deps{Config: &config.Config{}, Metrics: metrics.New("test", nil)})
	var routes []string
	for _, r := range s.Routes() {
		// "GET /{$}" is the ServeMux spelling of exactly "/".
		routes = append(routes, strings.Replace(r, "/{$}", "/", 1))
	}
	spec := specOperations(t)
	for _, r := range routes {
		if !slices.Contains(spec, r) {
			t.Errorf("route %q is not documented in api/openapi.yaml", r)
		}
	}
	for _, op := range spec {
		if !slices.Contains(routes, op) {
			t.Errorf("api/openapi.yaml documents %q, which the server does not serve", op)
		}
	}
}

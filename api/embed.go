// Package api embeds the OpenAPI specification so the server can serve it at
// /openapi.yaml. The specification in this directory is the source of truth
// for the REST API.
package api

import _ "embed"

// OpenAPI is the OpenAPI 3.1 document.
//
//go:embed openapi.yaml
var OpenAPI []byte

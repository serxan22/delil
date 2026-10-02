// Package migrations embeds the SQL schema migrations. Files are applied in
// lexical order by internal/db; an applied migration must never be edited
// (the runner stores and checks a SHA-256 checksum of every file).
package migrations

import "embed"

// FS contains every *.sql migration.
//
//go:embed *.sql
var FS embed.FS

// Package version carries build information, set with -ldflags:
//
//	-X github.com/serxan22/delil/internal/version.Version=0.1.0
//	-X github.com/serxan22/delil/internal/version.Commit=<git sha>
package version

// Build information.
var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String renders the full version.
func String() string {
	return Version + " (" + Commit + ", " + Date + ")"
}

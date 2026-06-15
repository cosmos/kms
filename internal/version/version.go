// Package version exposes the kms build version.
package version

// Version is the kms semantic version. Overridable at build time via
// -ldflags "-X github.com/cosmos/kms/internal/version.Version=...".
var Version = "0.1.0-dev"

// String returns the kms version string.
func String() string { return Version }

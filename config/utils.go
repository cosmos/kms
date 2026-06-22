package config

import "path/filepath"

// AbsPath resolves p against home unless it is already absolute or empty. It is
// the single home-relative path resolver used by config validation and by the
// app wiring (internal/app) when opening configured files.
func AbsPath(home, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(home, p)
}

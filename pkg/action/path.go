package action

import (
	"strings"
)

// Note: findFilesRecursively has been replaced with direct filepath.WalkDir usage
// in scan.go for better memory efficiency and streaming processing

// cleanPath removes the temporary directory prefix from the path.
func cleanPath(path string, prefix string) string {
	return strings.TrimPrefix(path, prefix)
}

// formatPath formats the path for display.
func formatPath(path string) string {
	if strings.Contains(path, "\\") {
		path = strings.ReplaceAll(path, "\\", "/")
	}
	return path
}

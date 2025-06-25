package action

import (
	"strings"
)

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

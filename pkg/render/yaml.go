// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"gopkg.in/yaml.v3"
)

type YAML struct {
	w          io.Writer
	files      map[string]*malcontent.FileReport // Collect files during streaming
	filesMutex sync.Mutex                        // Protect concurrent access
}

func NewYAML(w io.Writer) YAML {
	return YAML{
		w:     w,
		files: make(map[string]*malcontent.FileReport),
	}
}

func (r *YAML) Name() string { return "YAML" }

func (r *YAML) Scanning(_ context.Context, _ string) {}

func (r *YAML) File(ctx context.Context, fr *malcontent.FileReport) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Only collect non-skipped files for YAML output
	if fr.Skipped == "" {
		r.filesMutex.Lock()
		defer r.filesMutex.Unlock()
		// Create a copy and clean diff-related fields like the original implementation
		frCopy := *fr
		frCopy.ArchiveRoot = ""
		frCopy.FullPath = ""

		// For YAML keys, use the cleaned relative path like the original sync.Map approach
		// But preserve the full path in the FileReport for display
		key := fr.Path
		if strings.Contains(fr.Path, " ∴ ") {
			// Extract the relative path after the "∴" separator for archive files
			parts := strings.Split(fr.Path, " ∴ ")
			if len(parts) > 1 {
				key = parts[1]
			}
		}
		r.files[key] = &frCopy
	}

	return nil
}

func (r *YAML) Full(ctx context.Context, c *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	r.filesMutex.Lock()
	defer r.filesMutex.Unlock()

	yr := Report{
		Diff:   rep.Diff,
		Files:  r.files, // Use collected files instead of sync.Map
		Filter: "",
	}

	if c != nil && c.Stats && yr.Diff == nil {
		yr.Stats = serializedStats(c, rep)
	}

	yamlData, err := yaml.Marshal(yr)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.w, "%s\n", yamlData)
	return err
}

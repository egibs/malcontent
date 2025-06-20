// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

type JSON struct {
	w          io.Writer
	files      map[string]*malcontent.FileReport // Collect files during streaming
	filesMutex sync.Mutex                        // Protect concurrent access
}

func NewJSON(w io.Writer) JSON {
	return JSON{
		w:     w,
		files: make(map[string]*malcontent.FileReport),
	}
}

func (r *JSON) Name() string { return "JSON" }

func (r *JSON) Scanning(_ context.Context, _ string) {}

func (r *JSON) File(ctx context.Context, fr *malcontent.FileReport) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Only collect non-skipped files for JSON output
	if fr.Skipped == "" {
		r.filesMutex.Lock()
		defer r.filesMutex.Unlock()
		// Create a copy and clean diff-related fields like the original implementation
		frCopy := *fr
		frCopy.ArchiveRoot = ""
		frCopy.FullPath = ""

		// For JSON keys, use the cleaned relative path like the original sync.Map approach
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

func (r *JSON) Full(ctx context.Context, c *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	r.filesMutex.Lock()
	defer r.filesMutex.Unlock()

	jr := Report{
		Diff:   rep.Diff,
		Files:  r.files, // Use collected files instead of sync.Map
		Filter: "",
	}

	if c != nil && c.Stats && jr.Diff == nil {
		jr.Stats = serializedStats(c, rep)
	}

	j, err := json.MarshalIndent(jr, "", "    ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.w, "%s\n", j)
	return err
}

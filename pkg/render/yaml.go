// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"gopkg.in/yaml.v3"
)

type YAML struct {
	w            io.Writer
	files        map[string]*malcontent.FileReport // Collect files during streaming
	filesMutex   sync.Mutex                        // Protect concurrent access
	streamingDir string                            // Directory for streaming temp files
	fileCount    int                               // Count files for streaming
	batchSize    int                               // Files per batch before writing to disk
}

func NewYAML(w io.Writer) YAML {
	// Auto-enable streaming with temporary directory for memory safety
	tempDir, err := os.MkdirTemp("", "malcontent-yaml-*")
	if err != nil {
		// Fallback to in-memory mode if temp directory creation fails
		tempDir = ""
	}

	return YAML{
		w:            w,
		files:        make(map[string]*malcontent.FileReport),
		streamingDir: tempDir, // Always use streaming to prevent OOM
		batchSize:    batchSize,
	}
}

// NewYAMLWithBatchSize creates a YAML renderer with custom batch size (for testing)
func NewYAMLWithBatchSize(w io.Writer, customBatchSize int) YAML {
	tempDir, err := os.MkdirTemp("", "malcontent-yaml-*")
	if err != nil {
		tempDir = ""
	}

	return YAML{
		w:            w,
		files:        make(map[string]*malcontent.FileReport),
		streamingDir: tempDir,
		batchSize:    customBatchSize,
	}
}

func (r *YAML) Name() string { return "YAML" }

// StreamingDir returns the streaming directory path for testing
func (r *YAML) StreamingDir() string { return r.streamingDir }

func (r *YAML) Scanning(_ context.Context, _ string) {}

func (r *YAML) File(ctx context.Context, fr *malcontent.FileReport) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Only collect non-skipped files for YAML output
	if fr.Skipped == "" {
		r.filesMutex.Lock()
		defer r.filesMutex.Unlock()
		frCopy := *fr
		frCopy.ArchiveRoot = ""
		frCopy.FullPath = ""

		key := fr.Path
		if strings.Contains(fr.Path, " ∴ ") {
			parts := strings.Split(fr.Path, " ∴ ")
			if len(parts) > 1 {
				key = parts[1]
			}
		}

		r.files[key] = &frCopy
		r.fileCount++

		// Only flush if we have a streaming directory configured
		if r.streamingDir != "" && len(r.files) >= r.batchSize {
			if err := r.flushBatchToDisk(); err != nil {
				return fmt.Errorf("failed to flush batch to disk: %w", err)
			}
		}
	}

	return nil
}

// flushBatchToDisk writes the current batch of files to a temporary file and clears memory
func (r *YAML) flushBatchToDisk() error {
	if len(r.files) == 0 {
		return nil
	}

	// Create streaming directory if it doesn't exist
	if err := os.MkdirAll(r.streamingDir, 0o755); err != nil {
		return fmt.Errorf("failed to create streaming directory: %w", err)
	}

	batchNum := r.fileCount / r.batchSize
	tempFile := filepath.Join(r.streamingDir, fmt.Sprintf("batch_%d.json", batchNum))

	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(r.files); err != nil {
		return fmt.Errorf("failed to encode batch: %w", err)
	}

	r.files = make(map[string]*malcontent.FileReport)

	return nil
}

func (r *YAML) Full(ctx context.Context, c *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	r.filesMutex.Lock()
	defer r.filesMutex.Unlock()

	var allFiles map[string]*malcontent.FileReport

	// Handle streaming mode
	if r.streamingDir != "" {
		// Flush any remaining files in memory
		if len(r.files) > 0 {
			if err := r.flushBatchToDisk(); err != nil {
				return fmt.Errorf("failed to flush final batch: %w", err)
			}
		}

		// Assemble all batched files from disk
		var err error
		allFiles, err = r.assembleBatchedFiles()
		if err != nil {
			return fmt.Errorf("failed to assemble batched files: %w", err)
		}

		// Clean up temporary files
		defer r.cleanupTempFiles()
	} else {
		// In-memory mode - use files directly
		allFiles = r.files
	}

	yr := Report{
		Diff:   rep.Diff,
		Files:  allFiles,
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

// assembleBatchedFiles reads all temporary batch files and combines them into a single map
func (r *YAML) assembleBatchedFiles() (map[string]*malcontent.FileReport, error) {
	allFiles := make(map[string]*malcontent.FileReport)

	entries, err := os.ReadDir(r.streamingDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read streaming directory: %w", err)
	}

	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "batch_") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		batchPath := filepath.Join(r.streamingDir, entry.Name())
		file, err := os.Open(batchPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open batch file %s: %w", batchPath, err)
		}

		var batchFiles map[string]*malcontent.FileReport
		if err := json.NewDecoder(file).Decode(&batchFiles); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to decode batch file %s: %w", batchPath, err)
		}
		file.Close()

		// Merge into allFiles
		for key, fr := range batchFiles {
			allFiles[key] = fr
		}
	}

	return allFiles, nil
}

// cleanupTempFiles removes all temporary batch files and directory
func (r *YAML) cleanupTempFiles() {
	if r.streamingDir == "" {
		return
	}
	os.RemoveAll(r.streamingDir)
}

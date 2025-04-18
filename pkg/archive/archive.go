package archive

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

const (
	// 32KB buffer.
	bufferSize = 32 * 1024
	// 512MB file limit.
	maxBytes = 1 << 29
)

// Shared buffer pool for io.CopyBuffer operations.
var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, bufferSize)
		return &b
	},
}

// isValidPath checks if the target file is within the given directory.
func IsValidPath(target, dir string) bool {
	return strings.HasPrefix(filepath.Clean(target), filepath.Clean(dir))
}

// ExtractArchiveToTempDir creates a temporary directory and extracts the archive file for scanning.
func ExtractArchiveToTempDir(ctx context.Context, path string, out chan<- string, concurrent int) (string, error) {
	logger := clog.FromContext(ctx).With("path", path)

	tmpDir, err := os.MkdirTemp("", filepath.Base(path))
	if err != nil {
		close(out)
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	ft, err := programkind.File(path)
	if err != nil {
		close(out)
		return "", fmt.Errorf("failed to determine file type: %w", err)
	}

	extract := ExtractionMethod(programkind.GetExt(path))
	if ft != nil && ft.MIME == "application/zlib" {
		extract = ExtractZlib
	} else if ft != nil && ft.MIME == "application/x-upx" {
		extract = ExtractUPX
	}
	if extract == nil {
		close(out)
		return "", fmt.Errorf("unsupported archive type: %s", path)
	}

	if err := extract(ctx, tmpDir, path); err != nil {
		os.RemoveAll(tmpDir)
		close(out)
		return "", fmt.Errorf("extract error: %w", err)
	}

	go func() {
		defer close(out)

		var extracted sync.Map
		var wg sync.WaitGroup

		sem := make(chan struct{}, concurrent)

		var processDir func(string)
		processDir = func(dir string) {
			defer wg.Done()

			files, err := os.ReadDir(dir)
			if err != nil {
				logger.Warn("error reading directory", "path", dir, "error", err)
				return
			}

			for _, file := range files {
				if ctx.Err() != nil {
					return
				}

				fullPath := filepath.Join(dir, file.Name())

				if file.IsDir() {
					wg.Add(1)
					go processDir(fullPath)
					continue
				}

				if strings.HasSuffix(file.Name(), ".~") || strings.HasSuffix(file.Name(), ".000") {
					extracted.Store(fullPath, true)
					continue
				}

				if _, seen := extracted.LoadOrStore(fullPath, true); seen {
					continue
				}

				select {
				case out <- fullPath:
				case <-ctx.Done():
					return
				}

				sem <- struct{}{}
				wg.Add(1)
				go func(filePath, fileName string) {
					defer wg.Done()
					defer func() { <-sem }()

					ft, err := programkind.File(filePath)
					if err != nil {
						logger.Warn("error determining file type", "path", filePath, "error", err)
						return
					}

					isArchive := false
					var subExtract func(context.Context, string, string) error

					switch {
					case ft != nil && ft.MIME == "application/x-upx":
						isArchive = true
						subExtract = ExtractUPX
					case ft != nil && ft.MIME == "application/zlib":
						isArchive = true
						subExtract = ExtractZlib
					default:
						subExtract = ExtractionMethod(programkind.GetExt(fileName))
						isArchive = subExtract != nil
					}

					if isArchive && subExtract != nil {
						extractDir := filepath.Dir(filePath)
						if err := subExtract(ctx, extractDir, filePath); err != nil {
							logger.Warn("failed to extract nested archive", "path", filePath, "error", err)
							return
						}

						if err := os.Remove(filePath); err != nil {
							logger.Warn("failed to remove archive after extraction", "path", filePath, "error", err)
						}

						wg.Add(1)
						go processDir(extractDir)
					}
				}(fullPath, file.Name())
			}
		}

		wg.Add(1)
		processDir(tmpDir)
		wg.Wait()
	}()

	return tmpDir, nil
}

func ExtractionMethod(ext string) func(context.Context, string, string) error {
	// The ordering of these statements is important, especially for extensions
	// that are substrings of other extensions (e.g., `.gz` and `.tar.gz` or `.tgz`)
	switch ext {
	// New cases should go below this line so that the lengthier tar extensions are evaluated first
	case ".apk", ".gem", ".tar", ".tar.bz2", ".tar.gz", ".tgz", ".tar.xz", ".tbz", ".xz":
		return ExtractTar
	case ".gz", ".gzip":
		return ExtractGzip
	case ".jar", ".zip", ".whl":
		return ExtractZip
	case ".bz2", ".bzip2":
		return ExtractBz2
	case ".zst", ".zstd":
		return ExtractZstd
	case ".rpm":
		return ExtractRPM
	case ".deb":
		return ExtractDeb
	default:
		return nil
	}
}

// handleDirectory extracts valid directories within .deb or .tar archives.
func handleDirectory(target string) error {
	if err := os.MkdirAll(target, 0o700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	return nil
}

// handleFile extracts valid files within .deb or .tar archives.
func handleFile(target string, tr *tar.Reader) error {
	buf, ok := bufferPool.Get().(*[]byte)
	if !ok {
		return fmt.Errorf("failed to retrieve buffer")
	}
	defer bufferPool.Put(buf)

	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	written, err := io.CopyBuffer(out, io.LimitReader(tr, maxBytes), *buf)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}
	if written >= maxBytes {
		return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", maxBytes, target)
	}

	return nil
}

// handleSymlink creates valid symlinks when extracting .deb or .tar archives.
func handleSymlink(dir, linkName, target string) error {
	// Skip symlinks for targets that do not exist
	_, err := os.Readlink(target)
	if os.IsNotExist(err) {
		return nil
	}

	fullLink := filepath.Join(dir, linkName)

	// Remove existing symlinks
	if _, err := os.Lstat(fullLink); err == nil {
		if err := os.Remove(fullLink); err != nil {
			return fmt.Errorf("failed to remove existing symlink: %w", err)
		}
	}

	if err := os.Symlink(target, fullLink); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}

	linkReal, err := filepath.EvalSymlinks(fullLink)
	if err != nil {
		os.Remove(fullLink)
		return fmt.Errorf("failed to evaluate symlink: %w", err)
	}
	if !IsValidPath(linkReal, dir) {
		os.Remove(fullLink)
		return fmt.Errorf("symlink points outside temporary directory: %s", linkReal)
	}

	return nil
}

package archive

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

func ExtractUPX(ctx context.Context, d, f string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Check if UPX is installed
	if err := programkind.UPXInstalled(); err != nil {
		return err
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting upx")

	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	gf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer gf.Close()

	target := filepath.Join(d, filepath.Base(f))
	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid file path: %s", target)
	}

	// Create target file for streaming copy instead of loading entire file into memory
	targetFile, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("failed to create target file: %w", err)
	}
	defer targetFile.Close()

	// Set file permissions
	if err := targetFile.Chmod(0o600); err != nil {
		os.Remove(target)
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	// Stream copy the file content instead of loading it all into memory
	_, err = io.Copy(targetFile, gf)
	if err != nil {
		os.Remove(target)
		return fmt.Errorf("failed to copy file content: %w", err)
	}

	// Limit concurrent UPX processes to prevent process explosion
	programkind.AcquireUPXSemaphore()
	defer programkind.ReleaseUPXSemaphore()

	cmd := exec.Command("upx", "-d", "-k", target)
	output, err := cmd.CombinedOutput()
	if err != nil {
		os.Remove(target)
		return fmt.Errorf("failed to decompress upx file: %w, output: %s", err, output)
	}

	if !strings.Contains(string(output), "Decompressed") && !strings.Contains(string(output), "Unpacked") {
		os.Remove(target)
		return fmt.Errorf("upx decompression might have failed: %s", output)
	}

	logger.Debug("successfully decompressed upx file", "output", string(output), "target", target)
	return nil
}

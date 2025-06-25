// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/archive"
	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"golang.org/x/sync/errgroup"

	yarax "github.com/VirusTotal/yara-x/go"
)

func interactive(c malcontent.Config) bool {
	return c.Renderer != nil && c.Renderer.Name() == "Interactive"
}

var (
	// compiledRuleCache are a cache of previously compiled rules.
	compiledRuleCache atomic.Pointer[yarax.Rules]
	// compileOnce ensures that we compile rules only once even across threads.
	compileOnce         sync.Once
	ErrMatchedCondition = errors.New("matched exit criteria")
	// initializeOnce ensures that the file and scanner pools are only initialized once.
	initializeOnce sync.Once
)

const maxMmapSize = 1 << 31 // 2048MB

// scanFD scans a file descriptor using memory mapping for efficient large file handling.
// This avoids loading the entire file into memory while still using yara-x's byte slice scanning.
func scanFD(scanner *yarax.Scanner, fd uintptr, logger *clog.Logger) ([]byte, *yarax.ScanResults, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(fd), &stat); err != nil {
		return nil, nil, fmt.Errorf("fstat failed: %w", err)
	}

	size := stat.Size
	if size == 0 {
		mrs, err := scanner.Scan([]byte{})
		return nil, mrs, err
	}

	if size < 0 {
		return nil, nil, fmt.Errorf("invalid file size: %d", size)
	}

	if size > maxMmapSize {
		logger.Warn("file exceeds mmap limit, scanning first portion only",
			"size", size, "limit", maxMmapSize)
		size = maxMmapSize
	}

	data, err := syscall.Mmap(int(fd), 0, int(size), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		return nil, nil, fmt.Errorf("mmap failed: %w", err)
	}
	defer func() {
		if unmapErr := syscall.Munmap(data); unmapErr != nil {
			logger.Error("failed to unmap memory", "error", unmapErr)
		}
	}()

	mrs, err := scanner.Scan(data)
	if err != nil {
		return nil, nil, err
	}

	fc := make([]byte, len(data))
	copy(fc, data)

	return fc, mrs, err
}

// scanSinglePath YARA scans a single path and converts it to a fileReport.
func scanSinglePath(ctx context.Context, c malcontent.Config, path string, ruleFS []fs.FS, absPath string, archiveRoot string) (*malcontent.FileReport, error) {
	if ctx.Err() != nil {
		return &malcontent.FileReport{}, ctx.Err()
	}

	logger := clog.FromContext(ctx)
	logger = logger.With("path", path)

	isArchive := archiveRoot != ""

	type scannerResult struct {
		scanner *yarax.Scanner
		err     error
	}
	scannerChan := make(chan scannerResult, 1)

	go func() {
		var yrs *yarax.Rules
		var err error
		if c.Rules == nil {
			yrs, err = CachedRules(ctx, ruleFS)
			if err != nil {
				scannerChan <- scannerResult{err: fmt.Errorf("rules: %w", err)}
				return
			}
		} else {
			yrs = c.Rules
		}
		scanner := yarax.NewScanner(yrs)
		scannerChan <- scannerResult{scanner: scanner}
	}()

	f, err := os.Open(path)
	if err != nil {
		go func() {
			if result := <-scannerChan; result.scanner != nil {
				result.scanner.Destroy()
			}
		}()
		return nil, err
	}
	fd := f.Fd()
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		go func() {
			if result := <-scannerChan; result.scanner != nil {
				result.scanner.Destroy()
			}
		}()
		return nil, err
	}

	size := fi.Size()
	if size == 0 {
		go func() {
			if result := <-scannerChan; result.scanner != nil {
				result.scanner.Destroy()
			}
		}()
		if isArchive {
			defer os.RemoveAll(path)
		}
		return nil, nil
	}

	mime := "<unknown>"
	kind, err := programkind.File(path)
	if err != nil && !interactive(c) {
		logger.Errorf("file type failure: %s: %s", path, err)
	}
	if kind != nil {
		mime = kind.MIME
	}

	if !c.IncludeDataFiles && kind == nil {
		go func() {
			if result := <-scannerChan; result.scanner != nil {
				result.scanner.Destroy()
			}
		}()
		logger.Debugf("skipping %s [%s]: data file or empty", path, mime)
		if isArchive {
			defer os.RemoveAll(path)
		}
		return nil, nil
	}
	logger = logger.With("mime", mime)

	scannerRes := <-scannerChan
	if scannerRes.err != nil {
		return nil, scannerRes.err
	}
	scanner := scannerRes.scanner
	defer scanner.Destroy()

	fc, mrs, err := scanFD(scanner, fd, logger)
	if err != nil {
		logger.Debug("skipping", slog.Any("error", err))
		return nil, err
	}

	// If running a scan, only generate reports for mrs that satisfy the risk threshold of 3
	// This is a short-circuit that avoids any report generation logic
	risk := report.HighestMatchRisk(mrs)
	threshold := max(3, c.MinFileRisk, c.MinRisk)
	if c.Scan && risk < threshold {
		if isArchive {
			os.RemoveAll(path)
		}
		return nil, nil
	}

	fr, err := report.Generate(ctx, path, mrs, c, archiveRoot, logger, fc, kind)
	if err != nil {
		return nil, NewFileReportError(err, path, TypeGenerateError)
	}

	defer func() {
		mrs = nil //nolint:ineffassign // clear rule matches after report generation
	}()

	// Clean up the path if scanning an archive
	var clean string
	if isArchive || c.OCI {
		pathAbs, err := filepath.Abs(path)
		if err != nil {
			return nil, NewFileReportError(err, path, TypeGenerateError)
		}
		archiveRootAbs, err := filepath.Abs(archiveRoot)
		if err != nil {
			return nil, NewFileReportError(err, path, TypeGenerateError)
		}
		if runtime.GOOS == "darwin" {
			pathAbs = strings.TrimPrefix(pathAbs, "/private")
			archiveRootAbs = strings.TrimPrefix(archiveRootAbs, "/private")
		}
		fr.ArchiveRoot = archiveRootAbs
		fr.FullPath = pathAbs
		clean = formatPath(cleanPath(pathAbs, archiveRootAbs))

		if absPath != "" && absPath != path && (isArchive || c.OCI) {
			if len(c.TrimPrefixes) > 0 {
				absPath = report.TrimPrefixes(absPath, c.TrimPrefixes)
			}
			fr.Path = fmt.Sprintf("%s ∴ %s", absPath, clean)
		}
	}

	if len(fr.Behaviors) == 0 {
		if len(c.TrimPrefixes) > 0 {
			if isArchive {
				absPath = report.TrimPrefixes(absPath, c.TrimPrefixes)
			} else {
				path = report.TrimPrefixes(absPath, c.TrimPrefixes)
			}
		}
		if isArchive {
			return &malcontent.FileReport{Path: fmt.Sprintf("%s ∴ %s", absPath, clean)}, nil
		}
		return &malcontent.FileReport{Path: path}, nil
	}

	return fr, nil
}

// exitIfHitOrMiss generates the right error if a match is encountered.
func exitIfHitOrMiss(frs *sync.Map, scanPath string, errIfHit bool, errIfMiss bool) (*malcontent.FileReport, error) {
	var (
		bList []string
		bMap  sync.Map
		count int
		match *malcontent.FileReport
	)
	if frs == nil {
		return nil, nil
	}

	filesScanned := 0

	frs.Range(func(_, value any) bool {
		if value == nil {
			return true
		}
		if fr, ok := value.(*malcontent.FileReport); ok {
			if fr.Skipped != "" {
				return true
			}
			filesScanned++
			if len(fr.Behaviors) > 0 && match == nil {
				match = fr
			}
			for _, b := range fr.Behaviors {
				count++
				bMap.Store(b.ID, true)
			}
		}
		return true
	})

	bMap.Range(func(key, _ any) bool {
		if key == nil {
			return true
		}
		if k, ok := key.(string); ok {
			bList = append(bList, k)
		}
		return true
	})
	sort.Strings(bList)

	if filesScanned == 0 {
		return nil, nil
	}

	if errIfHit && count != 0 {
		return match, fmt.Errorf("%s %w", scanPath, ErrMatchedCondition)
	}

	if errIfMiss && count == 0 {
		return nil, fmt.Errorf("%s %w", scanPath, ErrMatchedCondition)
	}
	return nil, nil
}

func CachedRules(ctx context.Context, fss []fs.FS) (*yarax.Rules, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if rules := compiledRuleCache.Load(); rules != nil {
		return rules, nil
	}

	var err error
	compileOnce.Do(func() {
		var yrs *yarax.Rules
		yrs, err = compile.Recursive(ctx, fss)
		if err != nil {
			err = fmt.Errorf("compile: %w", err)
			return
		}
		compiledRuleCache.Store(yrs)
	})

	if err != nil {
		return nil, err
	}

	return compiledRuleCache.Load(), nil
}

// matchResult represents the outcome of a match operation.
type matchResult struct {
	fr  *malcontent.FileReport
	err error
}

// scanPathInfo contains information about the path being scanned.
type scanPathInfo struct {
	originalPath   string
	effectivePath  string
	ociExtractPath string
	imageURI       string
}

// recursiveScan recursively YARA scans the configured paths - handling archives and OCI images.
func recursiveScan(ctx context.Context, c malcontent.Config) (*malcontent.Report, error) {
	if ctx.Err() != nil {
		return &malcontent.Report{}, ctx.Err()
	}

	logger := clog.FromContext(ctx)
	r := initializeReport(c.IgnoreTags)
	matchChan := make(chan matchResult, 1)
	var matchOnce sync.Once

	for _, scanPath := range c.ScanPaths {
		if err := handleScanPath(ctx, scanPath, c, r, matchChan, &matchOnce, logger); err != nil {
			return r, err
		}
	}
	return r, nil
}

func initializeReport(ignoreTags []string) *malcontent.Report {
	r := &malcontent.Report{
		Stats: malcontent.NewAggregateStats(),
		Files: sync.Map{}, // Keep for backwards compatibility during transition
	}
	if len(ignoreTags) > 0 {
		r.Filter = strings.Join(ignoreTags, ",")
	}
	return r
}

func handleScanPath(ctx context.Context, scanPath string, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if c.Renderer != nil {
		c.Renderer.Scanning(ctx, scanPath)
	}

	scanInfo, err := prepareScanPath(ctx, scanPath, c.OCI, logger)
	if err != nil {
		return fmt.Errorf("failed to prepare scan path: %w", err)
	}

	if c.OCI && scanInfo.ociExtractPath != "" {
		defer cleanupOCIPath(scanInfo.ociExtractPath, logger)
	}

	return processPaths(ctx, scanInfo, c, r, matchChan, matchOnce, logger)
}

// processPaths uses filepath.WalkDir to stream files and process them concurrently.
func processPaths(ctx context.Context, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	maxConcurrency := getMaxConcurrency(c.Concurrency)
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		logger.Debug("parent context canceled, stopping scan")
		cancel()
	}()

	setupMatchHandler(scanCtx, matchChan, c, cancel, logger)

	// Follow symlink if provided at the root
	root, err := filepath.EvalSymlinks(scanInfo.effectivePath)
	if err != nil {
		// If the target does not exist, log the error but return gracefully
		if os.IsNotExist(err) {
			logger.Debugf("symlink target does not exist: %s", err.Error())
			return nil
		}
		// Allow /proc/XXX/exe to be scanned even if symlink is not resolveable
		if strings.HasPrefix(scanInfo.effectivePath, "/proc/") {
			root = scanInfo.effectivePath
		} else {
			return fmt.Errorf("eval %q: %w", scanInfo.effectivePath, err)
		}
	}

	g, gCtx := errgroup.WithContext(scanCtx)
	pathChan := make(chan string, maxConcurrency*8)

	for range maxConcurrency {
		g.Go(func() error {
			for path := range pathChan {
				if gCtx.Err() != nil {
					return gCtx.Err()
				}
				if err := processPath(gCtx, path, scanInfo, c, r, matchChan, matchOnce, logger); err != nil {
					return err
				}
			}
			return nil
		})
	}

	go func() {
		defer close(pathChan)
		walkErr := filepath.WalkDir(root, func(path string, info os.DirEntry, err error) error {
			if gCtx.Err() != nil {
				return gCtx.Err()
			}

			if err != nil {
				logger.Debugf("error: %s: %s", path, err)
				return nil
			}

			if info.IsDir() || strings.Contains(path, "/.git/") {
				return nil
			}

			if info.Type()&fs.ModeSymlink == fs.ModeSymlink {
				return nil
			}

			select {
			case pathChan <- path:
			case <-gCtx.Done():
				return gCtx.Err()
			}
			return nil
		})
		if walkErr != nil {
			logger.Debugf("walkdir error: %v", walkErr)
		}
	}()

	return g.Wait()
}

func prepareScanPath(ctx context.Context, scanPath string, isOCI bool, logger *clog.Logger) (scanPathInfo, error) {
	if ctx.Err() != nil {
		return scanPathInfo{}, ctx.Err()
	}

	info := scanPathInfo{
		originalPath:  scanPath,
		effectivePath: scanPath,
	}

	if !isOCI {
		return info, nil
	}

	info.imageURI = scanPath
	ociPath, err := archive.OCI(ctx, info.imageURI)
	if err != nil {
		return info, fmt.Errorf("failed to prepare OCI image for scanning: %w", err)
	}

	info.ociExtractPath = ociPath
	info.effectivePath = ociPath
	logger.Debug("oci image", slog.Any("scanPath", scanPath), slog.Any("ociExtractPath", ociPath))

	return info, nil
}

func getMaxConcurrency(configured int) int {
	if configured < 1 {
		return 1
	}
	return configured
}

func archiveConcurrency(mainConcurrency int) int {
	maxConcurrency := getMaxConcurrency(mainConcurrency)
	switch {
	case maxConcurrency >= 32:
		return max(16, (maxConcurrency*3)/4)
	case maxConcurrency <= 8:
		return max(1, maxConcurrency/2)
	default:
		baseConcurrency := int(math.Sqrt(float64(mainConcurrency)))
		log := max(int(math.Log2(float64(mainConcurrency))-3), 0)
		return max(2, baseConcurrency+log)
	}
}

func setupMatchHandler(ctx context.Context, matchChan chan matchResult, c malcontent.Config, cancel context.CancelFunc, logger *clog.Logger) {
	if ctx.Err() != nil {
		return
	}

	// Only create match handler goroutine if early exit conditions are enabled
	if !c.ExitFirstHit && !c.ExitFirstMiss {
		return
	}

	go func() {
		defer func() {
			// Ensure goroutine cleanup by draining match channel
			select {
			case <-matchChan:
			default:
			}
		}()

		select {
		case match := <-matchChan:
			if match.fr != nil && c.Renderer != nil && match.fr.RiskScore >= c.MinFileRisk {
				if err := c.Renderer.File(ctx, match.fr); err != nil {
					logger.Errorf("render error: %v", err)
				}
			}
			cancel()
		case <-ctx.Done():
			return
		}
	}()
}

func processPath(ctx context.Context, path string, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		if programkind.IsSupportedArchive(path) {
			return handleArchiveFile(ctx, path, c, r, matchChan, matchOnce, logger)
		}
		return handleSingleFile(ctx, path, scanInfo, c, r, matchChan, matchOnce, logger)
	}
}

func handleArchiveFile(ctx context.Context, path string, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	frs, err := processArchive(ctx, c, c.RuleFS, path, logger)
	if err != nil {
		logger.Errorf("unable to process %s: %v", path, err)
		return err
	}

	if !c.OCI && (c.ExitFirstHit || c.ExitFirstMiss) {
		match, err := exitIfHitOrMiss(frs, path, c.ExitFirstHit, c.ExitFirstMiss)
		if err != nil {
			matchOnce.Do(func() {
				matchChan <- matchResult{fr: match, err: err}
			})
			return err
		}
	}

	//nolint:nestif // ignore complexity of 14
	if frs != nil {
		frs.Range(func(key, value any) bool {
			if ctx.Err() != nil {
				return false
			}
			if key == nil || value == nil {
				return true
			}
			if _, ok := key.(string); ok {
				if fr, ok := value.(*malcontent.FileReport); ok {
					// Stream to aggregate statistics (eliminates memory accumulation)
					r.Stats.AddFileReport(fr)

					if c.Renderer != nil && r.Diff == nil {
						// For diff file collection, include all files regardless of risk score
						// For normal rendering, apply risk filtering
						includeFile := fr.RiskScore >= c.MinFileRisk || c.Renderer.Name() == "FileCollector"
						if includeFile {
							if err := c.Renderer.File(ctx, fr); err != nil {
								logger.Errorf("render error: %v", err)
							}
						}
					}
				}
			}
			return true
		})
	}
	return nil
}

func handleSingleFile(ctx context.Context, path string, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	trimPath := ""
	if c.OCI {
		scanInfo.effectivePath = scanInfo.imageURI
		trimPath = scanInfo.ociExtractPath
	}

	fr, err := processFile(ctx, c, c.RuleFS, path, scanInfo.effectivePath, trimPath, logger)
	if err != nil && !interactive(c) {
		if len(c.TrimPrefixes) > 0 {
			path = report.TrimPrefixes(path, c.TrimPrefixes)
		}

		// Create empty report for error case and add to stats
		errorReport := &malcontent.FileReport{Path: path, Skipped: "processing error"}
		r.Stats.AddFileReport(errorReport)
		return fmt.Errorf("process: %w", err)
	}
	if fr == nil {
		return nil
	}

	if !c.OCI && (c.ExitFirstHit || c.ExitFirstMiss) {
		var frMap sync.Map
		frMap.Store(path, fr)
		match, err := exitIfHitOrMiss(&frMap, path, c.ExitFirstHit, c.ExitFirstMiss)
		if err != nil {
			matchOnce.Do(func() {
				matchChan <- matchResult{fr: match, err: err}
			})
			return err
		}
	}

	// Note: TrimPrefixes not needed for streaming statistics

	// Stream to aggregate statistics (eliminates memory accumulation)
	r.Stats.AddFileReport(fr)

	if c.Renderer != nil && r.Diff == nil {
		// For diff file collection, include all files regardless of risk score
		// For normal rendering, apply risk filtering
		includeFile := fr.RiskScore >= c.MinFileRisk || c.Renderer.Name() == "FileCollector"
		if includeFile {
			if err := c.Renderer.File(ctx, fr); err != nil {
				return fmt.Errorf("render: %w", err)
			}
		}
	}
	return nil
}

func cleanupOCIPath(path string, logger *clog.Logger) {
	if err := os.RemoveAll(path); err != nil {
		logger.Errorf("remove %s: %v", path, err)
	}
}

// processArchive extracts and scans a single archive file.
func processArchive(ctx context.Context, c malcontent.Config, rfs []fs.FS, archivePath string, logger *clog.Logger) (*sync.Map, error) {
	logger = logger.With("archivePath", archivePath)

	var frs sync.Map

	tmpRoot, err := archive.ExtractArchiveToTempDir(ctx, archivePath)
	if err != nil {
		// Avoid failing an entire scan when encountering problematic archives
		// e.g., joblib_0.8.4_compressed_pickle_py27_np17.gz: not a valid gzip archive
		if !c.ExitExtraction {
			return nil, nil
		}
		return nil, fmt.Errorf("extract to temp: %w", err)
	}
	// Ensure that tmpRoot is removed before returning if created successfully
	defer func() {
		if err := os.RemoveAll(tmpRoot); err != nil {
			logger.Errorf("remove %s: %v", tmpRoot, err)
		}
	}()

	// macOS will prefix temporary directories with `/private`
	// update tmpRoot (if populated) with this prefix to allow strings.TrimPrefix to work
	if runtime.GOOS == "darwin" && tmpRoot != "" {
		tmpRoot = fmt.Sprintf("/private%s", tmpRoot)
	}

	// Use simple WalkDir for archive processing
	err = processArchives(ctx, tmpRoot, archivePath, c, rfs, &frs, logger)
	if err != nil {
		return nil, err
	}

	return &frs, nil
}

// processArchives processes extracted archive files at full speed.
func processArchives(ctx context.Context, tmpRoot, archivePath string, c malcontent.Config, rfs []fs.FS, frs *sync.Map, logger *clog.Logger) error {
	// Collect paths first - archive files are already extracted locally so memory impact is limited
	var paths []string
	err := filepath.WalkDir(tmpRoot, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			logger.Debugf("error: %s: %s", path, err)
			return nil
		}
		if info.IsDir() || strings.Contains(path, "/.git/") {
			return nil
		}

		// Skip symlinks to prevent loops and memory issues
		if info.Type()&fs.ModeSymlink == fs.ModeSymlink {
			return nil
		}

		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk archive directory: %w", err)
	}

	archiveConcurrency := archiveConcurrency(c.Concurrency)
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(archiveConcurrency)
	for _, path := range paths {
		g.Go(func() error {
			fr, err := processFile(gCtx, c, rfs, path, archivePath, tmpRoot, logger)
			if err != nil {
				logger.Debugf("archive file processing error: %s: %v", path, err)
				return nil // Continue processing other files in archive
			}
			if fr != nil {
				clean := strings.TrimPrefix(path, tmpRoot)
				frs.Store(clean, fr)
			}
			return nil
		})
	}

	return g.Wait()
}

// handleFileReportError returns the appropriate FileReport and error depending on the type of error.
func handleFileReportError(err error, path string, logger *clog.Logger) (*malcontent.FileReport, error) {
	var fileErr *FileReportError
	if !errors.As(err, &fileErr) {
		return nil, fmt.Errorf("failed to handle error for path %s: error type not FileReportError: %w", path, err)
	}

	switch fileErr.Type() {
	case TypeUnknown:
		return nil, fmt.Errorf("unknown error occurred while scanning path %s: %w", path, err)
	case TypeScanError:
		logger.Errorf("scan path: %v", err)
		return nil, fmt.Errorf("scan failed for path %s: %w", path, err)
	case TypeGenerateError:
		return &malcontent.FileReport{
			Path:    path,
			Skipped: errMsgGenerateFailed,
		}, nil
	default:
		return nil, fmt.Errorf("unhandled error type scanning path %s: %w", path, err)
	}
}

func processFile(ctx context.Context, c malcontent.Config, ruleFS []fs.FS, path string, scanPath string, archiveRoot string, logger *clog.Logger) (*malcontent.FileReport, error) {
	logger = logger.With("path", path)

	fr, err := scanSinglePath(ctx, c, path, ruleFS, scanPath, archiveRoot)
	if err != nil && !interactive(c) {
		return handleFileReportError(err, path, logger)
	}

	if fr == nil {
		return nil, nil
	}

	return fr, nil
}

// Scan YARA scans a data source, applying output filters if necessary.
func Scan(ctx context.Context, c malcontent.Config) (*malcontent.Report, error) {
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	r, err := recursiveScan(scanCtx, c)
	if errors.Is(err, context.Canceled) {
		return r, fmt.Errorf("scan operation cancelled: %w", err)
	}
	if err != nil && !interactive(c) {
		return r, err
	}

	// Note: File filtering is now handled during streaming (in renderer File() calls)
	// This eliminates the need to iterate through accumulated files for filtering
	if scanCtx.Err() == nil && c.Stats && c.Renderer.Name() != "JSON" && c.Renderer.Name() != "YAML" {
		// Ensure stats are initialized before rendering
		if r.Stats == nil {
			r.Stats = malcontent.NewAggregateStats()
		}
		err = render.Statistics(&c, r)
		if err != nil {
			return r, fmt.Errorf("stats: %w", err)
		}
	}
	return r, nil
}

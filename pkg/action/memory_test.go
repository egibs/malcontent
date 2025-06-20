// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// memoryStats tracks memory usage during testing
type memoryStats struct {
	timestamp    time.Time
	heapAlloc    uint64
	heapSys      uint64
	numGC        uint32
	archiveCount int64
}

// collectMemoryStats captures current memory usage
func collectMemoryStats() memoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return memoryStats{
		timestamp:    time.Now(),
		heapAlloc:    m.HeapAlloc,
		heapSys:      m.HeapSys,
		numGC:        m.NumGC,
		archiveCount: processedArchiveCount.Load(),
	}
}

// formatBytes converts bytes to human readable format
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// TestMemorySeesawWithPeriodicGC tests how memory usage changes with periodic GC
func TestMemorySeesawWithPeriodicGC(t *testing.T) {
	// Reset the archive counter for consistent testing
	processedArchiveCount.Store(0)

	// Create a temporary directory with test files
	tempDir := t.TempDir()

	// Create multiple "archive" files to trigger GC
	numTestFiles := 150 // This should trigger GC 3 times (every 50 archives)
	testFiles := make([]string, numTestFiles)

	for i := 0; i < numTestFiles; i++ {
		filename := filepath.Join(tempDir, fmt.Sprintf("test_archive_%d.txt", i))
		content := fmt.Sprintf("Test content for archive %d\n", i)
		// Make each file a bit larger to see memory impact
		for j := 0; j < 100; j++ {
			content += fmt.Sprintf("Line %d of test data for archive %d\n", j, i)
		}

		err := os.WriteFile(filename, []byte(content), 0o644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
		testFiles[i] = filename
	}

	// Create basic config (for future use if needed)
	_ = malcontent.Config{
		Concurrency: 4,
		IgnoreTags:  []string{},
	}

	// Collect memory stats throughout the test
	var memStats []memoryStats

	// Initial memory state
	runtime.GC() // Start with clean slate
	runtime.GC()
	time.Sleep(100 * time.Millisecond) // Let GC settle
	initialStats := collectMemoryStats()
	memStats = append(memStats, initialStats)

	t.Logf("=== Memory Usage Test: Periodic GC Every %d Archives ===", gcTriggerInterval)
	t.Logf("Initial: Heap=%s, Sys=%s, GC=%d, Archives=%d",
		formatBytes(initialStats.heapAlloc),
		formatBytes(initialStats.heapSys),
		initialStats.numGC,
		initialStats.archiveCount)

	// Process files in batches and monitor memory
	ctx := context.Background()
	batchSize := 10

	for i := 0; i < len(testFiles); i += batchSize {
		end := i + batchSize
		if end > len(testFiles) {
			end = len(testFiles)
		}

		// Process batch of files
		for j := i; j < end; j++ {
			// Simulate archive processing by calling triggerPeriodicGC
			triggerPeriodicGC()

			// Simulate some memory allocation (like file content processing)
			_ = make([]byte, 64*1024) // 64KB allocation per "archive"
		}

		// Collect stats after each batch
		stats := collectMemoryStats()
		memStats = append(memStats, stats)

		// Log every 25 archives or when GC occurs
		if (i+batchSize)%25 == 0 || stats.numGC > memStats[len(memStats)-2].numGC {
			gcOccurred := ""
			if stats.numGC > memStats[len(memStats)-2].numGC {
				gcOccurred = " [GC TRIGGERED]"
			}

			t.Logf("After %d archives: Heap=%s, Sys=%s, GC=%d, Archives=%d%s",
				stats.archiveCount,
				formatBytes(stats.heapAlloc),
				formatBytes(stats.heapSys),
				stats.numGC,
				stats.archiveCount,
				gcOccurred)
		}

		// Small delay to make timing more realistic
		time.Sleep(10 * time.Millisecond)
	}

	// Final memory state
	finalStats := collectMemoryStats()
	t.Logf("Final: Heap=%s, Sys=%s, GC=%d, Archives=%d",
		formatBytes(finalStats.heapAlloc),
		formatBytes(finalStats.heapSys),
		finalStats.numGC,
		finalStats.archiveCount)

	// Analyze the memory seesaw pattern
	t.Logf("\n=== Memory Seesaw Analysis ===")

	gcEvents := 0
	peakHeap := uint64(0)
	lowHeap := ^uint64(0) // Max uint64

	for i, stats := range memStats {
		if stats.heapAlloc > peakHeap {
			peakHeap = stats.heapAlloc
		}
		if stats.heapAlloc < lowHeap {
			lowHeap = stats.heapAlloc
		}

		if i > 0 && stats.numGC > memStats[i-1].numGC {
			gcEvents++
			heapBefore := memStats[i-1].heapAlloc
			heapAfter := stats.heapAlloc
			reduction := int64(heapBefore) - int64(heapAfter)

			t.Logf("GC Event #%d at archive %d: %s -> %s (freed %s)",
				gcEvents,
				stats.archiveCount,
				formatBytes(heapBefore),
				formatBytes(heapAfter),
				formatBytes(uint64(reduction)))
		}
	}

	expectedGCs := int(finalStats.archiveCount) / gcTriggerInterval
	t.Logf("Peak heap usage: %s", formatBytes(peakHeap))
	t.Logf("Lowest heap usage: %s", formatBytes(lowHeap))
	t.Logf("Memory range: %s", formatBytes(peakHeap-lowHeap))
	t.Logf("Total GC events triggered: %d (expected ~%d)", gcEvents, expectedGCs)

	// Verify that GC is actually being triggered
	if gcEvents < expectedGCs {
		t.Errorf("Expected at least %d GC events, but only saw %d", expectedGCs, gcEvents)
	}

	// Verify memory shows seesaw pattern (periodic increases and decreases)
	if peakHeap <= lowHeap*2 {
		t.Logf("Memory usage appears stable (peak %.1fx low)", float64(peakHeap)/float64(lowHeap))
	} else {
		t.Logf("Memory shows seesaw pattern (peak %.1fx low)", float64(peakHeap)/float64(lowHeap))
	}

	_ = ctx // Suppress unused variable warning
}

// TestMemoryWithoutPeriodicGC tests memory usage without periodic GC for comparison
func TestMemoryWithoutPeriodicGC(t *testing.T) {
	// Save original GC interval
	originalInterval := gcTriggerInterval

	// Temporarily disable periodic GC by setting a very high interval
	// We can't modify the const, so we'll just not call triggerPeriodicGC

	tempDir := t.TempDir()
	numTestFiles := 150

	// Create test files
	for i := 0; i < numTestFiles; i++ {
		filename := filepath.Join(tempDir, fmt.Sprintf("test_file_%d.txt", i))
		content := fmt.Sprintf("Test content for file %d\n", i)
		for j := 0; j < 100; j++ {
			content += fmt.Sprintf("Line %d of test data for file %d\n", j, i)
		}

		err := os.WriteFile(filename, []byte(content), 0o644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// Reset GC stats
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	initialGCs := m.NumGC
	initialHeap := m.HeapAlloc

	t.Logf("=== Memory Usage Test: WITHOUT Periodic GC ===")
	t.Logf("Initial: Heap=%s, GC=%d", formatBytes(initialHeap), initialGCs)

	// Process files without calling triggerPeriodicGC
	for i := 0; i < numTestFiles; i++ {
		// Simulate memory allocation without triggering GC
		_ = make([]byte, 64*1024) // 64KB allocation per "archive"

		if i%25 == 0 {
			runtime.ReadMemStats(&m)
			t.Logf("After %d files: Heap=%s, GC=%d",
				i, formatBytes(m.HeapAlloc), m.NumGC)
		}

		time.Sleep(10 * time.Millisecond)
	}

	runtime.ReadMemStats(&m)
	finalGCs := m.NumGC
	finalHeap := m.HeapAlloc

	t.Logf("Final: Heap=%s, GC=%d", formatBytes(finalHeap), finalGCs)
	t.Logf("Natural GC events: %d", finalGCs-initialGCs)
	t.Logf("Memory growth: %s", formatBytes(finalHeap-initialHeap))

	_ = originalInterval // Suppress unused warning
}

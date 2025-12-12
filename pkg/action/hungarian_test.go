// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"testing"
	"unsafe"
)

func TestOptimalAssignment_EmptyInput(t *testing.T) {
	result := optimalAssignment(nil, 0, 0)
	if len(result.RowToCol) != 0 {
		t.Errorf("expected empty RowToCol, got %v", result.RowToCol)
	}
	if len(result.ColToRow) != 0 {
		t.Errorf("expected empty ColToRow, got %v", result.ColToRow)
	}
}

func TestOptimalAssignment_SinglePair(t *testing.T) {
	entries := []SparseEntry{
		{Score: 0.9, Row: 0, Col: 0},
	}
	result := optimalAssignment(entries, 1, 1)

	if result.RowToCol[0] != 0 {
		t.Errorf("expected row 0 assigned to col 0, got %d", result.RowToCol[0])
	}
	if result.ColToRow[0] != 0 {
		t.Errorf("expected col 0 assigned to row 0, got %d", result.ColToRow[0])
	}
}

func TestOptimalAssignment_BeatsGreedy(t *testing.T) {
	// Test case where greedy would fail but Hungarian finds optimal
	//
	// Score matrix (higher is better):
	//        col0  col1
	// row0   0.9   0.8
	// row1   0.85  0.4
	//
	// Greedy picks highest first: row0->col0 (0.9), then row1->col1 (0.4) = 1.3 total
	// Optimal: row0->col1 (0.8), row1->col0 (0.85) = 1.65 total
	entries := []SparseEntry{
		{Score: 0.9, Row: 0, Col: 0},
		{Score: 0.8, Row: 0, Col: 1},
		{Score: 0.85, Row: 1, Col: 0},
		{Score: 0.4, Row: 1, Col: 1},
	}
	result := optimalAssignment(entries, 2, 2)

	// Should find optimal: row0->col1, row1->col0
	if result.RowToCol[0] != 1 {
		t.Errorf("expected row 0 assigned to col 1, got %d", result.RowToCol[0])
	}
	if result.RowToCol[1] != 0 {
		t.Errorf("expected row 1 assigned to col 0, got %d", result.RowToCol[1])
	}
}

func TestOptimalAssignment_RectangularMoreRows(t *testing.T) {
	// More removed files than added files
	entries := []SparseEntry{
		{Score: 0.9, Row: 0, Col: 0},
		{Score: 0.5, Row: 1, Col: 0},
		{Score: 0.3, Row: 2, Col: 0},
	}
	result := optimalAssignment(entries, 3, 1)

	// Only row 0 should be assigned (highest score)
	assignedCount := 0
	for _, col := range result.RowToCol {
		if col >= 0 {
			assignedCount++
		}
	}
	if assignedCount != 1 {
		t.Errorf("expected 1 assignment, got %d", assignedCount)
	}
	if result.RowToCol[0] != 0 {
		t.Errorf("expected row 0 assigned to col 0, got %d", result.RowToCol[0])
	}
}

func TestOptimalAssignment_RectangularMoreCols(t *testing.T) {
	// More added files than removed files
	entries := []SparseEntry{
		{Score: 0.5, Row: 0, Col: 0},
		{Score: 0.9, Row: 0, Col: 1},
		{Score: 0.3, Row: 0, Col: 2},
	}
	result := optimalAssignment(entries, 1, 3)

	// Row 0 should be assigned to col 1 (highest score)
	if result.RowToCol[0] != 1 {
		t.Errorf("expected row 0 assigned to col 1, got %d", result.RowToCol[0])
	}
}

func TestOptimalAssignment_InvalidEntries(t *testing.T) {
	// Test that invalid entries (out of bounds) are safely ignored
	entries := []SparseEntry{
		{Score: 0.9, Row: 0, Col: 0},  // valid
		{Score: 0.8, Row: -1, Col: 0}, // invalid: negative row
		{Score: 0.7, Row: 0, Col: -1}, // invalid: negative col
		{Score: 0.6, Row: 10, Col: 0}, // invalid: row out of bounds
		{Score: 0.5, Row: 0, Col: 10}, // invalid: col out of bounds
	}
	result := optimalAssignment(entries, 2, 2)

	// Only the valid entry should be assigned
	if result.RowToCol[0] != 0 {
		t.Errorf("expected row 0 assigned to col 0, got %d", result.RowToCol[0])
	}
	if result.RowToCol[1] != -1 {
		t.Errorf("expected row 1 unassigned, got %d", result.RowToCol[1])
	}
}

func TestOptimalAssignment_DoesNotMutateInput(t *testing.T) {
	// Verify that the input slice is not modified
	entries := []SparseEntry{
		{Score: 0.5, Row: 0, Col: 0},
		{Score: 0.9, Row: 1, Col: 1},
		{Score: 0.3, Row: 0, Col: 1},
	}

	// Save original order
	originalFirst := entries[0]

	_ = optimalAssignment(entries, 2, 2)

	// Verify original slice wasn't sorted
	if entries[0] != originalFirst {
		t.Errorf("optimalAssignment mutated input slice: first entry changed from %v to %v",
			originalFirst, entries[0])
	}
}

func TestBuildSparseMatrix(t *testing.T) {
	removedPaths := []string{"/path/to/libfoo.so.1", "/path/to/libbar.so.2"}
	addedPaths := []string{"/new/path/libfoo.so.2", "/new/path/libbaz.so.1"}

	scoreFunc := func(rpath, apath string) (float64, bool) {
		return computeLevenshteinScore(rpath, apath), true
	}

	entries := buildSparseMatrix(removedPaths, addedPaths, scoreFunc)

	// Should have entries for all pairs above threshold
	if len(entries) == 0 {
		t.Error("expected some entries, got none")
	}

	// Check that we have the high-scoring pair (libfoo.so.1 -> libfoo.so.2)
	foundHighScore := false
	for _, e := range entries {
		if e.Row == 0 && e.Col == 0 && e.Score > 0.8 {
			foundHighScore = true
			break
		}
	}
	if !foundHighScore {
		t.Error("expected high-scoring pair for similar filenames")
	}
}

func TestComputeLevenshteinScore(t *testing.T) {
	tests := []struct {
		rpath    string
		apath    string
		expected float64
	}{
		{"/a/file.txt", "/b/file.txt", 1.0},               // identical basenames
		{"/a/foo.txt", "/b/foo.txt", 1.0},                 // identical basenames
		{"/a/libfoo.so.1", "/b/libfoo.so.2", 0.9},         // very similar
		{"/a/completely_different", "/b/other_name", 0.0}, // very different
	}

	for _, tt := range tests {
		score := computeLevenshteinScore(tt.rpath, tt.apath)
		if tt.expected == 1.0 && score != 1.0 {
			t.Errorf("computeLevenshteinScore(%q, %q) = %f, expected %f",
				tt.rpath, tt.apath, score, tt.expected)
		}
		if tt.expected == 0.0 && score > 0.5 {
			t.Errorf("computeLevenshteinScore(%q, %q) = %f, expected low score",
				tt.rpath, tt.apath, score)
		}
	}
}

func BenchmarkOptimalAssignment_Small(b *testing.B) {
	entries := make([]SparseEntry, 0, 100)
	for i := range 10 {
		for j := range 10 {
			entries = append(entries, SparseEntry{
				Score: float64(i+j) / 20.0,
				Row:   i,
				Col:   j,
			})
		}
	}

	for b.Loop() {
		optimalAssignment(entries, 10, 10)
	}
}

func BenchmarkOptimalAssignment_Medium(b *testing.B) {
	entries := make([]SparseEntry, 0, 2500)
	for i := range 50 {
		for j := range 50 {
			entries = append(entries, SparseEntry{
				Score: float64(i+j) / 100.0,
				Row:   i,
				Col:   j,
			})
		}
	}

	for b.Loop() {
		optimalAssignment(entries, 50, 50)
	}
}

// BenchmarkOptimalAssignment_Sparse simulates real file matching with sparse matrices.
// In practice, most file pairs have low similarity and are filtered out.
func BenchmarkOptimalAssignment_Sparse(b *testing.B) {
	// 100 removed files, 100 added files, but only ~10% have meaningful similarity
	entries := make([]SparseEntry, 0, 200)
	// Diagonal entries (perfect matches - same file moved)
	for i := range 20 {
		entries = append(entries, SparseEntry{
			Score: 1.0, // Perfect match
			Row:   i,
			Col:   i,
		})
	}
	// Some partial matches (versioned files like libfoo.so.1 -> libfoo.so.2)
	for i := 20; i < 40; i++ {
		entries = append(entries, SparseEntry{
			Score: 0.85,
			Row:   i,
			Col:   i,
		})
		// Add a competing match with lower score
		entries = append(entries, SparseEntry{
			Score: 0.4,
			Row:   i,
			Col:   (i + 1) % 100,
		})
	}

	for b.Loop() {
		optimalAssignment(entries, 100, 100)
	}
}

// BenchmarkOptimalAssignment_ManyPerfect tests the fast path for many perfect matches.
func BenchmarkOptimalAssignment_ManyPerfect(b *testing.B) {
	entries := make([]SparseEntry, 0, 100)
	// All perfect matches (common when diffing similar images)
	for i := range 100 {
		entries = append(entries, SparseEntry{
			Score: 1.0,
			Row:   i,
			Col:   i,
		})
	}

	for b.Loop() {
		optimalAssignment(entries, 100, 100)
	}
}

// BenchmarkOptimalAssignment_Large tests fallback to greedy for large matrices.
func BenchmarkOptimalAssignment_Large(b *testing.B) {
	// 300x300 - exceeds hungarianSizeLimit (200), should use greedy
	entries := make([]SparseEntry, 0, 900)
	for i := range 300 {
		// Each row has ~3 candidate matches
		for d := range 3 {
			entries = append(entries, SparseEntry{
				Score: 0.9 - float64(d)*0.2,
				Row:   i,
				Col:   (i + d) % 300,
			})
		}
	}

	for b.Loop() {
		optimalAssignment(entries, 300, 300)
	}
}

// BenchmarkLevenshteinScore measures the Levenshtein scoring with cached params.
func BenchmarkLevenshteinScore(b *testing.B) {
	paths := []struct{ r, a string }{
		{"/usr/lib/libfoo.so.1", "/usr/lib/libfoo.so.2"},
		{"/bin/program", "/usr/bin/program"},
		{"/etc/config.yaml", "/etc/config.yml"},
	}

	for i := 0; b.Loop(); i++ {
		p := paths[i%len(paths)]
		computeLevenshteinScore(p.r, p.a)
	}
}

// BenchmarkBuildSparseMatrix measures sparse matrix construction.
func BenchmarkBuildSparseMatrix(b *testing.B) {
	removed := make([]string, 50)
	added := make([]string, 50)
	for i := range 50 {
		removed[i] = "/usr/lib/libfoo" + string(rune('a'+i)) + ".so.1"
		added[i] = "/usr/lib/libfoo" + string(rune('a'+i)) + ".so.2"
	}

	scoreFunc := func(r, a string) (float64, bool) {
		return computeLevenshteinScore(r, a), true
	}

	for b.Loop() {
		buildSparseMatrix(removed, added, scoreFunc)
	}
}

// BenchmarkStructSizes verifies struct sizes for cache efficiency.
func BenchmarkStructSizes(b *testing.B) {
	// SparseEntry should be 24 bytes (8+8+8) with no padding
	var entry SparseEntry
	entrySize := int(unsafe.Sizeof(entry))
	if entrySize != 24 {
		b.Errorf("SparseEntry size = %d bytes, expected 24 (may have padding)", entrySize)
	}

	// Verify alignment - Score (float64) should be at offset 0
	scoreOffset := unsafe.Offsetof(entry.Score)
	if scoreOffset != 0 {
		b.Errorf("Score offset = %d, expected 0 for optimal alignment", scoreOffset)
	}

	b.ReportMetric(float64(entrySize), "bytes/entry")
}

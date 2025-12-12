// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"testing"
)

func TestHungarianOptimal_EmptyInput(t *testing.T) {
	result := hungarianOptimal(nil, 0, 0)
	if len(result.RowToCol) != 0 {
		t.Errorf("expected empty RowToCol, got %v", result.RowToCol)
	}
	if len(result.ColToRow) != 0 {
		t.Errorf("expected empty ColToRow, got %v", result.ColToRow)
	}
}

func TestHungarianOptimal_SinglePair(t *testing.T) {
	entries := []SparseEntry{
		{Row: 0, Col: 0, Score: 0.9},
	}
	result := hungarianOptimal(entries, 1, 1)

	if result.RowToCol[0] != 0 {
		t.Errorf("expected row 0 assigned to col 0, got %d", result.RowToCol[0])
	}
	if result.ColToRow[0] != 0 {
		t.Errorf("expected col 0 assigned to row 0, got %d", result.ColToRow[0])
	}
}

func TestHungarianOptimal_OptimalAssignment(t *testing.T) {
	// Test case where greedy would fail but Hungarian finds optimal
	//
	// Cost matrix (as scores, higher is better):
	//        col0  col1
	// row0   0.9   0.5
	// row1   0.8   0.7
	//
	// Greedy: row0->col0 (0.9), row1->col1 (0.7) = 1.6
	// Optimal: row0->col1 (0.5), row1->col0 (0.8) = 1.3 - wait, that's worse
	//
	// Let me create a proper case:
	//        col0  col1
	// row0   0.9   0.8
	// row1   0.85  0.4
	//
	// Greedy: row0->col0 (0.9), row1->col1 (0.4) = 1.3
	// Optimal: row0->col1 (0.8), row1->col0 (0.85) = 1.65
	entries := []SparseEntry{
		{Row: 0, Col: 0, Score: 0.9},
		{Row: 0, Col: 1, Score: 0.8},
		{Row: 1, Col: 0, Score: 0.85},
		{Row: 1, Col: 1, Score: 0.4},
	}
	result := hungarianOptimal(entries, 2, 2)

	// Hungarian should find the optimal assignment:
	// row0 -> col1 (0.8), row1 -> col0 (0.85) = 1.65 total
	if result.RowToCol[0] != 1 {
		t.Errorf("expected row 0 assigned to col 1, got %d", result.RowToCol[0])
	}
	if result.RowToCol[1] != 0 {
		t.Errorf("expected row 1 assigned to col 0, got %d", result.RowToCol[1])
	}
}

func TestHungarianOptimal_RectangularMoreRows(t *testing.T) {
	// More removed files than added files
	entries := []SparseEntry{
		{Row: 0, Col: 0, Score: 0.9},
		{Row: 1, Col: 0, Score: 0.5},
		{Row: 2, Col: 0, Score: 0.3},
	}
	result := hungarianOptimal(entries, 3, 1)

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

func TestHungarianOptimal_RectangularMoreCols(t *testing.T) {
	// More added files than removed files
	entries := []SparseEntry{
		{Row: 0, Col: 0, Score: 0.5},
		{Row: 0, Col: 1, Score: 0.9},
		{Row: 0, Col: 2, Score: 0.3},
	}
	result := hungarianOptimal(entries, 1, 3)

	// Row 0 should be assigned to col 1 (highest score)
	if result.RowToCol[0] != 1 {
		t.Errorf("expected row 0 assigned to col 1, got %d", result.RowToCol[0])
	}
}

func TestGreedyAssignment(t *testing.T) {
	entries := []SparseEntry{
		{Row: 0, Col: 0, Score: 0.9},
		{Row: 0, Col: 1, Score: 0.8},
		{Row: 1, Col: 0, Score: 0.85},
		{Row: 1, Col: 1, Score: 0.4},
	}

	// Sort by score descending (greedy expects sorted input)
	sortEntriesByScore(entries)

	result := greedyAssignment(entries, 2, 2)

	// Greedy picks highest scores first:
	// First: row0->col0 (0.9)
	// Then: row1->col1 (0.4) since col0 is taken
	if result.RowToCol[0] != 0 {
		t.Errorf("greedy: expected row 0 assigned to col 0, got %d", result.RowToCol[0])
	}
	if result.RowToCol[1] != 1 {
		t.Errorf("greedy: expected row 1 assigned to col 1, got %d", result.RowToCol[1])
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
		{"/a/file.txt", "/b/file.txt", 1.0},                   // identical basenames
		{"/a/foo.txt", "/b/foo.txt", 1.0},                     // identical basenames
		{"/a/libfoo.so.1", "/b/libfoo.so.2", 0.9},             // very similar
		{"/a/completely_different", "/b/other_name", 0.0},     // very different
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

func TestSortEntriesByScore(t *testing.T) {
	entries := []SparseEntry{
		{Row: 0, Col: 0, Score: 0.3},
		{Row: 1, Col: 1, Score: 0.9},
		{Row: 2, Col: 2, Score: 0.5},
	}

	sortEntriesByScore(entries)

	if entries[0].Score != 0.9 {
		t.Errorf("expected first entry score 0.9, got %f", entries[0].Score)
	}
	if entries[1].Score != 0.5 {
		t.Errorf("expected second entry score 0.5, got %f", entries[1].Score)
	}
	if entries[2].Score != 0.3 {
		t.Errorf("expected third entry score 0.3, got %f", entries[2].Score)
	}
}

func TestOptimalAssignment_SmallUseHungarian(t *testing.T) {
	// Small enough to use Hungarian
	entries := []SparseEntry{
		{Row: 0, Col: 0, Score: 0.9},
		{Row: 0, Col: 1, Score: 0.8},
		{Row: 1, Col: 0, Score: 0.85},
		{Row: 1, Col: 1, Score: 0.4},
	}

	result := optimalAssignment(entries, 2, 2)

	// Should use Hungarian and find optimal
	if result.RowToCol[0] != 1 || result.RowToCol[1] != 0 {
		t.Errorf("optimalAssignment did not find optimal solution: got row0->%d, row1->%d",
			result.RowToCol[0], result.RowToCol[1])
	}
}

func BenchmarkHungarianOptimal_Small(b *testing.B) {
	entries := make([]SparseEntry, 0, 100)
	for i := 0; i < 10; i++ {
		for j := 0; j < 10; j++ {
			entries = append(entries, SparseEntry{
				Row:   i,
				Col:   j,
				Score: float64(i+j) / 20.0,
			})
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hungarianOptimal(entries, 10, 10)
	}
}

func BenchmarkHungarianOptimal_Medium(b *testing.B) {
	entries := make([]SparseEntry, 0, 2500)
	for i := 0; i < 50; i++ {
		for j := 0; j < 50; j++ {
			entries = append(entries, SparseEntry{
				Row:   i,
				Col:   j,
				Score: float64(i+j) / 100.0,
			})
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hungarianOptimal(entries, 50, 50)
	}
}

func BenchmarkGreedyAssignment_Large(b *testing.B) {
	entries := make([]SparseEntry, 0, 10000)
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			entries = append(entries, SparseEntry{
				Row:   i,
				Col:   j,
				Score: float64(i+j) / 200.0,
			})
		}
	}
	sortEntriesByScore(entries)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		greedyAssignment(entries, 100, 100)
	}
}

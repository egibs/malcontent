// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"path/filepath"
	"slices"

	"github.com/agext/levenshtein"
)

// SparseEntry represents a single entry in the sparse cost matrix.
// Fields are ordered for optimal memory alignment: float64 (8 bytes) first,
// then ints (8 bytes each on 64-bit). Total: 24 bytes, cache-line friendly.
type SparseEntry struct {
	Score float64 // similarity score (higher is better) - 8 bytes, aligned
	Row   int     // 8 bytes
	Col   int     // 8 bytes
}

// hungarianAssignment represents the result of the Hungarian algorithm.
type hungarianAssignment struct {
	RowToCol []int // rowToCol[i] = j means row i is assigned to column j (-1 if unassigned)
	ColToRow []int // colToRow[j] = i means column j is assigned to row i (-1 if unassigned)
}

// Cached Levenshtein parameters - avoid allocation on every call.
// This is safe for concurrent use as we only read from it.
var defaultLevenshteinParams = levenshtein.NewParams()

const (
	// minScoreThreshold is the minimum similarity score to consider a pair.
	// Pairs below this threshold are not added to the sparse matrix.
	minScoreThreshold = 0.3

	// perfectMatchThreshold is the score at which we consider a match perfect.
	// Perfect matches are handled separately for efficiency.
	perfectMatchThreshold = 0.999

	// hungarianSizeLimit is the maximum matrix dimension for Hungarian algorithm.
	// Beyond this, we use the greedy approach for performance.
	hungarianSizeLimit = 200
)

// buildSparseMatrix computes similarity scores for all candidate pairs and returns
// a sparse representation. Only pairs above minScoreThreshold are included.
func buildSparseMatrix(
	removedPaths []string,
	addedPaths []string,
	scoreFunc func(rpath, apath string) (float64, bool),
) []SparseEntry {
	// Pre-allocate with reasonable capacity, avoiding potential overflow
	// by checking sizes before multiplication
	const maxCapacity = 10000
	capacity := maxCapacity
	if len(removedPaths) < maxCapacity && len(addedPaths) < maxCapacity {
		if product := len(removedPaths) * len(addedPaths); product < maxCapacity {
			capacity = product
		}
	}
	entries := make([]SparseEntry, 0, capacity)

	// Pre-compute basenames for addedPaths to avoid repeated filepath.Base calls
	// in the inner loop. This is cache-friendly as we access sequentially.
	addedBases := make([]string, len(addedPaths))
	for j, apath := range addedPaths {
		addedBases[j] = filepath.Base(apath)
	}

	for i, rpath := range removedPaths {
		rbase := filepath.Base(rpath)
		for j, apath := range addedPaths {
			abase := addedBases[j] // Use pre-computed basename

			// Fast path: identical basenames get score 1.0
			if rbase == abase {
				entries = append(entries, SparseEntry{
					Score: 1.0,
					Row:   i,
					Col:   j,
				})
				continue
			}

			// Use the provided scoring function which handles pattern matching
			score, ok := scoreFunc(rpath, apath)
			if !ok {
				continue
			}

			// Only include entries above threshold
			if score >= minScoreThreshold {
				entries = append(entries, SparseEntry{
					Score: score,
					Row:   i,
					Col:   j,
				})
			}
		}
	}

	return entries
}

// computeLevenshteinScore returns the Levenshtein similarity score between two paths.
// Uses cached Levenshtein parameters to avoid allocation overhead.
func computeLevenshteinScore(rpath, apath string) float64 {
	rbase := filepath.Base(rpath)
	abase := filepath.Base(apath)

	if rbase == abase {
		return 1.0
	}

	return levenshtein.Match(rbase, abase, defaultLevenshteinParams)
}

// optimalAssignment finds the optimal one-to-one matching that maximizes total similarity.
// It uses a multi-phase approach:
// 1. Extract perfect matches (score >= 0.999) greedily - these are always optimal
// 2. For remaining entries, use Hungarian algorithm if small enough, otherwise greedy.
//
// The function does not mutate the input slice.
func optimalAssignment(entries []SparseEntry, numRows, numCols int) hungarianAssignment {
	result := hungarianAssignment{
		RowToCol: make([]int, numRows),
		ColToRow: make([]int, numCols),
	}

	// Initialize all as unassigned
	for i := range result.RowToCol {
		result.RowToCol[i] = -1
	}
	for j := range result.ColToRow {
		result.ColToRow[j] = -1
	}

	if len(entries) == 0 {
		return result
	}

	// Single pass: assign perfect matches immediately, collect non-perfect for later.
	// This avoids copying perfect matches (common case) and only allocates for entries
	// that need sorting. Perfect matches don't need sorting since they're all equivalent.
	remaining := make([]SparseEntry, 0, len(entries)/2) // estimate half are non-perfect
	hadPerfectMatches := false
	for _, e := range entries {
		// Validate bounds
		if e.Row < 0 || e.Row >= numRows || e.Col < 0 || e.Col >= numCols {
			continue
		}

		if e.Score >= perfectMatchThreshold {
			// Perfect matches: assign greedily (optimal since score can't improve)
			if result.RowToCol[e.Row] == -1 && result.ColToRow[e.Col] == -1 {
				result.RowToCol[e.Row] = e.Col
				result.ColToRow[e.Col] = e.Row
				hadPerfectMatches = true
			}
		} else if e.Score >= minScoreThreshold {
			// Non-perfect: collect for sorting
			remaining = append(remaining, e)
		}
	}

	// If no remaining entries need assignment, we're done
	if len(remaining) == 0 {
		return result
	}

	// Sort only the non-perfect entries (much smaller slice typically)
	slices.SortFunc(remaining, func(a, b SparseEntry) int {
		if a.Score > b.Score {
			return -1
		}
		if a.Score < b.Score {
			return 1
		}
		// Tie-breaker: prefer lower indices for determinism
		if a.Row != b.Row {
			return a.Row - b.Row
		}
		return a.Col - b.Col
	})

	// Only re-filter if perfect matches were assigned (which could invalidate entries)
	if hadPerfectMatches {
		filtered := remaining[:0] // reuse backing array
		for _, e := range remaining {
			if result.RowToCol[e.Row] == -1 && result.ColToRow[e.Col] == -1 {
				filtered = append(filtered, e)
			}
		}
		remaining = filtered
		if len(remaining) == 0 {
			return result
		}
	}

	// Phase 2: For remaining entries, decide between Hungarian and greedy
	// Count unassigned rows and columns
	unassignedRows := 0
	unassignedCols := 0
	for i := range result.RowToCol {
		if result.RowToCol[i] == -1 {
			unassignedRows++
		}
	}
	for j := range result.ColToRow {
		if result.ColToRow[j] == -1 {
			unassignedCols++
		}
	}

	effectiveSize := max(unassignedRows, unassignedCols)

	if effectiveSize <= hungarianSizeLimit && len(remaining) <= effectiveSize*effectiveSize {
		// Use Hungarian for small problems
		hungarianAssign(remaining, &result)
	} else {
		// Use greedy for large problems (entries already sorted)
		greedyAssign(remaining, &result)
	}

	return result
}

// hungarianAssign applies the Hungarian algorithm to assign remaining entries.
// It modifies result in place, only touching unassigned rows/columns.
func hungarianAssign(entries []SparseEntry, result *hungarianAssignment) {
	if len(entries) == 0 {
		return
	}

	// Build compact index mappings for unassigned rows/cols
	// Use slices instead of maps for O(1) lookup with bounded indices
	numOrigRows := len(result.RowToCol)
	numOrigCols := len(result.ColToRow)

	rowMap := make([]int, 0, numOrigRows) // compact index -> original row
	rowRevMap := make([]int, numOrigRows) // original row -> compact index (-1 if assigned)
	colMap := make([]int, 0, numOrigCols) // compact index -> original col
	colRevMap := make([]int, numOrigCols) // original col -> compact index (-1 if assigned)

	// Initialize reverse maps to -1 (assigned/invalid)
	for i := range rowRevMap {
		rowRevMap[i] = -1
	}
	for j := range colRevMap {
		colRevMap[j] = -1
	}

	for i, assigned := range result.RowToCol {
		if assigned == -1 {
			rowRevMap[i] = len(rowMap)
			rowMap = append(rowMap, i)
		}
	}
	for j, assigned := range result.ColToRow {
		if assigned == -1 {
			colRevMap[j] = len(colMap)
			colMap = append(colMap, j)
		}
	}

	numRows := len(rowMap)
	numCols := len(colMap)
	if numRows == 0 || numCols == 0 {
		return
	}

	// Build dense cost matrix (we maximize similarity, so cost = 1 - score)
	n := max(numRows, numCols)
	cost := make([]float64, n*n)
	for i := range cost {
		cost[i] = 1.0 // Default cost for missing entries
	}

	// Fill in sparse entries using compact indices
	for _, e := range entries {
		compactRow := rowRevMap[e.Row]
		compactCol := colRevMap[e.Col]
		if compactRow >= 0 && compactCol >= 0 {
			cost[compactRow*n+compactCol] = 1.0 - e.Score
		}
	}

	// Run Hungarian algorithm
	assignment := munkres(cost, n)

	// Apply assignments back to result
	for compactRow, compactCol := range assignment {
		if compactRow < numRows && compactCol >= 0 && compactCol < numCols {
			origRow := rowMap[compactRow]
			origCol := colMap[compactCol]
			// Only assign if the cost is not the default (i.e., there was an actual entry)
			if cost[compactRow*n+compactCol] < 1.0 {
				result.RowToCol[origRow] = origCol
				result.ColToRow[origCol] = origRow
			}
		}
	}
}

// greedyAssign assigns entries greedily by score (entries must be pre-sorted descending).
func greedyAssign(entries []SparseEntry, result *hungarianAssignment) {
	for _, e := range entries {
		if result.RowToCol[e.Row] == -1 && result.ColToRow[e.Col] == -1 {
			result.RowToCol[e.Row] = e.Col
			result.ColToRow[e.Col] = e.Row
		}
	}
}

// munkres implements the Munkres (Hungarian) algorithm for the assignment problem.
// It takes a flattened n×n cost matrix and returns the optimal row-to-column assignment.
// This implementation uses the standard O(n³) shortest augmenting path algorithm with:
// - Pre-allocated working arrays (reused across iterations)
// - Flattened cost matrix for cache-friendly row access
// - Dual variables (potentials) for efficient reduced cost computation.
func munkres(cost []float64, n int) []int {
	const inf = 1e18

	// Dual variables (potentials)
	u := make([]float64, n+1)
	v := make([]float64, n+1)

	// Assignment: p[j] = row assigned to column j (1-indexed, 0 = unassigned)
	p := make([]int, n+1)

	// Predecessor in augmenting path
	way := make([]int, n+1)

	// Pre-allocate working arrays outside the main loop
	minv := make([]float64, n+1)
	used := make([]bool, n+1)

	// Process each row
	for i := 1; i <= n; i++ {
		// Start augmenting path from row i
		p[0] = i
		j0 := 0 // Current column in path

		// Reset working arrays using clear() for cache-friendly memset
		// Then reinitialize minv to inf (used is already false after clear)
		clear(used)
		for j := range minv {
			minv[j] = inf
		}

		// Find augmenting path
		for p[j0] != 0 {
			used[j0] = true
			i0 := p[j0]
			delta := inf
			j1 := 0

			// Find minimum reduced cost among unvisited columns
			rowOffset := (i0 - 1) * n
			for j := 1; j <= n; j++ {
				if !used[j] {
					// Reduced cost = cost[i0-1][j-1] - u[i0] - v[j]
					cur := cost[rowOffset+j-1] - u[i0] - v[j]
					if cur < minv[j] {
						minv[j] = cur
						way[j] = j0
					}
					if minv[j] < delta {
						delta = minv[j]
						j1 = j
					}
				}
			}

			// Update dual variables
			for j := 0; j <= n; j++ {
				if used[j] {
					u[p[j]] += delta
					v[j] -= delta
				} else {
					minv[j] -= delta
				}
			}

			j0 = j1
		}

		// Trace back and update assignment
		for j0 != 0 {
			j1 := way[j0]
			p[j0] = p[j1]
			j0 = j1
		}
	}

	// Convert to 0-indexed assignment
	assignment := make([]int, n)
	for j := 1; j <= n; j++ {
		if p[j] > 0 {
			assignment[p[j]-1] = j - 1
		}
	}

	return assignment
}

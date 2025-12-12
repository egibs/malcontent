// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"math"
	"path/filepath"

	"github.com/agext/levenshtein"
)

// SparseEntry represents a single entry in the sparse cost matrix.
type SparseEntry struct {
	Row   int
	Col   int
	Score float64 // similarity score (higher is better)
}

// hungarianAssignment represents the result of the Hungarian algorithm.
type hungarianAssignment struct {
	RowToCol []int // rowToCol[i] = j means row i is assigned to column j (-1 if unassigned)
	ColToRow []int // colToRow[j] = i means column j is assigned to row i (-1 if unassigned)
}

const (
	// minScoreThreshold is the minimum similarity score to consider a pair.
	// Pairs below this threshold are not added to the sparse matrix.
	minScoreThreshold = 0.3

	// greedyFallbackThreshold is the number of pairs above which we fall back to greedy.
	// The Hungarian algorithm is O(n³), so we use greedy for very large matrices.
	greedyFallbackThreshold = 10000

	// inf represents infinity for the Hungarian algorithm.
	inf = math.MaxFloat64 / 2
)

// buildSparseMatrix computes similarity scores for all candidate pairs and returns
// a sparse representation. Only pairs above minScoreThreshold are included.
func buildSparseMatrix(
	removedPaths []string,
	addedPaths []string,
	scoreFunc func(rpath, apath string) (float64, bool),
) []SparseEntry {
	// Pre-allocate with reasonable capacity
	entries := make([]SparseEntry, 0, min(len(removedPaths)*len(addedPaths), 1000))

	for i, rpath := range removedPaths {
		rbase := filepath.Base(rpath)
		for j, apath := range addedPaths {
			// Use the provided scoring function which handles pattern matching
			score, ok := scoreFunc(rpath, apath)
			if !ok {
				continue
			}

			// Fast path: identical basenames get score 1.0
			if rbase == filepath.Base(apath) {
				score = 1.0
			}

			// Only include entries above threshold
			if score >= minScoreThreshold {
				entries = append(entries, SparseEntry{
					Row:   i,
					Col:   j,
					Score: score,
				})
			}
		}
	}

	return entries
}

// computeLevenshteinScore returns the Levenshtein similarity score between two paths.
func computeLevenshteinScore(rpath, apath string) float64 {
	rbase := filepath.Base(rpath)
	abase := filepath.Base(apath)

	if rbase == abase {
		return 1.0
	}

	return levenshtein.Match(rbase, abase, levenshtein.NewParams())
}

// hungarianOptimal solves the assignment problem using the Hungarian algorithm.
// It finds the optimal one-to-one matching that maximizes the total similarity score.
//
// The algorithm runs in O(n³) time where n = max(numRows, numCols).
// For sparse matrices, we use heuristics to reduce the effective problem size.
func hungarianOptimal(entries []SparseEntry, numRows, numCols int) hungarianAssignment {
	if numRows == 0 || numCols == 0 || len(entries) == 0 {
		return hungarianAssignment{
			RowToCol: make([]int, numRows),
			ColToRow: make([]int, numCols),
		}
	}

	// Convert similarity scores to costs (Hungarian minimizes)
	// cost = 1.0 - score, so higher scores become lower costs
	n := max(numRows, numCols)

	// Build dense cost matrix from sparse entries
	// Unspecified entries get cost = 1.0 (score = 0)
	cost := make([][]float64, n)
	for i := range cost {
		cost[i] = make([]float64, n)
		for j := range cost[i] {
			cost[i][j] = 1.0 // Default cost (score = 0)
		}
	}

	// Fill in sparse entries
	for _, e := range entries {
		if e.Row < n && e.Col < n {
			cost[e.Row][e.Col] = 1.0 - e.Score
		}
	}

	// Run Hungarian algorithm
	assignment := runHungarian(cost, n)

	// Extract assignments for original dimensions
	result := hungarianAssignment{
		RowToCol: make([]int, numRows),
		ColToRow: make([]int, numCols),
	}

	for i := range result.RowToCol {
		result.RowToCol[i] = -1
	}
	for j := range result.ColToRow {
		result.ColToRow[j] = -1
	}

	for i := 0; i < numRows; i++ {
		j := assignment[i]
		if j >= 0 && j < numCols {
			// Only accept assignments with non-default cost (actual sparse entries)
			if cost[i][j] < 1.0 {
				result.RowToCol[i] = j
				result.ColToRow[j] = i
			}
		}
	}

	return result
}

// runHungarian implements the Hungarian (Kuhn-Munkres) algorithm.
// It takes a square cost matrix and returns the optimal assignment.
func runHungarian(cost [][]float64, n int) []int {
	// u[i] and v[j] are the dual variables (potentials)
	u := make([]float64, n+1)
	v := make([]float64, n+1)

	// p[j] = i means column j is assigned to row i (0 means unassigned, 1-indexed)
	p := make([]int, n+1)

	// way[j] stores the previous column in the augmenting path
	way := make([]int, n+1)

	for i := 1; i <= n; i++ {
		// p[0] is a temporary assignment for row i
		p[0] = i

		// j0 is the current column being processed
		j0 := 0

		// minv[j] is the minimum reduced cost to column j
		minv := make([]float64, n+1)
		for j := range minv {
			minv[j] = inf
		}

		// used[j] marks if column j is in the current tree
		used := make([]bool, n+1)

		// Find augmenting path
		for p[j0] != 0 {
			used[j0] = true
			i0 := p[j0]
			delta := inf
			j1 := 0

			for j := 1; j <= n; j++ {
				if !used[j] {
					// Reduced cost
					cur := cost[i0-1][j-1] - u[i0] - v[j]
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

		// Reconstruct path
		for j0 != 0 {
			j1 := way[j0]
			p[j0] = p[j1]
			j0 = j1
		}
	}

	// Extract assignment (convert from 1-indexed to 0-indexed)
	assignment := make([]int, n)
	for j := 1; j <= n; j++ {
		if p[j] > 0 {
			assignment[p[j]-1] = j - 1
		}
	}

	return assignment
}

// greedyAssignment provides a fast O(n log n) greedy assignment.
// Used as a fallback when the problem size is too large for Hungarian.
func greedyAssignment(entries []SparseEntry, numRows, numCols int) hungarianAssignment {
	result := hungarianAssignment{
		RowToCol: make([]int, numRows),
		ColToRow: make([]int, numCols),
	}

	for i := range result.RowToCol {
		result.RowToCol[i] = -1
	}
	for j := range result.ColToRow {
		result.ColToRow[j] = -1
	}

	// Sort entries by score descending (done by caller typically)
	// Process in order, assigning unmatched pairs
	for _, e := range entries {
		if result.RowToCol[e.Row] == -1 && result.ColToRow[e.Col] == -1 {
			result.RowToCol[e.Row] = e.Col
			result.ColToRow[e.Col] = e.Row
		}
	}

	return result
}

// optimalAssignment chooses between Hungarian and greedy based on problem size.
func optimalAssignment(entries []SparseEntry, numRows, numCols int) hungarianAssignment {
	n := max(numRows, numCols)

	// For very large problems or sparse matrices, use greedy
	// The Hungarian algorithm is O(n³), so we need heuristics
	if n*n*n > greedyFallbackThreshold*1000 || len(entries) > greedyFallbackThreshold {
		// Sort by score descending for greedy
		sortEntriesByScore(entries)
		return greedyAssignment(entries, numRows, numCols)
	}

	return hungarianOptimal(entries, numRows, numCols)
}

// sortEntriesByScore sorts entries by score in descending order.
func sortEntriesByScore(entries []SparseEntry) {
	// Simple insertion sort for small arrays, otherwise use standard sort
	for i := 1; i < len(entries); i++ {
		key := entries[i]
		j := i - 1
		for j >= 0 && entries[j].Score < key.Score {
			entries[j+1] = entries[j]
			j--
		}
		entries[j+1] = key
	}
}

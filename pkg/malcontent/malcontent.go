// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package malcontent

import (
	"context"
	"io"
	"io/fs"
	"maps"
	"sync"

	yarax "github.com/VirusTotal/yara-x/go"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

// Renderer is a common interface for Renderers.
type Renderer interface {
	Scanning(context.Context, string)
	File(context.Context, *FileReport) error
	Full(context.Context, *Config, *Report) error
	Name() string
}

type Config struct {
	Concurrency           int
	ExitExtraction        bool
	ExitFirstHit          bool
	ExitFirstMiss         bool
	FileRiskChange        bool
	FileRiskIncrease      bool
	IgnoreSelf            bool
	IgnoreTags            []string
	IncludeDataFiles      bool
	MinFileRisk           int
	MinRisk               int
	OCI                   bool
	Output                io.Writer
	Processes             bool
	QuantityIncreasesRisk bool
	Renderer              Renderer
	RuleFS                []fs.FS
	Rules                 *yarax.Rules
	Scan                  bool
	ScanPaths             []string
	Stats                 bool
	TrimPrefixes          []string
}

type Behavior struct {
	Description string `json:",omitempty" yaml:",omitempty"`
	// MatchStrings are all strings found relating to this behavior
	MatchStrings []string `json:",omitempty" yaml:",omitempty"`
	RiskScore    int
	RiskLevel    string `json:",omitempty" yaml:",omitempty"`

	RuleURL      string `json:",omitempty" yaml:",omitempty"`
	ReferenceURL string `json:",omitempty" yaml:",omitempty"`

	RuleAuthor    string `json:",omitempty" yaml:",omitempty"`
	RuleAuthorURL string `json:",omitempty" yaml:",omitempty"`

	RuleLicense    string `json:",omitempty" yaml:",omitempty"`
	RuleLicenseURL string `json:",omitempty" yaml:",omitempty"`

	DiffAdded   bool `json:",omitempty" yaml:",omitempty"`
	DiffRemoved bool `json:",omitempty" yaml:",omitempty"`

	// ID is the original map key from map[string]*Behavior
	ID string `json:",omitempty" yaml:",omitempty"`

	// Name is the value of m.Rule
	RuleName string `json:",omitempty" yaml:",omitempty"`

	// The name of the rule(s) this behavior overrides
	Override []string `json:",omitempty" yaml:",omitempty"`
}

type FileReport struct {
	Path   string
	SHA256 string
	Size   int64
	// compiler -> x
	Skipped           string            `json:",omitempty" yaml:",omitempty"`
	Meta              map[string]string `json:",omitempty" yaml:",omitempty"`
	Syscalls          []string          `json:",omitempty" yaml:",omitempty"`
	Pledge            []string          `json:",omitempty" yaml:",omitempty"`
	Capabilities      []string          `json:",omitempty" yaml:",omitempty"`
	Behaviors         []*Behavior       `json:",omitempty" yaml:",omitempty"`
	FilteredBehaviors int               `json:",omitempty" yaml:",omitempty"`

	// The absolute path we think this moved fron
	PreviousPath string `json:",omitempty" yaml:",omitempty"`
	// The relative path we think this moved from.
	PreviousRelPath string `json:",omitempty" yaml:",omitempty"`
	// The levenshtein distance between the previous path and the current path
	PreviousRelPathScore float64 `json:",omitempty" yaml:",omitempty"`
	PreviousRiskScore    int     `json:",omitempty" yaml:",omitempty"`
	PreviousRiskLevel    string  `json:",omitempty" yaml:",omitempty"`

	RiskScore int
	RiskLevel string `json:",omitempty" yaml:",omitempty"`

	IsMalcontent bool `json:",omitempty" yaml:",omitempty"`

	Overrides []*Behavior `json:",omitempty" yaml:",omitempty"`

	// Diffing archives is less straightforward than single files
	// Store additional paths to help with relative pathing
	ArchiveRoot string `json:",omitempty" yaml:",omitempty"`
	FullPath    string `json:",omitempty" yaml:",omitempty"`
}

type DiffReport struct {
	Added    *orderedmap.OrderedMap[string, *FileReport] `json:",omitempty" yaml:",omitempty"`
	Removed  *orderedmap.OrderedMap[string, *FileReport] `json:",omitempty" yaml:",omitempty"`
	Modified *orderedmap.OrderedMap[string, *FileReport] `json:",omitempty" yaml:",omitempty"`
}

// AggregateStats stores aggregate statistics instead of individual file reports.
type AggregateStats struct {
	FilesScanned     int64            // Total files processed
	FilesWithRisk    int64            // Files with risk > 0
	TotalBehaviors   int64            // Total behavior count across all files
	RiskDistribution map[string]int64 // Count of files by risk level
	BehaviorCounts   map[string]int64 // Count of behaviors by ID
	BytesScanned     int64            // Total bytes processed
	SkippedFiles     int64            // Files skipped (too large, data files, etc.)
	mutex            sync.RWMutex     // Protect concurrent access
}

// NewAggregateStats creates a new AggregateStats with initialized maps.
func NewAggregateStats() *AggregateStats {
	return &AggregateStats{
		RiskDistribution: make(map[string]int64),
		BehaviorCounts:   make(map[string]int64),
	}
}

// AddFileReport processes a file report and updates aggregate statistics.
func (as *AggregateStats) AddFileReport(fr *FileReport) {
	as.mutex.Lock()
	defer as.mutex.Unlock()

	as.FilesScanned++
	as.BytesScanned += fr.Size

	if fr.Skipped != "" {
		as.SkippedFiles++
		return
	}

	if fr.RiskScore > 0 {
		as.FilesWithRisk++
		as.RiskDistribution[fr.RiskLevel]++
	}

	as.TotalBehaviors += int64(len(fr.Behaviors))
	for _, behavior := range fr.Behaviors {
		as.BehaviorCounts[behavior.ID]++
	}
}

// GetStats returns a copy of the statistics for safe read access.
func (as *AggregateStats) GetStats() AggregateStats {
	as.mutex.RLock()
	defer as.mutex.RUnlock()

	// Deep copy maps
	riskDist := make(map[string]int64)
	maps.Copy(riskDist, as.RiskDistribution)

	behaviorCounts := make(map[string]int64)
	maps.Copy(behaviorCounts, as.BehaviorCounts)

	return AggregateStats{
		FilesScanned:     as.FilesScanned,
		FilesWithRisk:    as.FilesWithRisk,
		TotalBehaviors:   as.TotalBehaviors,
		RiskDistribution: riskDist,
		BehaviorCounts:   behaviorCounts,
		BytesScanned:     as.BytesScanned,
		SkippedFiles:     as.SkippedFiles,
	}
}

type Report struct {
	Stats  *AggregateStats
	Diff   *DiffReport
	Filter string
	Files  sync.Map `json:"-"`
}

// GetFiles returns all file reports as a regular map for easier API access.
func (r *Report) GetFiles() map[string]*FileReport {
	files := make(map[string]*FileReport)
	r.Files.Range(func(key, value any) bool {
		if path, ok := key.(string); ok {
			if fr, ok := value.(*FileReport); ok {
				files[path] = fr
			}
		}
		return true
	})
	return files
}

// GetFilesCount returns the number of files scanned.
func (r *Report) GetFilesCount() int {
	return int(r.Stats.FilesScanned)
}

// GetFilesWithRiskCount returns the number of files with risk findings.
func (r *Report) GetFilesWithRiskCount() int {
	return int(r.Stats.FilesWithRisk)
}

// GetRiskDistribution returns risk level distribution as a regular map.
func (r *Report) GetRiskDistribution() map[string]int64 {
	stats := r.Stats.GetStats()
	return stats.RiskDistribution
}

// GetBehaviorCounts returns behavior counts as a regular map.
func (r *Report) GetBehaviorCounts() map[string]int64 {
	stats := r.Stats.GetStats()
	return stats.BehaviorCounts
}

type IntMetric struct {
	Count int
	Key   int
	Total int
	Value float64
}

type StrMetric struct {
	Count int
	Key   string
	Total int
	Value float64
}

type CombinedReport struct {
	Added     string
	AddedFR   *FileReport
	Removed   string
	RemovedFR *FileReport
	Score     float64
}

// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"io"
	"sort"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// Report stores a JSON- or YAML-friendly representation of File Reports.
type Report struct {
	Diff   *malcontent.DiffReport            `json:",omitempty" yaml:",omitempty"`
	Files  map[string]*malcontent.FileReport `json:",omitempty" yaml:",omitempty"`
	Filter string                            `json:",omitempty" yaml:",omitempty"`
	Stats  *Stats                            `json:",omitempty" yaml:",omitempty"`
}

// Stats stores a JSON- or YAML-friendly Statistics report.
type Stats struct {
	PkgStats       []malcontent.StrMetric `json:",omitempty" yaml:",omitempty"`
	ProcessedFiles int                    `json:",omitempty" yaml:",omitempty"`
	RiskStats      []malcontent.IntMetric `json:",omitempty" yaml:",omitempty"`
	SkippedFiles   int                    `json:",omitempty" yaml:",omitempty"`
	TotalBehaviors int                    `json:",omitempty" yaml:",omitempty"`
	TotalRisks     int                    `json:",omitempty" yaml:",omitempty"`
}

// New returns a new Renderer.
func New(kind string, w io.Writer) (malcontent.Renderer, error) {
	switch kind {
	case "", "auto", "terminal":
		return NewTerminal(w), nil
	case "terminal_brief":
		return NewTerminalBrief(w), nil
	case "markdown":
		return NewMarkdown(w), nil
	case "yaml":
		yaml := NewYAML(w)
		return &yaml, nil
	case "json":
		json := NewJSON(w)
		return &json, nil
	case "simple":
		return NewSimple(w), nil
	case "strings":
		return NewStringMatches(w), nil
	case "interactive":
		t := NewInteractive(w)
		t.Start()
		return t, nil
	default:
		return nil, fmt.Errorf("unknown renderer: %q", kind)
	}
}

func riskEmoji(score int) string {
	symbol := "🔵"
	switch score {
	case 2:
		symbol = "🟡"
	case 3:
		symbol = "🛑"
	case 4:
		symbol = "😈"
	}

	return symbol
}

func serializedStats(_ *malcontent.Config, r *malcontent.Report) *Stats {
	// Use aggregate statistics instead of sync.Map for memory efficiency
	stats := r.Stats.GetStats()

	// Convert aggregate statistics to the old format for compatibility
	var riskStats []malcontent.IntMetric
	var totalRisks int

	for riskLevel, count := range stats.RiskDistribution {
		if count > 0 {
			percentage := (float64(count) / float64(stats.FilesScanned)) * 100
			// Convert risk level string back to int for compatibility
			var riskInt int
			switch riskLevel {
			case "NONE":
				riskInt = 0
			case "LOW":
				riskInt = 1
			case "MEDIUM", "MED":
				riskInt = 2
			case "HIGH":
				riskInt = 3
			case "CRITICAL", "CRIT":
				riskInt = 4
			}
			riskStats = append(riskStats, malcontent.IntMetric{
				Key:   riskInt,
				Value: percentage,
				Count: int(count),
				Total: int(stats.FilesScanned),
			})
			totalRisks += int(count)
		}
	}

	// Convert behavior statistics
	var pkgStats []malcontent.StrMetric
	for behaviorID, count := range stats.BehaviorCounts {
		if count > 0 && stats.TotalBehaviors > 0 {
			percentage := (float64(count) / float64(stats.TotalBehaviors)) * 100
			pkgStats = append(pkgStats, malcontent.StrMetric{
				Key:   behaviorID,
				Value: percentage,
				Count: int(count),
				Total: int(stats.TotalBehaviors),
			})
		}
	}

	sort.Slice(pkgStats, func(i, j int) bool {
		return pkgStats[i].Key < pkgStats[j].Key
	})

	sort.Slice(riskStats, func(i, j int) bool {
		return riskStats[i].Key < riskStats[j].Key
	})

	return &Stats{
		PkgStats:       pkgStats,
		ProcessedFiles: int(stats.FilesScanned),
		RiskStats:      riskStats,
		SkippedFiles:   int(stats.SkippedFiles),
		TotalBehaviors: int(stats.TotalBehaviors),
		TotalRisks:     totalRisks,
	}
}

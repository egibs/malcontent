// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Terminal Brief renderer
//
// Example:
//
// [CRITICAL] /bin/ls: frobber (whatever), xavier (whatever)
// [HIGH    ] /bin/zxa:
// [MED     ] /bin/ar:

package render

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

type TerminalBrief struct {
	w io.Writer
}

func NewTerminalBrief(w io.Writer) TerminalBrief {
	return TerminalBrief{w: w}
}

func (r TerminalBrief) Scanning(_ context.Context, path string) {
	fmt.Fprintf(r.w, "🔎 Scanning %q\n", path)
}

func (r TerminalBrief) File(_ context.Context, fr *malcontent.FileReport) error {
	if len(fr.Behaviors) == 0 {
		return nil
	}

	fmt.Fprintf(r.w, "├─ %s %s\n", riskEmoji(fr.RiskScore), fr.Path)

	for _, b := range fr.Behaviors {
		evidence := []string{}
		for _, m := range b.MatchStrings {
			if len(m) > 2 && !strings.Contains(b.Description, m) {
				evidence = append(evidence, m)
			}
		}

		e := strings.Join(evidence, ", ")
		if len(e) > 32 {
			e = e[0:31] + "…"
		}
		if len(e) > 0 {
			e = ": " + e
		}

		fmt.Fprintf(r.w, "│  %s %s — %s%s\n", riskColor(fr.RiskLevel, "•"), riskColor(fr.RiskLevel, b.ID), b.Description, e)
	}

	return nil
}

func (r TerminalBrief) Full(_ context.Context, rep *malcontent.Report) error {
	// Non-diff files are handled on the fly by File()
	if rep.Diff == nil {
		return nil
	}

	return fmt.Errorf("diffs are unsupported by the TerminalBrief renderer")
}

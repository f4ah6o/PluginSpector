// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Meta stage: risk scoring and the static "fallback" enrichment. The Python
// meta-analyzer also performs per-file LLM filtering; that path is not ported,
// so the Go build always uses the fallback (static-only) behavior, matching the
// upstream behavior when no LLM credentials are available.

package scanner

import "strings"

// llmStatus mirrors the llm_* fields the Python meta-analyzer reports.
type llmStatus struct {
	used          bool
	failed        bool
	fallbackUsed  bool
	errorMsg      string
	filesAnalyzed int
	batches       int
}

// llmNotImplementedError is surfaced when --no-llm is not passed but the Go
// build cannot run semantic analysis.
const llmNotImplementedError = "LLM semantic analysis is not implemented in the Go port; run with --no-llm to silence this warning"

// runMeta applies the static fallback and returns the (filtered) findings plus
// the LLM status block. With useLLM=false it is a clean pass-through; with
// useLLM=true it records a fallback (the static result is identical either way).
func runMeta(st *scanState, findings []Finding, strictLLM bool) ([]Finding, llmStatus, error) {
	filtered := applyFallback(findings)
	if !st.UseLLM {
		return filtered, llmStatus{}, nil
	}
	if strictLLM {
		return nil, llmStatus{}, &scanError{msg: "LLM analysis failed and --strict-llm is set: " + llmNotImplementedError}
	}
	return filtered, llmStatus{failed: true, fallbackUsed: true, errorMsg: llmNotImplementedError}, nil
}

// applyFallback fills in default remediations (pass-through with defaults).
func applyFallback(findings []Finding) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		g := f
		if g.Remediation == "" {
			g.Remediation = getRemediation(f.RuleID)
		}
		if g.CodeSnippet == "" {
			g.CodeSnippet = f.Context
		}
		g.Intent = ""
		out = append(out, g)
	}
	return out
}

var riskSeverityBands = []struct {
	threshold int
	band      string
}{
	{81, "CRITICAL"}, {51, "HIGH"}, {21, "MEDIUM"}, {0, "LOW"},
}

var riskRecommendation = map[string]string{
	"LOW": "SAFE", "MEDIUM": "CAUTION", "HIGH": "DO_NOT_INSTALL", "CRITICAL": "DO_NOT_INSTALL",
}

// computeRiskScore mirrors report._compute_risk_score (v1 rules).
func computeRiskScore(findings []Finding, hasExecutableScripts bool) (int, string, string) {
	score := 0
	for _, f := range findings {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			score += 50
		case "HIGH":
			score += 25
		case "MEDIUM":
			score += 10
		case "LOW":
			score += 5
		}
	}
	if hasExecutableScripts {
		score = int(float64(score) * 1.3)
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	band := "LOW"
	for _, b := range riskSeverityBands {
		if score >= b.threshold {
			band = b.band
			break
		}
	}
	rec := riskRecommendation[band]
	if rec == "" {
		rec = "CAUTION"
	}
	return score, band, rec
}

type scanError struct{ msg string }

func (e *scanError) Error() string { return e.msg }

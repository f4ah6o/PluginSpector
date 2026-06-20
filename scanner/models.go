// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Go port of PluginSpector: a security scanner for Claude Code plugins and
// AI agent skills. This package preserves the upstream Python analyzer rules,
// risk-scoring philosophy, and output formats (terminal/JSON/Markdown/SARIF)
// so the same "is this plugin safe to install?" gate can run as a single
// pure-Go binary or be embedded as a library (e.g. from gh-agent-plugin).

package scanner

import "unicode/utf8"

// Version mirrors the Python package version for report/SARIF compatibility.
const Version = "2.2.0"

// Severity levels for findings (used by all analyzers).
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Location of a finding within a file.
type Location struct {
	File      string
	StartLine int
	EndLine   *int
}

// AnalyzerFinding is the common finding type produced by any analyzer
// (static, behavioral, MCP, etc.) before conversion to a graph-state Finding.
type AnalyzerFinding struct {
	RuleID      string
	Message     string
	Severity    Severity
	Location    Location
	Confidence  float64
	Remediation string
	Tags        []string
	Context     string
	MatchedText string
}

// Finding is the model used for reporting output (shape aligned with to_dict).
type Finding struct {
	RuleID      string
	Message     string
	Severity    string
	Confidence  float64
	File        string
	StartLine   int
	EndLine     *int
	Category    string
	Pattern     string
	Finding     string // short matched snippet
	Explanation string
	Remediation string
	CodeSnippet string
	Intent      string
	Tags        []string
	Context     string
	MatchedText string
}

// regionJSON / location structures used in the JSON "issues" array.
type findingLocationJSON struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   *int   `json:"end_line"`
}

type findingJSON struct {
	ID          string              `json:"id"`
	Category    *string             `json:"category"`
	Pattern     *string             `json:"pattern"`
	Severity    string              `json:"severity"`
	Confidence  float64             `json:"confidence"`
	Location    findingLocationJSON `json:"location"`
	Finding     *string             `json:"finding"`
	Explanation *string             `json:"explanation"`
	Remediation *string             `json:"remediation"`
	CodeSnippet *string             `json:"code_snippet"`
	Intent      *string             `json:"intent"`
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// toJSON renders the full finding shape matching Python Finding.to_dict().
func (f Finding) toJSON() findingJSON {
	expl := f.Explanation
	if expl == "" {
		expl = f.Message
	}
	code := f.CodeSnippet
	if code == "" {
		code = f.Context
	}
	return findingJSON{
		ID:          f.RuleID,
		Category:    nilIfEmpty(f.Category),
		Pattern:     nilIfEmpty(f.Pattern),
		Severity:    f.Severity,
		Confidence:  f.Confidence,
		Location:    findingLocationJSON{File: f.File, StartLine: f.StartLine, EndLine: f.EndLine},
		Finding:     nilIfEmpty(f.Finding),
		Explanation: nilIfEmpty(expl),
		Remediation: nilIfEmpty(f.Remediation),
		CodeSnippet: nilIfEmpty(code),
		Intent:      nilIfEmpty(f.Intent),
	}
}

// truncateRunes mirrors Python's str[:n] slicing (by code points, not bytes).
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

func intPtr(i int) *int { return &i }

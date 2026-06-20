// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Public scanner API. This is the entry point both the CLI and external callers
// (e.g. github.com/f4ah6o/gh-agent-plugin) use to gate a plugin/skill before
// preview or install.

package scanner

import (
	"encoding/json"
	"fmt"
)

// Format is an output format for the rendered report body.
type Format string

const (
	FormatTerminal Format = "terminal"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
	FormatSARIF    Format = "sarif"
)

// Options configures a scan.
type Options struct {
	// InputPath is a directory, .md file, .zip, git URL, or file URL.
	InputPath string
	// Format selects the rendered ReportBody. Defaults to terminal.
	Format Format
	// UseLLM requests semantic (LLM) analysis. The Go build does not implement
	// it, so when true the scan falls back to static analysis and reports the
	// fallback (matching upstream behavior with no LLM credentials).
	UseLLM bool
	// StrictLLM fails the scan if LLM analysis was requested but unavailable.
	StrictLLM bool
	// YaraRulesDir is accepted for CLI compatibility (YARA is not yet ported).
	YaraRulesDir string
}

// Result is the outcome of a scan: the gate decision plus the findings and the
// rendered report.
type Result struct {
	Findings           []Finding
	RiskScore          int
	RiskSeverity       string
	RiskRecommendation string
	ReportBody         string
	Sarif              SarifLog
	TargetType         string
	SkillName          string
	Source             string
	SkippedFiles       []string
}

// blockingRuleIDs gate installation regardless of the aggregate risk score.
// These are host-filesystem escapes that can smuggle external files into the
// scanned target; a single occurrence (HIGH = 25, below the >50 threshold)
// must still block an install, so they are special-cased here.
var blockingRuleIDs = map[string]bool{
	"CP002": true, // declared component path escapes the plugin/scan root
	"CP003": true, // symlink escapes the scan root
}

// ShouldBlockInstall reports whether the scanned target should be blocked from
// install/preview. It blocks when the aggregate risk score exceeds 50 (the CLI
// gate) or when any always-blocking structural finding is present.
func (r *Result) ShouldBlockInstall() bool {
	if r.RiskScore > 50 {
		return true
	}
	for _, f := range r.Findings {
		if blockingRuleIDs[f.RuleID] {
			return true
		}
	}
	return false
}

// BlockReasons returns the rule IDs of always-blocking findings present in the
// result (empty when the gate, if any, is driven purely by the risk score).
func (r *Result) BlockReasons() []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range r.Findings {
		if blockingRuleIDs[f.RuleID] && !seen[f.RuleID] {
			seen[f.RuleID] = true
			out = append(out, f.RuleID)
		}
	}
	return out
}

// SarifJSON returns the indented SARIF 2.1.0 document for the result.
func (r *Result) SarifJSON() []byte {
	b, _ := json.MarshalIndent(r.Sarif, "", "  ")
	return b
}

// Scan resolves the input, runs the analyzer pipeline, scores the risk, and
// renders the report in the requested format.
func Scan(opts Options) (*Result, error) {
	if opts.InputPath == "" {
		return nil, fmt.Errorf("input path is required")
	}
	format := opts.Format
	if format == "" {
		format = FormatTerminal
	}

	h := &inputHandler{}
	defer h.cleanup()
	skillDir, _, err := h.resolve(opts.InputPath)
	if err != nil {
		return nil, err
	}

	st := buildContext(skillDir, opts.YaraRulesDir, opts.UseLLM)

	findings := runAnalyzers(st)
	// Escaping symlinks are detected during the file walk; surface them as
	// findings so they affect the risk score even for non-plugin targets.
	findings = append(findings, symlinkEscapeFindings(st)...)

	filtered, llm, err := runMeta(st, findings, opts.StrictLLM)
	if err != nil {
		return nil, err
	}

	score, severity, rec := computeRiskScore(filtered, st.HasExecutableScripts)

	in := reportInput{
		findings:     filtered,
		components:   st.ComponentMetadata,
		skillName:    st.Manifest.Name,
		source:       skillDir,
		targetType:   st.TargetType,
		riskScore:    score,
		riskSeverity: severity,
		riskRec:      rec,
		hasExec:      st.HasExecutableScripts,
		useLLM:       opts.UseLLM,
		skipped:      st.SkippedFiles,
		llm:          llm,
		llmAvailable: !opts.UseLLM, // the Go build has no LLM backend
	}

	sarif := buildSarif(filtered)
	var body string
	switch format {
	case FormatJSON:
		body = formatJSON(in)
	case FormatMarkdown:
		body = formatMarkdown(in)
	case FormatSARIF:
		body = sarifJSON(filtered)
	default:
		body = formatTerminal(in)
	}

	return &Result{
		Findings:           filtered,
		RiskScore:          score,
		RiskSeverity:       severity,
		RiskRecommendation: rec,
		ReportBody:         body,
		Sarif:              sarif,
		TargetType:         st.TargetType,
		SkillName:          st.Manifest.Name,
		Source:             skillDir,
		SkippedFiles:       st.SkippedFiles,
	}, nil
}

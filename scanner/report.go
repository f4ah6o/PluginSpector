// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Report rendering: SARIF 2.1.0, JSON, Markdown, and a plain-text terminal
// report. Ported from src/pluginspector/nodes/report.py and sarif_models.py.

package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const sarifSchemaURI = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json"

// --- SARIF structures --------------------------------------------------------

type sarifRegion struct {
	StartLine   int  `json:"startLine"`
	StartColumn *int `json:"startColumn,omitempty"`
	EndLine     *int `json:"endLine,omitempty"`
	EndColumn   *int `json:"endColumn,omitempty"`
}

type sarifArtifactLocation struct {
	URI   string `json:"uri"`
	Index *int   `json:"index,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Message   sarifMessage    `json:"message"`
	Level     string          `json:"level"`
	Locations []sarifLocation `json:"locations"`
}

type sarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type sarifRun struct {
	Tool    struct {
		Driver sarifDriver `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}

// SarifLog is the top-level SARIF 2.1.0 document (exported for library callers).
type SarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema,omitempty"`
	Runs    []sarifRun `json:"runs"`
}

func severityToSarifLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

func buildSarif(findings []Finding) SarifLog {
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Message: sarifMessage{Text: f.Message},
			Level:   severityToSarifLevel(f.Severity),
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.File},
					Region:           &sarifRegion{StartLine: f.StartLine, EndLine: f.EndLine},
				},
			}},
		})
	}
	var run sarifRun
	run.Tool.Driver = sarifDriver{Name: "pluginspector", Version: Version}
	run.Results = results
	return SarifLog{Version: "2.1.0", Schema: sarifSchemaURI, Runs: []sarifRun{run}}
}

// --- JSON report -------------------------------------------------------------

type componentJSON struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Lines      int    `json:"lines"`
	Executable bool   `json:"executable"`
	SizeBytes  int64  `json:"size_bytes"`
}

type skillJSON struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	TargetType string `json:"target_type"`
	ScannedAt  string `json:"scanned_at"`
}

type riskJSON struct {
	Score          int    `json:"score"`
	Severity       string `json:"severity"`
	Recommendation string `json:"recommendation"`
}

type metadataJSON struct {
	HasExecutableScripts bool     `json:"has_executable_scripts"`
	TargetType           string   `json:"target_type"`
	PluginspectorVersion string   `json:"pluginspector_version"`
	LLMRequested         bool     `json:"llm_requested"`
	LLMAvailable         bool     `json:"llm_available"`
	LLMAvailabilityError *string  `json:"llm_availability_error,omitempty"`
	LLMUsed              bool     `json:"llm_used"`
	LLMFailed            bool     `json:"llm_failed"`
	LLMFallbackUsed      bool     `json:"llm_fallback_used"`
	LLMError             *string  `json:"llm_error"`
	LLMFilesAnalyzed     int      `json:"llm_files_analyzed"`
	LLMBatchesAnalyzed   int      `json:"llm_batches_analyzed"`
	PartialScan          bool     `json:"partial_scan"`
	SkippedFilesCount    int      `json:"skipped_files_count,omitempty"`
	SkippedFiles         []string `json:"skipped_files,omitempty"`
	StubAnalyzers        []string `json:"stub_analyzers,omitempty"`
	StubAnalyzersNote    string   `json:"stub_analyzers_note,omitempty"`
}

type jsonReport struct {
	Skill          skillJSON       `json:"skill"`
	RiskAssessment riskJSON        `json:"risk_assessment"`
	Components     []componentJSON `json:"components"`
	Issues         []findingJSON   `json:"issues"`
	Metadata       metadataJSON    `json:"metadata"`
}

// reportInput carries everything the renderers need.
type reportInput struct {
	findings     []Finding
	components   []componentMeta
	skillName    string
	source       string
	targetType   string
	riskScore    int
	riskSeverity string
	riskRec      string
	hasExec      bool
	useLLM       bool
	skipped      []string
	llm          llmStatus
	llmAvailable bool
}

func buildMetadata(in reportInput) metadataJSON {
	m := metadataJSON{
		HasExecutableScripts: in.hasExec,
		TargetType:           defaultStr(in.targetType, "standalone-skill"),
		PluginspectorVersion: Version,
		LLMRequested:         in.useLLM,
		LLMAvailable:         in.llmAvailable,
		LLMUsed:              in.llm.used,
		LLMFailed:            in.llm.failed,
		LLMFallbackUsed:      in.llm.fallbackUsed,
		LLMFilesAnalyzed:     in.llm.filesAnalyzed,
		LLMBatchesAnalyzed:   in.llm.batches,
	}
	if in.useLLM && !in.llmAvailable {
		e := in.llm.errorMsg
		m.LLMAvailabilityError = &e
	}
	if in.llm.errorMsg != "" {
		e := in.llm.errorMsg
		m.LLMError = &e
	}
	if len(in.skipped) > 0 {
		m.PartialScan = true
		m.SkippedFilesCount = len(in.skipped)
		cap := in.skipped
		if len(cap) > 50 {
			cap = cap[:50]
		}
		m.SkippedFiles = cap
	}
	if stubs := stubAnalyzerIDs(); len(stubs) > 0 {
		m.StubAnalyzers = stubs
		m.StubAnalyzersNote = "These analyzers are registered but return no findings. A clean report does not guarantee absence of issues in their categories."
	}
	return m
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func formatJSON(in reportInput) string {
	comps := make([]componentJSON, 0, len(in.components))
	for _, c := range in.components {
		comps = append(comps, componentJSON{Path: c.Path, Type: c.Type, Lines: c.Lines, Executable: c.Executable, SizeBytes: c.SizeBytes})
	}
	issues := make([]findingJSON, 0, len(in.findings))
	for _, f := range in.findings {
		issues = append(issues, f.toJSON())
	}
	report := jsonReport{
		Skill: skillJSON{
			Name:       defaultStr(in.skillName, "unknown"),
			Source:     in.source,
			TargetType: defaultStr(in.targetType, "standalone-skill"),
			ScannedAt:  time.Now().UTC().Format(time.RFC3339),
		},
		RiskAssessment: riskJSON{Score: in.riskScore, Severity: in.riskSeverity, Recommendation: in.riskRec},
		Components:     comps,
		Issues:         issues,
		Metadata:       buildMetadata(in),
	}
	b, _ := json.MarshalIndent(report, "", "  ")
	return string(b)
}

func sarifJSON(findings []Finding) string {
	b, _ := json.MarshalIndent(buildSarif(findings), "", "  ")
	return string(b)
}

// --- Markdown report ---------------------------------------------------------

func pct(conf float64) string { return fmt.Sprintf("%.0f%%", conf*100) }

func endRange(f Finding) string {
	if f.EndLine != nil && *f.EndLine != f.StartLine {
		return fmt.Sprintf("–%d", *f.EndLine)
	}
	return ""
}

func formatMarkdown(in reportInput) string {
	var b strings.Builder
	skillName := defaultStr(in.skillName, "unknown")
	b.WriteString("# PluginSpector Security Report\n\n")
	fmt.Fprintf(&b, "**Skill:** %s  \n", skillName)
	fmt.Fprintf(&b, "**Target Type:** %s  \n", defaultStr(in.targetType, "standalone-skill"))
	fmt.Fprintf(&b, "**Source:** `%s`  \n", in.source)
	fmt.Fprintf(&b, "**Scanned:** %s  \n\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

	b.WriteString("## Risk Assessment\n\n| Metric | Value |\n|--------|-------|\n")
	fmt.Fprintf(&b, "| Score | %d/100 |\n", in.riskScore)
	fmt.Fprintf(&b, "| Severity | %s |\n", in.riskSeverity)
	fmt.Fprintf(&b, "| Recommendation | %s |\n\n", strings.ReplaceAll(in.riskRec, "_", " "))

	fmt.Fprintf(&b, "## Components (%d)\n\n| File | Type | Lines | Executable |\n|------|------|-------|------------|\n", len(in.components))
	for _, c := range in.components {
		exec := "No"
		if c.Executable {
			exec = "Yes"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %d | %s |\n", c.Path, c.Type, c.Lines, exec)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "## Issues (%d)\n\n", len(in.findings))
	if len(in.findings) == 0 {
		b.WriteString("No security issues detected.\n")
	} else {
		for _, f := range in.findings {
			sev := strings.ToUpper(defaultStr(f.Severity, "LOW"))
			emoji := map[string]string{"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "🔴"}[sev]
			fmt.Fprintf(&b, "### %s %s: %s\n\n", emoji, sev, f.RuleID)
			fmt.Fprintf(&b, "**Location:** `%s:%d%s`  \n", f.File, f.StartLine, endRange(f))
			fmt.Fprintf(&b, "**Confidence:** %s  \n\n", pct(f.Confidence))
			fmt.Fprintf(&b, "**Message:** %s\n\n", f.Message)
			if f.Remediation != "" {
				fmt.Fprintf(&b, "**Remediation:** %s\n\n", f.Remediation)
			}
			b.WriteString("---\n\n")
		}
	}
	b.WriteString("## Metadata\n\n")
	exec := "No"
	if in.hasExec {
		exec = "Yes"
	}
	fmt.Fprintf(&b, "- **Executable Scripts:** %s\n", exec)
	fmt.Fprintf(&b, "\n*Generated by PluginSpector v%s*", Version)
	return b.String()
}

// --- Terminal (plain-text) report -------------------------------------------

func formatTerminal(in reportInput) string {
	var b strings.Builder
	skillName := defaultStr(in.skillName, "unknown")
	b.WriteString("\n=== PluginSpector Security Report ===  (v" + Version + ")\n\n")
	fmt.Fprintf(&b, "Skill:       %s\n", skillName)
	fmt.Fprintf(&b, "Target Type: %s\n", defaultStr(in.targetType, "standalone-skill"))
	fmt.Fprintf(&b, "Source:      %s\n", in.source)
	fmt.Fprintf(&b, "Scanned:     %s\n\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

	b.WriteString("Risk Assessment\n")
	fmt.Fprintf(&b, "  Score:          %d/100\n", in.riskScore)
	fmt.Fprintf(&b, "  Severity:       %s\n", in.riskSeverity)
	fmt.Fprintf(&b, "  Recommendation: %s\n\n", strings.ReplaceAll(in.riskRec, "_", " "))

	fmt.Fprintf(&b, "Components (%d)\n", len(in.components))
	shown := in.components
	if len(shown) > 15 {
		shown = shown[:15]
	}
	for _, c := range shown {
		exec := "No"
		if c.Executable {
			exec = "Yes"
		}
		fmt.Fprintf(&b, "  %-40s %-10s %5d lines  exec=%s\n", c.Path, c.Type, c.Lines, exec)
	}
	if len(in.components) > 15 {
		fmt.Fprintf(&b, "  ... and %d more\n", len(in.components)-15)
	}
	b.WriteString("\n")

	if len(in.findings) > 0 {
		fmt.Fprintf(&b, "Issues (%d)\n", len(in.findings))
		for _, f := range in.findings {
			sev := strings.ToUpper(defaultStr(f.Severity, "LOW"))
			fmt.Fprintf(&b, "  [%s] %s - %s\n", sev, f.RuleID, truncateRunes(f.Message, 60))
			fmt.Fprintf(&b, "      Location:   %s:%d%s\n", f.File, f.StartLine, endRange(f))
			fmt.Fprintf(&b, "      Confidence: %s\n", pct(f.Confidence))
			if f.Remediation != "" {
				fmt.Fprintf(&b, "      Remediation: %s\n", truncateRunes(f.Remediation, 150))
			}
			b.WriteString("\n")
		}
	} else {
		b.WriteString("No security issues detected.\n\n")
	}

	execStr := "No"
	if in.hasExec {
		execStr = "Yes"
	}
	fmt.Fprintf(&b, "Executable scripts: %s\n", execStr)

	if in.llm.fallbackUsed {
		b.WriteString("\nWarning: LLM analysis was requested but failed — results are static analysis only. Use --no-llm to suppress this warning.\n")
		if in.llm.errorMsg != "" {
			fmt.Fprintf(&b, "LLM error: %s\n", in.llm.errorMsg)
		}
	}
	if len(in.skipped) > 0 {
		fmt.Fprintf(&b, "\nWarning: Partial scan — %d file(s) were skipped due to size/depth limits.\n", len(in.skipped))
	}
	return b.String()
}

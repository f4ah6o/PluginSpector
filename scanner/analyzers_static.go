// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Static-pattern analyzer families (P/E/PE/EA/OH/MP/TM/RA/SC harmful) ported
// from src/pluginspector/nodes/analyzers/static_patterns_*.py.

package scanner

import (
	"strings"

	"github.com/dlclark/regexp2"
)

const maxFileBytes = 1_000_000

var evalDatasetFiles = map[string]bool{
	"evals/evals.json": true, "evals/evals.jsonl": true,
	"evals/evals.yaml": true, "evals/evals.yml": true,
	"eval/dataset.json": true, "eval/dataset.jsonl": true,
	"eval/dataset.yaml": true, "eval/dataset.yml": true,
}

var fileTypes = map[string]string{
	".md": "markdown", ".markdown": "markdown", ".py": "python",
	".sh": "shell", ".bash": "shell", ".zsh": "shell", ".json": "json",
	".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".txt": "text",
	".js": "javascript", ".ts": "typescript", ".rb": "ruby", ".go": "go", ".rs": "rust",
}

func inferFileType(path string) string {
	idx := strings.LastIndex(path, ".")
	if idx < 0 {
		return "other"
	}
	if t, ok := fileTypes[strings.ToLower(path[idx:])]; ok {
		return t
	}
	return "other"
}

func isEvalDataset(path string) bool {
	return evalDatasetFiles[strings.ReplaceAll(path, "\\", "/")]
}

// analyzerFindingToFinding mirrors static_runner.analyzer_finding_to_finding.
func analyzerFindingToFinding(af AnalyzerFinding) Finding {
	remediation := af.Remediation
	if remediation == "" {
		remediation = getRemediation(af.RuleID)
	}
	category := ""
	if len(af.Tags) > 0 {
		category = af.Tags[0]
	}
	if category == "" {
		category = getCategory(af.RuleID)
	}
	pattern := af.Message
	if pattern == "" {
		pattern = getPatternName(af.RuleID)
	}
	snippet := ""
	if af.MatchedText != "" {
		snippet = truncateRunes(af.MatchedText, 200)
	}
	return Finding{
		RuleID:      af.RuleID,
		Message:     af.Message,
		Severity:    string(af.Severity),
		Confidence:  af.Confidence,
		File:        af.Location.File,
		StartLine:   af.Location.StartLine,
		EndLine:     af.Location.EndLine,
		Remediation: remediation,
		Tags:        append([]string(nil), af.Tags...),
		Context:     af.Context,
		MatchedText: snippet,
		Category:    category,
		Pattern:     pattern,
		Finding:     snippet,
		Explanation: getExplanation(af.RuleID),
		CodeSnippet: af.Context,
	}
}

// patternAnalyzer is a per-file analyze function (content, path, fileType).
type patternAnalyzer func(content, filePath, fileType string) []AnalyzerFinding

// runStaticPatterns mirrors static_runner.run_static_patterns.
func runStaticPatterns(st *scanState, analyze patternAnalyzer) []Finding {
	var findings []Finding
	for _, path := range st.Components {
		if isEvalDataset(path) {
			continue
		}
		content, ok := st.FileCache[path]
		if !ok {
			continue
		}
		if len(content) > maxFileBytes {
			continue
		}
		ft := inferFileType(path)
		for _, af := range analyze(content, path, ft) {
			findings = append(findings, analyzerFindingToFinding(af))
		}
	}
	return findings
}

// emit is the common path: every match becomes a finding with fixed metadata.
func emit(content string, runes []rune, filePath string, pats []pat, ruleID, message string, sev Severity, tag string, ctxLines int, out *[]AnalyzerFinding) {
	for _, p := range pats {
		for _, m := range findAll(p.re, content) {
			ln := getLineNumber(runes, m.start)
			*out = append(*out, AnalyzerFinding{
				RuleID:      ruleID,
				Message:     message,
				Severity:    sev,
				Location:    Location{File: filePath, StartLine: ln},
				Confidence:  p.conf,
				Tags:        []string{tag},
				Context:     getContext(content, runes, m.start, ctxLines),
				MatchedText: truncateRunes(m.text, 200),
			})
		}
	}
}

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func isCodeFileType(ft string) bool {
	return ft == "python" || ft == "javascript" || ft == "shell"
}

// --- prompt injection (P1–P4) ------------------------------------------------

func analyzePromptInjection(content, filePath, fileType string) []AnalyzerFinding {
	runes := []rune(content)
	var out []AnalyzerFinding
	emit(content, runes, filePath, p1Pats, "P1", "Instruction Override", SeverityHigh, catPromptInjection, 3, &out)
	if fileType == "markdown" || fileType == "other" {
		emit(content, runes, filePath, p2Pats, "P2", "Hidden Instructions", SeverityHigh, catPromptInjection, 3, &out)
	}
	emit(content, runes, filePath, p3Pats, "P3", "Exfiltration Commands", SeverityHigh, catPromptInjection, 3, &out)
	emit(content, runes, filePath, p4Pats, "P4", "Behavior Manipulation", SeverityMedium, catPromptInjection, 3, &out)
	return out
}

// --- data exfiltration (E1–E4) -----------------------------------------------

func analyzeDataExfiltration(content, filePath, fileType string) []AnalyzerFinding {
	runes := []rune(content)
	var out []AnalyzerFinding
	for _, p := range e1Pats {
		for _, m := range findAll(p.re, content) {
			conf := p.conf
			if isCodeFileType(fileType) {
				conf = minf(1.0, p.conf+0.1)
			}
			out = append(out, mkAF("E1", "External Transmission", SeverityMedium, filePath, runes, content, m, conf, catDataExfiltration, 3))
		}
	}
	emit(content, runes, filePath, e2Pats, "E2", "Env Variable Harvesting", SeverityHigh, catDataExfiltration, 3, &out)
	emit(content, runes, filePath, e3Pats, "E3", "File System Enumeration", SeverityMedium, catDataExfiltration, 3, &out)
	emit(content, runes, filePath, e4Pats, "E4", "Context Leakage", SeverityHigh, catDataExfiltration, 3, &out)
	return out
}

// mkAF builds a single AnalyzerFinding for the customized loops.
func mkAF(ruleID, message string, sev Severity, filePath string, runes []rune, content string, m patMatch, conf float64, tag string, ctxLines int) AnalyzerFinding {
	return AnalyzerFinding{
		RuleID:      ruleID,
		Message:     message,
		Severity:    sev,
		Location:    Location{File: filePath, StartLine: getLineNumber(runes, m.start)},
		Confidence:  conf,
		Tags:        []string{tag},
		Context:     getContext(content, runes, m.start, ctxLines),
		MatchedText: truncateRunes(m.text, 200),
	}
}

// --- privilege escalation (PE1–PE3) ------------------------------------------

var pe2DocIndicators = []string{
	"example:", "for example", "e.g.", "such as", "documentation",
	"# warning:", "# note:", "**warning**", "**note**", "```",
	"settings >", "navigate to", "go to ", "> ci/cd", "> runners",
	"> merge request", "> access token", "| yes |", "| no |",
	"| required |", "| optional |", "env variable", "environment variable", "create ",
}

func isPEDocExample(context string) bool {
	low := strings.ToLower(context)
	for _, ind := range pe2DocIndicators {
		if strings.Contains(low, ind) {
			return true
		}
	}
	return false
}

func analyzePrivilegeEscalation(content, filePath, fileType string) []AnalyzerFinding {
	runes := []rune(content)
	var out []AnalyzerFinding
	emit(content, runes, filePath, pe1Pats, "PE1", "Excessive Permissions", SeverityLow, catPrivilegeEscalation, 3, &out)
	for _, p := range pe2Pats {
		for _, m := range findAll(p.re, content) {
			ctx := getContext(content, runes, m.start, 3)
			if isPEDocExample(ctx) {
				continue
			}
			out = append(out, mkAF("PE2", "Sudo/Root Execution", SeverityMedium, filePath, runes, content, m, p.conf, catPrivilegeEscalation, 3))
		}
	}
	for _, p := range pe3Pats {
		for _, m := range findAll(p.re, content) {
			ctx := getContext(content, runes, m.start, 3)
			if isPEDocExample(ctx) {
				continue
			}
			out = append(out, mkAF("PE3", "Credential Access", SeverityHigh, filePath, runes, content, m, p.conf, catPrivilegeEscalation, 3))
		}
	}
	return out
}

// --- harmful content (P5) ----------------------------------------------------

func analyzeHarmfulContent(content, filePath, fileType string) []AnalyzerFinding {
	runes := []rune(content)
	var out []AnalyzerFinding
	for _, p := range dangerousActions {
		for _, m := range findAll(p.re, content) {
			out = append(out, mkAF("P5", "Harmful Content Injection", SeverityCritical, filePath, runes, content, m, p.conf, catPromptInjection, 5))
		}
	}
	for _, p := range substancePats {
		for _, m := range findAll(p.re, content) {
			ctx := getContext(content, runes, m.start, 5)
			conf := p.conf
			if isInstructionalContext(content, runes, m.start) {
				conf = 0.95
			} else if isEducationalContext(ctx) {
				conf = 0.3
			} else if isWarningContext(ctx) {
				conf = 0.2
			}
			if conf >= 0.5 {
				out = append(out, mkAF("P5", "Harmful Content Injection", SeverityCritical, filePath, runes, content, m, conf, catPromptInjection, 5))
			}
		}
	}
	return dedupHarmful(out)
}

func sliceRunes(runes []rune, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(runes) {
		end = len(runes)
	}
	if start >= end {
		return ""
	}
	return string(runes[start:end])
}

func isInstructionalContext(content string, runes []rune, matchStart int) bool {
	surrounding := strings.ToLower(sliceRunes(runes, matchStart-250, matchStart+250))
	markers := []string{"step ", "recipe", "ingredient", "add ", "mix ", "stir ", "instructions", "how to", "directions", "prepare", "cook", "bake"}
	for _, mk := range markers {
		if strings.Contains(surrounding, mk) {
			return true
		}
	}
	return false
}

func isEducationalContext(context string) bool {
	markers := []string{"history of", "discovered by", "chemical compound", "periodic table", "forensic", "detective", "mystery", "agatha christie", "toxicology", "poison control", "symptoms of", "treatment for", "antidote", "emergency", "call 911", "warning", "danger", "never", "do not"}
	low := strings.ToLower(context)
	for _, mk := range markers {
		if strings.Contains(low, mk) {
			return true
		}
	}
	return false
}

var warningContextRe = []*regexp2.Regexp{
	compile(`do\s+not`, regexp2.None),
	compile(`never\s+(?:use|add|consume|eat|drink)`, regexp2.None),
	compile(`warning`, regexp2.None), compile(`danger`, regexp2.None),
	compile(`toxic`, regexp2.None), compile(`lethal`, regexp2.None),
	compile(`deadly`, regexp2.None), compile(`fatal`, regexp2.None),
	compile(`avoid`, regexp2.None), compile(`keep\s+away`, regexp2.None),
}

func isWarningContext(context string) bool {
	low := strings.ToLower(context)
	for _, re := range warningContextRe {
		if matchString(re, low) {
			return true
		}
	}
	return false
}

func dedupHarmful(findings []AnalyzerFinding) []AnalyzerFinding {
	type key struct {
		file string
		line int
	}
	seen := map[key]int{} // key -> index in unique
	var unique []AnalyzerFinding
	for _, f := range findings {
		k := key{f.Location.File, f.Location.StartLine}
		if idx, ok := seen[k]; ok {
			if f.Confidence > unique[idx].Confidence {
				unique[idx] = f
			}
			continue
		}
		seen[k] = len(unique)
		unique = append(unique, f)
	}
	return unique
}

// --- excessive agency (EA1–EA4) ----------------------------------------------

func analyzeExcessiveAgency(content, filePath, fileType string) []AnalyzerFinding {
	runes := []rune(content)
	var out []AnalyzerFinding
	emit(content, runes, filePath, ea1Pats, "EA1", "Unrestricted Tool Access", SeverityMedium, catExcessiveAgency, 3, &out)
	for _, p := range ea2Pats {
		for _, m := range findAll(p.re, content) {
			ctx := getContext(content, runes, m.start, 3)
			if isCodeExample(ctx) {
				continue
			}
			out = append(out, mkAF("EA2", "Autonomous Decision Making", SeverityMedium, filePath, runes, content, m, p.conf, catExcessiveAgency, 3))
		}
	}
	emit(content, runes, filePath, ea3Pats, "EA3", "Scope Creep", SeverityLow, catExcessiveAgency, 3, &out)
	emit(content, runes, filePath, ea4Pats, "EA4", "Unbounded Resource Access", SeverityMedium, catExcessiveAgency, 3, &out)
	return out
}

// --- output handling (OH1–OH3) -----------------------------------------------

func analyzeOutputHandling(content, filePath, fileType string) []AnalyzerFinding {
	runes := []rune(content)
	var out []AnalyzerFinding
	for _, p := range oh1Pats {
		for _, m := range findAll(p.re, content) {
			conf := p.conf
			if isCodeFileType(fileType) {
				conf = minf(1.0, p.conf+0.1)
			}
			out = append(out, mkAF("OH1", "Unvalidated Output Injection", SeverityHigh, filePath, runes, content, m, conf, catOutputHandling, 3))
		}
	}
	emit(content, runes, filePath, oh2Pats, "OH2", "Cross-Context Output", SeverityMedium, catOutputHandling, 3, &out)
	emit(content, runes, filePath, oh3Pats, "OH3", "Unbounded Output", SeverityMedium, catOutputHandling, 3, &out)
	return out
}

// --- system prompt leakage (P6–P8) -------------------------------------------

func analyzeSystemPromptLeakage(content, filePath, fileType string) []AnalyzerFinding {
	runes := []rune(content)
	var out []AnalyzerFinding
	emit(content, runes, filePath, p6Pats, "P6", "Direct Prompt Extraction", SeverityHigh, catSystemPromptLeakage, 3, &out)
	emit(content, runes, filePath, p7Pats, "P7", "Indirect Prompt Extraction", SeverityMedium, catSystemPromptLeakage, 3, &out)
	emit(content, runes, filePath, p8Pats, "P8", "Prompt Exfiltration via Tool", SeverityHigh, catSystemPromptLeakage, 3, &out)
	return out
}

// --- memory poisoning (MP1–MP3) ----------------------------------------------

func analyzeMemoryPoisoning(content, filePath, fileType string) []AnalyzerFinding {
	runes := []rune(content)
	var out []AnalyzerFinding
	emit(content, runes, filePath, mp1Pats, "MP1", "Persistent Context Injection", SeverityMedium, catMemoryPoisoning, 3, &out)
	emit(content, runes, filePath, mp2Pats, "MP2", "Context Window Stuffing", SeverityMedium, catMemoryPoisoning, 3, &out)
	for _, p := range mp3Pats {
		for _, m := range findAll(p.re, content) {
			ctx := getContext(content, runes, m.start, 3)
			if isCodeExample(ctx) {
				continue
			}
			out = append(out, mkAF("MP3", "Memory Manipulation", SeverityHigh, filePath, runes, content, m, p.conf, catMemoryPoisoning, 3))
		}
	}
	return out
}

// --- tool misuse (TM1–TM3) ---------------------------------------------------

var (
	safeContainerPats   []*regexp2.Regexp
	safeDockerfilePats  []*regexp2.Regexp
	dockerfileContextRe *regexp2.Regexp
)

func init() {
	safeContainerPats = []*regexp2.Regexp{
		compile(`docker\s+run\s+.*--rm`, regexp2.IgnoreCase),
		compile(`docker\s+run\s+.*-it`, regexp2.IgnoreCase),
		compile(`docker\s+(?:build|compose|pull|push)\b`, regexp2.IgnoreCase),
		compile(`podman\s+run\b`, regexp2.IgnoreCase),
	}
	safeDockerfilePats = []*regexp2.Regexp{
		compile(`rm\s+-rf\s+/var/lib/apt/lists`, regexp2.IgnoreCase),
		compile(`rm\s+-rf\s+/var/cache/apt`, regexp2.IgnoreCase),
		compile(`chown\s+-R\s+\w+:\w+\s+/`, regexp2.IgnoreCase),
		compile(`rm\s+-rf\s+/root/\.cache`, regexp2.IgnoreCase),
	}
	dockerfileContextRe = compile(`\b(?:FROM|RUN|WORKDIR|COPY|ADD|ENV|EXPOSE|ENTRYPOINT|CMD|USER|HEALTHCHECK|ARG)\s`, regexp2.None)
}

func isSafeContainerCommand(text string) bool {
	for _, re := range safeContainerPats {
		if matchString(re, text) {
			return true
		}
	}
	return false
}

func isSafeDockerfileIdiom(context, matched string) bool {
	if !matchString(dockerfileContextRe, context) {
		return false
	}
	for _, re := range safeDockerfilePats {
		if matchString(re, matched) || matchString(re, context) {
			return true
		}
	}
	return false
}

func analyzeToolMisuse(content, filePath, fileType string) []AnalyzerFinding {
	runes := []rune(content)
	var out []AnalyzerFinding
	for _, p := range tm1Pats {
		for _, m := range findAll(p.re, content) {
			ctx := getContext(content, runes, m.start, 3)
			matched := truncateRunes(m.text, 200)
			var conf float64
			var sev Severity
			if isSafeContainerCommand(ctx) || isSafeDockerfileIdiom(ctx, matched) {
				conf = minf(p.conf, 0.15)
				sev = SeverityLow
			} else {
				conf = p.conf
				if isCodeFileType(fileType) {
					conf = minf(1.0, p.conf+0.1)
				}
				sev = SeverityHigh
			}
			out = append(out, mkAF("TM1", "Tool Parameter Abuse", sev, filePath, runes, content, m, conf, catToolMisuse, 3))
		}
	}
	for _, p := range tm2Pats {
		for _, m := range findAll(p.re, content) {
			ctx := getContext(content, runes, m.start, 3)
			matched := truncateRunes(m.text, 200)
			var conf float64
			var sev Severity
			if isSafeDockerfileIdiom(ctx, matched) {
				conf = minf(p.conf, 0.15)
				sev = SeverityLow
			} else {
				conf = p.conf
				sev = SeverityHigh
			}
			out = append(out, mkAF("TM2", "Chaining Abuse", sev, filePath, runes, content, m, conf, catToolMisuse, 3))
		}
	}
	emit(content, runes, filePath, tm3Pats, "TM3", "Unsafe Defaults", SeverityMedium, catToolMisuse, 3, &out)
	return out
}

// --- rogue agent (RA1–RA2) ---------------------------------------------------

func analyzeRogueAgent(content, filePath, fileType string) []AnalyzerFinding {
	runes := []rune(content)
	var out []AnalyzerFinding
	emit(content, runes, filePath, ra1Pats, "RA1", "Self-Modification", SeverityHigh, catRogueAgent, 3, &out)
	emit(content, runes, filePath, ra2Pats, "RA2", "Session Persistence", SeverityMedium, catRogueAgent, 3, &out)
	return out
}

// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Analyzer registry. Mirrors the upstream node IDs and metadata. Analyzers not
// yet ported to pure Go (YARA signatures, Python-AST behavioral/taint, the
// LLM-backed semantic analyzers, and several MCP/Claude analyzers) are
// registered as stubs so a clean report still advertises their absence.

package scanner

type analyzerStatus string

const (
	statusProduction analyzerStatus = "production"
	statusBeta       analyzerStatus = "beta"
	statusStub       analyzerStatus = "stub"
)

type analyzerEntry struct {
	id              string
	status          analyzerStatus
	requiresNetwork bool
	requiresLLM     bool
	ruleIDs         []string
	fn              func(*scanState) []Finding // nil == stub (no findings)
	notes           string
}

func staticFamily(analyze patternAnalyzer) func(*scanState) []Finding {
	return func(st *scanState) []Finding { return runStaticPatterns(st, analyze) }
}

// analyzers preserves the upstream ANALYZER_NODE_IDS ordering.
var analyzers = []analyzerEntry{
	{id: "static_patterns_prompt_injection", status: statusProduction, ruleIDs: []string{"P1", "P2", "P3", "P4"}, fn: staticFamily(analyzePromptInjection)},
	{id: "static_patterns_data_exfiltration", status: statusProduction, ruleIDs: []string{"E1", "E2", "E3", "E4"}, fn: staticFamily(analyzeDataExfiltration)},
	{id: "static_patterns_privilege_escalation", status: statusProduction, ruleIDs: []string{"PE1", "PE2", "PE3"}, fn: staticFamily(analyzePrivilegeEscalation)},
	{id: "static_patterns_supply_chain", status: statusProduction, requiresNetwork: false, ruleIDs: []string{"SC1", "SC2", "SC3", "SC4", "SC5", "SC6"}, fn: supplyChainAnalyzer, notes: "SC4 uses the static offline fallback list; the live OSV.dev lookup is not ported."},
	{id: "static_patterns_harmful_content", status: statusProduction, ruleIDs: []string{"P5"}, fn: staticFamily(analyzeHarmfulContent)},
	{id: "static_patterns_excessive_agency", status: statusProduction, ruleIDs: []string{"EA1", "EA2", "EA3", "EA4"}, fn: staticFamily(analyzeExcessiveAgency)},
	{id: "static_patterns_output_handling", status: statusProduction, ruleIDs: []string{"OH1", "OH2", "OH3"}, fn: staticFamily(analyzeOutputHandling)},
	{id: "static_patterns_system_prompt_leakage", status: statusProduction, ruleIDs: []string{"P6", "P7", "P8"}, fn: staticFamily(analyzeSystemPromptLeakage)},
	{id: "static_patterns_memory_poisoning", status: statusProduction, ruleIDs: []string{"MP1", "MP2", "MP3"}, fn: staticFamily(analyzeMemoryPoisoning)},
	{id: "static_patterns_tool_misuse", status: statusProduction, ruleIDs: []string{"TM1", "TM2", "TM3"}, fn: staticFamily(analyzeToolMisuse)},
	{id: "static_patterns_rogue_agent", status: statusProduction, ruleIDs: []string{"RA1", "RA2"}, fn: staticFamily(analyzeRogueAgent)},
	{id: "static_yara", status: statusStub, ruleIDs: []string{"YARA"}, notes: "YARA signature scanning is not ported to pure Go."},
	{id: "behavioral_ast", status: statusStub, ruleIDs: []string{"BA1", "BA2"}, notes: "Python-AST behavioral analysis is not ported to pure Go."},
	{id: "behavioral_taint_tracking", status: statusStub, ruleIDs: []string{"BT1", "BT2"}, notes: "Python-AST taint tracking is not ported to pure Go."},
	{id: "mcp_least_privilege", status: statusStub, ruleIDs: []string{"LP1", "LP2", "LP3"}, notes: "Not yet ported."},
	{id: "mcp_tool_poisoning", status: statusStub, requiresLLM: true, ruleIDs: []string{"TP1", "TP2", "TP3", "TP4"}, notes: "Not yet ported."},
	{id: "mcp_rug_pull", status: statusStub, ruleIDs: []string{"RP1", "RP2", "RP3"}, notes: "Requires previous manifest for diff; not implemented."},
	{id: "semantic_security_discovery", status: statusStub, requiresLLM: true, ruleIDs: []string{"SD1"}, notes: "LLM analyzer; not ported."},
	{id: "semantic_developer_intent", status: statusStub, requiresLLM: true, ruleIDs: []string{"DI1"}, notes: "LLM analyzer; not ported."},
	{id: "semantic_quality_policy", status: statusStub, requiresLLM: true, ruleIDs: []string{"QP1"}, notes: "LLM analyzer; not ported."},
	{id: "claude_plugin_structure", status: statusProduction, ruleIDs: []string{"CP001", "CP002", "CP003"}, fn: claudePluginStructureAnalyzer},
	{id: "claude_hooks", status: statusStub, ruleIDs: []string{"CH1", "CH2", "CH3"}, notes: "Not yet ported."},
	{id: "claude_mcp_lsp", status: statusStub, ruleIDs: []string{"CML1", "CML2"}, notes: "Not yet ported."},
	{id: "claude_components", status: statusStub, ruleIDs: []string{"CC1", "CC2"}, notes: "Not yet ported."},
	{id: "claude_capability_correlation", status: statusStub, ruleIDs: []string{"CCC1", "CCC2"}, notes: "Not yet ported."},
}

func runAnalyzers(st *scanState) []Finding {
	var findings []Finding
	for _, a := range analyzers {
		if a.fn == nil {
			continue
		}
		findings = append(findings, a.fn(st)...)
	}
	return findings
}

func stubAnalyzerIDs() []string {
	var out []string
	for _, a := range analyzers {
		if a.status == statusStub {
			out = append(out, a.id)
		}
	}
	return out
}

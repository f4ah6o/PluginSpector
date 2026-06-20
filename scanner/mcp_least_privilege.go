// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// MCP least-privilege analyzer (B.3.1) — LP1 through LP4. Ported from
// src/pluginspector/nodes/analyzers/mcp_least_privilege.py.

package scanner

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/dlclark/regexp2"
)

const lpCategory = "MCP Least Privilege"

var lpTags = []string{"ASI02"}

var wildcardPerms = map[string]bool{"*": true, "all": true, "full": true, "any": true}

// capabilityGroup preserves the upstream _CAPABILITY_PATTERNS ordering.
type capabilityGroup struct {
	cap  string
	pats []*regexp2.Regexp
}

var capabilityGroups []capabilityGroup

// permKeyword preserves the insertion order of _PERM_TO_CAPABILITY so that the
// first keyword match wins (matching the Python break semantics).
type permKeyword struct {
	keyword string
	cat     string
	re      *regexp2.Regexp
}

var permKeywords []permKeyword

func init() {
	rawCaps := []struct {
		cap  string
		pats []string
	}{
		{"shell", []string{`subprocess`, `Popen`, `os\.system`, `os\.popen`, `os\.exec`, `\bcurl\b`, `\bwget\b`, `\bchmod\b`}},
		{"network", []string{`\bhttpx\b`, `\brequests\b`, `\burllib\b`, `\baiohttp\b`, `socket\.connect`, `fetch\(`, `XMLHttpRequest`}},
		{"file_read", []string{`open\s*\([^)]*['"]r['"]`, `open\s*\([^)]*['"][^'"]*r['"]`, `\.read_text\(`, `\.read_bytes\(`, `os\.listdir`, `os\.walk`, `glob\.glob`}},
		{"file_write", []string{`open\s*\([^)]*['"][wa]['"]`, `open\s*\([^)]*['"][^'"]*[wa]['"]`, `\.write_text\(`, `\.write_bytes\(`, `shutil\.copy`, `os\.rename`, `os\.mkdir`}},
		{"env", []string{`os\.environ`, `os\.getenv`, `process\.env`, `\bdotenv\b`}},
		{"mcp", []string{`create_session`, `MCPClient`, `mcp\.client`}},
	}
	for _, rc := range rawCaps {
		var res []*regexp2.Regexp
		for _, p := range rc.pats {
			res = append(res, compile(p, regexp2.IgnoreCase))
		}
		capabilityGroups = append(capabilityGroups, capabilityGroup{cap: rc.cap, pats: res})
	}

	rawPerms := []struct{ keyword, cat string }{
		{"bash", "shell"}, {"shell", "shell"}, {"terminal", "shell"}, {"command", "shell"},
		{"network", "network"}, {"http", "network"}, {"fetch", "network"}, {"api", "network"},
		{"read", "file_read"}, {"fs_read", "file_read"}, {"file_read", "file_read"},
		{"write", "file_write"}, {"fs_write", "file_write"}, {"file_write", "file_write"},
		{"env", "env"}, {"environment", "env"},
		{"mcp", "mcp"}, {"tools", "mcp"}, {"tool_use", "mcp"},
	}
	for _, rp := range rawPerms {
		permKeywords = append(permKeywords, permKeyword{
			keyword: rp.keyword, cat: rp.cat,
			re: compile(`\b`+regexp2.Escape(rp.keyword)+`\b`, regexp2.IgnoreCase),
		})
	}
}

func isTestFile(path string) bool {
	name := filepath.Base(path)
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	return strings.HasPrefix(name, "test_") || strings.HasSuffix(stem, "_test")
}

func detectCapabilities(content string) map[string]bool {
	found := map[string]bool{}
	for _, g := range capabilityGroups {
		for _, re := range g.pats {
			if matchString(re, content) {
				found[g.cap] = true
				break
			}
		}
	}
	return found
}

// mapPermissionToCategory returns the first matching capability category for a
// permission string (first keyword in declaration order wins).
func mapPermissionToCategory(permLower string) (string, bool) {
	for _, pk := range permKeywords {
		if matchString(pk.re, permLower) {
			return pk.cat, true
		}
	}
	return "", false
}

func mapPermissionsToCategories(permissions []string) map[string]bool {
	cats := map[string]bool{}
	for _, perm := range permissions {
		if cat, ok := mapPermissionToCategory(strings.TrimSpace(strings.ToLower(perm))); ok {
			cats[cat] = true
		}
	}
	return cats
}

func hasWildcard(permissions []string) bool {
	for _, p := range permissions {
		if wildcardPerms[strings.ToLower(strings.TrimSpace(p))] {
			return true
		}
	}
	return false
}

func lpFinding(ruleID, message, severity string, conf float64, file, explanation, remediation string) Finding {
	return Finding{
		RuleID: ruleID, Message: message, Severity: severity, Confidence: conf,
		File: file, StartLine: 1, Category: lpCategory, Tags: append([]string(nil), lpTags...),
		Explanation: explanation, Remediation: remediation,
	}
}

func mcpLeastPrivilegeAnalyzer(st *scanState) []Finding {
	if !st.Manifest.present {
		return nil
	}
	// Skip docs-only skills (no executable files).
	if !st.HasExecutableScripts {
		return nil
	}

	var findings []Finding
	permissions := st.Manifest.Permissions // empty slice == "absent"

	// LP2: wildcard permission.
	if hasWildcard(permissions) {
		findings = append(findings, lpFinding("LP2",
			"Permission list contains a wildcard entry ('*', 'all', 'full', or 'any'), granting blanket access with no least-privilege boundary.",
			"MEDIUM", 0.90, "SKILL.md",
			"Wildcard permissions disable permission-based security controls entirely. Specify only the permissions the skill actually requires.",
			"Replace '*'/'all'/'full'/'any' with an explicit list of required permissions. Request only the minimum access needed."))
	}

	// Detect per-file capabilities (executable files only), preserving order.
	var executablePaths []string
	for _, m := range st.ComponentMetadata {
		if m.Executable {
			executablePaths = append(executablePaths, m.Path)
		}
	}
	type fileCaps struct {
		path string
		caps map[string]bool
	}
	var fileCapabilities []fileCaps
	allCaps := map[string]bool{}
	for _, path := range executablePaths {
		caps := detectCapabilities(st.FileCache[path])
		if len(caps) > 0 {
			fileCapabilities = append(fileCapabilities, fileCaps{path: path, caps: caps})
			for c := range caps {
				allCaps[c] = true
			}
		}
	}

	permissionsAbsent := len(permissions) == 0

	// LP3: no declared permissions but capabilities detected.
	if permissionsAbsent && len(allCaps) > 0 {
		findings = append(findings, lpFinding("LP3",
			"Skill has no declared permissions but code capabilities were detected: "+strings.Join(sortedKeys(allCaps), ", ")+".",
			"MEDIUM", 0.70, "SKILL.md",
			"Without declared permissions the skill's intent is opaque and cannot be validated.",
			"Add a 'permissions' field to SKILL.md listing the capabilities this skill requires."))
	}

	wildcardPresent := hasWildcard(permissions)

	if len(permissions) > 0 {
		declaredCategories := mapPermissionsToCategories(permissions)

		// LP1: under-declared capabilities (skip when wildcard present).
		if !wildcardPresent {
			capInTestOnly := map[string]bool{}
			capInCode := map[string]bool{}
			for _, fc := range fileCapabilities {
				target := capInCode
				if isTestFile(fc.path) {
					target = capInTestOnly
				}
				for c := range fc.caps {
					target[c] = true
				}
			}
			testOnlyCaps := map[string]bool{}
			for c := range capInTestOnly {
				if !capInCode[c] {
					testOnlyCaps[c] = true
				}
			}

			for _, cap := range sortedKeys(allCaps) {
				if declaredCategories[cap] {
					continue
				}
				conf := 0.75
				if testOnlyCaps[cap] {
					conf = 0.55
				}
				primaryFile := "SKILL.md"
				for _, fc := range fileCapabilities {
					if fc.caps[cap] {
						primaryFile = fc.path
						break
					}
				}
				findings = append(findings, lpFinding("LP1",
					"Code capability '"+cap+"' detected in "+primaryFile+" but not covered by declared permissions.",
					"HIGH", conf, primaryFile,
					"The skill uses '"+cap+"' capability that is not listed in its permissions. This may indicate deceptive intent or missing permission declarations.",
					"Add the '"+cap+"' permission to SKILL.md, or remove the code that requires it."))
			}
		}

		// LP4: over-declared permissions.
		for _, perm := range permissions {
			permLower := strings.ToLower(strings.TrimSpace(perm))
			if wildcardPerms[permLower] {
				continue
			}
			matchedCat, ok := mapPermissionToCategory(permLower)
			if !ok {
				continue
			}
			if !allCaps[matchedCat] {
				findings = append(findings, lpFinding("LP4",
					"Permission '"+perm+"' is declared but no corresponding code capability ("+matchedCat+") was detected.",
					"LOW", 0.65, "SKILL.md",
					"Declared permissions with no matching code capability may indicate removed functionality or pre-staging for future abuse.",
					"Remove the '"+perm+"' permission if the corresponding capability is no longer used."))
			}
		}
	}

	return findings
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

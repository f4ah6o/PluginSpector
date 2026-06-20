// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Claude Code plugin target detection and structure parsing, ported from
// src/pluginspector/claude_plugin.py.

package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	pluginManifestPath      = ".claude-plugin/plugin.json"
	marketplaceManifestPath = ".claude-plugin/marketplace.json"
)

// Target classifications of a scanned directory.
const (
	TargetStandaloneSkill  = "standalone-skill"
	TargetClaudePlugin     = "claude-plugin"
	TargetClaudeMarket     = "claude-marketplace"
	TargetGenericDirectory = "generic-directory"
)

var versionRe = regexp.MustCompile(`^\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.\-]+)?$`)

// Declared-path keys in plugin.json that may point at component files/dirs.
var declaredPathKeys = []struct {
	key  string
	kind string
}{
	{"commands", "command"}, {"agents", "agent"}, {"hooks", "hooks"},
	{"mcpServers", "mcp"}, {"mcp", "mcp"}, {"lsp", "lsp"},
	{"monitors", "monitor"}, {"skills", "skill"}, {"bin", "bin"},
}

// PluginComponent is a single resolved component within a plugin.
type PluginComponent struct {
	Path         string   `json:"path"`
	Kind         string   `json:"kind"`
	SourceFile   string   `json:"source_file"`
	SourceLine   int      `json:"source_line"`
	Capabilities []string `json:"capabilities"`
}

// StructuralIssue is a path-traversal or symlink escape found while parsing.
type StructuralIssue struct {
	Kind       string `json:"kind"`
	Path       string `json:"path"`
	Resolved   string `json:"resolved"`
	SourceFile string `json:"source_file"`
	SourceLine int    `json:"source_line"`
}

// PluginModel is the parsed representation of a Claude plugin.
type PluginModel struct {
	TargetType       string                 `json:"target_type"`
	PluginRoot       string                 `json:"plugin_root"`
	Manifest         map[string]interface{} `json:"manifest"`
	Components       []PluginComponent      `json:"components"`
	StructuralIssues []StructuralIssue      `json:"structural_issues"`
	ManifestErrors   []string               `json:"manifest_errors"`
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func detectTargetType(root string) string {
	if fileExists(filepath.Join(root, pluginManifestPath)) {
		return TargetClaudePlugin
	}
	if fileExists(filepath.Join(root, marketplaceManifestPath)) {
		return TargetClaudeMarket
	}
	if fileExists(filepath.Join(root, "SKILL.md")) || fileExists(filepath.Join(root, "skill.md")) {
		return TargetStandaloneSkill
	}
	return TargetGenericDirectory
}

func lineOf(content, needle string) int {
	idx := strings.Index(content, needle)
	if idx < 0 {
		return 1
	}
	return strings.Count(content[:idx], "\n") + 1
}

// isWithin reports whether target resolves to a location inside rootResolved.
func isWithin(rootResolved, target string) bool {
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		// Fall back to a lexical check when the path does not exist yet.
		resolved = filepath.Clean(target)
	}
	rel, err := filepath.Rel(rootResolved, resolved)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func iterDeclaredPaths(value interface{}) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []interface{}:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func validateManifest(manifest map[string]interface{}) []string {
	var errors []string
	name, ok := manifest["name"].(string)
	if !ok || strings.TrimSpace(name) == "" {
		errors = append(errors, "plugin.json is missing a non-empty 'name' field")
	}
	if version, present := manifest["version"]; present {
		vs, ok := version.(string)
		if !ok || !versionRe.MatchString(vs) {
			errors = append(errors, fmt.Sprintf("plugin.json 'version' is not a valid version string: %v", version))
		}
	}
	for _, dk := range declaredPathKeys {
		val, present := manifest[dk.key]
		if !present || val == nil {
			continue
		}
		switch val.(type) {
		case string, []interface{}, map[string]interface{}:
			// ok
		default:
			errors = append(errors, fmt.Sprintf("plugin.json '%s' must be a string, list, or object", dk.key))
		}
	}
	return errors
}

func collectDeclaredComponents(rootResolved string, manifest map[string]interface{}, manifestText string) ([]PluginComponent, []StructuralIssue) {
	var components []PluginComponent
	var issues []StructuralIssue
	for _, dk := range declaredPathKeys {
		for _, decl := range iterDeclaredPaths(manifest[dk.key]) {
			line := lineOf(manifestText, decl)
			resolved := filepath.Join(rootResolved, decl)
			if !isWithin(rootResolved, resolved) {
				issues = append(issues, StructuralIssue{
					Kind: "path_escape", Path: decl, Resolved: resolved,
					SourceFile: pluginManifestPath, SourceLine: line,
				})
				continue
			}
			rel := strings.TrimLeft(strings.ReplaceAll(decl, "\\", "/"), "./")
			if rel == "" {
				rel = decl
			}
			components = append(components, PluginComponent{
				Path: rel, Kind: dk.kind, SourceFile: pluginManifestPath, SourceLine: line,
			})
		}
	}
	return components, issues
}

func collectConventionComponents(root string) []PluginComponent {
	var components []PluginComponent
	add := func(path, kind string) {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return
		}
		components = append(components, PluginComponent{
			Path: filepath.ToSlash(rel), Kind: kind, SourceFile: filepath.ToSlash(rel), SourceLine: 1,
		})
	}

	if fileExists(filepath.Join(root, "hooks", "hooks.json")) {
		add(filepath.Join(root, "hooks", "hooks.json"), "hooks")
	}
	if fileExists(filepath.Join(root, ".mcp.json")) {
		add(filepath.Join(root, ".mcp.json"), "mcp")
	}
	if fileExists(filepath.Join(root, ".lsp.json")) {
		add(filepath.Join(root, ".lsp.json"), "lsp")
	}

	for _, sub := range []struct{ dir, kind string }{
		{"commands", "command"}, {"agents", "agent"}, {"monitors", "monitor"},
	} {
		d := filepath.Join(root, sub.dir)
		if dirExists(d) {
			var files []string
			_ = filepath.Walk(d, func(p string, info os.FileInfo, err error) error {
				if err == nil && info != nil && !info.IsDir() && !strings.HasPrefix(info.Name(), ".") {
					files = append(files, p)
				}
				return nil
			})
			sort.Strings(files)
			for _, f := range files {
				add(f, sub.kind)
			}
		}
	}

	skillsDir := filepath.Join(root, "skills")
	if dirExists(skillsDir) {
		var skillMDs []string
		_ = filepath.Walk(skillsDir, func(p string, info os.FileInfo, err error) error {
			if err == nil && info != nil && !info.IsDir() && info.Name() == "SKILL.md" {
				skillMDs = append(skillMDs, p)
			}
			return nil
		})
		sort.Strings(skillMDs)
		for _, f := range skillMDs {
			add(f, "skill")
		}
	}

	binDir := filepath.Join(root, "bin")
	if dirExists(binDir) {
		entries, _ := os.ReadDir(binDir)
		var files []string
		for _, e := range entries {
			if !e.IsDir() {
				files = append(files, filepath.Join(binDir, e.Name()))
			}
		}
		sort.Strings(files)
		for _, f := range files {
			add(f, "bin")
		}
	}

	return components
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func collectSymlinkEscapes(root, rootResolved string) []StructuralIssue {
	var issues []StructuralIssue
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return nil
		}
		if !isWithin(rootResolved, p) {
			rel, relErr := filepath.Rel(root, p)
			relPath := filepath.ToSlash(rel)
			if relErr != nil {
				relPath = info.Name()
			}
			resolved, rerr := filepath.EvalSymlinks(p)
			if rerr != nil {
				resolved = "(unresolved)"
			}
			issues = append(issues, StructuralIssue{
				Kind: "symlink_escape", Path: relPath, Resolved: resolved,
				SourceFile: relPath, SourceLine: 1,
			})
		}
		return nil
	})
	return issues
}

func dedupComponents(components []PluginComponent) []PluginComponent {
	type key struct{ path, kind string }
	seen := map[key]bool{}
	var out []PluginComponent
	for _, c := range components {
		k := key{c.Path, c.Kind}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	return out
}

func parsePlugin(root string, fileCache map[string]string) *PluginModel {
	targetType := detectTargetType(root)
	rootResolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		rootResolved, _ = filepath.Abs(root)
	}
	model := &PluginModel{
		TargetType: targetType,
		PluginRoot: rootResolved,
		Manifest:   map[string]interface{}{},
	}
	if targetType != TargetClaudePlugin {
		return model
	}

	manifestText, ok := fileCache[pluginManifestPath]
	if !ok {
		if b, rerr := os.ReadFile(filepath.Join(root, pluginManifestPath)); rerr == nil {
			manifestText = string(b)
		}
	}

	var manifest map[string]interface{}
	if manifestText != "" {
		var parsed interface{}
		if jerr := json.Unmarshal([]byte(manifestText), &parsed); jerr != nil {
			model.ManifestErrors = append(model.ManifestErrors, "plugin.json is not valid JSON: "+jerr.Error())
		} else if m, isObj := parsed.(map[string]interface{}); isObj {
			manifest = m
			model.Manifest = m
			model.ManifestErrors = append(model.ManifestErrors, validateManifest(m)...)
		} else {
			model.ManifestErrors = append(model.ManifestErrors, "plugin.json must be a JSON object")
		}
	}
	if manifest == nil {
		manifest = map[string]interface{}{}
	}

	declared, declaredIssues := collectDeclaredComponents(rootResolved, manifest, manifestText)
	convention := collectConventionComponents(root)
	model.Components = dedupComponents(append(declared, convention...))
	model.StructuralIssues = append(declaredIssues, collectSymlinkEscapes(root, rootResolved)...)
	return model
}

// claudePluginStructureAnalyzer emits CP001/CP002/CP003 (issue #1).
func claudePluginStructureAnalyzer(st *scanState) []Finding {
	if st.PluginModel == nil || st.PluginModel.TargetType != TargetClaudePlugin {
		return nil
	}
	var findings []Finding
	for _, err := range st.PluginModel.ManifestErrors {
		findings = append(findings, makeClaudeFinding("CP001", "MEDIUM", pluginManifestPath, 1,
			"Invalid or inconsistent plugin manifest: "+err, 0.9, err))
	}
	for _, issue := range st.PluginModel.StructuralIssues {
		src := issue.SourceFile
		if src == "" {
			src = pluginManifestPath
		}
		switch issue.Kind {
		case "path_escape":
			findings = append(findings, makeClaudeFinding("CP002", "HIGH", src, issue.SourceLine,
				fmt.Sprintf("Component path '%s' escapes the plugin root (resolves to %s).", issue.Path, issue.Resolved), 0.9, issue.Path))
		case "symlink_escape":
			findings = append(findings, makeClaudeFinding("CP003", "HIGH", src, issue.SourceLine,
				fmt.Sprintf("Symlink '%s' points outside the plugin root (resolves to %s).", issue.Path, issue.Resolved), 0.9, issue.Path))
		}
	}
	return findings
}

// symlinkEscapeFindings turns walk-level symlink escapes into CP003 findings so
// the install gate is not bypassed for standalone skills / generic directories.
// Claude plugins already get CP003 from claudePluginStructureAnalyzer (which
// scans the plugin model), so they are skipped here to avoid double counting.
func symlinkEscapeFindings(st *scanState) []Finding {
	if st.PluginModel != nil && st.PluginModel.TargetType == TargetClaudePlugin {
		return nil
	}
	var out []Finding
	for _, s := range st.SkippedFiles {
		rel, ok := strings.CutPrefix(s, "symlink-escape:")
		if !ok {
			continue
		}
		out = append(out, makeClaudeFinding("CP003", "HIGH", rel, 1,
			fmt.Sprintf("Symlink '%s' points outside the scan root and was skipped during scanning; it can smuggle external host files into the scanned target.", rel),
			0.9, rel))
	}
	return out
}

// makeClaudeFinding mirrors claude_common.make_finding.
func makeClaudeFinding(ruleID, severity, file string, line int, message string, conf float64, matched string) Finding {
	if line <= 0 {
		line = 1
	}
	snippet := ""
	if matched != "" {
		snippet = truncateRunes(matched, 200)
	}
	return Finding{
		RuleID: ruleID, Message: message, Severity: severity, Confidence: conf,
		File: file, StartLine: line,
		Category: getCategory(ruleID), Pattern: getPatternName(ruleID),
		Explanation: getExplanation(ruleID), Remediation: getRemediation(ruleID),
		MatchedText: snippet, Finding: snippet,
		Tags: []string{getCategory(ruleID)},
	}
}

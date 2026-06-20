// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Build-context stage: walks a resolved skill/plugin directory and produces the
// flat scan state (components, file cache, manifest, component metadata, plugin
// model). Ported from src/pluginspector/nodes/build_context.py.

package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	maxFileCount      = 2_000
	maxTotalScanBytes = 200 * 1024 * 1024
	maxDirDepth       = 20
)

var skipDirs = map[string]bool{
	".git": true, "__pycache__": true, "node_modules": true,
	".venv": true, "venv": true, ".tox": true, ".pytest_cache": true,
}

var includedDotfiles = map[string]bool{".mcp.json": true, ".lsp.json": true}

var executableExtensions = map[string]bool{
	".py": true, ".sh": true, ".bash": true, ".zsh": true, ".js": true,
	".ts": true, ".rb": true, ".go": true, ".rs": true, ".pl": true,
}

// manifestData is the parsed SKILL.md frontmatter.
type manifestData struct {
	Name        string
	Description string
	Triggers    []string
	Permissions []string
	Parameters  []map[string]interface{}
	present     bool
}

// componentMeta describes a scanned file for reporting/scoring.
type componentMeta struct {
	Path       string
	Type       string
	Lines      int
	Executable bool
	SizeBytes  int64
}

// scanState is the shared state threaded through the analyzer pipeline.
type scanState struct {
	SkillPath            string
	Components           []string
	SkippedFiles         []string
	FileCache            map[string]string
	Manifest             manifestData
	ComponentMetadata    []componentMeta
	HasExecutableScripts bool
	TargetType           string
	PluginModel          *PluginModel
	YaraRulesDir         string
	UseLLM               bool
}

// errStopWalk halts the walk once the file-count budget is exhausted, bounding
// work on hostile inputs.
var errStopWalk = errors.New("scan budget reached")

func walkSkillFiles(skillDir string) (paths []string, skipped []string) {
	totalBytes := int64(0)
	rootResolved, _ := filepath.EvalSymlinks(skillDir)
	err := filepath.Walk(skillDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			// Prune excluded and over-deep directories before descending so the
			// scanner never traverses .git/node_modules/.venv trees (DoS guard).
			if p == skillDir {
				return nil
			}
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			if rel, relErr := filepath.Rel(skillDir, p); relErr == nil {
				if len(strings.Split(filepath.ToSlash(rel), "/")) > maxDirDepth {
					return filepath.SkipDir
				}
			}
			return nil
		}
		rel, relErr := filepath.Rel(skillDir, p)
		if relErr != nil {
			skipped = append(skipped, "out-of-root:"+p)
			return nil
		}
		rel = filepath.ToSlash(rel)
		parts := strings.Split(rel, "/")
		if len(parts) > maxDirDepth {
			skipped = append(skipped, "depth-limit:"+rel)
			return nil
		}
		base := info.Name()
		if strings.HasPrefix(base, ".") && !strings.HasPrefix(base, ".claude") && !includedDotfiles[base] {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, rerr := filepath.EvalSymlinks(p)
			if rerr != nil {
				skipped = append(skipped, "symlink-error:"+rel)
				return nil
			}
			if !isWithin(rootResolved, resolved) {
				skipped = append(skipped, "symlink-escape:"+rel)
				return nil
			}
		}
		if len(paths) >= maxFileCount {
			// Budget exhausted: record and stop traversing entirely.
			skipped = append(skipped, "file-count-limit:"+rel)
			return errStopWalk
		}
		size := info.Size()
		if totalBytes+size > maxTotalScanBytes {
			skipped = append(skipped, "bytes-limit:"+rel)
			return nil
		}
		totalBytes += size
		paths = append(paths, rel)
		return nil
	})
	if err != nil && err != errStopWalk {
		skipped = append(skipped, "walk-error:"+err.Error())
	}
	sort.Strings(paths)
	return paths, skipped
}

func countLines(content string) int {
	if content == "" {
		return 0
	}
	return len(strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")) - boolToInt(strings.HasSuffix(content, "\n"))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func readFileCache(skillDir string, components []string) map[string]string {
	cache := make(map[string]string, len(components))
	for _, rel := range components {
		full := filepath.Join(skillDir, filepath.FromSlash(rel))
		b, err := os.ReadFile(full)
		if err != nil {
			cache[rel] = ""
			continue
		}
		cache[rel] = string(b)
	}
	return cache
}

func buildComponentMetadata(skillDir string, components []string, fileCache map[string]string) ([]componentMeta, bool) {
	var meta []componentMeta
	hasExecutable := false
	for _, rel := range components {
		full := filepath.Join(skillDir, filepath.FromSlash(rel))
		info, err := os.Stat(full)
		if err != nil || info.IsDir() {
			continue
		}
		suffix := strings.ToLower(filepath.Ext(rel))
		fileType := inferFileType(rel)
		lines := countLines(fileCache[rel])
		norm := filepath.ToSlash(rel)
		inBin := strings.HasPrefix(norm, "bin/") || strings.Contains(norm, "/bin/")
		execBit := info.Mode().Perm()&0o100 != 0
		executable := executableExtensions[suffix] || execBit || inBin
		if executable {
			hasExecutable = true
		}
		meta = append(meta, componentMeta{
			Path: rel, Type: fileType, Lines: lines,
			Executable: executable, SizeBytes: info.Size(),
		})
	}
	return meta, hasExecutable
}

var frontmatterEndRe = regexp.MustCompile(`\n---\s*\n`)

func parseManifest(skillDir string) manifestData {
	for _, name := range []string{"SKILL.md", "skill.md"} {
		full := filepath.Join(skillDir, name)
		b, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		content := string(b)
		if !strings.HasPrefix(content, "---") {
			return manifestData{}
		}
		loc := frontmatterEndRe.FindStringIndex(content[3:])
		if loc == nil {
			return manifestData{}
		}
		frontmatter := content[3 : loc[0]+3]
		var data map[string]interface{}
		if yaml.Unmarshal([]byte(frontmatter), &data) != nil || data == nil {
			return manifestData{}
		}
		m := manifestData{present: true}
		if v, ok := data["name"].(string); ok {
			m.Name = v
		}
		if v, ok := data["description"].(string); ok {
			m.Description = v
		}
		m.Triggers = toStringList(data["triggers"])
		m.Permissions = toStringList(data["permissions"])
		if params, ok := data["parameters"].([]interface{}); ok {
			for _, p := range params {
				if pm, ok := p.(map[string]interface{}); ok {
					m.Parameters = append(m.Parameters, pm)
				}
			}
		}
		return m
	}
	return manifestData{}
}

func toStringList(v interface{}) []string {
	list, ok := v.([]interface{})
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, toScalarString(item))
	}
	return out
}

func toScalarString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return strings.TrimSpace(yamlScalar(x))
	}
}

func yamlScalar(v interface{}) string {
	b, err := yaml.Marshal(v)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// buildContext resolves the skill directory and assembles scanState.
func buildContext(skillDir, yaraRulesDir string, useLLM bool) *scanState {
	components, skipped := walkSkillFiles(skillDir)
	fileCache := readFileCache(skillDir, components)
	manifest := parseManifest(skillDir)
	componentMeta, hasExec := buildComponentMetadata(skillDir, components, fileCache)
	pluginModel := parsePlugin(skillDir, fileCache)
	return &scanState{
		SkillPath:            skillDir,
		Components:           components,
		SkippedFiles:         skipped,
		FileCache:            fileCache,
		Manifest:             manifest,
		ComponentMetadata:    componentMeta,
		HasExecutableScripts: hasExec,
		TargetType:           pluginModel.TargetType,
		PluginModel:          pluginModel,
		YaraRulesDir:         yaraRulesDir,
		UseLLM:               useLLM,
	}
}

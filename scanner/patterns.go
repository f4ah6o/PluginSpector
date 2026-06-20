// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"time"

	"github.com/dlclark/regexp2"
)

// We use dlclark/regexp2 (pure Go, .NET-compatible) rather than the stdlib
// regexp (RE2) because several upstream Python patterns rely on features RE2
// does not support: negative lookahead (e.g. `sudo\s+(?!-v...)`) and
// backreferences (e.g. the MP2 context-stuffing pattern `((\S)(?!\2)...)\1{20,}`).
// regexp2's IgnoreCase/Multiline/Singleline map to Python re.I/re.M/re.S.

const patternMatchTimeout = 5 * time.Second

// pat is a compiled rule pattern with its confidence weight.
type pat struct {
	re   *regexp2.Regexp
	conf float64
}

// patMatch is a single match with rune-based offset semantics matching Python.
type patMatch struct {
	start int    // rune offset of the match start
	text  string // matched text (group 0)
	conf  float64
}

func compile(src string, opts regexp2.RegexOptions) *regexp2.Regexp {
	re := regexp2.MustCompile(src, opts)
	re.MatchTimeout = patternMatchTimeout
	return re
}

// mkPats compiles a list of (pattern, confidence) pairs with the given options.
func mkPats(pairs [][2]any, opts regexp2.RegexOptions) []pat {
	out := make([]pat, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, pat{re: compile(p[0].(string), opts), conf: p[1].(float64)})
	}
	return out
}

// optsIM = re.IGNORECASE | re.MULTILINE (the most common combination).
const optsIM = regexp2.IgnoreCase | regexp2.Multiline

// optsIMS = re.IGNORECASE | re.MULTILINE | re.DOTALL.
const optsIMS = regexp2.IgnoreCase | regexp2.Multiline | regexp2.Singleline

// optsIDot = re.IGNORECASE | re.DOTALL.
const optsIDot = regexp2.IgnoreCase | regexp2.Singleline

// findAll returns every non-overlapping match of re in content, with rune
// offsets so line/context computation matches the Python implementation.
func findAll(re *regexp2.Regexp, content string) []patMatch {
	var out []patMatch
	m, err := re.FindStringMatch(content)
	if err != nil {
		return out
	}
	for m != nil {
		out = append(out, patMatch{start: m.Index, text: m.String()})
		m, err = re.FindNextMatch(m)
		if err != nil {
			break
		}
	}
	return out
}

// matchString reports whether re matches anywhere in s (re.search equivalent).
func matchString(re *regexp2.Regexp, s string) bool {
	ok, err := re.MatchString(s)
	return err == nil && ok
}

// getLineNumber returns the 1-based line number for a rune offset in content.
func getLineNumber(runes []rune, offset int) int {
	if offset > len(runes) {
		offset = len(runes)
	}
	n := 1
	for i := 0; i < offset; i++ {
		if runes[i] == '\n' {
			n++
		}
	}
	return n
}

// getContext extracts surrounding lines around the match (default 3 lines),
// mirroring common.get_context.
func getContext(content string, runes []rune, matchStart, contextLines int) string {
	lines := strings.Split(content, "\n")
	matchLine := 0
	limit := matchStart
	if limit > len(runes) {
		limit = len(runes)
	}
	for i := 0; i < limit; i++ {
		if runes[i] == '\n' {
			matchLine++
		}
	}
	start := matchLine - contextLines
	if start < 0 {
		start = 0
	}
	end := matchLine + contextLines + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

var codeExampleIndicators = []string{
	"```", "example:", "for example", "e.g.", "such as", "documentation",
	"# warning:", "# note:", "**warning**", "**note**",
	"// ✅", "// ❌", "// good:", "// bad:", "// correct:", "// incorrect:", "// wrong:",
}

// isCodeExample reports whether the context looks like a doc/code example.
func isCodeExample(context string) bool {
	low := strings.ToLower(context)
	for _, ind := range codeExampleIndicators {
		if strings.Contains(low, ind) {
			return true
		}
	}
	return false
}

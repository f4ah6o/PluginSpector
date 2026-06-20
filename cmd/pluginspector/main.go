// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// pluginspector CLI — a thin wrapper over the scanner package. Maps CLI args to
// scanner.Options, runs the scan, writes the report, and exits with a gate code
// (1 when risk score > 50, 2 on error) so it can guard preview/install flows.

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/f4ah6o/pluginspector/scanner"
)

const usage = `PluginSpector - Security scanner for Claude Code plugins and AI agent skills.

Usage:
  pluginspector scan <path|url> [flags]
  pluginspector --version

Arguments:
  <path|url>   Git URL, file URL, .zip file, .md file, or directory to scan.

Flags:
  -f, --format string     Output format: terminal|json|markdown|sarif (default "terminal")
  -o, --output string     Write the report to a file instead of stdout
      --no-llm            Skip LLM analysis (static analysis only)
      --strict-llm        Exit 2 if LLM analysis was requested but unavailable
      --yara-rules-dir s  Additional YARA rules directory (accepted; YARA not yet ported)
  -V, --verbose           Show detailed progress
  -v, --version           Show version and exit

Exit codes:
  0  scan completed, risk score <= 50
  1  scan completed, risk score > 50 (DO NOT INSTALL / CAUTION gate)
  2  error (bad input, or --strict-llm with LLM unavailable)
`

func main() {
	os.Exit(run(os.Args[1:]))
}

// valueFlags take a following token as their value.
var valueFlags = map[string]bool{
	"-f": true, "--format": true, "-o": true, "--output": true, "--yara-rules-dir": true,
}

// splitArgs separates flag tokens (and their values) from positional arguments
// so flags may appear before or after the input path.
func splitArgs(args []string) (flags []string, positionals []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			positionals = append(positionals, args[i+1:]...)
			return flags, positionals
		case strings.HasPrefix(a, "-") && a != "-":
			flags = append(flags, a)
			if valueFlags[a] && !strings.Contains(a, "=") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		default:
			positionals = append(positionals, a)
		}
	}
	return flags, positionals
}

func run(args []string) int {
	// Top-level --version/-v handling.
	for _, a := range args {
		if a == "--version" || a == "-v" {
			fmt.Printf("PluginSpector v%s\n", scanner.Version)
			return 0
		}
		if a == "-h" || a == "--help" {
			fmt.Print(usage)
			return 0
		}
	}
	if len(args) == 0 {
		fmt.Print(usage)
		return 0
	}
	if args[0] != "scan" {
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n\n%s", args[0], usage)
		return 2
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		format       string
		output       string
		noLLM        bool
		strictLLM    bool
		yaraRulesDir string
		verbose      bool
	)
	fs.StringVar(&format, "format", "terminal", "Output format")
	fs.StringVar(&format, "f", "terminal", "Output format (shorthand)")
	fs.StringVar(&output, "output", "", "Output file path")
	fs.StringVar(&output, "o", "", "Output file path (shorthand)")
	fs.BoolVar(&noLLM, "no-llm", false, "Skip LLM analysis")
	fs.BoolVar(&strictLLM, "strict-llm", false, "Fail if LLM unavailable")
	fs.StringVar(&yaraRulesDir, "yara-rules-dir", "", "Additional YARA rules dir")
	fs.BoolVar(&verbose, "verbose", false, "Verbose output")
	fs.BoolVar(&verbose, "V", false, "Verbose output (shorthand)")

	// Allow flags to appear before or after the positional path argument.
	flagArgs, positionals := splitArgs(args[1:])
	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	positionals = append(positionals, fs.Args()...)
	if len(positionals) < 1 {
		fmt.Fprintf(os.Stderr, "Error: missing input path\n\n%s", usage)
		return 2
	}
	inputPath := positionals[0]

	switch strings.ToLower(format) {
	case "terminal", "json", "markdown", "sarif":
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid format %q (terminal|json|markdown|sarif)\n", format)
		return 2
	}

	if verbose {
		fmt.Fprintln(os.Stderr, "Running scan...")
	}

	result, err := scanner.Scan(scanner.Options{
		InputPath:    inputPath,
		Format:       scanner.Format(strings.ToLower(format)),
		UseLLM:       !noLLM,
		StrictLLM:    strictLLM,
		YaraRulesDir: yaraRulesDir,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 2
	}

	if output != "" {
		if werr := os.WriteFile(output, []byte(result.ReportBody), 0o644); werr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", werr)
			return 2
		}
		fmt.Printf("Report saved to: %s\n", output)
	} else {
		fmt.Println(result.ReportBody)
	}

	if result.ShouldBlockInstall() {
		if result.RiskScore <= 50 {
			// Score alone would pass; a structural escape forced the block.
			fmt.Fprintf(os.Stderr, "Blocked: structural finding(s) %v gate installation regardless of risk score (%d/100).\n",
				result.BlockReasons(), result.RiskScore)
		}
		return 1
	}
	return 0
}

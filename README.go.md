# PluginSpector (Go port)

A pure-Go port of [PluginSpector](https://github.com/f4ah6o/PluginSpector) — a
security scanner that answers **"Is this Claude Code plugin / AI agent skill safe
to install?"** before you preview or install it.

This port preserves PluginSpector's philosophy, rule set, risk scoring, and
output formats (terminal / JSON / Markdown / SARIF) so it can run as a single
static binary or be embedded as a library — for example as the scanner behind
[`gh-agent-plugin`](https://github.com/f4ah6o/gh-agent-plugin)'s pre-install gate.

## Install / build

```sh
go build -o pluginspector ./cmd/pluginspector
```

## CLI

```sh
pluginspector scan ./my-skill/
pluginspector scan ./my-plugin/ --format json --output report.json
pluginspector scan https://github.com/user/my-skill --no-llm
```

Inputs: a directory, a `.md` file, a `.zip`, a git URL, or a file URL.

Exit codes (so it can gate an install/preview flow):

| Code | Meaning |
|------|---------|
| `0`  | Scan completed, risk score ≤ 50 |
| `1`  | Scan completed, risk score > 50 (CAUTION / DO NOT INSTALL) |
| `2`  | Error (bad input, or `--strict-llm` with LLM unavailable) |

Risk bands match the upstream tool: 0–20 LOW (SAFE), 21–50 MEDIUM (CAUTION),
51–80 HIGH and 81–100 CRITICAL (both DO NOT INSTALL).

## Library use (e.g. from gh-agent-plugin)

```go
import "github.com/f4ah6o/pluginspector/scanner"

res, err := scanner.Scan(scanner.Options{
    InputPath: dir,
    Format:    scanner.FormatJSON,
    UseLLM:    false,
})
if err != nil { /* ... */ }
if res.ShouldBlockInstall() {
    // res.RiskScore, res.RiskSeverity, res.RiskRecommendation, res.Findings
    // res.ReportBody, res.SarifJSON()
}
```

## What is ported

The full scan pipeline (input resolution → context build → analyzers → risk
scoring → report) is ported, with these analyzers **fully faithful** to the
Python rules (identical rule IDs, severities, confidences, and finding shape):

- All static pattern families: prompt injection (P1–P4), data exfiltration
  (E1–E4), privilege escalation (PE1–PE3), harmful content (P5), excessive
  agency (EA1–EA4), output handling (OH1–OH3), system prompt leakage (P6–P8),
  memory poisoning (MP1–MP3), tool misuse (TM1–TM3), rogue agent (RA1–RA2).
- Supply chain (SC1–SC6) and trigger abuse (TR1–TR3). *SC4 uses the static
  offline fallback list; the live OSV.dev lookup is not yet ported.*
- Claude plugin structure (CP001–CP003), with full plugin manifest/structure
  parsing and target-type detection.

The regex rules are evaluated with [`dlclark/regexp2`](https://github.com/dlclark/regexp2)
(pure Go) because several upstream patterns use negative lookahead and
backreferences that Go's stdlib `regexp` (RE2) does not support.

## Not yet ported (registered as stubs)

These analyzers are advertised in the report's `metadata.stub_analyzers` so a
clean report does **not** imply absence of issues in their categories:

- `static_yara` — YARA signature scanning (pure-Go decision: no cgo/libyara).
- `behavioral_ast`, `behavioral_taint_tracking` — depend on a Python AST parser.
- `mcp_least_privilege`, `mcp_tool_poisoning`, `mcp_rug_pull`.
- `semantic_*` — LLM-backed analyzers. Requesting LLM analysis (the default;
  pass `--no-llm` to opt out) reports a static-only fallback, matching the
  upstream behavior when no LLM credentials are configured.
- `claude_hooks`, `claude_mcp_lsp`, `claude_components`,
  `claude_capability_correlation`.

Fidelity is verified against the Python implementation: on fixtures whose
findings come only from ported analyzers, the Go output matches exactly.

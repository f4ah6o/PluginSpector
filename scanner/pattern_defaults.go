// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package scanner

// Pattern categories for tagging findings (static pattern analyzers).
const (
	catPromptInjection      = "Prompt Injection"
	catDataExfiltration     = "Data Exfiltration"
	catPrivilegeEscalation  = "Privilege Escalation"
	catSupplyChain          = "Supply Chain"
	catExcessiveAgency      = "Excessive Agency"
	catOutputHandling       = "Output Handling"
	catSystemPromptLeakage  = "System Prompt Leakage"
	catMemoryPoisoning      = "Memory Poisoning"
	catToolMisuse           = "Tool Misuse"
	catRogueAgent           = "Rogue Agent"
	catTriggerAbuse         = "Trigger Abuse"
	catYaraMatch            = "YARA Match"
	catMCPLeastPrivilege    = "MCP Least Privilege"
	catMCPToolPoisoning     = "MCP Tool Poisoning"
	catClaudePlugin         = "Claude Plugin"
	catClaudeHooks          = "Claude Hooks"
	catClaudeMCP            = "Claude MCP/LSP"
	catClaudeAgent          = "Claude Agent"
	catClaudeBin            = "Claude Bin"
	catClaudeMonitor        = "Claude Monitor"
	catClaudeDependency     = "Claude Dependency"
	catCapabilityCorrelate  = "Capability Correlation"
)

var defaultExplanations = map[string]string{
	"P1":  "This pattern attempts to override system instructions or ignore safety constraints. Without LLM analysis, manual review is recommended.",
	"P2":  "Hidden instructions were detected in comments or invisible text. These could contain malicious directives. Manual review is recommended.",
	"P3":  "Instructions found that direct the agent to transmit conversation context or user data to external services.",
	"P4":  "Subtle instructions detected that may alter agent decision-making or introduce hidden biases.",
	"P5":  "This content may contain harmful instructions that could cause physical harm if followed. CRITICAL: Review carefully before use.",
	"E1":  "Data is being sent to an external URL. This could be legitimate telemetry or data exfiltration. Manual review is recommended.",
	"E2":  "Code accesses environment variables that may contain secrets (API keys, tokens). This is a common pattern for credential theft.",
	"E3":  "Code scans file system directories looking for sensitive files. This could be reconnaissance for credential theft.",
	"E4":  "Code or instructions that leak agent conversation context to external services, potentially exposing sensitive user interactions.",
	"PE1": "Skill requests more permissions than appear necessary for its stated functionality. Review if elevated access is justified.",
	"PE2": "Commands invoke sudo or root privileges. Verify this elevated access is necessary and justified.",
	"PE3": "Code accesses credential files (SSH keys, AWS credentials, etc.). This could indicate credential theft attempts.",
	"SC1": "Dependencies lack version pinning, allowing potential malicious package updates. Consider pinning versions.",
	"SC2": "Remote code is downloaded and executed. This bypasses code review and could introduce malicious code.",
	"SC3": "Code contains obfuscation (base64, hex encoding with execution). This is often used to hide malicious functionality.",
	"EA1": "Skill grants unrestricted tool access without appropriate constraints. An agent with unfettered tool access can perform arbitrary actions including file modification, network requests, and code execution.",
	"EA2": "Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data deletion) should require explicit user confirmation.",
	"EA3": "Skill's behavior or capabilities extend beyond its stated purpose. Scope creep allows an agent to perform actions unrelated to its documented functionality, increasing the attack surface.",
	"EA4": "Skill allows unbounded resource consumption (API calls, storage, compute). Without rate limits or quotas, a compromised or misbehaving agent can cause denial-of-service or cost overruns.",
	"OH1": "Model output is used without validation or sanitization. Unvalidated output injected into downstream contexts (SQL, shell, HTML) enables injection attacks and arbitrary code execution.",
	"OH2": "Output from one security context is used in another without boundary enforcement. Cross-context output flow can leak sensitive information or escalate privileges across trust boundaries.",
	"OH3": "Output size or generation rate is not bounded. Unbounded output enables denial-of-service through resource exhaustion, log flooding, or context-window stuffing.",
	"P6":  "Skill contains instructions that could directly expose system prompts, internal rules, or hidden instructions to users or external parties.",
	"P7":  "Skill contains patterns that could indirectly extract system prompts through rephrasing, translation, summarization, or side-channel techniques.",
	"P8":  "Skill contains patterns that exfiltrate system prompts or internal instructions via tool calls (file writes, network requests, logging).",
	"MP1": "Skill injects content designed to persist in agent memory or context across interactions. Persistent injection can alter agent behavior long after the initial interaction.",
	"MP2": "Skill attempts to fill the context window with filler content, displacing legitimate instructions and safety constraints. This can degrade agent performance or bypass safety boundaries.",
	"MP3": "Skill manipulates agent memory, state, or stored context. Memory corruption can alter personality, override safety rules, or cause unpredictable behavior.",
	"TM1": "Tool parameters are crafted to achieve unintended or unsafe behavior. Parameter abuse can bypass intended safety checks (e.g. shell=True, --force, dangerous glob patterns).",
	"TM2": "Tool calls are chained to bypass individual safety checks or escalate capabilities beyond what any single tool call would allow.",
	"TM3": "Tool defaults are unsafe or overly permissive (e.g. disabled TLS verification, no authentication, world-writable permissions). Unsafe defaults widen the attack surface.",
	"RA1": "Skill modifies its own code, configuration, or behavior at runtime. Self-modification enables an agent to escalate privileges, disable safety constraints, or install persistent backdoors.",
	"RA2": "Skill establishes unauthorized persistence across sessions via cron jobs, startup scripts, or state files. Session persistence allows an attacker to maintain access beyond the current interaction.",
	"SC4": "Dependency has known vulnerabilities (CVEs). Using packages with unpatched security flaws exposes the environment to known exploits.",
	"SC5": "Dependency appears abandoned or unmaintained. Abandoned packages no longer receive security patches, leaving known and future vulnerabilities unaddressed.",
	"SC6": "Package name closely resembles a popular package, suggesting possible typosquatting. Attackers publish malicious packages with similar names to trick developers into installing them.",
	"TR1": "Skill uses overly broad trigger patterns that match common words or phrases, causing it to activate in unintended contexts and potentially shadow other skills.",
	"TR2": "Skill trigger shadows a common built-in command or another skill's trigger, potentially intercepting requests meant for trusted functionality.",
	"TR3": "Skill trigger uses vague or generic keywords designed to maximize activation frequency rather than target specific use cases.",
	"CP001": "The plugin manifest (.claude-plugin/plugin.json) is invalid or inconsistent (malformed JSON, missing required fields, or wrong field types). A manifest that does not match the plugin's real structure undermines every downstream trust decision.",
	"CP002": "A component path declared in the plugin manifest resolves outside the plugin root (path traversal). This lets a plugin reference or load files from arbitrary locations on the host.",
	"CP003": "A symlink inside the plugin points to a target outside the plugin root. Escaping symlinks can read host secrets or smuggle external files into the plugin's effective contents.",
}

var defaultRemediations = map[string]string{
	"P1":  "Remove or rewrite any text that instructs the agent to ignore prompts, override safety rules, or trust unverified content. Ensure skill content cannot be injected to alter agent behavior.",
	"P2":  "Audit all comments and invisible characters. Remove any instructions that direct the agent to perform unauthorized actions. Use plain, reviewable content.",
	"P3":  "Remove instructions that send user data, prompts, or context to external URLs. If telemetry is needed, use documented, privacy-preserving methods.",
	"P4":  "Review content for implicit steering or bias. Ensure instructions are explicit and align with the skill's stated purpose.",
	"P5":  "Remove all content that could lead to harmful outcomes. Add safety guardrails and human oversight for any high-risk operations.",
	"E1":  "Verify the destination URL is trusted and necessary. Remove or replace with documented APIs. Ensure no secrets, tokens, or PII are transmitted.",
	"E2":  "Avoid reading sensitive env vars (API keys, tokens) unless strictly required. Use secrets managers or secure config. Never log or transmit credentials.",
	"E3":  "Remove unnecessary filesystem scanning. If file access is needed, use explicit, scoped paths. Avoid reading ~/.ssh, ~/.aws, or credential directories.",
	"E4":  "Remove any code that sends prompts, responses, or session data externally. Preserve user privacy; never exfiltrate conversation content.",
	"PE1": "Request only the minimum permissions required. Document why each permission is needed. Remove broad permissions like '*' or 'all'.",
	"PE2": "Avoid sudo/root unless strictly required. Prefer least-privilege patterns. If elevation is needed, document the justification and scope.",
	"PE3": "Remove references to credential paths. Use environment variables or secrets managers. For docs, use placeholder paths (e.g., /path/to/config). Never load .env or token files in production code paths.",
	"SC1": "Pin all dependency versions in requirements.txt or pyproject.toml. Use exact versions (==) or compatible ranges. Run pip-audit regularly.",
	"SC2": "Avoid downloading and executing remote scripts. Use trusted packages from PyPI/npm. If remote fetch is required, verify checksums and use HTTPS.",
	"SC3": "Remove obfuscated code. Use plain, readable implementations. Obfuscation hinders security review and raises trust concerns.",
	"EA1": "Restrict tool access to only the tools required for the skill's stated purpose. Use an explicit allowlist rather than granting blanket access.",
	"EA2": "Add human-in-the-loop confirmation for destructive, irreversible, or high-impact operations. Never auto-execute commands that modify files, send data, or alter system state.",
	"EA3": "Limit the skill's scope to its documented purpose. Remove instructions that enable the agent to perform actions outside its stated functionality.",
	"EA4": "Set explicit rate limits, timeouts, and resource quotas for API calls, file operations, and compute. Implement circuit breakers for runaway loops.",
	"OH1": "Validate and sanitize all model output before using it in downstream contexts. Use parameterized queries for SQL, shell quoting for commands, and HTML encoding for web output.",
	"OH2": "Enforce strict context boundaries. Do not pass output from one security domain into another without explicit validation and redaction of sensitive content.",
	"OH3": "Set explicit limits on output length, generation count, and rate. Use max_tokens and truncation to prevent unbounded output.",
	"P6":  "Remove any instructions that reveal, print, or output system prompts or internal rules. System instructions should never be exposed to end users.",
	"P7":  "Guard against indirect extraction by refusing to summarize, translate, or rephrase system instructions. Add explicit anti-extraction clauses.",
	"P8":  "Prevent system prompts from being written to files, sent via network, or logged. Treat system instructions as confidential and filter them from all tool outputs.",
	"MP1": "Do not allow untrusted input to persist in agent memory or context. Validate all content before storing and implement memory isolation between sessions.",
	"MP2": "Implement context-window management that detects and rejects padding or stuffing attempts. Prioritize system instructions over user-injected content.",
	"MP3": "Protect agent memory and state from modification by untrusted content. Use read-only memory for critical instructions and validate all state changes.",
	"TM1": "Validate all tool parameters against an allowlist. Reject dangerous parameter values (shell=True, --force, -rf /) and use safe defaults.",
	"TM2": "Limit tool chaining depth and validate the output of each tool before passing it to the next. Require explicit user approval for multi-step chains.",
	"TM3": "Override unsafe defaults with secure settings (verify=True, auth required, restrictive permissions). Review and harden all tool configurations.",
	"RA1": "Prevent the skill from modifying its own code, SKILL.md, or configuration files. Treat skill files as read-only at runtime.",
	"RA2": "Remove any persistence mechanisms (cron jobs, startup scripts, state files). Skills should not maintain state across sessions without explicit user consent.",
	"SC4": "Update the dependency to a patched version that addresses the known CVE. Check OSV (osv.dev) or NVD for details on the vulnerability.",
	"SC5": "Replace the abandoned dependency with an actively maintained alternative. Check the package's repository for last commit date and open issues.",
	"SC6": "Verify the package name is correct and not a typosquatting variant. Compare against the official package name on PyPI or npm.",
	"TR1": "Use specific, narrow trigger patterns that match only the skill's intended use case. Avoid single-word or common-phrase triggers.",
	"TR2": "Choose triggers that do not conflict with built-in commands or other skills. Prefix with a unique namespace if necessary.",
	"TR3": "Use descriptive triggers that clearly indicate the skill's purpose rather than generic keywords designed to maximize activation.",
	"CP001": "Fix .claude-plugin/plugin.json: ensure it is valid JSON, includes a non-empty 'name', a valid 'version', and that declared component fields use the correct types.",
	"CP002": "Remove the path-traversal component reference. Declare component paths relative to and within the plugin root; never use '../' to reach outside it.",
	"CP003": "Remove the escaping symlink or repoint it inside the plugin root. Plugins must not symlink to host files outside their own directory.",
}

var ruleIDToCategory = map[string]string{
	"P1": catPromptInjection, "P2": catPromptInjection, "P3": catPromptInjection, "P4": catPromptInjection, "P5": catPromptInjection,
	"P6": catSystemPromptLeakage, "P7": catSystemPromptLeakage, "P8": catSystemPromptLeakage,
	"E1": catDataExfiltration, "E2": catDataExfiltration, "E3": catDataExfiltration, "E4": catDataExfiltration,
	"PE1": catPrivilegeEscalation, "PE2": catPrivilegeEscalation, "PE3": catPrivilegeEscalation,
	"SC1": catSupplyChain, "SC2": catSupplyChain, "SC3": catSupplyChain, "SC4": catSupplyChain, "SC5": catSupplyChain, "SC6": catSupplyChain,
	"EA1": catExcessiveAgency, "EA2": catExcessiveAgency, "EA3": catExcessiveAgency, "EA4": catExcessiveAgency,
	"OH1": catOutputHandling, "OH2": catOutputHandling, "OH3": catOutputHandling,
	"MP1": catMemoryPoisoning, "MP2": catMemoryPoisoning, "MP3": catMemoryPoisoning,
	"TM1": catToolMisuse, "TM2": catToolMisuse, "TM3": catToolMisuse,
	"RA1": catRogueAgent, "RA2": catRogueAgent,
	"TR1": catTriggerAbuse, "TR2": catTriggerAbuse, "TR3": catTriggerAbuse,
	"CP001": catClaudePlugin, "CP002": catClaudePlugin, "CP003": catClaudePlugin,
}

var patternNames = map[string]string{
	"P1": "Override Instructions", "P2": "Hidden Instructions", "P3": "External Transmission Instructions", "P4": "Subtle Steering", "P5": "Harmful Content",
	"P6": "System Prompt Leakage", "P7": "System Prompt Leakage", "P8": "System Prompt Leakage",
	"E1": "External Transmission", "E2": "Env Variable Harvesting", "E3": "File System Enumeration", "E4": "Conversation Context Leak",
	"PE1": "Excessive Permissions", "PE2": "Sudo/Root Invocation", "PE3": "Credential File Access",
	"SC1": "Unpinned Dependencies", "SC2": "Remote Code Execution", "SC3": "Obfuscated Code",
	"EA1": "Unrestricted Tool Access", "EA2": "Autonomous Decision Making", "EA3": "Scope Creep", "EA4": "Unbounded Resource Access",
	"OH1": "Unvalidated Output Injection", "OH2": "Cross-Context Output", "OH3": "Unbounded Output",
	"MP1": "Persistent Context Injection", "MP2": "Context Window Stuffing", "MP3": "Memory Manipulation",
	"TM1": "Tool Parameter Abuse", "TM2": "Chaining Abuse", "TM3": "Unsafe Defaults",
	"RA1": "Self-Modification", "RA2": "Session Persistence",
	"SC4": "Known Vulnerable Dependency", "SC5": "Abandoned Dependency", "SC6": "Typosquatting Dependency",
	"TR1": "Overly Broad Trigger", "TR2": "Shadow Command Trigger", "TR3": "Keyword Baiting Trigger",
	"CP001": "Invalid Plugin Manifest", "CP002": "Component Path Escape", "CP003": "Symlink Escape",
}

func getExplanation(id string) string {
	if v, ok := defaultExplanations[id]; ok {
		return v
	}
	return "Potential security issue detected. Manual review is recommended."
}

func getRemediation(id string) string {
	if v, ok := defaultRemediations[id]; ok {
		return v
	}
	return "Review the flagged content for security risks. Ensure no credentials, secrets, or sensitive data are exposed."
}

func getCategory(id string) string {
	if v, ok := ruleIDToCategory[id]; ok {
		return v
	}
	return "Security"
}

func getPatternName(id string) string {
	if v, ok := patternNames[id]; ok {
		return v
	}
	return "Unknown"
}

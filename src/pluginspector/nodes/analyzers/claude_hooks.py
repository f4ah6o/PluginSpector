# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Claude plugin hooks analyzer (issue #1) — HK001 through HK004.

Parses hook configuration (hooks/hooks.json or .claude-plugin-declared hook files)
and inspects each command for shell execution, external network access, automatic
lifecycle execution, and download-and-execute patterns.
"""

from __future__ import annotations

import json
import re

from pluginspector.logging_config import get_logger
from pluginspector.models import Finding
from pluginspector.state import AnalyzerNodeResponse, SkillspectorState

from .claude_common import get_components, is_claude_plugin, make_finding
from .common import get_line_number

ANALYZER_ID = "claude_hooks"
logger = get_logger(__name__)

# Hook events that fire automatically during the agent lifecycle.
_AUTO_LIFECYCLE = frozenset(
    {
        "SessionStart",
        "SessionEnd",
        "UserPromptSubmit",
        "Stop",
        "SubagentStop",
        "PreCompact",
        "Notification",
        "PreToolUse",
        "PostToolUse",
    }
)

# External HTTP / network egress indicators.
_HTTP_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|telnet|Invoke-WebRequest|Invoke-RestMethod)\b|https?://|\bfetch\s*\(",
    re.IGNORECASE,
)

# External command execution indicators (network, remote shells, interpreters).
_EXTERNAL_CMD_RE = re.compile(
    r"\b(?:curl|wget|ssh|scp|sftp|nc|ncat|telnet|bash|sh|zsh|python3?|node|npx|uvx|"
    r"eval|base64|osascript|powershell|pwsh)\b|https?://",
    re.IGNORECASE,
)

# Download-and-execute (curl/wget piped or chained into an interpreter).
_DOWNLOAD_EXEC_RE = re.compile(
    r"(?:curl|wget)\s+[^|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh"
    r"|(?:curl|wget)\s+[^|]*\|\s*(?:sudo\s+)?(?:python3?|node|ruby|perl)"
    r"|(?:curl|wget)\s+[^&]*-o\S*\s+\S+\s*&&\s*(?:sudo\s+)?(?:ba|z)?sh",
    re.IGNORECASE,
)


def _iter_commands(data: dict[str, object]) -> list[tuple[str, str]]:
    """Return (event_name, command) pairs from a parsed hooks.json structure."""
    event_map = data.get("hooks") if isinstance(data.get("hooks"), dict) else data
    pairs: list[tuple[str, str]] = []
    if not isinstance(event_map, dict):
        return pairs
    for event, entries in event_map.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            hooks = entry.get("hooks")
            if not isinstance(hooks, list):
                continue
            for hook in hooks:
                if not isinstance(hook, dict):
                    continue
                command = hook.get("command")
                if isinstance(command, str) and command.strip():
                    pairs.append((str(event), command))
    return pairs


def _analyze_file(path: str, content: str) -> list[Finding]:
    """Analyze a single hooks config file's content."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []
    for event, command in _iter_commands(data):
        line = get_line_number(content, content.find(command)) if command in content else 1
        is_lifecycle = event in _AUTO_LIFECYCLE

        # HK001: any command hook executes a shell command.
        findings.append(
            make_finding(
                rule_id="HK001",
                severity="MEDIUM",
                file=path,
                start_line=line,
                message=f"Hook on '{event}' executes a shell command.",
                confidence=0.7,
                matched_text=command,
            )
        )

        # HK004: download-and-execute (highest severity, check first for messaging).
        if _DOWNLOAD_EXEC_RE.search(command):
            findings.append(
                make_finding(
                    rule_id="HK004",
                    severity="CRITICAL",
                    file=path,
                    start_line=line,
                    message=f"Hook on '{event}' downloads and executes remote code.",
                    confidence=0.95,
                    matched_text=command,
                )
            )

        # HK002: hook contacts an external HTTP endpoint.
        if _HTTP_RE.search(command):
            findings.append(
                make_finding(
                    rule_id="HK002",
                    severity="HIGH",
                    file=path,
                    start_line=line,
                    message=f"Hook on '{event}' calls an external HTTP endpoint.",
                    confidence=0.8,
                    matched_text=command,
                )
            )

        # HK003: automatic lifecycle hook executes an external command.
        if is_lifecycle and _EXTERNAL_CMD_RE.search(command):
            findings.append(
                make_finding(
                    rule_id="HK003",
                    severity="HIGH",
                    file=path,
                    start_line=line,
                    message=(f"Automatic lifecycle hook '{event}' executes an external command."),
                    confidence=0.85,
                    matched_text=command,
                )
            )

    return findings


def node(state: SkillspectorState) -> AnalyzerNodeResponse:
    """Analyze plugin hook configuration files; emit HK001-HK004."""
    if not is_claude_plugin(state):
        return {"findings": []}

    file_cache: dict[str, str] = state.get("file_cache") or {}
    # Collect hook config paths from parsed components, plus the default location.
    hook_paths = {
        str(c.get("path"))
        for c in get_components(state)
        if c.get("kind") == "hooks" and isinstance(c.get("path"), str)
    }
    hook_paths.add("hooks/hooks.json")

    findings: list[Finding] = []
    for path in sorted(hook_paths):
        content = file_cache.get(path)
        if content:
            findings.extend(_analyze_file(path, content))

    logger.info("%s: %d findings", ANALYZER_ID, len(findings))
    return {"findings": findings}

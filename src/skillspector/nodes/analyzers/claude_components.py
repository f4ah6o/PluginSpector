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

"""Claude plugin component analyzer (issue #1) — AG001, BIN001, MON001, DEP001.

Covers agents (broad permissions), bin/ command shadowing, monitors (background
execution), and plugin dependency pinning.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

import yaml

from skillspector.claude_plugin import PLUGIN_MANIFEST_PATH
from skillspector.logging_config import get_logger
from skillspector.models import Finding
from skillspector.state import AnalyzerNodeResponse, SkillspectorState

from .claude_common import get_components, get_plugin_model, is_claude_plugin, make_finding
from .common import get_line_number

ANALYZER_ID = "claude_components"
logger = get_logger(__name__)

# Common commands a plugin bin/ entry must not shadow.
_COMMON_COMMANDS = frozenset(
    {
        "git",
        "node",
        "npm",
        "npx",
        "python",
        "python3",
        "pip",
        "pip3",
        "sh",
        "bash",
        "zsh",
        "ls",
        "cat",
        "curl",
        "wget",
        "ssh",
        "scp",
        "sudo",
        "docker",
        "kubectl",
        "make",
        "go",
        "ruby",
        "perl",
        "env",
        "uv",
        "uvx",
    }
)

# Agent permission/tool grants considered broad.
_BROAD_TOOLS = frozenset({"*", "bash", "write", "edit", "multiedit", "notebookedit"})

# Background/persistent execution indicators in monitor definitions.
_BACKGROUND_RE = re.compile(
    r"\b(daemon|background|persistent|forever|nohup|setInterval|while\s+true)\b"
    r"|\"interval\"|\"schedule\"|\"cron\"|--watch\b|&\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def _parse_frontmatter(content: str) -> dict[str, object]:
    """Parse YAML frontmatter from a Markdown agent file."""
    if not content.startswith("---"):
        return {}
    end = re.search(r"\n---\s*\n", content[3:])
    if not end:
        return {}
    try:
        data = yaml.safe_load(content[3 : end.start() + 3])
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _tool_tokens(value: object) -> list[str]:
    """Normalize a tools/permissions field (str or list) to lowercase tokens."""
    tokens: list[str] = []
    if isinstance(value, str):
        tokens = re.split(r"[,\s]+", value)
    elif isinstance(value, list):
        tokens = [str(v) for v in value]
    return [t.strip().lower() for t in tokens if t and t.strip()]


def _broad_grants(frontmatter: dict[str, object]) -> list[str]:
    """Return broad tool/permission grants declared by an agent."""
    grants: set[str] = set()
    for key in ("tools", "allowed-tools", "allowed_tools", "permissions"):
        for tok in _tool_tokens(frontmatter.get(key)):
            base = tok.split("(")[0]  # e.g. "bash(rm:*)" -> "bash"
            if base in _BROAD_TOOLS:
                grants.add(base)
    return sorted(grants)


def _analyze_agents(state: SkillspectorState, file_cache: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for comp in get_components(state):
        if comp.get("kind") != "agent":
            continue
        path = str(comp.get("path"))
        content = file_cache.get(path)
        if not content:
            continue
        grants = _broad_grants(_parse_frontmatter(content))
        if grants:
            findings.append(
                make_finding(
                    rule_id="AG001",
                    severity="MEDIUM",
                    file=path,
                    message=(f"Agent declares broad permissions: {', '.join(grants)}."),
                    confidence=0.75,
                    matched_text=", ".join(grants),
                )
            )
    return findings


def _analyze_bin(state: SkillspectorState) -> list[Finding]:
    findings: list[Finding] = []
    for comp in get_components(state):
        if comp.get("kind") != "bin":
            continue
        path = str(comp.get("path"))
        name = PurePosixPath(path).name
        if name in _COMMON_COMMANDS:
            findings.append(
                make_finding(
                    rule_id="BIN001",
                    severity="HIGH",
                    file=path,
                    message=f"Plugin bin/ entry '{name}' shadows a common command.",
                    confidence=0.8,
                    matched_text=name,
                )
            )
    return findings


def _analyze_monitors(state: SkillspectorState, file_cache: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for comp in get_components(state):
        if comp.get("kind") != "monitor":
            continue
        path = str(comp.get("path"))
        content = file_cache.get(path)
        if not content:
            continue
        match = _BACKGROUND_RE.search(content)
        if match:
            line = get_line_number(content, match.start())
            findings.append(
                make_finding(
                    rule_id="MON001",
                    severity="MEDIUM",
                    file=path,
                    start_line=line,
                    message="Monitor starts persistent background execution.",
                    confidence=0.7,
                    matched_text=match.group(0),
                )
            )
    return findings


def _dep_is_pinned(spec: str) -> bool:
    """Return True if a dependency spec is pinned to an immutable revision."""
    s = spec.strip()
    if not s:
        return False
    low = s.lower()
    if low in {"latest", "*", "x"}:
        return False
    if any(op in s for op in ("^", "~", ">=", "<=", ">", "<")):
        return False
    if (
        s.startswith(("http://", "https://", "git+", "git@"))
        or s.endswith(".git")
        or "github.com" in low
    ):
        return bool(re.search(r"@[0-9a-f]{7,40}$", s) or re.search(r"@v?\d", s))
    if s.startswith("==") or re.match(r"^v?\d", s):
        return True
    return False  # branch/tag names like main/master are mutable


def _iter_dependencies(manifest: dict[str, object]) -> list[tuple[str, str]]:
    """Return (name, spec) pairs from manifest 'dependencies'."""
    deps = manifest.get("dependencies")
    pairs: list[tuple[str, str]] = []
    if isinstance(deps, dict):
        for k, v in deps.items():
            pairs.append((str(k), str(v) if not isinstance(v, dict) else _dict_spec(v)))
    elif isinstance(deps, list):
        for el in deps:
            if isinstance(el, str):
                name, _, spec = el.partition("@")
                pairs.append((name or el, spec))
            elif isinstance(el, dict):
                name = str(el.get("name", el.get("source", "dependency")))
                pairs.append((name, _dict_spec(el)))
    return pairs


def _dict_spec(d: dict[str, object]) -> str:
    """Extract a version/revision spec from a dependency object."""
    for key in ("rev", "ref", "commit", "sha", "version", "tag"):
        val = d.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


def _analyze_dependencies(state: SkillspectorState, file_cache: dict[str, str]) -> list[Finding]:
    manifest = get_plugin_model(state).get("manifest")
    if not isinstance(manifest, dict):
        return []
    content = file_cache.get(PLUGIN_MANIFEST_PATH, "")
    findings: list[Finding] = []
    for name, spec in _iter_dependencies(manifest):
        if _dep_is_pinned(spec):
            continue
        needle = spec or name
        line = get_line_number(content, content.find(needle)) if needle and needle in content else 1
        shown = f"{name}@{spec}" if spec else name
        findings.append(
            make_finding(
                rule_id="DEP001",
                severity="MEDIUM",
                file=PLUGIN_MANIFEST_PATH,
                start_line=line,
                message=f"Plugin dependency '{shown}' is not pinned to an immutable revision.",
                confidence=0.75,
                matched_text=shown,
            )
        )
    return findings


def node(state: SkillspectorState) -> AnalyzerNodeResponse:
    """Analyze agents, bin/, monitors, and dependencies; emit AG001/BIN001/MON001/DEP001."""
    if not is_claude_plugin(state):
        return {"findings": []}

    file_cache: dict[str, str] = state.get("file_cache") or {}
    findings: list[Finding] = []
    findings.extend(_analyze_agents(state, file_cache))
    findings.extend(_analyze_bin(state))
    findings.extend(_analyze_monitors(state, file_cache))
    findings.extend(_analyze_dependencies(state, file_cache))

    logger.info("%s: %d findings", ANALYZER_ID, len(findings))
    return {"findings": findings}

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

"""Claude plugin capability-correlation analyzer (issue #1) — CC001/CC002/CC003.

Computes a capability set per component, then raises elevated-severity findings for
dangerous combinations either within a single component or across the plugin.
"""

from __future__ import annotations

import re

from pluginspector.claude_plugin import PLUGIN_MANIFEST_PATH
from pluginspector.logging_config import get_logger
from pluginspector.models import Finding
from pluginspector.state import AnalyzerNodeResponse, SkillspectorState

from .claude_common import get_components, is_claude_plugin, make_finding
from .mcp_least_privilege import _detect_capabilities

ANALYZER_ID = "claude_capability_correlation"
logger = get_logger(__name__)

# Map mcp_least_privilege capability categories to the correlation vocabulary.
_CATEGORY_TO_CAP = {
    "shell": "process_exec",
    "network": "network_egress",
    "file_read": "file_read",
    "file_write": "file_write",
    "env": "secret_access",
    "mcp": "tool_invocation",
}

_HTTP_RE = re.compile(r"https?://|\b(?:curl|wget|fetch)\b", re.IGNORECASE)
_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|bearer)"
    r"|sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}"
)

# Dangerous capability pairs → (rule_id, label).
_COMBINATIONS = [
    (("secret_access", "network_egress"), "CC001", "secret access combined with network egress"),
    (("auto_activation", "process_exec"), "CC002", "automatic activation with process execution"),
    (("background_exec", "network_egress"), "CC003", "background execution with network access"),
]


def _component_caps(kind: str, content: str) -> set[str]:
    """Compute the capability set for a component from its kind and file content."""
    caps: set[str] = set()
    for category in _detect_capabilities(content):
        mapped = _CATEGORY_TO_CAP.get(category)
        if mapped:
            caps.add(mapped)
    if _HTTP_RE.search(content):
        caps.add("network_egress")
    if _SECRET_RE.search(content):
        caps.add("secret_access")

    # Structural capabilities implied by the component kind.
    if kind == "hooks":
        caps.update({"auto_activation", "process_exec"})
    elif kind == "monitor":
        caps.update({"background_exec", "auto_activation"})
    elif kind == "bin":
        caps.add("process_exec")
    elif kind == "mcp":
        caps.add("process_exec")
    return caps


def node(state: SkillspectorState) -> AnalyzerNodeResponse:
    """Correlate component capabilities; emit CC001-CC003 for dangerous combinations."""
    if not is_claude_plugin(state):
        return {"findings": []}

    file_cache: dict[str, str] = state.get("file_cache") or {}

    # Capability set per component path.
    comp_caps: dict[str, set[str]] = {}
    for comp in get_components(state):
        path = str(comp.get("path"))
        kind = str(comp.get("kind"))
        content = file_cache.get(path, "")
        caps = _component_caps(kind, content)
        if caps:
            comp_caps.setdefault(path, set()).update(caps)

    union: set[str] = set()
    for caps in comp_caps.values():
        union |= caps

    findings: list[Finding] = []
    for (a, b), rule_id, label in _COMBINATIONS:
        # Per-component (high confidence): one component holds both capabilities.
        attributed = False
        for path, caps in sorted(comp_caps.items()):
            if a in caps and b in caps:
                findings.append(
                    make_finding(
                        rule_id=rule_id,
                        severity="HIGH",
                        file=path,
                        message=f"Component '{path}' exhibits {label}.",
                        confidence=0.75,
                        matched_text=f"{a} + {b}",
                        context=f"capabilities: {', '.join(sorted(caps))}",
                    )
                )
                attributed = True
        # Cross-component (lower confidence): the pair is split across components.
        if not attributed and a in union and b in union:
            findings.append(
                make_finding(
                    rule_id=rule_id,
                    severity="HIGH",
                    file=PLUGIN_MANIFEST_PATH,
                    message=(f"Plugin combines {label} across multiple components."),
                    confidence=0.6,
                    matched_text=f"{a} + {b}",
                )
            )

    logger.info("%s: %d findings", ANALYZER_ID, len(findings))
    return {"findings": findings}

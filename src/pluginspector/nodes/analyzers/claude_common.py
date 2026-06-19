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

"""Shared helpers for the Claude Code plugin analyzer nodes (issue #1)."""

from __future__ import annotations

import json

from pluginspector.claude_plugin import TargetType
from pluginspector.models import Finding
from pluginspector.state import SkillspectorState

from .pattern_defaults import get_category, get_explanation, get_pattern_name, get_remediation


def is_claude_plugin(state: SkillspectorState) -> bool:
    """Return True when the scanned target was classified as a Claude plugin."""
    model = state.get("plugin_model") or {}
    return model.get("target_type") == TargetType.CLAUDE_PLUGIN.value


def get_plugin_model(state: SkillspectorState) -> dict[str, object]:
    """Return the serialized plugin model dict (empty dict when absent)."""
    model = state.get("plugin_model")
    return model if isinstance(model, dict) else {}


def get_components(state: SkillspectorState) -> list[dict[str, object]]:
    """Return the plugin component dicts from the model (empty list when absent)."""
    comps = get_plugin_model(state).get("components")
    return [c for c in comps if isinstance(c, dict)] if isinstance(comps, list) else []


def load_json_component(file_cache: dict[str, str], path: str) -> dict[str, object] | None:
    """Parse a JSON component file from the cache; return None on missing/invalid."""
    content = file_cache.get(path)
    if not content:
        return None
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def make_finding(
    *,
    rule_id: str,
    severity: str,
    file: str,
    message: str,
    start_line: int = 1,
    confidence: float = 0.8,
    matched_text: str | None = None,
    context: str | None = None,
    tags: list[str] | None = None,
) -> Finding:
    """Build a Finding with category/pattern/explanation/remediation from pattern_defaults."""
    return Finding(
        rule_id=rule_id,
        message=message,
        severity=severity,
        confidence=confidence,
        file=file,
        start_line=start_line,
        category=get_category(rule_id),
        pattern=get_pattern_name(rule_id),
        explanation=get_explanation(rule_id),
        remediation=get_remediation(rule_id),
        matched_text=matched_text[:200] if matched_text else None,
        finding=matched_text[:200] if matched_text else None,
        context=context,
        code_snippet=context,
        tags=tags if tags is not None else [get_category(rule_id)],
    )

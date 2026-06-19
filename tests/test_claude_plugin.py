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

"""Tests for Claude plugin target detection and structure parsing (issue #1)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from pluginspector.claude_plugin import TargetType, detect_target_type, parse_plugin


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _plugin(root: Path, manifest: dict | str) -> Path:
    text = manifest if isinstance(manifest, str) else json.dumps(manifest)
    _write(root / ".claude-plugin" / "plugin.json", text)
    return root


# ---------------------------------------------------------------------------
# detect_target_type
# ---------------------------------------------------------------------------


def test_detect_claude_plugin(tmp_path: Path) -> None:
    _plugin(tmp_path, {"name": "p", "version": "1.0.0"})
    assert detect_target_type(tmp_path) is TargetType.CLAUDE_PLUGIN


def test_detect_marketplace(tmp_path: Path) -> None:
    _write(tmp_path / ".claude-plugin" / "marketplace.json", "{}")
    assert detect_target_type(tmp_path) is TargetType.CLAUDE_MARKETPLACE


def test_detect_standalone_skill(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "---\nname: s\n---\n")
    assert detect_target_type(tmp_path) is TargetType.STANDALONE_SKILL


def test_detect_generic_directory(tmp_path: Path) -> None:
    _write(tmp_path / "README.md", "# hi\n")
    assert detect_target_type(tmp_path) is TargetType.GENERIC_DIRECTORY


def test_plugin_wins_over_bundled_skill(tmp_path: Path) -> None:
    _plugin(tmp_path, {"name": "p", "version": "1.0.0"})
    _write(tmp_path / "SKILL.md", "---\nname: s\n---\n")
    assert detect_target_type(tmp_path) is TargetType.CLAUDE_PLUGIN


# ---------------------------------------------------------------------------
# parse_plugin: stub for non-plugin
# ---------------------------------------------------------------------------


def test_parse_non_plugin_returns_stub(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "---\nname: s\n---\n")
    model = parse_plugin(tmp_path, {})
    assert model.target_type == TargetType.STANDALONE_SKILL.value
    assert model.components == []
    assert model.structural_issues == []


# ---------------------------------------------------------------------------
# parse_plugin: manifest validation (CP001 inputs)
# ---------------------------------------------------------------------------


def test_invalid_json_manifest_records_error(tmp_path: Path) -> None:
    _plugin(tmp_path, "{ not valid json ")
    model = parse_plugin(tmp_path, {})
    assert any("not valid JSON" in e for e in model.manifest_errors)


def test_missing_name_records_error(tmp_path: Path) -> None:
    _plugin(tmp_path, {"version": "1.0.0"})
    model = parse_plugin(tmp_path, {})
    assert any("name" in e for e in model.manifest_errors)


def test_bad_version_records_error(tmp_path: Path) -> None:
    _plugin(tmp_path, {"name": "p", "version": "not-a-version"})
    model = parse_plugin(tmp_path, {})
    assert any("version" in e for e in model.manifest_errors)


def test_clean_manifest_no_errors(tmp_path: Path) -> None:
    _plugin(tmp_path, {"name": "p", "version": "1.2.3"})
    model = parse_plugin(tmp_path, {})
    assert model.manifest_errors == []


# ---------------------------------------------------------------------------
# parse_plugin: component enumeration
# ---------------------------------------------------------------------------


def test_convention_components_discovered(tmp_path: Path) -> None:
    _plugin(tmp_path, {"name": "p", "version": "1.0.0"})
    _write(tmp_path / "hooks" / "hooks.json", "{}")
    _write(tmp_path / ".mcp.json", "{}")
    _write(tmp_path / ".lsp.json", "{}")
    _write(tmp_path / "agents" / "a.md", "---\nname: a\n---\n")
    _write(tmp_path / "monitors" / "m.json", "{}")
    _write(tmp_path / "bin" / "tool", "#!/bin/sh\n")
    model = parse_plugin(tmp_path, {})
    kinds = {(c.kind, c.path) for c in model.components}
    assert ("hooks", "hooks/hooks.json") in kinds
    assert ("mcp", ".mcp.json") in kinds
    assert ("lsp", ".lsp.json") in kinds
    assert ("agent", "agents/a.md") in kinds
    assert ("monitor", "monitors/m.json") in kinds
    assert ("bin", "bin/tool") in kinds


# ---------------------------------------------------------------------------
# parse_plugin: structural issues (CP002/CP003 inputs)
# ---------------------------------------------------------------------------


def test_path_escape_detected(tmp_path: Path) -> None:
    _plugin(tmp_path, {"name": "p", "version": "1.0.0", "commands": "../outside/evil"})
    model = parse_plugin(tmp_path, {})
    escapes = [s for s in model.structural_issues if s.kind == "path_escape"]
    assert len(escapes) == 1
    assert "../outside/evil" in escapes[0].path


def test_symlink_escape_detected(tmp_path: Path) -> None:
    _plugin(tmp_path, {"name": "p", "version": "1.0.0"})
    (tmp_path / "bin").mkdir()
    link = tmp_path / "bin" / "escape"
    os.symlink("/etc", link)
    model = parse_plugin(tmp_path, {})
    symlinks = [s for s in model.structural_issues if s.kind == "symlink_escape"]
    assert len(symlinks) == 1
    assert symlinks[0].path == "bin/escape"


def test_to_dict_is_json_serializable(tmp_path: Path) -> None:
    _plugin(tmp_path, {"name": "p", "version": "1.0.0", "commands": "../x"})
    _write(tmp_path / "bin" / "tool", "#!/bin/sh\n")
    model = parse_plugin(tmp_path, {})
    # Must round-trip through JSON for LangGraph state serialization.
    dumped = json.dumps(model.to_dict())
    assert "claude-plugin" in dumped

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

"""Tests for claude_plugin_structure analyzer (CP001/CP002/CP003)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from skillspector.nodes.analyzers import claude_plugin_structure
from skillspector.nodes.build_context import build_context


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _run(root: Path) -> list:
    state = dict(build_context({"skill_path": str(root)}))
    return claude_plugin_structure.node(state)["findings"]


def _ids(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


def test_clean_plugin_no_findings(tmp_path: Path) -> None:
    _write(
        tmp_path / ".claude-plugin" / "plugin.json", json.dumps({"name": "p", "version": "1.0.0"})
    )
    assert _ids(_run(tmp_path)) == set()


def test_cp001_missing_name(tmp_path: Path) -> None:
    _write(tmp_path / ".claude-plugin" / "plugin.json", json.dumps({"version": "1.0.0"}))
    assert "CP001" in _ids(_run(tmp_path))


def test_cp002_path_escape(tmp_path: Path) -> None:
    _write(
        tmp_path / ".claude-plugin" / "plugin.json",
        json.dumps({"name": "p", "version": "1.0.0", "agents": "../../etc"}),
    )
    findings = _run(tmp_path)
    assert "CP002" in _ids(findings)
    cp002 = next(f for f in findings if f.rule_id == "CP002")
    assert cp002.severity == "HIGH"


def test_cp003_symlink_escape(tmp_path: Path) -> None:
    _write(
        tmp_path / ".claude-plugin" / "plugin.json", json.dumps({"name": "p", "version": "1.0.0"})
    )
    (tmp_path / "bin").mkdir()
    os.symlink("/etc", tmp_path / "bin" / "escape")
    findings = _run(tmp_path)
    assert "CP003" in _ids(findings)


def test_non_plugin_target_skipped(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "---\nname: s\n---\n")
    assert _run(tmp_path) == []

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

"""Tests for claude_components analyzer (AG001/BIN001/MON001/DEP001)."""

from __future__ import annotations

import json
from pathlib import Path

from pluginspector.nodes.analyzers import claude_components
from pluginspector.nodes.build_context import build_context


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _manifest(root: Path, extra: dict | None = None) -> None:
    data = {"name": "p", "version": "1.0.0"}
    if extra:
        data.update(extra)
    _write(root / ".claude-plugin" / "plugin.json", json.dumps(data, indent=2))


def _run(root: Path) -> list:
    state = dict(build_context({"skill_path": str(root)}))
    return claude_components.node(state)["findings"]


def _ids(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


def test_ag001_broad_agent_permissions(tmp_path: Path) -> None:
    _manifest(tmp_path)
    _write(
        tmp_path / "agents" / "broad.md", "---\nname: broad\ntools: [Bash, Write]\n---\n# Agent\n"
    )
    assert "AG001" in _ids(_run(tmp_path))


def test_agent_narrow_tools_no_ag001(tmp_path: Path) -> None:
    _manifest(tmp_path)
    _write(tmp_path / "agents" / "ok.md", "---\nname: ok\ntools: [Read, Grep]\n---\n# Agent\n")
    assert "AG001" not in _ids(_run(tmp_path))


def test_bin001_shadows_git(tmp_path: Path) -> None:
    _manifest(tmp_path)
    _write(tmp_path / "bin" / "git", "#!/bin/sh\necho hi\n")
    findings = _run(tmp_path)
    assert "BIN001" in _ids(findings)
    assert next(f for f in findings if f.rule_id == "BIN001").severity == "HIGH"


def test_bin_unique_name_no_bin001(tmp_path: Path) -> None:
    _manifest(tmp_path)
    _write(tmp_path / "bin" / "my-unique-tool", "#!/bin/sh\n")
    assert "BIN001" not in _ids(_run(tmp_path))


def test_mon001_background_monitor(tmp_path: Path) -> None:
    _manifest(tmp_path)
    _write(
        tmp_path / "monitors" / "watch.json",
        json.dumps({"command": "tail -f log", "background": True}),
    )
    assert "MON001" in _ids(_run(tmp_path))


def test_dep001_unpinned_dependency(tmp_path: Path) -> None:
    _manifest(tmp_path, {"dependencies": {"other-plugin": "^1.0.0"}})
    assert "DEP001" in _ids(_run(tmp_path))


def test_dep001_pinned_dependency_clean(tmp_path: Path) -> None:
    _manifest(tmp_path, {"dependencies": {"other-plugin": "1.2.3"}})
    assert "DEP001" not in _ids(_run(tmp_path))


def test_dep001_git_without_sha(tmp_path: Path) -> None:
    _manifest(tmp_path, {"dependencies": ["https://github.com/acme/plugin.git"]})
    assert "DEP001" in _ids(_run(tmp_path))

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

"""Tests for claude_mcp_lsp analyzer (MCP001/MCP002/MCP003)."""

from __future__ import annotations

import json
from pathlib import Path

from skillspector.nodes.analyzers import claude_mcp_lsp
from skillspector.nodes.build_context import build_context


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _plugin_with_mcp(root: Path, mcp: dict) -> None:
    _write(root / ".claude-plugin" / "plugin.json", json.dumps({"name": "p", "version": "1.0.0"}))
    _write(root / ".mcp.json", json.dumps(mcp, indent=2))


def _run(root: Path) -> list:
    state = dict(build_context({"skill_path": str(root)}))
    return claude_mcp_lsp.node(state)["findings"]


def _ids(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


def test_unpinned_secret_and_insecure(tmp_path: Path) -> None:
    _plugin_with_mcp(
        tmp_path,
        {
            "mcpServers": {
                "svc": {
                    "command": "npx",
                    "args": ["-y", "some-pkg"],
                    "env": {"API_KEY": "sk-live0123456789abcdef0123"},
                    "url": "http://remote.example/mcp",
                }
            }
        },
    )
    findings = _run(tmp_path)
    ids = _ids(findings)
    assert "MCP001" in ids
    assert "MCP002" in ids
    assert "MCP003" in ids
    assert next(f for f in findings if f.rule_id == "MCP002").severity == "CRITICAL"


def test_pinned_package_no_mcp001(tmp_path: Path) -> None:
    _plugin_with_mcp(
        tmp_path,
        {"mcpServers": {"svc": {"command": "npx", "args": ["-y", "some-pkg@1.2.3"]}}},
    )
    assert "MCP001" not in _ids(_run(tmp_path))


def test_env_reference_not_flagged_as_secret(tmp_path: Path) -> None:
    _plugin_with_mcp(
        tmp_path,
        {
            "mcpServers": {
                "svc": {"command": "node", "args": ["s.js"], "env": {"API_KEY": "${API_KEY}"}}
            }
        },
    )
    assert "MCP002" not in _ids(_run(tmp_path))


def test_localhost_http_is_low_severity(tmp_path: Path) -> None:
    _plugin_with_mcp(
        tmp_path,
        {"mcpServers": {"svc": {"url": "http://localhost:3000/mcp"}}},
    )
    findings = _run(tmp_path)
    mcp003 = [f for f in findings if f.rule_id == "MCP003"]
    assert mcp003 and mcp003[0].severity == "LOW"


def test_https_endpoint_clean(tmp_path: Path) -> None:
    _plugin_with_mcp(
        tmp_path,
        {
            "mcpServers": {
                "svc": {"command": "node", "args": ["s.js"], "url": "https://remote.example"}
            }
        },
    )
    assert _ids(_run(tmp_path)) == set()

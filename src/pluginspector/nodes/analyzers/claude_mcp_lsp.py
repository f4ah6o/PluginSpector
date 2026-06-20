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

"""Claude plugin MCP/LSP configuration analyzer (issue #1) — MCP001/MCP002/MCP003."""

from __future__ import annotations

import json
import re

from pluginspector.logging_config import get_logger
from pluginspector.models import Finding
from pluginspector.state import AnalyzerNodeResponse, SkillspectorState

from .claude_common import get_components, is_claude_plugin, make_finding
from .common import get_line_number

ANALYZER_ID = "claude_mcp_lsp"
logger = get_logger(__name__)

# Package runners whose default invocation pulls the latest published code.
_RUNNERS = frozenset({"npx", "uvx", "bunx", "pnpx", "pipx"})

# Server-config keys that may hold a server definition map.
_SERVER_MAP_KEYS = ("mcpServers", "servers", "lspServers", "lsp")

# Endpoint URL fields.
_URL_KEYS = ("url", "endpoint", "baseUrl", "base_url", "uri")

_SECRET_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd|bearer|access[_-]?key|private[_-]?key)"
)
_SECRET_VAL_RE = re.compile(
    r"sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_\-]{20,}"
)
# A value that is an env reference (${VAR} or $VAR) rather than a literal secret.
_ENV_REF_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")


def _is_unpinned_spec(spec: str) -> bool:
    """Return True if a package spec has no immutable version/revision pin."""
    s = spec.strip()
    if "==" in s:
        return False
    if re.search(r"@[\^~]?\d", s):  # pkg@1, @scope/pkg@1.2.3
        return False
    if re.search(r"@[0-9a-f]{7,40}$", s):  # git commit sha
        return False
    return True


def _runner_and_spec(command: str, args: list[str]) -> tuple[str, str] | None:
    """Return (runner, package_spec) if this is an unpinned runner invocation, else None."""
    cmd = command.strip().split("/")[-1]
    runner = ""
    rest = list(args)
    if cmd in _RUNNERS:
        runner = cmd
    elif cmd == "pnpm" and args and args[0] == "dlx":
        runner = "pnpm dlx"
        rest = args[1:]
    else:
        return None
    # First non-flag argument is the package spec.
    for a in rest:
        if isinstance(a, str) and not a.startswith("-"):
            return (runner, a)
    return None


def _scan_secret_values(server: dict[str, object]) -> list[tuple[str, str]]:
    """Return (where, value) pairs that look like embedded secrets."""
    hits: list[tuple[str, str]] = []
    env = server.get("env")
    if isinstance(env, dict):
        for k, v in env.items():
            if not isinstance(v, str) or not v.strip():
                continue
            if _ENV_REF_RE.match(v.strip()):
                continue
            if _SECRET_VAL_RE.search(v) or (_SECRET_KEY_RE.search(str(k)) and len(v.strip()) >= 8):
                hits.append((f"env.{k}", v))
    # args and url strings may also carry inline secrets.
    args = server.get("args")
    if isinstance(args, list):
        for a in args:
            if isinstance(a, str) and _SECRET_VAL_RE.search(a):
                hits.append(("args", a))
    for key in _URL_KEYS:
        val = server.get(key)
        if isinstance(val, str) and _SECRET_VAL_RE.search(val):
            hits.append((key, val))
    return hits


def _analyze_server(name: str, server: dict[str, object], path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []

    # MCP001: unpinned runtime package execution.
    command = server.get("command")
    args = server.get("args")
    arg_list = [a for a in args if isinstance(a, str)] if isinstance(args, list) else []
    if isinstance(command, str):
        runner_spec = _runner_and_spec(command, arg_list)
        if runner_spec and _is_unpinned_spec(runner_spec[1]):
            runner, spec = runner_spec
            line = get_line_number(content, content.find(spec)) if spec in content else 1
            findings.append(
                make_finding(
                    rule_id="MCP001",
                    severity="HIGH",
                    file=path,
                    start_line=line,
                    message=(f"MCP server '{name}' runs unpinned package via {runner}: '{spec}'."),
                    confidence=0.85,
                    matched_text=f"{command} {' '.join(arg_list)}".strip(),
                )
            )

    # MCP002: secret embedded directly in configuration.
    for where, value in _scan_secret_values(server):
        line = get_line_number(content, content.find(value)) if value in content else 1
        findings.append(
            make_finding(
                rule_id="MCP002",
                severity="CRITICAL",
                file=path,
                start_line=line,
                message=f"MCP server '{name}' embeds a secret directly in {where}.",
                confidence=0.9,
                matched_text=value,
            )
        )

    # MCP003: remote endpoint over insecure transport.
    for key in _URL_KEYS:
        url = server.get(key)
        if isinstance(url, str) and url.lower().startswith("http://"):
            is_local = bool(re.search(r"://(localhost|127\.0\.0\.1|\[::1\])", url, re.IGNORECASE))
            line = get_line_number(content, content.find(url)) if url in content else 1
            findings.append(
                make_finding(
                    rule_id="MCP003",
                    severity="LOW" if is_local else "HIGH",
                    file=path,
                    start_line=line,
                    message=(
                        f"MCP server '{name}' uses insecure transport: {url}"
                        + (" (localhost)" if is_local else "")
                    ),
                    confidence=0.7 if is_local else 0.85,
                    matched_text=url,
                )
            )

    return findings


def _analyze_file(path: str, content: str) -> list[Finding]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []
    server_maps: list[dict[str, object]] = []
    for key in _SERVER_MAP_KEYS:
        candidate = data.get(key)
        if isinstance(candidate, dict):
            server_maps.append(candidate)
    # Some configs put the server map at the top level (name -> config dict).
    if not server_maps and all(isinstance(v, dict) for v in data.values()) and data:
        server_maps.append(data)

    for server_map in server_maps:
        for name, server in server_map.items():
            if isinstance(server, dict):
                findings.extend(_analyze_server(str(name), server, path, content))
    return findings


def node(state: SkillspectorState) -> AnalyzerNodeResponse:
    """Analyze .mcp.json / .lsp.json configuration; emit MCP001-MCP003."""
    if not is_claude_plugin(state):
        return {"findings": []}

    file_cache: dict[str, str] = state.get("file_cache") or {}
    config_paths = {
        str(c.get("path"))
        for c in get_components(state)
        if c.get("kind") in ("mcp", "lsp") and isinstance(c.get("path"), str)
    }
    config_paths.update({".mcp.json", ".lsp.json"})

    findings: list[Finding] = []
    for path in sorted(config_paths):
        content = file_cache.get(path)
        if content:
            findings.extend(_analyze_file(path, content))

    logger.info("%s: %d findings", ANALYZER_ID, len(findings))
    return {"findings": findings}

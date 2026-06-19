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

"""Claude Code plugin target detection and structure parsing.

Detects whether a scanned directory is a standalone skill, a Claude Code plugin,
a Claude plugin marketplace, or a generic directory, and (for plugins) parses the
effective plugin structure into a capability graph the analyzer nodes can inspect.

This is a data-layer module used by ``build_context``; it builds the typed
``PluginModel`` then serializes it to plain dicts for graph state (LangGraph merges
state, so analyzers read dicts, not dataclasses).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from pluginspector.logging_config import get_logger

logger = get_logger(__name__)

# Manifest locations relative to the plugin/marketplace root.
PLUGIN_MANIFEST_PATH = ".claude-plugin/plugin.json"
MARKETPLACE_MANIFEST_PATH = ".claude-plugin/marketplace.json"

# Version string accepted by CP001 (semver-ish: 1, 1.2, 1.2.3, with pre-release/build).
_VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.\-]+)?$")


class TargetType(StrEnum):
    """Classification of a scanned directory."""

    STANDALONE_SKILL = "standalone-skill"
    CLAUDE_PLUGIN = "claude-plugin"
    CLAUDE_MARKETPLACE = "claude-marketplace"
    GENERIC_DIRECTORY = "generic-directory"


class ComponentKind(StrEnum):
    """Kinds of components a Claude plugin may contain."""

    SKILL = "skill"
    COMMAND = "command"
    AGENT = "agent"
    HOOKS = "hooks"
    MCP = "mcp"
    LSP = "lsp"
    MONITOR = "monitor"
    BIN = "bin"
    MANIFEST = "manifest"


# Declared-path keys in plugin.json that may point at component files/dirs.
# Only string (or list-of-string) values are treated as paths; inline object
# values (e.g. an embedded mcpServers map) are configuration, not paths.
_DECLARED_PATH_KEYS: dict[str, ComponentKind] = {
    "commands": ComponentKind.COMMAND,
    "agents": ComponentKind.AGENT,
    "hooks": ComponentKind.HOOKS,
    "mcpServers": ComponentKind.MCP,
    "mcp": ComponentKind.MCP,
    "lsp": ComponentKind.LSP,
    "monitors": ComponentKind.MONITOR,
    "skills": ComponentKind.SKILL,
    "bin": ComponentKind.BIN,
}


@dataclass
class PluginComponent:
    """A single resolved component within a plugin, with its source location."""

    path: str  # plugin-root-relative, posix-style
    kind: str  # ComponentKind value
    source_file: str  # where it was referenced/discovered
    source_line: int = 1  # 1-based line in source_file (best-effort)
    capabilities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "kind": self.kind,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "capabilities": list(self.capabilities),
        }


@dataclass
class StructuralIssue:
    """A path-traversal or symlink escape discovered while parsing the plugin."""

    kind: str  # "path_escape" | "symlink_escape"
    path: str  # offending declared/relative path (posix-style)
    resolved: str  # resolved absolute path (for the message)
    source_file: str
    source_line: int = 1

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "path": self.path,
            "resolved": self.resolved,
            "source_file": self.source_file,
            "source_line": self.source_line,
        }


@dataclass
class PluginModel:
    """Parsed representation of a Claude plugin (or a stub for non-plugin targets)."""

    target_type: str
    plugin_root: str
    manifest: dict[str, object] = field(default_factory=dict)
    components: list[PluginComponent] = field(default_factory=list)
    structural_issues: list[StructuralIssue] = field(default_factory=list)
    manifest_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "target_type": self.target_type,
            "plugin_root": self.plugin_root,
            "manifest": self.manifest,
            "components": [c.to_dict() for c in self.components],
            "structural_issues": [s.to_dict() for s in self.structural_issues],
            "manifest_errors": list(self.manifest_errors),
        }


def detect_target_type(root: Path) -> TargetType:
    """Classify *root* as skill, plugin, marketplace, or generic directory.

    Order matters: a plugin manifest wins over a bundled ``SKILL.md`` because a
    plugin may legitimately ship skills.
    """
    if (root / PLUGIN_MANIFEST_PATH).is_file():
        return TargetType.CLAUDE_PLUGIN
    if (root / MARKETPLACE_MANIFEST_PATH).is_file():
        return TargetType.CLAUDE_MARKETPLACE
    if (root / "SKILL.md").is_file() or (root / "skill.md").is_file():
        return TargetType.STANDALONE_SKILL
    return TargetType.GENERIC_DIRECTORY


def _line_of(content: str, needle: str) -> int:
    """Return the 1-based line in *content* where *needle* first appears (1 if absent)."""
    idx = content.find(needle)
    if idx < 0:
        return 1
    return content[:idx].count("\n") + 1


def _is_within(root_resolved: Path, target: Path) -> bool:
    """Return True if *target* resolves to a location inside *root_resolved*."""
    try:
        return target.resolve().is_relative_to(root_resolved)
    except (OSError, RuntimeError):
        return False


def _iter_declared_paths(value: object) -> list[str]:
    """Yield string paths from a manifest value (str or list-of-str); ignore objects."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _validate_manifest(manifest: dict[str, object]) -> list[str]:
    """Return CP001 manifest errors for *manifest* (already parsed as a dict)."""
    errors: list[str] = []
    name = manifest.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append("plugin.json is missing a non-empty 'name' field")
    version = manifest.get("version")
    if version is not None and (not isinstance(version, str) or not _VERSION_RE.match(version)):
        errors.append(f"plugin.json 'version' is not a valid version string: {version!r}")
    for key in _DECLARED_PATH_KEYS:
        val = manifest.get(key)
        if val is not None and not isinstance(val, (str, list, dict)):
            errors.append(f"plugin.json '{key}' must be a string, list, or object")
    return errors


def _collect_declared_components(
    root_resolved: Path,
    manifest: dict[str, object],
    manifest_text: str,
) -> tuple[list[PluginComponent], list[StructuralIssue]]:
    """Resolve manifest-declared component paths, flagging path escapes (CP002)."""
    components: list[PluginComponent] = []
    issues: list[StructuralIssue] = []
    for key, kind in _DECLARED_PATH_KEYS.items():
        for decl in _iter_declared_paths(manifest.get(key)):
            line = _line_of(manifest_text, decl)
            resolved = root_resolved / decl
            if not _is_within(root_resolved, resolved):
                issues.append(
                    StructuralIssue(
                        kind="path_escape",
                        path=decl,
                        resolved=str(resolved.resolve()) if resolved else decl,
                        source_file=PLUGIN_MANIFEST_PATH,
                        source_line=line,
                    )
                )
                continue
            rel = decl.replace("\\", "/").lstrip("./") or decl
            components.append(
                PluginComponent(
                    path=rel,
                    kind=kind.value,
                    source_file=PLUGIN_MANIFEST_PATH,
                    source_line=line,
                )
            )
    return components, issues


def _collect_convention_components(root: Path) -> list[PluginComponent]:
    """Discover components by Claude plugin directory/file conventions on disk."""
    components: list[PluginComponent] = []

    def add(path: Path, kind: ComponentKind) -> None:
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            return
        components.append(
            PluginComponent(path=rel, kind=kind.value, source_file=rel, source_line=1)
        )

    # Single-file conventions.
    if (root / "hooks" / "hooks.json").is_file():
        add(root / "hooks" / "hooks.json", ComponentKind.HOOKS)
    if (root / ".mcp.json").is_file():
        add(root / ".mcp.json", ComponentKind.MCP)
    if (root / ".lsp.json").is_file():
        add(root / ".lsp.json", ComponentKind.LSP)

    # Directory conventions: enumerate contained files.
    for sub, kind in (
        ("commands", ComponentKind.COMMAND),
        ("agents", ComponentKind.AGENT),
        ("monitors", ComponentKind.MONITOR),
    ):
        d = root / sub
        if d.is_dir():
            for f in sorted(d.rglob("*")):
                if f.is_file() and not f.name.startswith("."):
                    add(f, kind)

    # Skills: each skill directory's SKILL.md.
    skills_dir = root / "skills"
    if skills_dir.is_dir():
        for skill_md in sorted(skills_dir.rglob("SKILL.md")):
            if skill_md.is_file():
                add(skill_md, ComponentKind.SKILL)

    # bin/: every regular file directly under bin/ (extensionless allowed).
    bin_dir = root / "bin"
    if bin_dir.is_dir():
        for f in sorted(bin_dir.iterdir()):
            if f.is_file():
                add(f, ComponentKind.BIN)

    return components


def _collect_symlink_escapes(root: Path, root_resolved: Path) -> list[StructuralIssue]:
    """Find symlinks under *root* whose target escapes the plugin root (CP003)."""
    issues: list[StructuralIssue] = []
    try:
        candidates = list(root.rglob("*"))
    except OSError:
        return issues
    for item in candidates:
        try:
            if not item.is_symlink():
                continue
        except OSError:
            continue
        if not _is_within(root_resolved, item):
            try:
                rel = item.relative_to(root).as_posix()
            except ValueError:
                rel = item.name
            try:
                resolved = str(item.resolve())
            except (OSError, RuntimeError):
                resolved = "(unresolved)"
            issues.append(
                StructuralIssue(
                    kind="symlink_escape",
                    path=rel,
                    resolved=resolved,
                    source_file=rel,
                    source_line=1,
                )
            )
    return issues


def _dedup_components(components: list[PluginComponent]) -> list[PluginComponent]:
    """Drop duplicate (path, kind) components, keeping the first (declared) occurrence."""
    seen: set[tuple[str, str]] = set()
    result: list[PluginComponent] = []
    for c in components:
        key = (c.path, c.kind)
        if key in seen:
            continue
        seen.add(key)
        result.append(c)
    return result


def parse_plugin(root: Path, file_cache: dict[str, str]) -> PluginModel:
    """Parse the effective plugin structure rooted at *root*.

    For non-plugin targets, returns a stub model carrying only the target type so
    skill scans flow through unchanged and the Claude analyzers no-op.
    """
    target_type = detect_target_type(root)
    root_resolved = root.resolve()
    model = PluginModel(target_type=target_type.value, plugin_root=str(root_resolved))

    if target_type is not TargetType.CLAUDE_PLUGIN:
        return model

    manifest_text = file_cache.get(PLUGIN_MANIFEST_PATH)
    if manifest_text is None:
        try:
            manifest_text = (root / PLUGIN_MANIFEST_PATH).read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            manifest_text = ""

    manifest: dict[str, object] = {}
    try:
        parsed = json.loads(manifest_text) if manifest_text else None
    except json.JSONDecodeError as e:
        model.manifest_errors.append(f"plugin.json is not valid JSON: {e}")
        parsed = None
    if parsed is not None and not isinstance(parsed, dict):
        model.manifest_errors.append("plugin.json must be a JSON object")
        parsed = None
    if isinstance(parsed, dict):
        manifest = parsed
        model.manifest = manifest
        model.manifest_errors.extend(_validate_manifest(manifest))

    declared, declared_issues = _collect_declared_components(root_resolved, manifest, manifest_text)
    convention = _collect_convention_components(root)
    model.components = _dedup_components(declared + convention)
    model.structural_issues = declared_issues + _collect_symlink_escapes(root, root_resolved)

    logger.info(
        "parse_plugin: %d components, %d structural issues, %d manifest errors",
        len(model.components),
        len(model.structural_issues),
        len(model.manifest_errors),
    )
    return model

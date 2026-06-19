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

"""Build-context node for Skillspector workflow.

Builds flat ScanContext fields (components, file_cache, manifest, etc.)
from a local skill directory.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

import yaml

from skillspector.claude_plugin import parse_plugin
from skillspector.constants import MODEL_CONFIG
from skillspector.logging_config import get_logger
from skillspector.state import SkillspectorState

logger = get_logger(__name__)

# File-cache budget constants
MAX_FILE_COUNT = 2_000
MAX_TOTAL_SCAN_BYTES = 200 * 1024 * 1024  # 200 MB
MAX_DIR_DEPTH = 20

# Directories to skip when walking
_SKIP_DIRS = frozenset(
    {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox", ".pytest_cache"}
)

# Dotfiles that are first-class Claude plugin components and must be collected
# despite the general "skip hidden files" rule.
_INCLUDED_DOTFILES = frozenset({".mcp.json", ".lsp.json"})

# File type by extension
_FILE_TYPES: dict[str, str] = {
    ".md": "markdown",
    ".markdown": "markdown",
    ".py": "python",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".txt": "text",
    ".js": "javascript",
    ".ts": "typescript",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
}
_EXECUTABLE_EXTENSIONS = frozenset(
    {".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".rb", ".go", ".rs", ".pl"}
)


def _resolve_skill_dir(state: SkillspectorState) -> Path:
    """Resolve state skill_path to an existing directory Path."""
    skill_path = state.get("skill_path")
    if not skill_path or not isinstance(skill_path, str) or not skill_path.strip():
        raise ValueError("skill_path is required; provide input_path or skill_path to scan")
    try:
        resolved = Path(skill_path).resolve()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid skill_path: {skill_path}") from e
    if not resolved.is_dir():
        raise ValueError(f"Invalid skill_path: {skill_path} is not an existing directory")
    return resolved


def _walk_skill_files(
    skill_dir: Path,
) -> tuple[list[str], list[str]]:
    """Walk skill directory and return (included_paths, skipped_paths).

    Skips _SKIP_DIRS, hidden files (except .claude* / _INCLUDED_DOTFILES),
    symlinks escaping the root, files exceeding MAX_DIR_DEPTH, and files that
    would push the total count or byte budget over the limit.  Returns both the
    accepted relative path strings and a list of skipped-reason strings so
    callers can surface partial-scan information.
    """
    paths: list[str] = []
    skipped: list[str] = []
    skill_dir_resolved = skill_dir.resolve()
    total_bytes = 0

    for item in skill_dir.rglob("*"):
        if not item.is_file():
            continue

        # Depth limit
        try:
            rel = item.relative_to(skill_dir)
        except ValueError:
            logger.debug("Skipping path (not under skill_dir): %s", item)
            skipped.append(f"out-of-root:{item}")
            continue
        if len(rel.parts) > MAX_DIR_DEPTH:
            skipped.append(f"depth-limit:{rel}")
            continue

        if any(skip in item.parts for skip in _SKIP_DIRS):
            continue
        if (
            item.name.startswith(".")
            and not item.name.startswith(".claude")
            and item.name not in _INCLUDED_DOTFILES
        ):
            continue
        # Do not read content through symlinks that escape the scan root.
        if item.is_symlink():
            try:
                if not item.resolve().is_relative_to(skill_dir_resolved):
                    skipped.append(f"symlink-escape:{rel}")
                    continue
            except (OSError, RuntimeError):
                skipped.append(f"symlink-error:{rel}")
                continue

        # File-count budget
        if len(paths) >= MAX_FILE_COUNT:
            skipped.append(f"file-count-limit:{rel}")
            continue

        # Total-bytes budget (use stat to avoid reading the file twice)
        try:
            size = item.stat().st_size
        except OSError:
            size = 0
        if total_bytes + size > MAX_TOTAL_SCAN_BYTES:
            skipped.append(f"bytes-limit:{rel}")
            continue
        total_bytes += size

        paths.append(str(rel))

    paths.sort()
    return paths, skipped


def _infer_file_type(path: str) -> str:
    """Infer file type from path (extension)."""
    idx = path.rfind(".")
    suffix = path[idx:].lower() if idx >= 0 else ""
    return _FILE_TYPES.get(suffix, "other")


def _count_lines(file_path: Path) -> int:
    """Count lines in a file, handling binary and errors gracefully."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return len(content.splitlines())
    except OSError:
        logger.debug("Could not read file for line count: %s", file_path)
        return 0


def _build_component_metadata(
    skill_dir: Path, components: list[str]
) -> tuple[list[dict[str, object]], bool]:
    """Build component_metadata list and has_executable_scripts from paths."""
    metadata: list[dict[str, object]] = []
    has_executable = False
    for path in components:
        full = skill_dir / path
        if not full.is_file():
            continue
        suffix = full.suffix.lower()
        file_type = _infer_file_type(path)
        lines = _count_lines(full)
        # Mark executable by extension, by exec permission bit, or by location under
        # bin/ (covers extensionless plugin bin/ entrypoints such as bin/git).
        norm_path = path.replace("\\", "/")
        in_bin = norm_path.startswith("bin/") or "/bin/" in norm_path
        try:
            exec_bit = bool(full.stat().st_mode & stat.S_IXUSR)
        except OSError:
            exec_bit = False
        executable = suffix in _EXECUTABLE_EXTENSIONS or exec_bit or in_bin
        if executable:
            has_executable = True
        try:
            size_bytes = full.stat().st_size
        except OSError:
            logger.debug("Could not stat file: %s", path)
            size_bytes = 0
        metadata.append(
            {
                "path": path,
                "type": file_type,
                "lines": lines,
                "executable": executable,
                "size_bytes": size_bytes,
            }
        )
    return metadata, has_executable


def _read_file_cache(skill_dir: Path, components: list[str]) -> dict[str, str]:
    """Build file_cache: relative path -> file contents. Uses utf-8 with replace for errors."""
    file_cache: dict[str, str] = {}
    for path in components:
        full = skill_dir / path
        if not full.is_file():
            continue
        try:
            content = full.read_text(encoding="utf-8", errors="replace")
            file_cache[path] = content
        except OSError:
            logger.debug("Could not read file: %s", path)
            file_cache[path] = ""
    return file_cache


def _parse_manifest(skill_dir: Path) -> dict[str, object]:
    """Parse SKILL.md or skill.md YAML frontmatter into a manifest dict.

    Returns dict with name, description, triggers (list), permissions (list).
    Returns {} if no file or parse fails.
    """
    for name in ("SKILL.md", "skill.md"):
        path = skill_dir / name
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            logger.debug("Could not read manifest file: %s", name)
            return {}
        if not content.startswith("---"):
            return {}
        end_match = re.search(r"\n---\s*\n", content[3:])
        if not end_match:
            return {}
        frontmatter = content[3 : end_match.start() + 3]
        try:
            data = yaml.safe_load(frontmatter)
        except yaml.YAMLError:
            logger.debug("Manifest parse failed for %s", name)
            return {}
        if not isinstance(data, dict):
            return {}
        manifest: dict[str, object] = {}
        if "name" in data:
            manifest["name"] = data["name"]
        if "description" in data:
            manifest["description"] = data["description"]
        triggers = data.get("triggers", [])
        manifest["triggers"] = [str(t) for t in triggers] if isinstance(triggers, list) else []
        permissions = data.get("permissions", [])
        manifest["permissions"] = (
            [str(p) for p in permissions] if isinstance(permissions, list) else []
        )
        # Preserve parameter definitions as dicts so the MCP tool-poisoning
        # analyzer (TP1/TP2/TP3 parameter checks) can inspect them. Without
        # this, those checks never fire on real scans because the manifest
        # carried no `parameters` key.
        parameters = data.get("parameters", [])
        manifest["parameters"] = (
            [p for p in parameters if isinstance(p, dict)] if isinstance(parameters, list) else []
        )
        return manifest
    return {}


def build_context(state: SkillspectorState) -> dict[str, object]:
    """Build flat ScanContext fields from state skill_path (local directory).

    Resolves skill_path to a directory, walks files, builds file_cache
    and manifest. Returns only context keys; leaves findings untouched.
    Raises ValueError if skill_path is missing or not an existing directory.
    """
    skill_dir = _resolve_skill_dir(state)

    components, skipped_files = _walk_skill_files(skill_dir)
    if skipped_files:
        logger.warning(
            "Scan is partial — %d file(s) skipped due to budget/depth limits: %s",
            len(skipped_files),
            skipped_files[:10],
        )
    file_cache = _read_file_cache(skill_dir, components)
    manifest = _parse_manifest(skill_dir)
    component_metadata, has_executable_scripts = _build_component_metadata(skill_dir, components)
    plugin_model = parse_plugin(skill_dir, file_cache)

    return {
        "components": components,
        "skipped_files": skipped_files,
        "file_cache": file_cache,
        "ast_cache": {},
        "manifest": manifest,
        "previous_manifest": None,
        "model_config": MODEL_CONFIG,
        "component_metadata": component_metadata,
        "has_executable_scripts": has_executable_scripts,
        "target_type": plugin_model.target_type,
        "plugin_model": plugin_model.to_dict(),
    }

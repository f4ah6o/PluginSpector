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

"""Tests for skillspector input_handler (resolve directory, zip, single file)."""

import io
import zipfile
from pathlib import Path

import pytest

from pluginspector.input_handler import InputHandler


def test_resolve_directory(tmp_path: Path) -> None:
    """Resolving a local directory returns path and source_type directory."""
    (tmp_path / "SKILL.md").write_text("# Skill", encoding="utf-8")
    handler = InputHandler()
    try:
        resolved, source_type = handler.resolve(str(tmp_path))
        assert resolved.is_dir()
        assert (resolved / "SKILL.md").exists()
        assert source_type == "directory"
    finally:
        handler.cleanup()


def test_resolve_single_md_file(tmp_path: Path) -> None:
    """Resolving a single .md file wraps it in a temp dir."""
    f = tmp_path / "doc.md"
    f.write_text("# Doc", encoding="utf-8")
    handler = InputHandler()
    try:
        resolved, source_type = handler.resolve(str(f))
        assert resolved.is_dir()
        assert (resolved / "doc.md").exists()
        assert source_type == "file"
    finally:
        handler.cleanup()


def test_resolve_zip_file(tmp_path: Path) -> None:
    """Resolving a .zip file extracts and returns the extract dir."""
    (tmp_path / "SKILL.md").write_text("# Skill", encoding="utf-8")
    zip_path = tmp_path / "skill.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(tmp_path / "SKILL.md", "SKILL.md")
    handler = InputHandler()
    try:
        resolved, source_type = handler.resolve(str(zip_path))
        assert resolved.is_dir()
        assert source_type == "zip"
    finally:
        handler.cleanup()


def test_resolve_nonexistent_raises() -> None:
    """Resolving a nonexistent path raises FileNotFoundError or ValueError."""
    handler = InputHandler()
    with pytest.raises((FileNotFoundError, ValueError)):
        handler.resolve("/nonexistent/path/xyz")


def test_resolve_single_non_md_file(tmp_path: Path) -> None:
    """Resolving a single non-.md file (e.g. .txt) wraps it in a temp dir."""
    f = tmp_path / "readme.txt"
    f.write_text("Read me", encoding="utf-8")
    handler = InputHandler()
    try:
        resolved, source_type = handler.resolve(str(f))
        assert resolved.is_dir()
        assert (resolved / "readme.txt").exists()
        assert source_type == "file"
    finally:
        handler.cleanup()


def test_cleanup_idempotent(tmp_path: Path) -> None:
    """cleanup() can be called after resolve and does not raise."""
    (tmp_path / "a.md").write_text("x", encoding="utf-8")
    handler = InputHandler()
    handler.resolve(str(tmp_path / "a.md"))
    handler.cleanup()
    handler.cleanup()


# ---------------------------------------------------------------------------
# Security hardening tests (issue #5)
# ---------------------------------------------------------------------------


def _make_zip(tmp_path: Path, members: list[tuple[str, bytes]]) -> Path:
    """Helper: create a zip with given (name, content) pairs."""
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return zip_path


def test_zip_path_traversal_rejected(tmp_path: Path) -> None:
    """Archive entries with ../ traversal must be rejected."""
    zip_path = _make_zip(tmp_path, [("../evil.py", b"print('pwned')")])
    handler = InputHandler()
    try:
        with pytest.raises(ValueError, match="traversal|escape"):
            handler._extract_zip(zip_path)
    finally:
        handler.cleanup()


def test_zip_absolute_path_rejected(tmp_path: Path) -> None:
    """Archive entries with absolute paths must be rejected."""
    # zipfile.writestr won't accept absolute paths; write raw bytes instead
    zip_path = tmp_path / "abs.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("/etc/passwd")
        zf.writestr(info, "root:x:0:0")
    zip_path.write_bytes(buf.getvalue())

    handler = InputHandler()
    try:
        with pytest.raises(ValueError, match="absolute"):
            handler._extract_zip(zip_path)
    finally:
        handler.cleanup()


def test_zip_symlink_entry_skipped(tmp_path: Path) -> None:
    """Symlink entries in archives are skipped (not extracted, no error)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("safe.txt")
        zf.writestr(info, "safe content")
        # Create a symlink entry: Unix mode 0xA1FF (symlink + rwxrwxrwx)
        sym_info = zipfile.ZipInfo("link.txt")
        sym_info.external_attr = 0xA1FF0000  # symlink type bits
        zf.writestr(sym_info, "../evil")
    zip_path = tmp_path / "sym.zip"
    zip_path.write_bytes(buf.getvalue())

    handler = InputHandler()
    try:
        result = handler._extract_zip(zip_path)
        # safe.txt extracted; link.txt skipped
        assert (result / "safe.txt").exists()
        assert not (result / "link.txt").exists()
    finally:
        handler.cleanup()


def test_zip_too_many_entries_rejected(tmp_path: Path) -> None:
    """Archives exceeding MAX_ARCHIVE_ENTRIES are rejected."""
    from pluginspector.input_handler import MAX_ARCHIVE_ENTRIES

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(MAX_ARCHIVE_ENTRIES + 1):
            zf.writestr(f"file_{i}.txt", "x")
    zip_path = tmp_path / "big.zip"
    zip_path.write_bytes(buf.getvalue())

    handler = InputHandler()
    try:
        with pytest.raises(ValueError, match="too many entries"):
            handler._extract_zip(zip_path)
    finally:
        handler.cleanup()


def test_zip_expansion_ratio_rejected(tmp_path: Path) -> None:
    """Zip bombs (high expansion ratio) are rejected."""
    from pluginspector.input_handler import MAX_ARCHIVE_RATIO

    # Create a file that looks like it expands to way more than its compressed size
    # We fake the file_size in the central directory by writing raw
    buf = io.BytesIO()
    payload = b"\x00" * 1024  # small payload
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Write a large-looking entry by using a large uncompressed declaration
        info = zipfile.ZipInfo("bomb.txt")
        info.file_size = 1024 * 1024 * 1024 * 5  # claim 5 GB uncompressed
        # writestr won't let us set file_size; use compress_type=STORED and raw
        # Instead use compress to get a real high-ratio entry with repeated bytes
        zf.writestr("bomb.txt", b"\x00" * (1024 * MAX_ARCHIVE_RATIO * 2))
    zip_path = tmp_path / "bomb.zip"
    zip_path.write_bytes(buf.getvalue())

    handler = InputHandler()
    try:
        with pytest.raises(ValueError, match="ratio|bomb|expanded"):
            handler._extract_zip(zip_path)
    finally:
        handler.cleanup()

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

"""
Input handler for Skillspector.

Handles various input formats:
- Git repository URLs
- Raw file URLs
- Local zip files
- Single markdown files
- Local directories

Ported from legacy implementation.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import httpx

from skillspector.logging_config import get_logger

logger = get_logger(__name__)

# Ingestion budget constants
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_ARCHIVE_ENTRIES = 1_000
MAX_ARCHIVE_EXPANDED_BYTES = 200 * 1024 * 1024  # 200 MB
MAX_ARCHIVE_RATIO = 100  # expansion ratio limit (zip bomb guard)
MAX_ARCHIVE_COMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB


class InputHandler:
    """
    Handles input resolution for different source types.

    Normalizes all inputs to a local directory path for scanning.
    """

    def __init__(self) -> None:
        self._temp_dir: Path | None = None

    def resolve(self, input_path: str) -> tuple[Path, str]:
        """
        Resolve input to a scannable directory.

        Args:
            input_path: Path or URL to resolve

        Returns:
            Tuple of (resolved_path, source_type)
            source_type is one of: "git", "url", "zip", "file", "directory"

        Raises:
            ValueError: If input type cannot be determined
            FileNotFoundError: If local path doesn't exist
        """
        input_path = input_path.strip()

        if self._is_git_url(input_path):
            return self._clone_git(input_path), "git"
        if self._is_file_url(input_path):
            return self._download_file(input_path), "url"
        if input_path.endswith(".zip"):
            return self._extract_zip(Path(input_path)), "zip"
        if input_path.endswith(".md"):
            return self._wrap_single_file(Path(input_path)), "file"
        if Path(input_path).is_dir():
            return Path(input_path).resolve(), "directory"
        if Path(input_path).is_file():
            return self._wrap_single_file(Path(input_path)), "file"
        raise ValueError(
            f"Cannot determine input type for: {input_path}\n"
            "Supported formats: Git URL, file URL, .zip file, .md file, or directory"
        )

    def cleanup(self) -> None:
        """Clean up temporary files created during resolution."""
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None

    def temp_dir_for_cleanup(self) -> Path | None:
        """Return the temp directory path if one was created (for caller to clean up after graph)."""
        return self._temp_dir

    def _get_temp_dir(self) -> Path:
        """Get or create a temporary directory for this session."""
        if not self._temp_dir:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="skillspector_"))
        return self._temp_dir

    def _is_git_url(self, path: str) -> bool:
        """Check if path is a Git repository URL."""
        if not path.startswith(("http://", "https://", "git@")):
            return False
        parsed = urlparse(path)
        git_hosts = ["github.com", "gitlab.com", "bitbucket.org"]
        if any(host in parsed.netloc for host in git_hosts):
            if "/raw/" in path or "/blob/" in path or path.endswith((".md", ".py", ".sh")):
                return False
            return True
        if path.endswith(".git"):
            return True
        return False

    def _is_file_url(self, path: str) -> bool:
        """Check if path is a direct file URL."""
        if not path.startswith(("http://", "https://")):
            return False
        return not self._is_git_url(path)

    def _clone_git(self, url: str) -> Path:
        """Clone a Git repository to a temporary directory."""
        temp_dir = self._get_temp_dir()
        clone_dir = temp_dir / "repo"
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(clone_dir)],
                check=True,
                capture_output=True,
                timeout=60,
                shell=False,
            )
        except subprocess.CalledProcessError as e:
            logger.warning("Git clone failed for %s: %s", url, e)
            raise ValueError(f"Failed to clone repository: {e.stderr.decode()}") from e
        except subprocess.TimeoutExpired:
            logger.warning("Git clone timed out for %s", url)
            raise ValueError("Git clone timed out after 60 seconds") from None
        except FileNotFoundError:
            logger.warning("Git not found when cloning %s", url)
            raise ValueError(
                "Git is not installed. Please install git to scan repositories."
            ) from None
        return clone_dir

    def _download_file(self, url: str) -> Path:
        """Download a file from URL to a temporary directory (size-limited streaming)."""
        temp_dir = self._get_temp_dir()
        parsed = urlparse(url)
        filename = Path(parsed.path).name or "SKILL.md"
        content_chunks: list[bytes] = []
        total = 0
        try:
            with httpx.Client(follow_redirects=True, timeout=30) as client:
                with client.stream("GET", url) as response:
                    response.raise_for_status()
                    for chunk in response.iter_bytes(chunk_size=65536):
                        total += len(chunk)
                        if total > MAX_DOWNLOAD_BYTES:
                            raise ValueError(
                                f"Download exceeded {MAX_DOWNLOAD_BYTES // (1024*1024)} MB limit: {url}"
                            )
                        content_chunks.append(chunk)
        except httpx.HTTPError as e:
            logger.warning("Download failed for %s: %s", url, e)
            raise ValueError(f"Failed to download file: {e}") from e
        content = b"".join(content_chunks)
        content_type = ""
        # response is closed here; use filename heuristic for type detection
        if filename.endswith(".zip"):
            content_type = "application/zip"
        if filename.endswith(".zip") or content_type.startswith("application/zip"):
            zip_path = temp_dir / "download.zip"
            zip_path.write_bytes(content)
            return self._extract_zip(zip_path)
        file_path = temp_dir / filename
        file_path.write_bytes(content)
        return temp_dir

    def _extract_zip(self, zip_path: Path) -> Path:
        """Extract a zip file safely, rejecting path traversal and enforcing budgets."""
        if not zip_path.exists():
            raise FileNotFoundError(f"Zip file not found: {zip_path}") from None

        # Reject oversized compressed archives before opening
        compressed_size = zip_path.stat().st_size
        if compressed_size > MAX_ARCHIVE_COMPRESSED_BYTES:
            raise ValueError(
                f"Archive too large ({compressed_size // (1024*1024)} MB, "
                f"limit {MAX_ARCHIVE_COMPRESSED_BYTES // (1024*1024)} MB): {zip_path}"
            )

        temp_dir = self._get_temp_dir()
        extract_dir = temp_dir / "extracted"
        extract_dir.mkdir(exist_ok=True)
        extract_dir_resolved = extract_dir.resolve()

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                members = zf.infolist()

                # Entry count budget
                if len(members) > MAX_ARCHIVE_ENTRIES:
                    raise ValueError(
                        f"Archive has too many entries ({len(members)}, "
                        f"limit {MAX_ARCHIVE_ENTRIES}): {zip_path}"
                    )

                # Expanded-bytes budget and zip-bomb ratio check
                total_expanded = sum(m.file_size for m in members)
                if total_expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                    raise ValueError(
                        f"Archive expands to too many bytes ({total_expanded // (1024*1024)} MB, "
                        f"limit {MAX_ARCHIVE_EXPANDED_BYTES // (1024*1024)} MB): {zip_path}"
                    )
                if compressed_size > 0 and total_expanded / compressed_size > MAX_ARCHIVE_RATIO:
                    raise ValueError(
                        f"Archive expansion ratio too high "
                        f"({total_expanded / compressed_size:.0f}x, "
                        f"limit {MAX_ARCHIVE_RATIO}x) — possible zip bomb: {zip_path}"
                    )

                for member in members:
                    # Reject symlinks (external_attr Unix mode bits)
                    unix_mode = (member.external_attr >> 16) & 0xFFFF
                    is_symlink = (unix_mode & 0xA000) == 0xA000
                    if is_symlink:
                        logger.warning("Skipping symlink entry in archive: %s", member.filename)
                        continue

                    # Sanitize member path: reject absolute paths and traversal sequences
                    member_path = Path(member.filename)
                    if member_path.is_absolute():
                        raise ValueError(
                            f"Archive contains absolute path entry: {member.filename}"
                        )
                    parts = member_path.parts
                    if any(part in ("..", ".") or part.startswith("/") for part in parts[:-1]):
                        raise ValueError(
                            f"Archive contains path traversal entry: {member.filename}"
                        )

                    # Resolve final destination and verify it stays under extract_dir
                    dest = (extract_dir / member.filename).resolve()
                    try:
                        dest.relative_to(extract_dir_resolved)
                    except ValueError:
                        raise ValueError(
                            f"Archive entry would escape extraction directory: {member.filename}"
                        ) from None

                    # Extract single member
                    if member.filename.endswith("/"):
                        dest.mkdir(parents=True, exist_ok=True)
                    else:
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(member) as src, dest.open("wb") as dst:
                            shutil.copyfileobj(src, dst)

        except zipfile.BadZipFile:
            logger.warning("Invalid zip or extract failed: %s", zip_path)
            raise ValueError(f"Invalid zip file: {zip_path}") from None

        contents = list(extract_dir.iterdir())
        if len(contents) == 1 and contents[0].is_dir():
            return contents[0]
        return extract_dir

    def _wrap_single_file(self, file_path: Path) -> Path:
        """Wrap a single file in a temporary directory for consistent handling."""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}") from None
        temp_dir = self._get_temp_dir()
        dest = temp_dir / file_path.name
        shutil.copy2(file_path, dest)
        return temp_dir

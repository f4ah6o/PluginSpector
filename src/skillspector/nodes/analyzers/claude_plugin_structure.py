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

"""Claude plugin manifest/structure analyzer (issue #1) — CP001/CP002/CP003."""

from __future__ import annotations

from skillspector.claude_plugin import PLUGIN_MANIFEST_PATH
from skillspector.logging_config import get_logger
from skillspector.models import Finding
from skillspector.state import AnalyzerNodeResponse, SkillspectorState

from .claude_common import get_plugin_model, is_claude_plugin, make_finding

ANALYZER_ID = "claude_plugin_structure"
logger = get_logger(__name__)


def node(state: SkillspectorState) -> AnalyzerNodeResponse:
    """Emit CP001 (manifest errors), CP002 (path escapes), CP003 (symlink escapes)."""
    if not is_claude_plugin(state):
        return {"findings": []}

    model = get_plugin_model(state)
    findings: list[Finding] = []

    manifest_errors = model.get("manifest_errors")
    if isinstance(manifest_errors, list):
        for err in manifest_errors:
            findings.append(
                make_finding(
                    rule_id="CP001",
                    severity="MEDIUM",
                    file=PLUGIN_MANIFEST_PATH,
                    message=f"Invalid or inconsistent plugin manifest: {err}",
                    confidence=0.9,
                    matched_text=str(err),
                )
            )

    issues = model.get("structural_issues")
    if isinstance(issues, list):
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            kind = issue.get("kind")
            path = str(issue.get("path", ""))
            resolved = str(issue.get("resolved", ""))
            source_file = str(issue.get("source_file") or PLUGIN_MANIFEST_PATH)
            source_line = issue.get("source_line", 1)
            line = source_line if isinstance(source_line, int) else 1
            if kind == "path_escape":
                findings.append(
                    make_finding(
                        rule_id="CP002",
                        severity="HIGH",
                        file=source_file,
                        start_line=line,
                        message=(
                            f"Component path '{path}' escapes the plugin root "
                            f"(resolves to {resolved})."
                        ),
                        confidence=0.9,
                        matched_text=path,
                    )
                )
            elif kind == "symlink_escape":
                findings.append(
                    make_finding(
                        rule_id="CP003",
                        severity="HIGH",
                        file=source_file,
                        start_line=line,
                        message=(
                            f"Symlink '{path}' points outside the plugin root "
                            f"(resolves to {resolved})."
                        ),
                        confidence=0.9,
                        matched_text=path,
                    )
                )

    logger.info("%s: %d findings", ANALYZER_ID, len(findings))
    return {"findings": findings}

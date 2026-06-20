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

"""LLM preflight check node: runs before all analyzers.

Centralises the ``is_llm_available()`` check and ``strict_llm`` enforcement so
that semantic analyzers never need to call ``_resolve_llm_credentials()``
themselves.  Any ``ValueError`` from a missing API key is raised here (when
``strict_llm=True``) or suppressed (when ``strict_llm=False``), before the
parallel analyzer fan-out starts.
"""

from __future__ import annotations

from typing import TypedDict

from pluginspector.llm_utils import is_llm_available
from pluginspector.logging_config import get_logger
from pluginspector.state import SkillspectorState

logger = get_logger(__name__)


class LLMPreflightResponse(TypedDict, total=False):
    llm_available: bool
    llm_availability_error: str | None


def llm_preflight(state: SkillspectorState) -> LLMPreflightResponse:
    """Check LLM credential availability before the analyzer fan-out.

    When ``use_llm`` is False the check is skipped and ``llm_available`` is set
    to False so that all LLM-using analyzers no-op immediately.

    When ``use_llm`` is True and credentials are missing:
    - ``strict_llm=True``: raises ``ValueError`` (scan aborts with exit code 2).
    - ``strict_llm=False``: sets ``llm_available=False`` so analyzers skip
      gracefully; the scan continues with static findings only.
    """
    if not state.get("use_llm", True):
        return {"llm_available": False, "llm_availability_error": None}

    available, error = is_llm_available()

    if not available:
        strict_llm: bool = state.get("strict_llm", False)
        logger.warning("LLM credentials unavailable: %s", error)
        if strict_llm:
            raise ValueError(
                f"LLM credentials unavailable and --strict-llm is set: {error}"
            )
        return {"llm_available": False, "llm_availability_error": error}

    return {"llm_available": True, "llm_availability_error": None}

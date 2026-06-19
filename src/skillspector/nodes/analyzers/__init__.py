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

"""Analyzer node registry for PluginSpector."""

from __future__ import annotations

from skillspector.nodes.analyzers.behavioral_ast import node as behavioral_ast_node
from skillspector.nodes.analyzers.behavioral_taint_tracking import (
    node as behavioral_taint_tracking_node,
)
from skillspector.nodes.analyzers.claude_capability_correlation import (
    node as claude_capability_correlation_node,
)
from skillspector.nodes.analyzers.claude_components import node as claude_components_node
from skillspector.nodes.analyzers.claude_hooks import node as claude_hooks_node
from skillspector.nodes.analyzers.claude_mcp_lsp import node as claude_mcp_lsp_node
from skillspector.nodes.analyzers.claude_plugin_structure import (
    node as claude_plugin_structure_node,
)
from skillspector.nodes.analyzers.mcp_least_privilege import node as mcp_least_privilege_node
from skillspector.nodes.analyzers.mcp_rug_pull import node as mcp_rug_pull_node
from skillspector.nodes.analyzers.mcp_tool_poisoning import node as mcp_tool_poisoning_node
from skillspector.nodes.analyzers.semantic_developer_intent import (
    node as semantic_developer_intent_node,
)
from skillspector.nodes.analyzers.semantic_quality_policy import (
    node as semantic_quality_policy_node,
)
from skillspector.nodes.analyzers.semantic_security_discovery import (
    node as semantic_security_discovery_node,
)
from skillspector.nodes.analyzers.static_patterns_data_exfiltration import (
    node as static_patterns_data_exfiltration_node,
)
from skillspector.nodes.analyzers.static_patterns_excessive_agency import (
    node as static_patterns_excessive_agency_node,
)
from skillspector.nodes.analyzers.static_patterns_harmful_content import (
    node as static_patterns_harmful_content_node,
)
from skillspector.nodes.analyzers.static_patterns_memory_poisoning import (
    node as static_patterns_memory_poisoning_node,
)
from skillspector.nodes.analyzers.static_patterns_output_handling import (
    node as static_patterns_output_handling_node,
)
from skillspector.nodes.analyzers.static_patterns_privilege_escalation import (
    node as static_patterns_privilege_escalation_node,
)
from skillspector.nodes.analyzers.static_patterns_prompt_injection import (
    node as static_patterns_prompt_injection_node,
)
from skillspector.nodes.analyzers.static_patterns_rogue_agent import (
    node as static_patterns_rogue_agent_node,
)
from skillspector.nodes.analyzers.static_patterns_supply_chain import (
    node as static_patterns_supply_chain_node,
)
from skillspector.nodes.analyzers.static_patterns_system_prompt_leakage import (
    node as static_patterns_system_prompt_leakage_node,
)
from skillspector.nodes.analyzers.static_patterns_tool_misuse import (
    node as static_patterns_tool_misuse_node,
)
from skillspector.nodes.analyzers.static_yara import node as static_yara_node

ANALYZER_NODE_IDS: list[str] = [
    "static_patterns_prompt_injection",
    "static_patterns_data_exfiltration",
    "static_patterns_privilege_escalation",
    "static_patterns_supply_chain",
    "static_patterns_harmful_content",
    "static_patterns_excessive_agency",
    "static_patterns_output_handling",
    "static_patterns_system_prompt_leakage",
    "static_patterns_memory_poisoning",
    "static_patterns_tool_misuse",
    "static_patterns_rogue_agent",
    "static_yara",
    "behavioral_ast",
    "behavioral_taint_tracking",
    "mcp_least_privilege",
    "mcp_tool_poisoning",
    "mcp_rug_pull",
    "semantic_security_discovery",
    "semantic_developer_intent",
    "semantic_quality_policy",
    "claude_plugin_structure",
    "claude_hooks",
    "claude_mcp_lsp",
    "claude_components",
    "claude_capability_correlation",
]

ANALYZER_NODES = {
    "static_patterns_prompt_injection": static_patterns_prompt_injection_node,
    "static_patterns_data_exfiltration": static_patterns_data_exfiltration_node,
    "static_patterns_privilege_escalation": static_patterns_privilege_escalation_node,
    "static_patterns_supply_chain": static_patterns_supply_chain_node,
    "static_patterns_harmful_content": static_patterns_harmful_content_node,
    "static_patterns_excessive_agency": static_patterns_excessive_agency_node,
    "static_patterns_output_handling": static_patterns_output_handling_node,
    "static_patterns_system_prompt_leakage": static_patterns_system_prompt_leakage_node,
    "static_patterns_memory_poisoning": static_patterns_memory_poisoning_node,
    "static_patterns_tool_misuse": static_patterns_tool_misuse_node,
    "static_patterns_rogue_agent": static_patterns_rogue_agent_node,
    "static_yara": static_yara_node,
    "behavioral_ast": behavioral_ast_node,
    "behavioral_taint_tracking": behavioral_taint_tracking_node,
    "mcp_least_privilege": mcp_least_privilege_node,
    "mcp_tool_poisoning": mcp_tool_poisoning_node,
    "mcp_rug_pull": mcp_rug_pull_node,
    "semantic_security_discovery": semantic_security_discovery_node,
    "semantic_developer_intent": semantic_developer_intent_node,
    "semantic_quality_policy": semantic_quality_policy_node,
    "claude_plugin_structure": claude_plugin_structure_node,
    "claude_hooks": claude_hooks_node,
    "claude_mcp_lsp": claude_mcp_lsp_node,
    "claude_components": claude_components_node,
    "claude_capability_correlation": claude_capability_correlation_node,
}

# ---------------------------------------------------------------------------
# Analyzer readiness metadata
# ---------------------------------------------------------------------------
# status values:
#   "production" — fully implemented, golden fixtures exist
#   "beta"       — implemented but coverage or edge cases are incomplete
#   "stub"       — not yet implemented; returns no findings
#
# requires_network: True if the analyzer makes external HTTP calls
# requires_llm:     True if the analyzer calls an LLM (use_llm must be True)

ANALYZER_METADATA: dict[str, dict[str, object]] = {
    # Static pattern analyzers — regex/heuristic, no external dependencies
    "static_patterns_prompt_injection": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["P1", "P2", "P3", "P4"],
    },
    "static_patterns_data_exfiltration": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["E1", "E2", "E3", "E4"],
    },
    "static_patterns_privilege_escalation": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["PE1", "PE2", "PE3"],
    },
    "static_patterns_supply_chain": {
        "status": "production",
        "requires_network": True,  # OSV.dev lookups for SC4
        "requires_llm": False,
        "rule_ids": ["SC1", "SC2", "SC3", "SC4", "SC5", "SC6"],
    },
    "static_patterns_harmful_content": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["HC1", "HC2", "HC3"],
    },
    "static_patterns_excessive_agency": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["EA1", "EA2", "EA3", "EA4"],
    },
    "static_patterns_output_handling": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["OH1", "OH2", "OH3"],
    },
    "static_patterns_system_prompt_leakage": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["P6", "P7", "P8"],
    },
    "static_patterns_memory_poisoning": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["MP1", "MP2", "MP3"],
    },
    "static_patterns_tool_misuse": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["TM1", "TM2", "TM3"],
    },
    "static_patterns_rogue_agent": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["RA1", "RA2"],
    },
    # Signature-based
    "static_yara": {
        "status": "beta",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["YARA"],
        "notes": "YARA engine available; built-in rule coverage is limited",
    },
    # Behavioral analyzers
    "behavioral_ast": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["BA1", "BA2"],
    },
    "behavioral_taint_tracking": {
        "status": "beta",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["BT1", "BT2"],
        "notes": "Taint tracking implemented for Python; coverage of other languages is limited",
    },
    # MCP analyzers
    "mcp_least_privilege": {
        "status": "beta",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["LP1", "LP2", "LP3"],
    },
    "mcp_tool_poisoning": {
        "status": "production",
        "requires_network": False,
        "requires_llm": True,  # TP4 uses LLM when use_llm=True
        "rule_ids": ["TP1", "TP2", "TP3", "TP4"],
    },
    "mcp_rug_pull": {
        "status": "stub",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["RP1", "RP2", "RP3"],
        "notes": "Requires previous manifest for diff; not yet implemented",
    },
    # Semantic (LLM-based) analyzers
    "semantic_security_discovery": {
        "status": "beta",
        "requires_network": False,
        "requires_llm": True,
        "rule_ids": ["SD1"],
        "notes": "LLM-based novel finding discovery; skipped when use_llm=False",
    },
    "semantic_developer_intent": {
        "status": "beta",
        "requires_network": False,
        "requires_llm": True,
        "rule_ids": ["DI1"],
        "notes": "LLM-based intent classification; skipped when use_llm=False",
    },
    "semantic_quality_policy": {
        "status": "beta",
        "requires_network": False,
        "requires_llm": True,
        "rule_ids": ["QP1"],
        "notes": "LLM-based policy check; skipped when use_llm=False",
    },
    # Claude plugin analyzers
    "claude_plugin_structure": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["CP001", "CP002", "CP003", "CP004", "CP005"],
    },
    "claude_hooks": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["CH1", "CH2", "CH3"],
    },
    "claude_mcp_lsp": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["CML1", "CML2"],
    },
    "claude_components": {
        "status": "production",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["CC1", "CC2"],
    },
    "claude_capability_correlation": {
        "status": "beta",
        "requires_network": False,
        "requires_llm": False,
        "rule_ids": ["CCC1", "CCC2"],
        "notes": "Cross-component correlation; heuristic coverage is incomplete",
    },
}

__all__ = ["ANALYZER_NODE_IDS", "ANALYZER_NODES", "ANALYZER_METADATA"]

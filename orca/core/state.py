"""
ORCA Workflow State — LangGraph TypedDict used by the meta-orchestrator.

Each domain sub-graph has its own Pydantic state model (in core/models.py).
This module defines the top-level LangGraph state that composes them.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional, TypedDict, Annotated
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages


class OrcaWorkflowState(TypedDict):
    # ── inputs ─────────────────────────────────────────────────
    binary_path: Optional[str]
    pcap_path: Optional[str]
    binary_functionality: Optional[str]
    goal: Optional[str]            # capabilities | malware | triage | network | comprehensive
    user_message: Optional[str]    # chatbot follow-up

    # ── domain results (serialised Pydantic → dict) ────────────
    binary_domain: Optional[Dict[str, Any]]
    malware_domain: Optional[Dict[str, Any]]
    network_domain: Optional[Dict[str, Any]]
    correlation: Optional[Dict[str, Any]]

    # ── planning / routing ─────────────────────────────────────
    plan: Optional[List[str]]
    current_step: Optional[int]
    completed_steps: List[str]
    analysis_complete: Optional[bool]

    # ── outputs ────────────────────────────────────────────────
    final_report: Optional[Dict[str, Any]]
    messages: Annotated[List[AnyMessage], add_messages]

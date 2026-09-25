"""
ORCA Meta-Orchestrator

Composes domain sub-graphs dynamically based on what inputs are provided
(binary? pcap? both?) and the analysis goal. Produces a unified OrcaReport.
"""
from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from langgraph.graph import StateGraph, END
from langchain_core.messages import AIMessage, HumanMessage

from orca.core.state import OrcaWorkflowState
from orca.core.llm.provider import LLMProvider

llm = LLMProvider()

# Optional malware domain. The QUIC-focused FINE 2026 build does not ship
# malware agents; we tolerate the absence so the workflow runs end-to-end
# without a ModuleNotFoundError at plan time.
try:
    from orca.domains.malware.workflow import (  # noqa: F401
        triage_agent as _triage_agent,
        ioc_extraction_agent as _ioc_extraction_agent,
        mitre_mapping_agent as _mitre_mapping_agent,
        malware_assessment_agent as _malware_assessment_agent,
    )
    MALWARE_AVAILABLE = True
except ImportError:
    MALWARE_AVAILABLE = False


# ── Planning Agent ─────────────────────────────────────────────

def planning_agent(state: OrcaWorkflowState) -> Dict:
    """Build a dynamic execution plan based on inputs and goal."""
    goal = (state.get("goal") or "comprehensive").lower()
    has_binary = bool(state.get("binary_path"))
    has_pcap = bool(state.get("pcap_path"))
    plan: List[str] = []

    # Binary domain steps
    if has_binary:
        plan.append("static_analysis")
        # Deep analysis agents (cross-refs, string threat, string cross-refs)
        plan.extend(["api_crossrefs", "string_threat_analysis", "string_crossref_analysis"])
        if "capabilities" in goal or "comprehensive" in goal:
            plan.extend(["api_clustering", "capabilities_analysis"])
        if MALWARE_AVAILABLE and ("malware" in goal or "triage" in goal or "comprehensive" in goal):
            plan.extend(["triage", "ioc_extraction", "mitre_mapping", "malware_assessment"])
        plan.append("binary_summary")

    # Network domain steps
    if has_pcap:
        plan.extend([
            "pcap_ingest", "traffic_statistics", "qlog_analysis",
            "quic_handshake", "attack_classification", "anomaly_detection",
        ])
        # FINE 2026 attack-specific evidence agents. Always run when
        # pcap is provided so the fusion agent has each attack class's
        # qlog/PCAP evidence regardless of the upstream classifier
        # label. Skip them by passing goal="quic_classify_only".
        if "classify_only" not in goal:
            plan.extend([
                "zero_rtt_replay", "retry_token_abuse", "cid_exhaustion",
                "flood", "slowloris", "mitm",
            ])

    # Cross-domain analysis (when both binary and network data exist)
    if has_binary and has_pcap:
        plan.append("quic_binary_assessment")
        plan.append("correlation")

    # Evidence fusion runs after every classifier-style agent. It
    # consumes whichever upstream outputs exist (network, binary,
    # 0-RTT, retry-token, CID, qlog) and emits the integrated
    # assessment + the shipped-but-silent finding. Always run when at
    # least one classifier ran (i.e. when pcap is provided).
    if has_pcap:
        plan.append("evidence_fusion")

    # Final summary always
    plan.append("final_summary")

    return {
        "plan": plan,
        "current_step": 0,
        "completed_steps": [],
        "messages": [AIMessage(content=f"Plan created ({len(plan)} steps): {', '.join(plan)}")],
    }


# ── Final Summary Agent ───────────────────────────────────────

def final_summary_agent(state: OrcaWorkflowState) -> Dict:
    """Generate executive summary consolidating all domains."""
    data = {
        "binary_domain": state.get("binary_domain", {}),
        "malware_domain": state.get("malware_domain", {}),
        "network_domain": state.get("network_domain", {}),
        "goal": state.get("goal", ""),
    }
    try:
        report = llm.query_json(
            system="You are ORCA, a security analysis platform. Generate a final report.",
            user=f"""Generate executive summary covering all analysis domains.
Return JSON: executive_summary, recommendations[], threat_assessment.
Data: {json.dumps(data, default=str)[:5000]}""",
        )
    except Exception as exc:
        report = {"executive_summary": f"Report generation failed: {exc}", "recommendations": []}

    return {
        "final_report": report,
        "analysis_complete": True,
        "current_step": (state.get("current_step") or 0) + 1,
        "completed_steps": (state.get("completed_steps") or []) + ["final_summary"],
        "messages": [AIMessage(content="Analysis complete. Final report generated.")],
    }


# ── Routing ────────────────────────────────────────────────────

def route_next(state: OrcaWorkflowState) -> str:
    plan = state.get("plan") or []
    step = state.get("current_step") or 0
    if step >= len(plan):
        return END
    return plan[step]


# ── Correlation Agent ──────────────────────────────────────────

def correlation_agent(state: OrcaWorkflowState) -> Dict:
    """Run cross-domain correlation engine."""
    from orca.correlation.engine import correlate
    try:
        result = correlate(state)
    except Exception as exc:
        result = {"error": str(exc), "unified_threat_score": 0}

    return {
        "correlation": result,
        "current_step": (state.get("current_step") or 0) + 1,
        "completed_steps": (state.get("completed_steps") or []) + ["correlation"],
        "messages": [AIMessage(content=f"Correlation done — threat score: {result.get('unified_threat_score', 0)}/100.")],
    }


# ── Agent imports (lazy) ───────────────────────────────────────

def _get_agent_map():
    from orca.domains.binary.workflow import (
        static_analysis_agent, api_crossref_agent,
        string_threat_agent, string_crossref_agent,
        api_clustering_agent,
        capabilities_agent, binary_summary_agent,
    )
    from orca.domains.network.workflow import (
        pcap_ingest_agent, traffic_statistics_agent,
        qlog_analysis_agent,
        quic_handshake_agent, attack_classification_agent,
        anomaly_detection_agent, quic_binary_assessment_agent,
        zero_rtt_replay_agent, retry_token_abuse_agent,
        cid_exhaustion_agent,
        flood_agent, slowloris_agent, mitm_agent,
        evidence_fusion_agent,
    )
    agent_map = {
        "static_analysis": static_analysis_agent,
        "api_crossrefs": api_crossref_agent,
        "string_threat_analysis": string_threat_agent,
        "string_crossref_analysis": string_crossref_agent,
        "api_clustering": api_clustering_agent,
        "capabilities_analysis": capabilities_agent,
        "binary_summary": binary_summary_agent,
        "pcap_ingest": pcap_ingest_agent,
        "traffic_statistics": traffic_statistics_agent,
        "qlog_analysis": qlog_analysis_agent,
        "quic_handshake": quic_handshake_agent,
        "attack_classification": attack_classification_agent,
        "anomaly_detection": anomaly_detection_agent,
        "zero_rtt_replay": zero_rtt_replay_agent,
        "retry_token_abuse": retry_token_abuse_agent,
        "cid_exhaustion": cid_exhaustion_agent,
        "flood": flood_agent,
        "slowloris": slowloris_agent,
        "mitm": mitm_agent,
        "quic_binary_assessment": quic_binary_assessment_agent,
        "evidence_fusion": evidence_fusion_agent,
        "correlation": correlation_agent,
    }
    if MALWARE_AVAILABLE:
        agent_map.update({
            "triage": _triage_agent,
            "ioc_extraction": _ioc_extraction_agent,
            "mitre_mapping": _mitre_mapping_agent,
            "malware_assessment": _malware_assessment_agent,
        })
    return agent_map


# ── Graph Builder ──────────────────────────────────────────────

def create_orca_workflow() -> StateGraph:
    agent_map = _get_agent_map()

    g = StateGraph(OrcaWorkflowState)

    # Add all agent nodes
    g.add_node("planning", planning_agent)
    for name, fn in agent_map.items():
        g.add_node(name, fn)
    g.add_node("final_summary", final_summary_agent)

    g.set_entry_point("planning")

    # Build routing targets
    targets = {name: name for name in agent_map}
    targets["final_summary"] = "final_summary"
    targets[END] = END

    # Planning routes to first step
    g.add_conditional_edges("planning", route_next, targets)

    # Each agent routes to next step
    for name in list(agent_map.keys()) + ["final_summary"]:
        g.add_conditional_edges(name, route_next, targets)

    return g


def run_orca(
    *,
    binary_path: Optional[str] = None,
    pcap_path: Optional[str] = None,
    functionality: str = "",
    goal: str = "comprehensive",
) -> Dict[str, Any]:
    """Main entry point — run the full ORCA pipeline."""
    workflow = create_orca_workflow()
    app = workflow.compile()

    initial_state: Dict[str, Any] = {
        "binary_path": binary_path,
        "pcap_path": pcap_path,
        "binary_functionality": functionality,
        "goal": goal,
        "user_message": None,
        "messages": [HumanMessage(content=f"Analyse: binary={binary_path}, pcap={pcap_path}, goal={goal}")],
        "completed_steps": [],
        "binary_domain": {},
        "malware_domain": {},
        "network_domain": {},
    }

    return app.invoke(initial_state)

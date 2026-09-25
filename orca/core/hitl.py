"""
ORCA Human-in-the-Loop (HITL)

LangGraph interrupt-based HITL that pauses the workflow at configurable
checkpoints for analyst review/override before continuing.

Supported interrupt points:
  - after_triage    : pause after malware triage for analyst confirmation
  - after_mitre     : pause after MITRE mapping for review
  - after_assessment: pause after malware classification before report
  - after_anomaly   : pause after network anomaly detection
  - after_correlation: pause after cross-domain correlation
"""
from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional, Set
from langgraph.graph import StateGraph, END
from langchain_core.messages import AIMessage, HumanMessage

from orca.core.state import OrcaWorkflowState

# Default steps that trigger human review
DEFAULT_INTERRUPT_POINTS: Set[str] = {
    "malware_assessment",
    "correlation",
}


class HITLManager:
    """
    Manages human-in-the-loop interrupts for ORCA workflows.

    Usage::

        hitl = HITLManager(interrupt_after={"triage", "malware_assessment"})
        app = create_orca_workflow_with_hitl(hitl)

        # Run until first interrupt
        state = app.invoke(initial_state)

        # Check if interrupted
        if hitl.is_waiting(state):
            # Show analyst the current findings
            findings = hitl.get_pending_review(state)

            # Analyst provides feedback
            state = hitl.submit_review(state, approved=True, notes="Looks correct")

            # Resume
            state = app.invoke(state)
    """

    def __init__(
        self,
        interrupt_after: Optional[Set[str]] = None,
        auto_approve_low_risk: bool = False,
        risk_threshold: int = 50,
    ):
        self.interrupt_points = interrupt_after or DEFAULT_INTERRUPT_POINTS
        self.auto_approve_low_risk = auto_approve_low_risk
        self.risk_threshold = risk_threshold

    def should_interrupt(self, state: OrcaWorkflowState) -> bool:
        """Check if current step requires human review."""
        completed = state.get("completed_steps") or []
        if not completed:
            return False

        last_step = completed[-1]
        if last_step not in self.interrupt_points:
            return False

        # Auto-approve low-risk findings
        if self.auto_approve_low_risk:
            threat_score = self._get_threat_score(state)
            if threat_score < self.risk_threshold:
                return False

        return True

    def is_waiting(self, state: OrcaWorkflowState) -> bool:
        """Check if the workflow is paused waiting for human input."""
        return state.get("_hitl_waiting", False)

    def get_pending_review(self, state: OrcaWorkflowState) -> Dict[str, Any]:
        """Get the findings that need analyst review."""
        completed = state.get("completed_steps") or []
        last_step = completed[-1] if completed else ""

        review = {
            "step": last_step,
            "threat_score": self._get_threat_score(state),
        }

        if last_step in ("triage", "malware_assessment"):
            md = state.get("malware_domain") or {}
            review["triage"] = md.get("triage")
            review["assessment"] = md.get("analysis")
            review["mitre"] = md.get("mitre")
            review["iocs"] = md.get("iocs")

        if last_step == "correlation":
            review["correlation"] = state.get("correlation")

        if last_step in ("anomaly_detection",):
            nd = state.get("network_domain") or {}
            review["anomalies"] = nd.get("anomalies")
            review["traffic_patterns"] = nd.get("traffic_patterns")

        return review

    def submit_review(
        self,
        state: Dict[str, Any],
        *,
        approved: bool = True,
        notes: str = "",
        override_classification: Optional[str] = None,
        override_threat_level: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submit analyst review and resume the workflow."""
        state["_hitl_waiting"] = False
        state["_hitl_approved"] = approved

        review_record = {
            "approved": approved,
            "notes": notes,
            "override_classification": override_classification,
            "override_threat_level": override_threat_level,
        }

        # Apply overrides
        if override_classification and "malware_domain" in state:
            md = state["malware_domain"] or {}
            analysis = md.get("analysis") or {}
            analysis["classification"] = override_classification
            analysis["analyst_override"] = True
            md["analysis"] = analysis
            state["malware_domain"] = md

        if override_threat_level and "malware_domain" in state:
            md = state["malware_domain"] or {}
            analysis = md.get("analysis") or {}
            analysis["threat_level"] = override_threat_level
            analysis["analyst_override"] = True
            md["analysis"] = analysis
            state["malware_domain"] = md

        # Record the review
        reviews = state.get("_hitl_reviews") or []
        reviews.append(review_record)
        state["_hitl_reviews"] = reviews

        msg = f"Analyst review: {'approved' if approved else 'rejected'}"
        if notes:
            msg += f" — {notes}"
        state["messages"] = state.get("messages", []) + [HumanMessage(content=msg)]

        return state

    def create_interrupt_node(self):
        """Create a LangGraph node that pauses for human review."""
        manager = self

        def hitl_checkpoint(state: OrcaWorkflowState) -> Dict:
            if manager.should_interrupt(state):
                return {
                    "_hitl_waiting": True,
                    "messages": [AIMessage(content=f"⏸️  HITL: Pausing for analyst review after '{(state.get('completed_steps') or [''])[-1]}'")],
                }
            return {}

        return hitl_checkpoint

    def _get_threat_score(self, state: OrcaWorkflowState) -> int:
        md = state.get("malware_domain") or {}
        mitre = md.get("mitre") or {}
        score = mitre.get("threat_score", 0)

        corr = state.get("correlation") or {}
        if corr.get("unified_threat_score"):
            score = max(score, corr["unified_threat_score"])

        return score

"""
Binary Domain Sub-Graph

LangGraph sub-graph that orchestrates binary static analysis agents:
  1. static_analysis     — RE backend extraction + function scoring + enrichment
  2. api_crossrefs       — map imports to calling functions with assembly context
  3. string_threat       — pattern-based suspicious string detection
  4. string_crossrefs    — trace suspicious strings to functions, LLM analysis
  5. api_clustering      — LLM groups APIs by behavioural purpose (with code context)
  6. capabilities        — LLM-driven capability identification (with decompiled code)
  7. binary_summary      — final summary generation
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from langgraph.graph import StateGraph, END
from langchain_core.messages import AIMessage

from orca.core.state import OrcaWorkflowState
from orca.core.config import config
from orca.core.llm.provider import LLMProvider
from orca.core.re_backends.selector import REBackendSelector
from orca.core.models import (
    FileInfo, StaticAnalysisResult, StringCategory, SectionInfo,
    FunctionInfo, REBackendType, APIAnalysisResult, APICluster,
    BinaryDomainState,
)

llm = LLMProvider()


# ── Agent: Static Analysis + Enrichment ──────────────────────

def static_analysis_agent(state: OrcaWorkflowState) -> Dict:
    """Run RE backend, extract static features, score and enrich top functions."""
    from orca.domains.binary.function_filter import filter_functions, score_function
    binary_path = Path(state["binary_path"])

    try:
        file_info = FileInfo.from_path(binary_path)

        selector = REBackendSelector()
        backends = selector.select(binary_path)
        chosen = backends[0]

        # Try chosen backend; fall back to other if it fails
        backend = None
        for attempt_backend in [chosen, REBackendType.BINARY_NINJA, REBackendType.GHIDRA]:
            if backend is not None:
                break
            try:
                candidate = selector.create_backend(attempt_backend, binary_path)
                candidate.open()
                backend = candidate
                chosen = attempt_backend
            except Exception:
                continue

        if backend is None:
            raise RuntimeError(f"No RE backend could load {binary_path}")

        try:
            imports = backend.get_imports()
            exports = backend.get_exports()
            sections = [s.model_dump() for s in backend.get_sections()]
            raw_strings = backend.get_strings()
            functions = backend.get_functions()

            file_info.architecture = backend.get_architecture()
            file_info.binary_format = backend.get_binary_format()
            file_info.is_stripped = backend.is_stripped()
            file_info.has_cpp_symbols = backend.has_cpp_symbols()

            # Score and filter functions
            top_n = config.get("analysis.function_enrich_top_n", 20)
            top_functions = filter_functions(functions, top_n=top_n)

            # Enrich top functions with decompiled code and assembly
            enriched_functions = []
            for func in top_functions:
                enrichment = backend.enrich_function(func.name)
                func.decompiled_code = enrichment.get("decompiled_code")
                func.assembly = enrichment.get("assembly")
                func.hlil = enrichment.get("hlil")
                func.mlil = enrichment.get("mlil")
                enriched_functions.append(func)
        finally:
            backend.close()

        result = {
            "file_info": file_info.model_dump(),
            "imports": imports,
            "exports": exports,
            "sections": sections,
            "strings": {"raw": raw_strings[:500]},
            "functions": [f.model_dump() for f in functions],
            "enriched_functions": [f.model_dump() for f in enriched_functions],
            "functions_total_count": len(functions),
            "enriched_count": len(enriched_functions),
            "backend_used": chosen.value,
        }

        bd = state.get("binary_domain") or {}
        bd["static_analysis"] = result

        return {
            "binary_domain": bd,
            "current_step": (state.get("current_step") or 0) + 1,
            "completed_steps": (state.get("completed_steps") or []) + ["static_analysis"],
            "messages": [AIMessage(content=f"Static analysis done — {len(functions)} functions ({len(enriched_functions)} enriched with decompiled code), {len(imports)} imports ({chosen.value}).")],
        }
    except Exception as exc:
        bd = state.get("binary_domain") or {}
        bd["static_analysis"] = {"error": str(exc)}
        return {
            "binary_domain": bd,
            "current_step": (state.get("current_step") or 0) + 1,
            "completed_steps": (state.get("completed_steps") or []) + ["static_analysis"],
            "messages": [AIMessage(content=f"Static analysis failed: {exc}")],
        }


# ── Agent: API Cross-References ──────────────────────────────

def api_crossref_agent(state: OrcaWorkflowState) -> Dict:
    """Map top imports to calling functions with assembly and decompiled context."""
    from orca.domains.binary.function_filter import prioritize_apis
    bd = state.get("binary_domain") or {}
    sa = bd.get("static_analysis", {})
    imports = sa.get("imports", [])

    if not imports or sa.get("error"):
        return _step_forward(state, bd, "api_crossrefs", "API cross-refs skipped — no imports.")

    # Prioritize imports by security relevance
    top_apis = prioritize_apis(imports, top_n=config.get("analysis.max_crossref_apis", 30))

    try:
        binary_path = Path(state["binary_path"])
        backend_type = sa.get("backend_used", "binary_ninja")
        selector = REBackendSelector()
        backend = selector.create_backend(
            REBackendType(backend_type), binary_path
        )

        crossrefs = []
        with backend:
            max_funcs_per_api = config.get("analysis.max_crossref_functions_per_api", 3)
            for api_name, category, priority in top_apis:
                calling_funcs = backend.get_cross_references(api_name)
                if not calling_funcs:
                    continue

                api_entry = {
                    "api_name": api_name,
                    "category": category,
                    "priority": priority,
                    "calling_functions": [],
                }

                for func_name in calling_funcs[:max_funcs_per_api]:
                    enrichment = backend.enrich_function(func_name)
                    api_entry["calling_functions"].append({
                        "function_name": func_name,
                        "decompiled_code": (enrichment.get("decompiled_code") or "")[:500],
                        "assembly": (enrichment.get("assembly") or "")[:500],
                    })

                crossrefs.append(api_entry)

        # LLM analyses the cross-reference patterns
        if crossrefs:
            try:
                xref_summary = json.dumps(crossrefs[:10], default=str)[:3000]
                llm_analysis = llm.query_json(
                    system="You are a binary security analyst examining how APIs are used in compiled code.",
                    user=f"""Examine these API cross-references. For each API, you can see which functions call it and the decompiled code around the call.

Determine:
1. Which APIs are used in a security-relevant way (not just standard library usage)
2. Whether any API usage patterns suggest malicious intent (e.g., process injection, network exfiltration, privilege escalation)
3. Whether the usage appears legitimate (e.g., a system utility performing its normal function)

Return JSON: {{"security_relevant_apis": [...], "suspicious_patterns": [...], "assessment": "benign|suspicious|malicious", "reasoning": "..."}}

Cross-references: {xref_summary}""",
                )
                bd["api_crossref_analysis"] = llm_analysis
            except Exception:
                pass

        bd["api_crossrefs"] = crossrefs
        found = sum(len(c["calling_functions"]) for c in crossrefs)
        return _step_forward(state, bd, "api_crossrefs",
                             f"API cross-refs done — {len(crossrefs)} APIs traced to {found} functions.")

    except Exception as exc:
        bd["api_crossrefs"] = []
        return _step_forward(state, bd, "api_crossrefs", f"API cross-refs failed: {exc}")


# ── Agent: String Threat Analysis ────────────────────────────

def string_threat_agent(state: OrcaWorkflowState) -> Dict:
    """Analyse binary strings for security threats using pattern matching and LLM reasoning."""
    from orca.domains.binary.string_analysis import StringThreatAnalyzer
    bd = state.get("binary_domain") or {}
    sa = bd.get("static_analysis", {})
    strings = sa.get("strings", {}).get("raw", [])

    if not strings:
        return _step_forward(state, bd, "string_threat_analysis", "String threat skipped — no strings.")

    # Pattern-based pre-filtering to reduce what we send to the LLM
    analyzer = StringThreatAnalyzer()
    results = analyzer.analyze(strings)

    # LLM analyses the strings for deeper assessment
    try:
        # Send a sample of strings to the LLM for contextual analysis
        string_sample = strings[:100]
        suspicious_found = results.get("high_risk_strings", [])[:20]
        encoded = results.get("encoded_strings", [])[:10]

        llm_result = llm.query_json(
            system="You are a binary security analyst examining strings extracted from a compiled binary.",
            user=f"""Examine these strings extracted from a binary file.

A pre-filter identified {len(suspicious_found)} potentially suspicious strings and {len(encoded)} possibly encoded strings.

Your task:
1. Assess whether the suspicious strings indicate genuine security concerns or are benign
2. Identify any additional strings from the full sample that the pre-filter may have missed
3. Determine the overall threat level from the string content alone

Pre-filter suspicious strings: {json.dumps(suspicious_found[:15])}
Possibly encoded strings: {json.dumps(encoded[:5], default=str)}
Full string sample (first 100): {json.dumps(string_sample[:50])}

Return JSON: {{
    "confirmed_threats": ["strings that are genuinely concerning"],
    "false_positives": ["strings flagged by pre-filter but actually benign"],
    "additional_findings": ["suspicious strings the pre-filter missed"],
    "threat_assessment": "none|low|medium|high",
    "reasoning": "explanation of the assessment"
}}""",
        )
        results["llm_analysis"] = llm_result
        results["llm_threat_assessment"] = llm_result.get("threat_assessment", "unknown")
    except Exception:
        pass

    bd["string_threat_analysis"] = results

    return _step_forward(state, bd, "string_threat_analysis",
                         f"String threat analysis done — risk score {results['risk_score']}/100, "
                         f"{len(results.get('high_risk_strings', []))} high-risk strings.")


# ── Agent: String Cross-References ───────────────────────────

def string_crossref_agent(state: OrcaWorkflowState) -> Dict:
    """Trace suspicious strings to functions, get decompiled code, LLM analysis."""
    from orca.domains.binary.string_analysis import score_string
    bd = state.get("binary_domain") or {}
    sa = bd.get("static_analysis", {})
    threat = bd.get("string_threat_analysis", {})

    # Collect top suspicious strings
    suspicious = threat.get("high_risk_strings", [])
    for cat_strings in threat.get("suspicious_by_category", {}).values():
        suspicious.extend(cat_strings[:3])

    # Deduplicate and score
    seen = set()
    scored_strings = []
    for s in suspicious:
        if s in seen or len(s) < 4:
            continue
        seen.add(s)
        sc, reason = score_string(s)
        if sc >= config.get("analysis.string_threat_min_score", 50):
            scored_strings.append((s, sc, reason))

    scored_strings.sort(key=lambda x: x[1], reverse=True)
    max_strings = config.get("analysis.max_suspicious_strings_for_crossref", 10)
    scored_strings = scored_strings[:max_strings]

    if not scored_strings or sa.get("error"):
        return _step_forward(state, bd, "string_crossref_analysis", "String cross-refs skipped.")

    try:
        binary_path = Path(state["binary_path"])
        backend_type = sa.get("backend_used", "binary_ninja")
        selector = REBackendSelector()
        backend = selector.create_backend(REBackendType(backend_type), binary_path)

        string_xrefs = []
        with backend:
            for target, sc, reason in scored_strings:
                refs = backend.find_string_references(target, max_results=3)
                if refs:
                    string_xrefs.append({
                        "string": target,
                        "score": sc,
                        "reason": reason,
                        "references": refs,
                    })

        # LLM analysis of the most interesting string references
        if string_xrefs:
            try:
                xref_data = json.dumps(string_xrefs[:5], default=str)[:3000]
                llm_analysis = llm.query_json(
                    system="You are a binary security analyst. Analyse how these strings are used in the code.",
                    user=f"""For each string and its referencing functions (with decompiled code), determine:
1. Is this string usage benign or suspicious?
2. What is the purpose of the function that references it?
3. Does the usage context indicate malicious intent?
Return JSON: {{"string_assessments": [{{"string": "...", "assessment": "benign|suspicious|malicious", "purpose": "...", "explanation": "..."}}]}}

Data: {xref_data}""",
                )
                for xref in string_xrefs:
                    xref["llm_analysis"] = llm_analysis
            except Exception:
                pass

        bd["string_crossref_analysis"] = string_xrefs
        return _step_forward(state, bd, "string_crossref_analysis",
                             f"String cross-refs done — {len(string_xrefs)} strings traced to functions.")

    except Exception as exc:
        bd["string_crossref_analysis"] = []
        return _step_forward(state, bd, "string_crossref_analysis", f"String cross-refs failed: {exc}")


# ── Agent: API Clustering (enriched) ─────────────────────────

def api_clustering_agent(state: OrcaWorkflowState) -> Dict:
    """LLM clusters imported APIs into functional groups, now with code context."""
    bd = state.get("binary_domain") or {}
    sa = bd.get("static_analysis", {})
    imports = sa.get("imports", [])[:100]

    if not imports:
        bd["api_analysis"] = bd.get("api_analysis", {})
        return _step_forward(state, bd, "api_clustering", "API clustering skipped — no imports.")

    # Build context from cross-references
    crossref_context = ""
    crossrefs = bd.get("api_crossrefs", [])
    if crossrefs:
        context_parts = []
        for xref in crossrefs[:10]:
            for cf in xref.get("calling_functions", [])[:1]:
                code = cf.get("decompiled_code", "")
                if code:
                    context_parts.append(f"API {xref['api_name']} used in {cf['function_name']}:\n{code[:300]}")
        crossref_context = "\n\n".join(context_parts[:5])

    try:
        prompt = f"""Cluster these APIs into logical functional groups.
For each cluster provide: name, description, apis list, security_assessment (safe|potentially_dangerous|dangerous), potential_usage.
Return JSON: {{"clusters": [...]}}

APIs: {json.dumps(imports)}"""

        if crossref_context:
            prompt += f"\n\nCode context showing how some of these APIs are actually used:\n{crossref_context}"
            prompt += "\n\nIMPORTANT: Consider the usage context. APIs used for legitimate system management are different from the same APIs used for injection or evasion."

        result = llm.query_json(
            system="You are an expert reverse engineer. Analyse APIs considering both their names and how they are used in the code.",
            user=prompt,
        )
        aa = bd.get("api_analysis") or {}
        aa["clusters"] = result.get("clusters", [])
        bd["api_analysis"] = aa
        return _step_forward(state, bd, "api_clustering", f"API clustering done — {len(aa['clusters'])} clusters.")
    except Exception as exc:
        return _step_forward(state, bd, "api_clustering", f"API clustering failed: {exc}")


# ── Agent: Capabilities Analysis (enriched) ──────────────────

def capabilities_agent(state: OrcaWorkflowState) -> Dict:
    """LLM identifies binary capabilities from static analysis + decompiled code."""
    bd = state.get("binary_domain") or {}
    sa = bd.get("static_analysis", {})

    if not sa or sa.get("error"):
        return _step_forward(state, bd, "capabilities_analysis", "Capabilities skipped — no static data.")

    # Select top enriched functions for context
    enriched = sa.get("enriched_functions", [])
    top_funcs = []
    for f in enriched[:5]:
        code = f.get("decompiled_code", "")
        if code:
            top_funcs.append({"name": f["name"], "code": code[:1000], "score": f.get("interest_score", 0)})

    data = {
        "file_info": sa.get("file_info", {}),
        "imports": sa.get("imports", [])[:80],
        "functions_count": sa.get("functions_total_count", 0),
        "clusters": (bd.get("api_analysis") or {}).get("clusters", []),
    }

    prompt = f"Analyse:\n{json.dumps(data, indent=2)}\n\nReturn JSON with: core_functionality, network_capabilities, file_system_operations, process_manipulation, persistence_mechanisms, anti_analysis_techniques, other_capabilities."

    if top_funcs:
        prompt += f"\n\nDecompiled code of the most security-relevant functions:\n{json.dumps(top_funcs, indent=2)}"
        prompt += "\n\nUse the decompiled code to understand what the binary actually does, not just what APIs it imports."

    # Add string threat context
    string_threat = bd.get("string_threat_analysis", {})
    if string_threat.get("risk_score", 0) > 20:
        prompt += f"\n\nString analysis: risk_score={string_threat['risk_score']}/100, risk_level={string_threat.get('risk_level', 'unknown')}"
        high_risk = string_threat.get("high_risk_strings", [])[:5]
        if high_risk:
            prompt += f", high_risk_strings={high_risk}"

    try:
        caps = llm.query_json(
            system="You are a binary analysis expert. Identify the binary's capabilities based on both API imports and actual code behaviour.",
            user=prompt,
        )
        bd["capabilities"] = caps
        return _step_forward(state, bd, "capabilities_analysis", "Capabilities analysis done.")
    except Exception as exc:
        bd["capabilities"] = {"error": str(exc)}
        return _step_forward(state, bd, "capabilities_analysis", f"Capabilities failed: {exc}")


# ── Agent: Binary Summary ────────────────────────────────────

def binary_summary_agent(state: OrcaWorkflowState) -> Dict:
    """Generate a concise summary of the binary."""
    bd = state.get("binary_domain") or {}
    sa = bd.get("static_analysis", {})

    try:
        data = {
            "file_info": sa.get("file_info", {}),
            "imports_count": len(sa.get("imports", [])),
            "functions_count": sa.get("functions_total_count", 0),
            "enriched_functions_count": sa.get("enriched_count", 0),
            "capabilities": bd.get("capabilities", {}),
            "string_threat_risk_score": bd.get("string_threat_analysis", {}).get("risk_score", 0),
            "api_crossrefs_count": len(bd.get("api_crossrefs", [])),
        }
        summary = llm.query(
            system="You are a binary analysis expert.",
            user=f"Summarise this binary in 3-5 paragraphs:\n{json.dumps(data, indent=2)}",
        )
        bd["binary_summary"] = summary
    except Exception as exc:
        bd["binary_summary"] = f"Summary generation failed: {exc}"

    return _step_forward(state, bd, "binary_summary", "Binary summary done.")


# ── Helpers ──────────────────────────────────────────────────

def _step_forward(state, bd, step_name, msg_text):
    return {
        "binary_domain": bd,
        "current_step": (state.get("current_step") or 0) + 1,
        "completed_steps": (state.get("completed_steps") or []) + [step_name],
        "messages": [AIMessage(content=msg_text)],
    }


# ── Sub-graph builder ────────────────────────────────────────

def should_continue(state: OrcaWorkflowState) -> str:
    plan = state.get("plan") or []
    step = state.get("current_step") or 0
    if step >= len(plan):
        return END
    return plan[step]

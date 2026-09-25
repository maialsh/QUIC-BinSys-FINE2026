"""
ORCA Reporting Engine

Generates reports in multiple formats:
  - JSON   (machine-readable, default)
  - HTML   (rich visual report with Jinja2 templates)
  - SARIF  (Static Analysis Results Interchange Format for CI/CD integration)
"""
from __future__ import annotations
import json, html as html_mod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class ReportEngine:
    """Generate analysis reports in JSON, HTML, or SARIF format."""

    def __init__(self, result: Dict[str, Any]):
        self.result = result
        self.timestamp = datetime.utcnow().isoformat()

    # ── JSON ───────────────────────────────────────────────────

    def to_json(self, path: Optional[str] = None, indent: int = 2) -> str:
        report = self._build_report()
        text = json.dumps(report, indent=indent, default=str)
        if path:
            Path(path).write_text(text)
        return text

    # ── HTML ───────────────────────────────────────────────────

    def to_html(self, path: Optional[str] = None) -> str:
        report = self._build_report()
        html = self._render_html(report)
        if path:
            Path(path).write_text(html)
        return html

    # ── SARIF ──────────────────────────────────────────────────

    def to_sarif(self, path: Optional[str] = None) -> str:
        sarif = self._build_sarif()
        text = json.dumps(sarif, indent=2, default=str)
        if path:
            Path(path).write_text(text)
        return text

    # ── Internal ───────────────────────────────────────────────

    def _build_report(self) -> Dict[str, Any]:
        binary = self.result.get("binary_domain") or {}
        malware = self.result.get("malware_domain") or {}
        network = self.result.get("network_domain") or {}
        final = self.result.get("final_report") or {}

        return {
            "orca_version": "2.0.0-alpha",
            "timestamp": self.timestamp,
            "completed_steps": self.result.get("completed_steps", []),
            "file_info": (binary.get("static_analysis") or {}).get("file_info"),
            "binary_analysis": {
                "imports_count": len((binary.get("static_analysis") or {}).get("imports", [])),
                "functions_count": (binary.get("static_analysis") or {}).get("functions_total_count", 0),
                "backend_used": (binary.get("static_analysis") or {}).get("backend_used"),
                "capabilities": binary.get("capabilities"),
                "api_clusters": (binary.get("api_analysis") or {}).get("clusters"),
                "summary": binary.get("binary_summary"),
            },
            "malware_analysis": {
                "triage": malware.get("triage"),
                "iocs": malware.get("iocs"),
                "mitre": malware.get("mitre"),
                "assessment": malware.get("analysis"),
            },
            "network_analysis": {
                "connections": network.get("connections"),
                "handshake": network.get("handshake_analysis"),
                "traffic_patterns": network.get("traffic_patterns"),
                "anomalies": network.get("anomalies"),
            },
            "executive_summary": final.get("executive_summary", ""),
            "recommendations": final.get("recommendations", []),
            "threat_assessment": final.get("threat_assessment", ""),
        }

    def _render_html(self, report: Dict) -> str:
        """Render an HTML report using inline template (no Jinja2 dependency)."""
        fi = report.get("file_info") or {}
        ba = report.get("binary_analysis") or {}
        ma = report.get("malware_analysis") or {}
        na = report.get("network_analysis") or {}
        e = html_mod.escape

        def _json_block(obj):
            if not obj:
                return "<em>N/A</em>"
            return f"<pre>{e(json.dumps(obj, indent=2, default=str)[:3000])}</pre>"

        mitre = ma.get("mitre") or {}
        techniques = mitre.get("techniques", [])
        mitre_rows = ""
        for t in techniques[:15]:
            tid = t.get("technique_id", "")
            name = t.get("name", "")
            tactic = t.get("tactic", "")
            sev = t.get("severity", "")
            mitre_rows += f"<tr><td>{e(tid)}</td><td>{e(name)}</td><td>{e(tactic)}</td><td>{e(sev)}</td></tr>"

        triage = ma.get("triage") or {}
        assessment = ma.get("assessment") or {}
        iocs = ma.get("iocs") or []
        ioc_rows = ""
        for ioc in iocs[:20]:
            ioc_rows += f"<tr><td>{e(str(ioc.get('ioc_type','')))}</td><td>{e(str(ioc.get('value','')))}</td><td>{e(str(ioc.get('confidence','')))}</td></tr>"

        connections = na.get("connections") or []
        conn_rows = ""
        for c in connections[:10]:
            conn_rows += f"<tr><td>{e(str(c.get('src_ip','')))}</td><td>{c.get('src_port','')}</td><td>{e(str(c.get('dst_ip','')))}</td><td>{c.get('dst_port','')}</td><td>{c.get('packets','')}</td></tr>"

        recs = report.get("recommendations", [])
        rec_html = "".join(f"<li>{e(str(r))}</li>" for r in recs[:10])

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>ORCA Analysis Report</title>
<style>
body{{font-family:'Segoe UI',Tahoma,sans-serif;margin:40px;background:#0d1117;color:#c9d1d9}}
h1{{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:10px}}
h2{{color:#79c0ff;margin-top:30px}} h3{{color:#d2a8ff}}
table{{border-collapse:collapse;width:100%;margin:10px 0}}
th,td{{border:1px solid #30363d;padding:8px;text-align:left}}
th{{background:#161b22;color:#58a6ff}}
tr:nth-child(even){{background:#161b22}}
pre{{background:#161b22;padding:12px;border-radius:6px;overflow-x:auto;font-size:13px}}
.badge{{display:inline-block;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold}}
.critical{{background:#f85149;color:#fff}} .high{{background:#d29922;color:#000}}
.medium{{background:#58a6ff;color:#000}} .low{{background:#3fb950;color:#000}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:10px 0}}
</style></head><body>
<h1>🐋 ORCA Analysis Report</h1>
<p><strong>Generated:</strong> {self.timestamp} &nbsp;|&nbsp; <strong>Steps:</strong> {', '.join(report.get('completed_steps',[]))}</p>

<h2>📄 File Information</h2>
<div class="card">
<table><tr><th>Name</th><td>{e(str(fi.get('name','')))}</td><th>Size</th><td>{fi.get('size',0):,} bytes</td></tr>
<tr><th>SHA-256</th><td colspan="3"><code>{e(str(fi.get('sha256','')))}</code></td></tr>
<tr><th>Format</th><td>{e(str(fi.get('binary_format','')))}</td><th>Arch</th><td>{e(str(fi.get('architecture','')))}</td></tr>
<tr><th>Stripped</th><td>{fi.get('is_stripped','')}</td><th>Packed</th><td>{fi.get('is_packed','')}</td></tr></table></div>

<h2>🔬 Binary Analysis</h2>
<div class="card"><p><strong>Backend:</strong> {e(str(ba.get('backend_used','')))} &nbsp;|&nbsp;
<strong>Functions:</strong> {ba.get('functions_count',0)} &nbsp;|&nbsp;
<strong>Imports:</strong> {ba.get('imports_count',0)}</p>
<h3>Capabilities</h3>{_json_block(ba.get('capabilities'))}
<h3>Summary</h3><p>{e(str(ba.get('summary','')))[:1000]}</p></div>

<h2>🦠 Malware Analysis</h2>
<div class="card">
<h3>Triage</h3>
<table><tr><th>Entropy</th><td>{triage.get('entropy_score','')}</td><th>Packed</th><td>{triage.get('is_packed','')}</td><th>Verdict</th><td><span class="badge {e(str(triage.get('quick_verdict',''))).lower()}">{e(str(triage.get('quick_verdict','')))}</span></td></tr></table>
<h3>Classification</h3>
<p><strong>Classification:</strong> {e(str(assessment.get('classification','')))} &nbsp;|&nbsp;
<strong>Threat Level:</strong> <span class="badge {e(str(assessment.get('threat_level',''))).lower()}">{e(str(assessment.get('threat_level','')))}</span> &nbsp;|&nbsp;
<strong>Confidence:</strong> {assessment.get('confidence','')}%</p>
<h3>IOCs ({len(iocs)})</h3>
<table><tr><th>Type</th><th>Value</th><th>Confidence</th></tr>{ioc_rows}</table>
<h3>MITRE ATT&CK ({len(techniques)} techniques)</h3>
<table><tr><th>ID</th><th>Name</th><th>Tactic</th><th>Severity</th></tr>{mitre_rows}</table></div>

<h2>🌐 Network Analysis</h2>
<div class="card">
<h3>Connections ({len(connections)})</h3>
<table><tr><th>Src IP</th><th>Src Port</th><th>Dst IP</th><th>Dst Port</th><th>Packets</th></tr>{conn_rows}</table>
<h3>Traffic Patterns</h3>{_json_block(na.get('traffic_patterns'))}
<h3>Anomalies</h3>{_json_block(na.get('anomalies'))}</div>

<h2>📋 Executive Summary</h2>
<div class="card"><p>{e(str(report.get('executive_summary','')))[:2000]}</p></div>

<h2>💡 Recommendations</h2>
<div class="card"><ol>{rec_html}</ol></div>

<footer style="margin-top:40px;padding-top:10px;border-top:1px solid #30363d;color:#8b949e;font-size:12px">
ORCA v2.0-alpha | Multi-Agentic Security Analysis Platform</footer>
</body></html>"""

    def _build_sarif(self) -> Dict:
        """Build SARIF 2.1.0 output for CI/CD integration."""
        ma = (self.result.get("malware_domain") or {})
        mitre = ma.get("mitre") or {}
        techniques = mitre.get("techniques", [])
        iocs = ma.get("iocs") or []
        na = (self.result.get("network_domain") or {})
        anomalies = (na.get("anomalies") or {}).get("anomalies", [])

        results = []
        for t in techniques:
            results.append({
                "ruleId": t.get("technique_id", "unknown"),
                "level": self._sarif_level(t.get("severity", "medium")),
                "message": {"text": f"MITRE ATT&CK: {t.get('name','')} ({t.get('tactic','')})"},
                "properties": {"confidence": t.get("confidence", 0), "supporting_apis": t.get("supporting_apis", [])},
            })
        for ioc in iocs:
            results.append({
                "ruleId": f"ioc-{ioc.get('ioc_type','unknown')}",
                "level": "warning",
                "message": {"text": f"IOC: {ioc.get('value','')} ({ioc.get('ioc_type','')})"},
                "properties": {"confidence": ioc.get("confidence", 0)},
            })
        for a in anomalies:
            results.append({
                "ruleId": f"anomaly-{a.get('anomaly_type','unknown')}",
                "level": self._sarif_level(a.get("severity", "medium")),
                "message": {"text": a.get("description", "")},
                "properties": {"rfc_reference": a.get("rfc_reference")},
            })

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "ORCA", "version": "2.0.0-alpha",
                                     "informationUri": "https://github.com/maialsh/OgBinsleuth"}},
                "results": results,
            }],
        }

    @staticmethod
    def _sarif_level(severity: str) -> str:
        return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(severity.lower(), "warning")

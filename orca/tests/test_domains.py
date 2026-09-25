"""Tests for ORCA domain-specific components."""
import json
import pytest


# ── YARA Scanner ───────────────────────────────────────────────

class TestYaraScanner:
    def test_scanner_init(self):
        from orca.domains.malware.yara_scanner import YaraScanner
        scanner = YaraScanner()
        # Either yara is installed or not — both are valid
        assert isinstance(scanner.available, bool)

    def test_scanner_builtin_rules(self):
        from orca.domains.malware.yara_scanner import BUILTIN_RULES_SOURCE
        assert "upx_packed" in BUILTIN_RULES_SOURCE
        assert "anti_debug_techniques" in BUILTIN_RULES_SOURCE
        assert "shellcode_patterns" in BUILTIN_RULES_SOURCE


# ── JA4 Fingerprinter ─────────────────────────────────────────

class TestJA4:
    def test_compute_ja4(self):
        from orca.domains.network.ja4_fingerprinter import JA4Fingerprinter
        fp = JA4Fingerprinter()
        ch = {
            "tls_version": "1.3",
            "cipher_suites": [0x1301, 0x1302, 0x1303],
            "extensions": [0, 10, 11, 13, 43, 51],
            "signature_algorithms": [0x0403, 0x0503],
            "protocol": "tcp",
            "sni": "example.com",
            "alpn": ["h2"],
        }
        ja4 = fp.compute_ja4(ch)
        assert ja4 is not None
        assert ja4.startswith("t13d")
        assert "_" in ja4
        parts = ja4.split("_")
        assert len(parts) == 3

    def test_quic_prefix(self):
        from orca.domains.network.ja4_fingerprinter import JA4Fingerprinter
        fp = JA4Fingerprinter()
        ch = {
            "tls_version": "1.3",
            "cipher_suites": [0x1301],
            "extensions": [0, 43],
            "signature_algorithms": [],
            "protocol": "quic",
            "sni": "example.com",
            "alpn": ["h3"],
        }
        ja4 = fp.compute_ja4(ch)
        assert ja4.startswith("q13d")

    def test_identify_unknown(self):
        from orca.domains.network.ja4_fingerprinter import JA4Fingerprinter
        fp = JA4Fingerprinter()
        assert fp.identify_client("x_y_z") == "unknown"

    def test_grease_filter(self):
        from orca.domains.network.ja4_fingerprinter import JA4Fingerprinter
        assert JA4Fingerprinter._is_grease(0x0A0A)
        assert JA4Fingerprinter._is_grease(0x1A1A)
        assert not JA4Fingerprinter._is_grease(0x0301)


# ── QLOG Parser ────────────────────────────────────────────────

class TestQlogParser:
    def test_parse_json(self, tmp_path):
        from orca.domains.network.qlog_parser import QlogParser
        qlog = {
            "traces": [{
                "common_fields": {"group_id": "test"},
                "vantage_point": {"type": "client"},
                "events": [
                    [0, "transport", "packet_sent", {"header": {"packet_type": "initial"}}],
                    [10, "transport", "packet_received", {"header": {"packet_type": "initial"}}],
                    [50, "transport", "packet_sent", {}],
                    [100, "connectivity", "handshake_done_received", {}],
                    [200, "transport", "packet_lost", {}],
                ],
            }],
        }
        p = tmp_path / "test.qlog"
        p.write_text(json.dumps(qlog))
        parser = QlogParser(str(p))

        assert len(parser.events) == 5
        summary = parser.get_event_summary()
        assert "transport:packet_sent" in summary

        loss = parser.get_packet_loss_stats()
        assert loss["packets_lost"] == 1
        assert loss["packets_sent"] == 2

        hs = parser.get_handshake_duration()
        assert hs == 100  # 100 - 0

    def test_anomaly_detection(self, tmp_path):
        from orca.domains.network.qlog_parser import QlogParser
        events = [[i, "transport", "packet_sent", {}] for i in range(100)]
        events += [[i, "transport", "packet_lost", {}] for i in range(20)]
        qlog = {"traces": [{"common_fields": {}, "events": events}]}
        p = tmp_path / "lossy.qlog"
        p.write_text(json.dumps(qlog))
        parser = QlogParser(str(p))
        anomalies = parser.detect_anomalies()
        assert any(a["type"] == "high_packet_loss" for a in anomalies)


# ── Correlation Engine ─────────────────────────────────────────

class TestCorrelation:
    def test_quic_library_detection(self):
        from orca.correlation.engine import QUIC_LIBRARY_SIGNATURES
        assert "quiche" in QUIC_LIBRARY_SIGNATURES
        assert "msquic" in QUIC_LIBRARY_SIGNATURES
        assert len(QUIC_LIBRARY_SIGNATURES) >= 8

    def test_c2_api_patterns(self):
        from orca.correlation.engine import C2_API_PATTERNS
        assert "socket_creation" in C2_API_PATTERNS
        assert "connect" in C2_API_PATTERNS["connection"]


# ── Hash Lookup ────────────────────────────────────────────────

class TestHashLookup:
    def test_merge_verdicts_malicious(self):
        from orca.domains.malware.hash_lookup import HashLookup
        hl = HashLookup(vt_api_key="", bazaar_enabled=False)
        results = {
            "virustotal": {"malicious_count": 25, "popular_threat_name": "trojan.generic"},
        }
        verdict = hl._merge_verdicts(results)
        assert verdict["classification"] == "malicious"
        assert verdict["confidence"] > 50

    def test_merge_verdicts_clean(self):
        from orca.domains.malware.hash_lookup import HashLookup
        hl = HashLookup(vt_api_key="", bazaar_enabled=False)
        results = {"virustotal": {"malicious_count": 0}}
        verdict = hl._merge_verdicts(results)
        assert verdict["classification"] == "unknown"


# ── HITL Manager ───────────────────────────────────────────────

class TestHITL:
    def test_should_not_interrupt_empty(self):
        from orca.core.hitl import HITLManager
        hitl = HITLManager()
        assert not hitl.should_interrupt({"completed_steps": []})

    def test_should_interrupt_after_assessment(self):
        from orca.core.hitl import HITLManager
        hitl = HITLManager(interrupt_after={"malware_assessment"})
        state = {"completed_steps": ["static_analysis", "malware_assessment"]}
        assert hitl.should_interrupt(state)

    def test_auto_approve_low_risk(self):
        from orca.core.hitl import HITLManager
        hitl = HITLManager(
            interrupt_after={"malware_assessment"},
            auto_approve_low_risk=True,
            risk_threshold=50,
        )
        state = {
            "completed_steps": ["malware_assessment"],
            "malware_domain": {"mitre": {"threat_score": 20}},
        }
        assert not hitl.should_interrupt(state)

    def test_submit_review(self):
        from orca.core.hitl import HITLManager
        hitl = HITLManager()
        state = {
            "_hitl_waiting": True,
            "malware_domain": {"analysis": {"classification": "unknown"}},
            "messages": [],
        }
        state = hitl.submit_review(
            state, approved=True,
            override_classification="trojan",
            notes="Confirmed by analyst",
        )
        assert not state["_hitl_waiting"]
        assert state["malware_domain"]["analysis"]["classification"] == "trojan"
        assert state["malware_domain"]["analysis"]["analyst_override"] is True


# ── Reporting Engine ───────────────────────────────────────────

class TestReporting:
    def test_json_report(self):
        from orca.core.reporting.engine import ReportEngine
        engine = ReportEngine({"completed_steps": ["static_analysis"], "binary_domain": {}})
        text = engine.to_json()
        data = json.loads(text)
        assert "orca_version" in data
        assert "timestamp" in data

    def test_html_report(self):
        from orca.core.reporting.engine import ReportEngine
        engine = ReportEngine({"completed_steps": ["triage"], "malware_domain": {"triage": {"entropy_score": 5.5}}})
        html = engine.to_html()
        assert "<!DOCTYPE html>" in html
        assert "ORCA Analysis Report" in html

    def test_sarif_report(self):
        from orca.core.reporting.engine import ReportEngine
        engine = ReportEngine({
            "malware_domain": {
                "mitre": {"techniques": [{"technique_id": "T1055", "name": "Process Injection", "severity": "high"}]},
                "iocs": [{"ioc_type": "ip", "value": "1.2.3.4", "confidence": 0.9}],
            },
        })
        text = engine.to_sarif()
        data = json.loads(text)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) >= 2

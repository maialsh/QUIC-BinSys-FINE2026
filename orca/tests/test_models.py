"""Tests for ORCA Pydantic models."""
import json
import pytest
from pathlib import Path


def test_file_info_creation():
    from orca.core.models import FileInfo, BinaryFormat, Architecture
    fi = FileInfo(path="/tmp/test", name="test", size=1024, sha256="abc123")
    assert fi.name == "test"
    assert fi.size == 1024
    assert fi.binary_format == BinaryFormat.UNKNOWN


def test_file_info_serialization():
    from orca.core.models import FileInfo
    fi = FileInfo(path="/tmp/test", name="test", size=512)
    data = fi.model_dump()
    assert data["path"] == "/tmp/test"
    assert json.loads(fi.model_dump_json())["name"] == "test"


def test_function_info_with_behaviors():
    from orca.core.models import FunctionInfo, BehaviorIndicator
    bi = BehaviorIndicator(category="network", evidence="calls connect()", confidence=0.8)
    fi = FunctionInfo(name="main", address="0x1000", behaviors=[bi])
    assert len(fi.behaviors) == 1
    assert fi.behaviors[0].confidence == 0.8


def test_quic_connection_info():
    from orca.core.models import QUICConnectionInfo
    conn = QUICConnectionInfo(
        connection_id="abc",
        src_ip="10.0.0.1", src_port=12345,
        dst_ip="8.8.8.8", dst_port=443,
        quic_version="1",
    )
    assert conn.dst_port == 443


def test_mitre_technique():
    from orca.core.models import MitreTechnique
    t = MitreTechnique(technique_id="T1055", name="Process Injection", tactic="defense-evasion")
    assert t.technique_id == "T1055"


def test_orca_report():
    from orca.core.models import OrcaReport, AnalysisGoal
    report = OrcaReport(goal=AnalysisGoal.MALWARE)
    data = report.model_dump()
    assert data["goal"] == "malware"
    assert "timestamp" in data


def test_network_analysis_result():
    from orca.core.models import NetworkAnalysisResult, TrafficPattern
    tp = TrafficPattern(pattern_type="beaconing", confidence=0.85, description="Regular intervals")
    result = NetworkAnalysisResult(traffic_patterns=[tp])
    assert result.traffic_patterns[0].pattern_type == "beaconing"


def test_enums():
    from orca.core.models import ThreatLevel, REBackendType, RepresentationType
    assert ThreatLevel.CRITICAL.value == "critical"
    assert REBackendType.BOTH.value == "both"
    assert RepresentationType.HLIL.value == "hlil"

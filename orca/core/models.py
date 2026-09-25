"""
ORCA Core Data Models

Pydantic v2 models used across all domains. These replace the ad-hoc dicts
that were threaded through the old BinSleuth workflow and give us:
  - validation at every agent boundary
  - clean JSON serialization for reports and caching
  - IDE autocompletion / type-safety everywhere
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field, field_validator


# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────
class BinaryFormat(str, Enum):
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    WASM = "wasm"
    RAW = "raw"
    UNKNOWN = "unknown"


class Architecture(str, Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    PPC = "ppc"
    RISCV = "riscv"
    UNKNOWN = "unknown"


class REBackendType(str, Enum):
    BINARY_NINJA = "binja"
    GHIDRA = "ghidra"
    BOTH = "both"


class RepresentationType(str, Enum):
    """Code representation types for LLM consumption."""
    ASSEMBLY = "assembly"
    HLIL = "hlil"           # Binary Ninja High-Level IL
    MLIL = "mlil"           # Binary Ninja Medium-Level IL
    PCODE = "pcode"         # Ghidra P-Code
    DECOMPILED = "decompiled"
    SUMMARY = "summary"


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"
    UNKNOWN = "unknown"


class AnalysisGoal(str, Enum):
    CAPABILITIES = "capabilities"
    MALWARE = "malware"
    TRIAGE = "triage"
    COMPREHENSIVE = "comprehensive"
    NETWORK = "network"


# ─────────────────────────────────────────────
# Binary Analysis Models
# ─────────────────────────────────────────────
class FileInfo(BaseModel):
    """Core metadata about the file under analysis."""
    path: str
    name: str
    size: int
    sha256: str = ""
    md5: str = ""
    file_type: str = ""
    binary_format: BinaryFormat = BinaryFormat.UNKNOWN
    architecture: Architecture = Architecture.UNKNOWN
    is_executable: bool = False
    is_stripped: bool = False
    has_cpp_symbols: bool = False
    is_packed: bool = False
    permissions: str = ""
    created: Optional[str] = None
    modified: Optional[str] = None

    @classmethod
    def from_path(cls, path: Path) -> "FileInfo":
        """Create FileInfo by reading a file from disk (hashes computed lazily)."""
        import os
        data = path.read_bytes()
        return cls(
            path=str(path),
            name=path.name,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            md5=hashlib.md5(data).hexdigest(),
            is_executable=os.access(path, os.X_OK),
            permissions=oct(os.stat(path).st_mode)[-3:],
        )


class SectionInfo(BaseModel):
    """Information about a binary section / memory segment."""
    name: str
    start: str = ""
    end: str = ""
    size: int = 0
    entropy: Optional[float] = None
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = True
    section_type: str = ""


class ParameterInfo(BaseModel):
    """Function parameter descriptor."""
    name: str
    data_type: str = "unknown"
    index: int = 0


class FunctionInfo(BaseModel):
    """Enriched function descriptor produced by RE backends."""
    name: str
    address: str = "0x0"
    size: int = 0
    callers: List[str] = Field(default_factory=list)
    callees: List[str] = Field(default_factory=list)
    parameters: List[ParameterInfo] = Field(default_factory=list)
    is_library: bool = False
    is_thunk: bool = False
    decompiled_code: Optional[str] = None
    assembly: Optional[str] = None
    hlil: Optional[str] = None
    mlil: Optional[str] = None
    pcode: Optional[str] = None
    behaviors: List[BehaviorIndicator] = Field(default_factory=list)
    interest_score: int = 0
    interest_rank: int = 0
    backend_used: Optional[REBackendType] = None

    class Config:
        arbitrary_types_allowed = True


class BehaviorIndicator(BaseModel):
    """A single behavioral observation about a function."""
    category: str  # e.g. "network", "anti_analysis", "persistence"
    evidence: str  # human-readable description
    function_call: Optional[str] = None
    confidence: float = 0.5  # 0..1


class ImportInfo(BaseModel):
    name: str
    library: Optional[str] = None
    ordinal: Optional[int] = None


class ExportInfo(BaseModel):
    name: str
    address: Optional[str] = None


class StringCategory(BaseModel):
    """Categorised strings extracted from a binary."""
    apis: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    ip_addresses: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    file_paths: List[str] = Field(default_factory=list)
    commands: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    registry_keys: List[str] = Field(default_factory=list)
    suspicious: List[str] = Field(default_factory=list)
    user_agents: List[str] = Field(default_factory=list)


class StaticAnalysisResult(BaseModel):
    """Output of the static analysis agent."""
    file_info: FileInfo
    strings: StringCategory = Field(default_factory=StringCategory)
    imports: List[str] = Field(default_factory=list)
    exports: List[str] = Field(default_factory=list)
    sections: List[SectionInfo] = Field(default_factory=list)
    functions: List[FunctionInfo] = Field(default_factory=list)
    functions_total_count: int = 0
    elf_info: Dict[str, Any] = Field(default_factory=dict)
    backend_used: Optional[REBackendType] = None
    error: Optional[str] = None


# ─────────────────────────────────────────────
# API Analysis Models
# ─────────────────────────────────────────────
class APICluster(BaseModel):
    """A logical grouping of APIs by behaviour."""
    name: str
    description: str = ""
    apis: List[str] = Field(default_factory=list)
    libraries: List[str] = Field(default_factory=list)
    security_assessment: str = "safe"
    potential_usage: str = ""


class APICrossRef(BaseModel):
    """Cross-reference mapping: which functions call which APIs."""
    api_name: str
    calling_functions: List[str] = Field(default_factory=list)
    call_count: int = 0
    assembly_context: Optional[str] = None


class APIAnalysisResult(BaseModel):
    referenced_apis: List[str] = Field(default_factory=list)
    filtered_functions: List[str] = Field(default_factory=list)
    clusters: List[APICluster] = Field(default_factory=list)
    cross_refs: List[APICrossRef] = Field(default_factory=list)
    api_relevance: Dict[str, float] = Field(default_factory=dict)
    error: Optional[str] = None


# ─────────────────────────────────────────────
# Malware Analysis Models
# ─────────────────────────────────────────────
class IOC(BaseModel):
    """Indicator of Compromise."""
    ioc_type: str  # ip, domain, url, hash, mutex, filepath, registry
    value: str
    context: str = ""
    confidence: float = 0.5


class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str = ""
    confidence: int = 0
    severity: str = "medium"
    evidence_count: int = 0
    supporting_apis: List[str] = Field(default_factory=list)
    description: str = ""


class MitreMapping(BaseModel):
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    threat_score: int = 0
    techniques: List[MitreTechnique] = Field(default_factory=list)
    attack_chain: List[Dict[str, str]] = Field(default_factory=list)
    summary: str = ""


class TriageResult(BaseModel):
    """Quick triage output before deep analysis."""
    file_type: str = ""
    packer_detected: Optional[str] = None
    is_packed: bool = False
    entropy_score: float = 0.0
    imphash: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    yara_matches: List[str] = Field(default_factory=list)
    quick_verdict: str = "unknown"  # clean, suspicious, malicious, unknown


class SimilarityMatch(BaseModel):
    """Result of fuzzy-hash / family clustering."""
    family_name: str = ""
    match_type: str = ""  # ssdeep, tlsh, imphash
    similarity_score: float = 0.0
    reference_hash: str = ""


class MalwareAnalysisResult(BaseModel):
    triage: Optional[TriageResult] = None
    classification: str = "unknown"
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: int = 0
    malicious_indicators: List[str] = Field(default_factory=list)
    suspicious_behaviors: List[str] = Field(default_factory=list)
    iocs: List[IOC] = Field(default_factory=list)
    mitre: Optional[MitreMapping] = None
    similarity_matches: List[SimilarityMatch] = Field(default_factory=list)
    functionality_validation: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


# ─────────────────────────────────────────────
# Network / QUIC Protocol Models
# ─────────────────────────────────────────────
class QUICConnectionInfo(BaseModel):
    """Metadata for a single QUIC connection."""
    connection_id: str = ""
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    quic_version: str = ""
    sni: Optional[str] = None
    alpn: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_ms: Optional[float] = None
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0


class TLSFingerprint(BaseModel):
    """JA4 / JA4+ fingerprint for a TLS/QUIC handshake."""
    ja4: Optional[str] = None
    ja4h: Optional[str] = None
    ja4s: Optional[str] = None
    cipher_suites: List[str] = Field(default_factory=list)
    extensions: List[str] = Field(default_factory=list)
    supported_versions: List[str] = Field(default_factory=list)
    known_client: Optional[str] = None  # e.g. "Chrome 120", "curl", "unknown"


class QUICTransportParams(BaseModel):
    """QUIC transport parameters from handshake."""
    max_idle_timeout: Optional[int] = None
    max_udp_payload_size: Optional[int] = None
    initial_max_data: Optional[int] = None
    initial_max_stream_data_bidi_local: Optional[int] = None
    initial_max_stream_data_bidi_remote: Optional[int] = None
    initial_max_stream_data_uni: Optional[int] = None
    initial_max_streams_bidi: Optional[int] = None
    initial_max_streams_uni: Optional[int] = None
    disable_active_migration: bool = False
    active_connection_id_limit: Optional[int] = None
    raw_params: Dict[str, Any] = Field(default_factory=dict)


class TrafficPattern(BaseModel):
    """Behavioural pattern extracted from encrypted traffic."""
    pattern_type: str  # beaconing, bulk_transfer, interactive, tunneling
    confidence: float = 0.0
    description: str = ""
    packet_size_distribution: Optional[Dict[str, float]] = None
    timing_characteristics: Optional[Dict[str, float]] = None


class ProtocolAnomaly(BaseModel):
    """Deviation from RFC or expected behaviour."""
    anomaly_type: str
    description: str
    severity: str = "medium"  # low, medium, high, critical
    rfc_reference: Optional[str] = None


class NetworkAnalysisResult(BaseModel):
    pcap_path: Optional[str] = None
    qlog_path: Optional[str] = None
    connections: List[QUICConnectionInfo] = Field(default_factory=list)
    fingerprints: List[TLSFingerprint] = Field(default_factory=list)
    transport_params: List[QUICTransportParams] = Field(default_factory=list)
    traffic_patterns: List[TrafficPattern] = Field(default_factory=list)
    anomalies: List[ProtocolAnomaly] = Field(default_factory=list)
    error: Optional[str] = None


# ─────────────────────────────────────────────
# Cross-Domain Correlation
# ─────────────────────────────────────────────
class CrossDomainCorrelation(BaseModel):
    """Findings that span binary ↔ network analysis."""
    binary_network_links: List[Dict[str, Any]] = Field(default_factory=list)
    quic_library_detected: Optional[str] = None  # quiche, ngtcp2, msquic
    c2_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    unified_threat_score: int = 0
    summary: str = ""


# ─────────────────────────────────────────────
# Composable Workflow State
# ─────────────────────────────────────────────
class BinaryDomainState(BaseModel):
    """State for the binary analysis domain sub-graph."""
    static_analysis: Optional[StaticAnalysisResult] = None
    api_analysis: Optional[APIAnalysisResult] = None
    capabilities: Dict[str, Any] = Field(default_factory=dict)
    binary_summary: str = ""


class MalwareDomainState(BaseModel):
    """State for the malware analysis domain sub-graph."""
    triage: Optional[TriageResult] = None
    analysis: Optional[MalwareAnalysisResult] = None
    mitre: Optional[MitreMapping] = None


class NetworkDomainState(BaseModel):
    """State for the network protocol analysis domain sub-graph."""
    analysis: Optional[NetworkAnalysisResult] = None


class OrcaReport(BaseModel):
    """Final consolidated report from ORCA."""
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    version: str = "2.0.0-alpha"
    goal: AnalysisGoal = AnalysisGoal.COMPREHENSIVE
    file_info: Optional[FileInfo] = None
    binary: Optional[BinaryDomainState] = None
    malware: Optional[MalwareDomainState] = None
    network: Optional[NetworkDomainState] = None
    correlation: Optional[CrossDomainCorrelation] = None
    executive_summary: str = ""
    recommendations: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


# Fix forward reference — FunctionInfo.behaviors uses BehaviorIndicator
FunctionInfo.model_rebuild()

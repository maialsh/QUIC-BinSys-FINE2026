"""
ORCA Cross-Domain Correlation Engine

Links findings across binary ↔ malware ↔ network domains to surface:
  - C2 indicators (binary network APIs + PCAP connections)
  - QUIC library detection (binary imports matched to known libraries)
  - IOC ↔ network traffic correlation
  - Unified threat scoring
"""
from __future__ import annotations
import json
from typing import Any, Dict, List
from orca.core.llm.provider import LLMProvider

llm = LLMProvider()

# Known QUIC library signatures (import patterns)
QUIC_LIBRARY_SIGNATURES = {
    "quiche": ["quiche_connect", "quiche_accept", "quiche_conn_recv", "quiche_h3_conn_new"],
    "ngtcp2": ["ngtcp2_conn_client_new", "ngtcp2_conn_read_pkt", "ngtcp2_crypto_"],
    "msquic": ["MsQuicOpen", "QuicAddr", "QUIC_API_TABLE", "MsQuicConnection"],
    "lsquic": ["lsquic_engine_new", "lsquic_conn_make_stream", "lsquic_stream_write"],
    "picoquic": ["picoquic_create", "picoquic_incoming_packet", "picoquic_start_client"],
    "quinn": ["quinn::", "quinn_proto", "quinn_udp"],
    "aioquic": ["aioquic", "QuicConnection", "H3Connection"],
    "s2n-quic": ["s2n_quic", "s2n_quic_provider"],
    "chromium_quic": ["quic::Quic", "QuicSession", "QuicStream", "QuicConnection"],
    "nginx_quic": ["ngx_quic", "ngx_http_v3", "ngx_quic_connection", "ngx_quic_stream"],
}

# Network-related API patterns for C2 detection
C2_API_PATTERNS = {
    "socket_creation": ["socket", "WSASocket", "socketpair"],
    "connection": ["connect", "WSAConnect", "ConnectEx"],
    "dns_resolution": ["getaddrinfo", "gethostbyname", "DnsQuery", "res_query"],
    "http_client": ["curl_easy_perform", "WinHttpSendRequest", "HttpSendRequest", "URLDownloadToFile"],
    "ssl_tls": ["SSL_connect", "SSL_read", "SSL_write", "SSL_CTX_new"],
    "data_exfil": ["send", "sendto", "WSASend", "TransmitFile", "WriteFile"],
}


def correlate(state: Dict[str, Any]) -> Dict[str, Any]:
    """Run cross-domain correlation on analysis state."""
    bd = state.get("binary_domain") or {}
    md = state.get("malware_domain") or {}
    nd = state.get("network_domain") or {}

    result: Dict[str, Any] = {
        "binary_network_links": [],
        "quic_library_detected": None,
        "c2_indicators": [],
        "unified_threat_score": 0,
        "summary": "",
    }

    # 1. Detect QUIC library from binary imports
    sa = bd.get("static_analysis") or {}
    imports = [i.lower() for i in sa.get("imports", [])]
    strings = sa.get("strings", {})
    raw_strings = strings.get("raw", []) if isinstance(strings, dict) else []

    for lib_name, signatures in QUIC_LIBRARY_SIGNATURES.items():
        matches = [s for s in signatures if any(s.lower() in imp for imp in imports)]
        if not matches:
            matches = [s for s in signatures if any(s.lower() in st.lower() for st in raw_strings[:200])]
        if matches:
            result["quic_library_detected"] = lib_name
            result["binary_network_links"].append({
                "type": "quic_library",
                "library": lib_name,
                "evidence": matches,
                "significance": "Binary uses QUIC protocol library",
            })
            break

    # 2. Correlate binary network APIs with PCAP connections
    network_apis = []
    for category, apis in C2_API_PATTERNS.items():
        found = [a for a in apis if any(a.lower() in imp for imp in imports)]
        if found:
            network_apis.extend(found)
            result["binary_network_links"].append({
                "type": "network_api",
                "category": category,
                "apis": found,
            })

    # 3. IOC ↔ Network correlation
    iocs = md.get("iocs") or []
    connections = nd.get("connections") or []
    for ioc in iocs:
        if ioc.get("ioc_type") in ("ip", "domain"):
            val = ioc.get("value", "")
            for conn in connections:
                if val in str(conn.get("dst_ip", "")) or val in str(conn.get("src_ip", "")):
                    result["c2_indicators"].append({
                        "ioc": val,
                        "connection": conn,
                        "correlation": "IOC found in network traffic",
                        "confidence": 0.9,
                    })

    # 4. Unified threat score
    mitre = md.get("mitre") or {}
    malware_score = mitre.get("threat_score", 0)
    anomaly_count = len((nd.get("anomalies") or {}).get("anomalies", []))
    c2_count = len(result["c2_indicators"])

    score = malware_score
    if c2_count > 0:
        score = min(100, score + 20 * c2_count)
    if anomaly_count > 0:
        score = min(100, score + 5 * anomaly_count)
    if result["quic_library_detected"]:
        score = min(100, score + 5)
    result["unified_threat_score"] = score

    # 5. LLM summary if there's meaningful data
    if result["binary_network_links"] or result["c2_indicators"]:
        try:
            summary = llm.query(
                system="You are a threat intelligence analyst.",
                user=f"Summarise these cross-domain correlations in 2-3 sentences:\n{json.dumps(result, default=str)[:2000]}",
            )
            result["summary"] = summary
        except Exception:
            result["summary"] = f"Found {len(result['binary_network_links'])} binary-network links, {c2_count} C2 indicators. Threat score: {score}/100."

    return result

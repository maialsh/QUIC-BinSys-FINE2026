"""
Network Protocol Domain Sub-Graph (QUIC Focus)

LangGraph sub-graph for network protocol analysis:
  1. pcap_ingest           — parse PCAP, extract UDP flows, compute traffic statistics
  2. traffic_statistics     — compute per-connection and aggregate statistics (no LLM)
  3. quic_handshake        — analyse handshake patterns, JA4 fingerprinting
  4. attack_classification — classify traffic as specific QUIC attack type
  5. anomaly_detect        — flag RFC non-conformance and protocol violations
"""
from __future__ import annotations
import json
from typing import Any, Dict, List
from langgraph.graph import StateGraph, END
from langchain_core.messages import AIMessage

from orca.core.state import OrcaWorkflowState
from orca.core.llm.provider import LLMProvider

llm = LLMProvider()


def _step(state, nd, step_name, msg):
    return {
        "network_domain": nd,
        "current_step": (state.get("current_step") or 0) + 1,
        "completed_steps": (state.get("completed_steps") or []) + [step_name],
        "messages": [AIMessage(content=msg)],
    }


# ── Agent: PCAP Ingestion ─────────────────────────────────────

def pcap_ingest_agent(state: OrcaWorkflowState) -> Dict:
    """Parse PCAP with scapy, extract UDP flows, compute per-flow packet counts."""
    nd = state.get("network_domain") or {}
    pcap_path = state.get("pcap_path")

    if not pcap_path:
        return _step(state, nd, "pcap_ingest", "PCAP ingestion skipped — no pcap_path provided.")

    try:
        from scapy.all import rdpcap, UDP
        packets = rdpcap(pcap_path)
        udp_packets = [p for p in packets if p.haslayer(UDP)]

        # Extract all UDP flows
        flows = {}
        for pkt in udp_packets:
            udp = pkt[UDP]
            src_ip = pkt.src if hasattr(pkt, 'src') else ''
            dst_ip = pkt.dst if hasattr(pkt, 'dst') else ''
            flow_key = (src_ip, udp.sport, dst_ip, udp.dport)
            reverse_key = (dst_ip, udp.dport, src_ip, udp.sport)

            if flow_key not in flows and reverse_key not in flows:
                flows[flow_key] = {
                    "src_ip": src_ip, "src_port": udp.sport,
                    "dst_ip": dst_ip, "dst_port": udp.dport,
                    "packets_sent": 0, "packets_received": 0,
                    "bytes_sent": 0, "bytes_received": 0,
                    "first_seen": float(pkt.time), "last_seen": float(pkt.time),
                }

            if flow_key in flows:
                flows[flow_key]["packets_sent"] += 1
                flows[flow_key]["bytes_sent"] += len(pkt)
                flows[flow_key]["last_seen"] = max(flows[flow_key]["last_seen"], float(pkt.time))
            elif reverse_key in flows:
                flows[reverse_key]["packets_received"] += 1
                flows[reverse_key]["bytes_received"] += len(pkt)
                flows[reverse_key]["last_seen"] = max(flows[reverse_key]["last_seen"], float(pkt.time))

        # Filter to QUIC-relevant flows
        connections = []
        for flow_key, flow in flows.items():
            quic_ports = (443, 4433, 4434, 4435, 4436, 4437, 4438, 4567, 8443)
            is_quic = flow["dst_port"] in quic_ports or flow["src_port"] in quic_ports
            if is_quic or len(flows) < 500:
                flow["total_packets"] = flow["packets_sent"] + flow["packets_received"]
                flow["duration"] = round(flow["last_seen"] - flow["first_seen"], 4)
                flow["bidirectional"] = flow["packets_received"] > 0
                connections.append(flow)

        # Compute capture duration
        if udp_packets:
            capture_start = float(udp_packets[0].time)
            capture_end = float(udp_packets[-1].time)
            capture_duration = round(capture_end - capture_start, 2)
        else:
            capture_duration = 0

        nd["pcap_path"] = pcap_path
        nd["connections"] = connections
        nd["total_packets"] = len(packets)
        nd["udp_packets"] = len(udp_packets)
        nd["capture_duration_seconds"] = capture_duration

        return _step(state, nd, "pcap_ingest",
                     f"PCAP ingested — {len(connections)} flows, {len(udp_packets)} UDP packets, {capture_duration}s duration.")
    except ImportError:
        return _step(state, nd, "pcap_ingest", "PCAP ingestion failed — scapy not installed.")
    except Exception as exc:
        nd["error"] = str(exc)
        return _step(state, nd, "pcap_ingest", f"PCAP ingestion failed: {exc}")


# ── Agent: Traffic Statistics (no LLM) ───────────────────────

def traffic_statistics_agent(state: OrcaWorkflowState) -> Dict:
    """Compute statistical features from connection data. No LLM call."""
    nd = state.get("network_domain") or {}
    connections = nd.get("connections", [])
    duration = nd.get("capture_duration_seconds", 0)

    if not connections:
        nd["statistics"] = {}
        return _step(state, nd, "traffic_statistics", "Statistics skipped — no connections.")

    total_connections = len(connections)
    total_packets = sum(c.get("total_packets", 0) for c in connections)
    bidirectional = sum(1 for c in connections if c.get("bidirectional"))
    unidirectional = total_connections - bidirectional
    packets_per_conn = [c.get("total_packets", 0) for c in connections]
    durations = [c.get("duration", 0) for c in connections]

    # Unique source ports (indicator of many different clients or spoofed sources)
    unique_src_ports = len(set(c.get("src_port") for c in connections))

    # Handshake completion estimate: bidirectional flows with >3 packets
    completed_handshakes = sum(1 for c in connections if c.get("bidirectional") and c.get("total_packets", 0) > 3)
    handshake_completion_rate = round(completed_handshakes / max(total_connections, 1), 3)

    # Single-packet flows (incomplete connections)
    single_packet_flows = sum(1 for c in connections if c.get("total_packets", 0) == 1)
    single_packet_ratio = round(single_packet_flows / max(total_connections, 1), 3)

    # Connections per second
    connections_per_second = round(total_connections / max(duration, 0.1), 2)

    # Packet size statistics
    avg_packets_per_conn = round(sum(packets_per_conn) / max(len(packets_per_conn), 1), 2)
    max_packets_per_conn = max(packets_per_conn) if packets_per_conn else 0
    min_packets_per_conn = min(packets_per_conn) if packets_per_conn else 0

    stats = {
        "total_connections": total_connections,
        "total_packets": total_packets,
        "capture_duration_seconds": duration,
        "connections_per_second": connections_per_second,
        "bidirectional_flows": bidirectional,
        "unidirectional_flows": unidirectional,
        "unique_source_ports": unique_src_ports,
        "handshake_completion_rate": handshake_completion_rate,
        "single_packet_flows": single_packet_flows,
        "single_packet_ratio": single_packet_ratio,
        "avg_packets_per_connection": avg_packets_per_conn,
        "max_packets_per_connection": max_packets_per_conn,
        "min_packets_per_connection": min_packets_per_conn,
    }

    # LLM interpretation of the statistical profile.
    # Note: this is decorative — the downstream classifier is told to
    # ignore the `traffic_profile` label and apply protocol-grounded
    # signatures directly. Kept (rather than dropped) so cost
    # tracking attributes any LLM time spent here under
    # "traffic_statistics" rather than `_untagged`. Drop the call
    # entirely once the cost is measured and confirmed wasteful.
    usage_checkpoint = LLMProvider.usage_count()
    try:
        llm_stats = llm.query_json(
            system="You are a network traffic analyst examining QUIC protocol traffic statistics.",
            user=f"""Interpret these traffic statistics from a QUIC capture:

- Total connections: {total_connections}
- Capture duration: {duration} seconds
- Connections per second: {connections_per_second}
- Bidirectional flows: {bidirectional} ({round(bidirectional/max(total_connections,1)*100,1)}%)
- Unidirectional flows: {unidirectional} ({round(unidirectional/max(total_connections,1)*100,1)}%)
- Handshake completion rate: {handshake_completion_rate}
- Single-packet flows: {single_packet_flows} ({single_packet_ratio} ratio)
- Avg packets per connection: {avg_packets_per_conn}
- Min/Max packets per connection: {min_packets_per_conn}/{max_packets_per_conn}
- Unique source ports: {unique_src_ports}

Return JSON describing the traffic in numeric terms only — do NOT
classify it as an attack, that is the next agent's job:
{{
    "traffic_profile": "normal|high_volume|burst_pattern|probe_pattern|mixed",
    "notable_findings": ["specific stat-level observations"],
    "preliminary_assessment": "describe what these numbers show, no attack-class label"
}}""",
            agent="traffic_statistics",
        )
        stats["llm_interpretation"] = llm_stats
    except Exception:
        pass
    stats["usage"] = LLMProvider.usage_since(usage_checkpoint)
    stats["agent_id"] = "traffic_statistics"

    nd["statistics"] = stats

    return _step(state, nd, "traffic_statistics",
                 f"Statistics: {total_connections} connections, {connections_per_second} conn/s, "
                 f"handshake completion {handshake_completion_rate}, single-packet ratio {single_packet_ratio}.")


# ── Agent: QUIC Handshake Analysis ────────────────────────────

def quic_handshake_agent(state: OrcaWorkflowState) -> Dict:
    """Analyse QUIC handshake patterns and JA4 fingerprints."""
    nd = state.get("network_domain") or {}
    connections = nd.get("connections", [])
    pcap_path = nd.get("pcap_path") or state.get("pcap_path")

    if not connections:
        return _step(state, nd, "quic_handshake", "Handshake analysis skipped — no connections.")

    # JA4 fingerprinting
    ja4_results = []
    if pcap_path:
        try:
            from orca.domains.network.ja4_fingerprinter import JA4Fingerprinter
            fingerprinter = JA4Fingerprinter()
            ja4_results = fingerprinter.extract_from_pcap(pcap_path)
            nd["ja4_fingerprints"] = ja4_results
        except Exception:
            pass

    usage_checkpoint = LLMProvider.usage_count()
    try:
        stats = nd.get("statistics", {})
        data = {
            "connections_sample": connections[:15],
            "statistics": stats,
            "ja4_fingerprints": ja4_results[:10],
        }
        result = llm.query_json(
            system="You are a QUIC protocol analyst with knowledge of RFC 9000, RFC 9001, and RFC 9114.",
            user=f"""Examine these QUIC connection flows and statistics.

The downstream classifier will assign the attack label. Your job is
narrower: surface anything in the connection set that the classifier
should be aware of (anomalous CIDs, suspicious source-port patterns,
handshake-byte irregularities). Do NOT emit an attack label.

Statistics show: {stats.get('total_connections', 0)} connections,
{stats.get('connections_per_second', 0)} connections/sec, handshake
completion rate {stats.get('handshake_completion_rate', 0)},
single-packet ratio {stats.get('single_packet_ratio', 0)}.

Return JSON:
{{
  "handshake_summary": "one-line description",
  "completed_handshakes_estimate": 0,
  "failed_handshakes_estimate": 0,
  "suspicious_findings": ["..."],
  "rfc_citations": ["RFC 9000 §..."]
}}

Data: {json.dumps(data, default=str)[:3000]}""",
            agent="quic_handshake",
        )
        result["agent_id"] = "quic_handshake"
        result["usage"] = LLMProvider.usage_since(usage_checkpoint)
        nd["handshake_analysis"] = result
        ja4_info = f", {len(ja4_results)} JA4 fingerprints" if ja4_results else ""
        cost = result["usage"].get("cost_usd", 0.0)
        return _step(state, nd, "quic_handshake", f"Handshake analysis done{ja4_info} (${cost:.4f}).")
    except Exception as exc:
        nd["handshake_analysis"] = {
            "agent_id": "quic_handshake",
            "error": str(exc),
            "usage": LLMProvider.usage_since(usage_checkpoint),
        }
        return _step(state, nd, "quic_handshake", f"Handshake analysis failed: {exc}")


# ── Agent: Attack Classification ─────────────────────────────

def _detect_bursts(connections_list, gap_seconds: float = 1.0, min_burst: int = 5):
    """Return list of burst sizes detected in connection start times."""
    first_times = sorted(c.get("first_seen", 0) for c in connections_list if c.get("first_seen"))
    if not first_times:
        return []
    bursts = []
    current = 1
    for i in range(1, len(first_times)):
        if first_times[i] - first_times[i-1] < gap_seconds:
            current += 1
        else:
            if current > min_burst:
                bursts.append(current)
            current = 1
    if current > min_burst:
        bursts.append(current)
    return bursts


CLASSIFIER_SYSTEM_PROMPT = """You are a network security analyst classifying a QUIC traffic capture.

For each capture you receive numeric statistics from PCAP and an
optional qlog summary. Where available you also receive the same
implementation's BENIGN BASELINE statistics so you can judge what
"normal" looks like for THIS server. Reason from deltas relative to
the implementation's own baseline; do not invoke absolute thresholds.

[Note. When ≥3 baseline runs are available, deviations should be
interpreted in σ-units against the per-stat baseline distribution.
When only a single baseline run is available, reason qualitatively
from the protocol-grounded signatures below; do not invent
σ-quantitative bounds. When no baseline is provided, reason
qualitatively against the protocol signatures alone.]

CLASSES AND PROTOCOL-GROUNDED SIGNATURES (each derived from RFC
clauses, not from observed dataset values):

1. NORMAL — RFC 9000 §7 (handshake), §19.6 (CRYPTO frames).
   Legitimate handshakes complete; bidirectional flows; no anti-replay
   violations; no mass connection issuance.
   THEREFORE: per-stat values fall within baseline jitter; no
   structural shift in flow ratios; qlog event mix matches the
   baseline distribution.

2. FLOODING_DOS — RFC 9000 §8.1 (address validation requirement),
   §21.1.5 (DDoS via UDP amplification), §17.2.5 (Retry packet).
   An attacker issues high-rate Initial packets without completing
   handshakes, forcing the server to decrypt each Initial under the
   version-derived initial secret and maintain per-CID state until
   validation or idle expiration.
   THEREFORE: many distinct destination CIDs in Initial packets;
   high Initial-to-1RTT count ratio; many flows that never reach
   Handshake. The server may ABSORB the flood (admission far below
   attempted; handshake completion among admitted may stay high) or
   SATURATE (legit handshake completion drops). The defining signal
   is volume relative to baseline plus Initial-heavy traffic, not
   any absolute connection rate.

3. SLOWLORIS_DOS — RFC 9000 §10.1 (idle timeout), §19.2 (PING
   frame, used to keep a connection live without application data),
   §4.6 (initial_max_streams_bidi / _uni stream-limit enforcement).
   An attacker completes the handshake and then sends PING frames
   at intervals < negotiated max_idle_timeout to prevent idle
   expiration. Each held connection keeps an active CID, an
   event-loop fd registration, and per-connection state.
   THEREFORE: bidirectional flows that persist; mean concurrent
   flows scales linearly with held-connection count; sustained
   low-rate traffic per CID; handshake completion stays normal-to-
   high (the attack is post-handshake hold, not handshake failure).
   Differs from flooding in that handshake completion is
   normal-or-high while concurrent-flow count is anomalously high.

4. CONNECTION_ID_MANIPULATION — RFC 9000 §5.1 (connection IDs),
   §17.2 (long header), §17.2.1 (Version Negotiation packet).
   An attacker emits Initial packets with random destination CIDs
   that map to no active server connection. Each forged Initial
   produces no subsequent Handshake or 1-RTT traffic for that CID.
   THEREFORE: many distinct destination CIDs; almost all flows
   single-packet; near-zero handshake completion; near-zero
   bidirectional flows. Defining signal: NO connection ever
   completes, distinguishing from FLOODING_DOS even at high rates.

5. MAN_IN_THE_MIDDLE — RFC 9000 §13.4.2 (anti-replay packet-number
   window per packet-number space — Initial, Handshake, Application),
   RFC 9001 §6.6 (AEAD limits), §7 (key schedule).
   An attacker captures packets and re-injects them. The server's
   anti-replay window per packet-number space rejects packets whose
   PN is below the window's left edge or already received.
   THEREFORE: the packet-level decision (accepted vs dropped) is
   inside AEAD-encrypted payload and is NOT visible from PCAP
   alone. qlog packet_dropped events with reason
   duplicate_packet_number, unknown_connection_id, or
   decryption_failure are the authoritative signal. PCAP-level
   symptom is roughly equal bidirectional (legit) and unidirectional
   (forged/dropped) flows in the same capture. If qlog is
   unavailable and PCAP shows this split, classify as MitM with
   reduced confidence and record the unsoundness in
   uncertainty_notes.

6. ZERO_RTT_REPLAY — RFC 9001 §9.2 (anti-replay for 0-RTT data;
   implementations MUST limit and ideally reject replayed early
   data), §4.2 (early-data semantics), RFC 8446 §8 (TLS 1.3 0-RTT
   anti-replay strategies).
   An attacker replays 0-RTT packets from a captured session.
   THEREFORE: 0-RTT-typed packets visible in the QUIC long header
   (packet type bits 0b01); qlog `early_data_accepted` /
   `early_data_rejected` events are the authoritative signal. PCAP
   alone CANNOT distinguish a legitimate 0-RTT session from a
   replay; if qlog is unavailable, classification is "uncertain"
   and the unsoundness is recorded in uncertainty_notes.

7. RETRY_TOKEN_ABUSE — RFC 9000 §8.1.4 (Retry token semantics —
   server MUST reject malformed, expired, or address-mismatched
   tokens), §17.2.5 (Retry packet format).
   An attacker sends Initial packets carrying malformed, expired,
   or cross-client tokens.
   THEREFORE: Initial packets with non-zero token-length field;
   qlog `retry_token_validation_failed` events (where logged);
   subsequent connection_closed or no further activity per CID;
   handshake completion ratio drops sharply for the affected CIDs.
   PCAP-level signal alone is weak; qlog token-validation events
   are the authoritative signal.

8. CID_EXHAUSTION — RFC 9000 §5.1.1 (Issuing Connection IDs),
   §5.1.2 (Consuming and Retiring), §9 (Connection Migration),
   §8.2 (Path Validation).
   An attacker either repeatedly requests new CIDs (NEW_CONNECTION_ID
   frame requests) or simulates migration (source-address change
   for the same DCID), forcing the server to maintain extra CID
   state and run path validation.
   THEREFORE: source IP/port flapping for stable DCIDs (migration);
   qlog `connection_id_issued` events grow without proportional
   `connection_id_retired`; `path_validation_started/succeeded/failed`
   events accompany the migration attempts. Handshake completes
   normally — distinguishing from CONNECTION_ID_MANIPULATION which
   has near-zero completion.

9. UNKNOWN_ATTACK — Deviations from baseline exceed jitter but the
   pattern matches no protocol-grounded signature above.

REASONING RULES:
- Reason RELATIVE to the implementation's own baseline. The same
  numeric value can be normal for one impl and abnormal for another.
- No dataset-derived thresholds. Protocol-grounded thresholds
  (e.g. RFC 9000 §8.1's 3× anti-amplification bound) and σ-grounded
  thresholds (when ≥3 baselines exist) are acceptable. "Below 80%"
  with no protocol or σ basis is not.
- Cite specific stat-level deviations as evidence_for. List
  observations that would support an alternative class as
  evidence_against. Use uncertainty_notes for borderline data.
- Cite the RFC sections that ground the matched signature.
- Each individual call must output its own confidence. Do not
  emit confidence 1.0 unless every alternative is unambiguously
  ruled out.

OUTPUT JSON (exact schema, used by the fusion agent):
{
  "agent_id": "attack_classification",
  "classification": "NORMAL|FLOODING_DOS|SLOWLORIS_DOS|CONNECTION_ID_MANIPULATION|MAN_IN_THE_MIDDLE|ZERO_RTT_REPLAY|RETRY_TOKEN_ABUSE|CID_EXHAUSTION|UNKNOWN_ATTACK",
  "confidence": 0.0-1.0,
  "evidence_for":     ["specific stat-level observations supporting the chosen label"],
  "evidence_against": ["observations consistent with alternative labels"],
  "uncertainty_notes": ["where the data is borderline or inconclusive"],
  "reasoning": "match the deviations to the chosen class's RFC-grounded signature",
  "rfc_citations": ["RFC 9000 §...", "RFC 9001 §..."]
}"""


def _format_baseline_block(attack_stats: Dict, baseline_stats: Optional[Dict]) -> str:
    """Format the impl's own benign-baseline statistics as a delta/ratio block.

    Returns a baseline-relative comparison if `baseline_stats` is supplied;
    otherwise emits an explicit note that no baseline was provided so the
    classifier reasons qualitatively from protocol signatures alone.
    """
    if not baseline_stats:
        return ("Same implementation, BENIGN BASELINE: NOT PROVIDED. "
                "Reason qualitatively from the protocol-grounded "
                "signatures in the system prompt; do not invoke "
                "σ-quantitative bounds.")

    keys = [
        "total_connections", "connections_per_second",
        "bidirectional_flows", "unidirectional_flows",
        "handshake_completion_rate", "single_packet_ratio",
        "avg_packets_per_connection", "unique_source_ports",
    ]
    lines = ["Same implementation, BENIGN BASELINE statistics + per-stat deltas:"]
    for k in keys:
        a = attack_stats.get(k, 0) or 0
        b = baseline_stats.get(k, 0) or 0
        delta = a - b
        if b:
            ratio = f"{a / b:.2f}x"
        else:
            ratio = "n/a (baseline=0)" if a == 0 else "inf (baseline=0, attack>0)"
        lines.append(f"  {k}: attack={a}, baseline={b}, delta={delta:+}, ratio={ratio}")
    lines.append(
        "[Reason from the deltas/ratios. Single-baseline ratios are "
        "qualitative; ≥3-baseline σ-units are not yet plumbed.]"
    )
    return "\n".join(lines)


def _classifier_user_prompt(stats, handshake, baseline_stats, data):
    baseline_block = _format_baseline_block(stats, baseline_stats)
    return f"""Classify this QUIC traffic.

Implementation: {data.get('implementation', 'unknown')}
Capture duration: {stats.get('capture_duration_seconds', 0)} seconds

Attack-time statistics:
- Total connections: {stats.get('total_connections', 0)}
- Connections per second: {stats.get('connections_per_second', 0)}
- Bidirectional flows: {stats.get('bidirectional_flows', 0)}
- Unidirectional flows: {stats.get('unidirectional_flows', 0)}
- Handshake completion rate: {stats.get('handshake_completion_rate', 0)}
- Single-packet flows: {stats.get('single_packet_flows', 0)} (ratio {stats.get('single_packet_ratio', 0)})
- Avg packets per connection: {stats.get('avg_packets_per_connection', 0)}
- Unique source ports: {stats.get('unique_source_ports', 0)}

{baseline_block}

Optional qlog/handshake summary: {json.dumps(handshake, default=str)[:1000]}

Reason from the deltas and the protocol-grounded signatures. Return
the JSON described in the system prompt."""


CLASSIFIER_VOTES = 5


def attack_classification_agent(state: OrcaWorkflowState) -> Dict:
    """Classify a QUIC capture by reasoning from the implementation's own
    benign baseline against protocol-grounded signatures (no rule
    execution in the prompt).

    Runs the classifier CLASSIFIER_VOTES times. Aggregates confidence as
    mean(per-vote confidence) × (matching votes / N), so a unanimous-but-
    unsure vote is not reported as confidence 1.0.
    """
    nd = state.get("network_domain") or {}
    stats = nd.get("statistics", {})
    handshake = nd.get("handshake_analysis", {})
    baseline_stats = nd.get("baseline_statistics") or state.get("baseline_statistics")

    if not stats:
        return _step(state, nd, "attack_classification", "Classification skipped — no statistics.")

    usage_checkpoint = LLMProvider.usage_count()

    try:
        data = {
            "statistics": stats,
            "handshake_analysis": handshake,
            "connections_sample": nd.get("connections", [])[:10],
            "implementation": state.get("implementation", "unknown"),
        }
        user_prompt = _classifier_user_prompt(stats, handshake, baseline_stats, data)

        votes: List[str] = []
        per_vote_confs: List[float] = []
        responses: List[Dict] = []
        for _ in range(CLASSIFIER_VOTES):
            try:
                r = llm.query_json(
                    system=CLASSIFIER_SYSTEM_PROMPT,
                    user=user_prompt,
                    agent="attack_classification",
                )
                label = r.get("classification", "UNKNOWN_ATTACK")
                conf = float(r.get("confidence", 0.5) or 0.5)
                votes.append(label)
                per_vote_confs.append(conf)
                responses.append(r)
            except Exception:
                continue

        if not votes:
            raise RuntimeError("All classifier votes failed")

        tally: Dict[str, int] = {}
        for v in votes:
            tally[v] = tally.get(v, 0) + 1
        winner = max(tally, key=lambda k: (tally[k], -votes.index(k)))
        vote_fraction = tally[winner] / len(votes)
        per_vote_conf_mean = sum(per_vote_confs) / len(per_vote_confs)
        aggregated_confidence = round(per_vote_conf_mean * vote_fraction, 3)

        result = next(r for r, v in zip(responses, votes) if v == winner)
        result["agent_id"] = "attack_classification"
        result["classification"] = winner
        result["confidence"] = aggregated_confidence
        result["vote_distribution"] = tally
        result["per_vote_confidence_mean"] = round(per_vote_conf_mean, 3)
        # Standardised schema; tolerate older response shapes.
        result.setdefault("evidence_for", result.pop("evidence", []) if "evidence" in result else [])
        result.setdefault("evidence_against", [])
        result.setdefault("uncertainty_notes", [])
        result.setdefault("reasoning", result.pop("description", "") if "description" in result else "")
        result.setdefault("rfc_citations", [])
        result["self_consistency"] = {
            "votes": votes,
            "vote_fraction": round(vote_fraction, 3),
            "tally": tally,
        }
        result["usage"] = LLMProvider.usage_since(usage_checkpoint)

        nd["attack_classification"] = result
        cost = result["usage"].get("cost_usd", 0.0)
        return _step(state, nd, "attack_classification",
                     f"Classification: {winner} (conf {aggregated_confidence}, "
                     f"{tally[winner]}/{len(votes)} votes, ${cost:.4f}).")
    except Exception as exc:
        nd["attack_classification"] = {
            "agent_id": "attack_classification",
            "classification": "ERROR",
            "error": str(exc),
            "usage": LLMProvider.usage_since(usage_checkpoint),
        }
        return _step(state, nd, "attack_classification", f"Classification failed: {exc}")


# ── Agent: Anomaly Detection ──────────────────────────────────

def anomaly_detection_agent(state: OrcaWorkflowState) -> Dict:
    """Flag RFC 9000 / RFC 9001 violations and protocol anomalies.

    Reasons from the classified attack + statistics; cites RFC sections
    for every finding. Output schema matches the standardised classifier
    schema (agent_id, evidence_for, etc.) so the fusion agent can
    consume it uniformly.
    """
    nd = state.get("network_domain") or {}
    stats = nd.get("statistics", {})
    classification = nd.get("attack_classification", {})

    usage_checkpoint = LLMProvider.usage_count()
    try:
        data = {
            "statistics": stats,
            "classification": classification,
            "connections_sample": nd.get("connections", [])[:10],
            "handshake": nd.get("handshake_analysis", {}),
        }
        result = llm.query_json(
            system="You are a QUIC protocol security researcher with detailed knowledge of RFC 9000 and RFC 9001.",
            user=f"""Identify specific protocol violations and security concerns
in this capture, given the upstream classification
({classification.get('classification', 'unknown')}).

For each finding, cite the specific RFC section that grounds it.
Do NOT re-classify the attack — that is the upstream classifier's
job. Your output is a list of RFC-grounded violations and concerns.

Focus areas (cite exact sections):
- Incomplete handshakes (RFC 9000 §7)
- Connection ID handling violations (RFC 9000 §5.1)
- Amplification indicators (RFC 9000 §8.1)
- Connection migration anomalies (RFC 9000 §9)
- Flow control violations (RFC 9000 §4)
- AEAD / anti-replay violations (RFC 9001 §6.6, §13.4.2)

Return JSON:
{{
  "agent_id": "anomaly_detection",
  "anomalies": [
    {{
      "type": "...",
      "description": "...",
      "severity": "high|medium|low",
      "rfc_section": "RFC 9000 §X.Y",
      "evidence": "specific stat or observation that triggered the finding",
      "recommendation": "..."
    }}
  ],
  "rfc_citations": ["RFC 9000 §...", "RFC 9001 §..."],
  "uncertainty_notes": ["where the data does not let us confirm a finding"]
}}

Data: {json.dumps(data, default=str)[:3000]}""",
            agent="anomaly_detection",
        )
        result.setdefault("agent_id", "anomaly_detection")
        result.setdefault("anomalies", [])
        result.setdefault("rfc_citations", [])
        result.setdefault("uncertainty_notes", [])
        result["usage"] = LLMProvider.usage_since(usage_checkpoint)
        nd["anomalies"] = result
        cost = result["usage"].get("cost_usd", 0.0)
        return _step(state, nd, "anomaly_detection",
                     f"Anomaly detection done — {len(result.get('anomalies', []))} findings (${cost:.4f}).")
    except Exception as exc:
        nd["anomalies"] = {
            "agent_id": "anomaly_detection",
            "anomalies": [],
            "error": str(exc),
            "usage": LLMProvider.usage_since(usage_checkpoint),
        }
        return _step(state, nd, "anomaly_detection", f"Anomaly detection failed: {exc}")


# ── Agent: QUIC Binary Security Assessment ────────────────────

def quic_binary_assessment_agent(state: OrcaWorkflowState) -> Dict:
    """Analyse QUIC-specific functions in the binary for security properties.

    This is the cross-domain agent: it takes the attack classification from
    traffic analysis and examines the binary to explain WHY the attack
    works or doesn't work against this implementation.

    Unlike other agents, this one reopens the binary and specifically searches
    for QUIC-related functions by name pattern, then decompiles them directly.
    This avoids relying on the generic top-N enrichment which may miss
    security-critical QUIC functions.
    """
    nd = state.get("network_domain") or {}
    bd = state.get("binary_domain") or {}
    sa = bd.get("static_analysis", {})
    classification = nd.get("attack_classification", {})
    attack_type = classification.get("classification", "UNKNOWN")
    traffic_stats = nd.get("statistics", {})

    if not sa or sa.get("error"):
        return _step(state, nd, "quic_binary_assessment", "QUIC binary assessment skipped — no binary analysis data.")

    usage_checkpoint = LLMProvider.usage_count()

    # QUIC keywords — match broadly to catch all QUIC-related functions
    QUIC_KEYWORDS = [
        "quic", "h3", "http3", "http_v3",
        "picoquic", "ngtcp2", "lsquic", "msquic", "quiche",
    ]
    # Secondary keywords for non-QUIC-prefixed security functions
    SECURITY_KEYWORDS = [
        "flood", "limit", "rate", "throttle", "timeout", "idle",
        "amplif", "migration", "path_valid", "connid", "conn_id",
        "retry", "token", "replay", "early_data", "0rtt",
        "close_connection", "shutdown", "reset", "reject",
        "stream", "crypto", "ssl", "tls", "handshake",
        # Connection management patterns
        "busy", "refuse", "incoming", "accept", "max_conn",
        "max_half_open", "adjust_max", "connection_limit",
        "too_many", "overload", "backpressure",
    ]

    # Step 1: Reopen the binary — do a FULL function name census + targeted decompilation
    binary_path = state.get("binary_path")
    quic_functions = []
    function_name_census = {}  # Maps security category -> list of function names

    # Security mechanism indicators — if a function name contains these, the mechanism likely exists
    MECHANISM_INDICATORS = {
        "connection_limits": ["max_conn", "adjust_max", "max_number", "max_inchoate", "max_half_open",
                              "server_busy", "queue_busy", "too_many", "connection_limit", "reject_conn"],
        "rate_limiting": ["rate_limit", "throttle", "flood", "cooldown", "batch_size", "shrink_batch",
                          "max_packets", "pacing", "max_operations", "noprogress"],
        "anti_amplification": ["amplif", "amp_factor", "path_limit", "path_allowance", "bytes_recv",
                               "bytes_sent", "anti_amp", "validated_path", "dcid_tx_left"],
        "connection_id_validation": ["validate_cid", "verify_cid", "connection_id_frame", "retire_cid",
                                     "new_connection_id", "retire_connection_id", "cid_sequence", "dcid"],
        "idle_timeout": ["idle_timeout", "idle_conn", "noprogress_timeout", "max_idle", "close_idle"],
        "retry_and_tokens": ["retry", "token", "stateless_reset", "new_token", "verify_token",
                             "validate_token", "send_retry", "queue_retry"],
        "path_validation": ["path_challenge", "path_response", "path_valid", "migration"],
        "anti_replay": ["replay", "early_data", "0rtt", "pn_already_received", "max_pkt_num"],
    }

    if binary_path:
        try:
            from pathlib import Path
            from orca.core.re_backends.selector import REBackendSelector
            from orca.core.models import REBackendType

            selector = REBackendSelector()
            backends = selector.select(Path(binary_path))
            backend = None
            for attempt in [backends[0], REBackendType.BINARY_NINJA, REBackendType.GHIDRA]:
                try:
                    candidate = selector.create_backend(attempt, Path(binary_path))
                    candidate.open()
                    backend = candidate
                    break
                except Exception:
                    continue

            if backend:
                try:
                    all_functions = backend.get_functions()

                    # PHASE 1: Function name census — scan ALL function names
                    all_names = [f.name for f in all_functions]
                    for category, indicators in MECHANISM_INDICATORS.items():
                        matches = []
                        for name in all_names:
                            name_lower = name.lower()
                            if any(ind in name_lower for ind in indicators):
                                matches.append(name)
                        if matches:
                            function_name_census[category] = matches

                    # Also scan binary strings for mechanism indicators
                    raw_strings = sa.get("strings", {}).get("raw", [])
                    string_indicators = {
                        "connection_limits": ["server busy", "max connections", "too many connections",
                                              "connection limit", "max_nb_connections"],
                        "rate_limiting": ["rate limit", "flood detected", "too many requests"],
                        "anti_amplification": ["amplification", "anti-amplification", "amp factor"],
                        "idle_timeout": ["idle timeout", "connection timed out", "noprogress"],
                    }
                    for category, phrases in string_indicators.items():
                        for s in raw_strings[:500]:
                            s_lower = s.lower()
                            if any(phrase in s_lower for phrase in phrases):
                                if category not in function_name_census:
                                    function_name_census[category] = []
                                function_name_census[category].append(f"STRING: {s[:80]}")
                                break

                    # PHASE 2: Targeted decompilation of security-relevant functions
                    tier1_names = []
                    tier2_names = []
                    tier3_names = []
                    for f in all_functions:
                        name_lower = f.name.lower()
                        is_quic = any(kw in name_lower for kw in QUIC_KEYWORDS)
                        is_security = any(kw in name_lower for kw in SECURITY_KEYWORDS)
                        if is_quic and is_security:
                            tier1_names.append(f.name)
                        elif is_quic:
                            tier2_names.append(f.name)
                        elif is_security:
                            tier3_names.append(f.name)

                    max_funcs = 80
                    quic_func_names = tier1_names[:max_funcs]
                    remaining = max_funcs - len(quic_func_names)
                    if remaining > 0:
                        quic_func_names += tier2_names[:remaining]
                        remaining = max_funcs - len(quic_func_names)
                    if remaining > 0:
                        quic_func_names += tier3_names[:remaining]

                    tier1_set = set(tier1_names)
                    for fname in quic_func_names[:max_funcs]:
                        max_chars = 2500 if fname in tier1_set else 1500
                        enrichment = backend.enrich_function(fname, max_decompiled_chars=max_chars)
                        code = enrichment.get("decompiled_code", "")
                        if code:
                            quic_functions.append({
                                "name": fname,
                                "code": code,
                            })
                finally:
                    backend.close()
        except Exception as exc:
            pass  # Fall back to pre-enriched functions below

    # Step 2: If direct decompilation didn't work, fall back to pre-enriched
    if not quic_functions:
        enriched = sa.get("enriched_functions", [])
        for f in enriched:
            name = f.get("name", "").lower()
            if any(kw in name for kw in QUIC_KEYWORDS + SECURITY_KEYWORDS):
                code = f.get("decompiled_code", "")
                if code:
                    quic_functions.append({
                        "name": f.get("name"),
                        "code": code[:800],
                    })

    # Also check imports for QUIC-related APIs
    imports = sa.get("imports", [])
    quic_imports = [i for i in imports if any(kw in i.lower() for kw in ["quic", "h3", "http3", "ssl", "tls", "crypto"])]

    if not quic_functions and not quic_imports:
        nd["quic_binary_assessment"] = {"assessment": "No QUIC-specific code found in binary"}
        return _step(state, nd, "quic_binary_assessment", "No QUIC functions found in binary.")

    # Build function summaries — group by category for the LLM
    func_by_category = {
        "security_and_validation": [],
        "connection_management": [],
        "stream_and_flow_control": [],
        "crypto_and_tls": [],
        "other_quic": [],
    }
    for f in quic_functions:
        name_lower = f["name"].lower()
        if any(kw in name_lower for kw in ["flood", "limit", "rate", "throttle", "amplif", "retry", "token", "reject", "replay", "valid", "path_limit", "path_challenge", "path_response", "new_connection_id", "retire_connection_id", "new_sr_token", "new_token", "send_retry", "busy", "refuse", "max_conn", "max_half_open", "adjust_max", "incoming_client_initial", "overload"]):
            func_by_category["security_and_validation"].append(f)
        elif any(kw in name_lower for kw in ["close", "shutdown", "timeout", "idle", "migration", "init_connection", "finalize"]):
            func_by_category["connection_management"].append(f)
        elif any(kw in name_lower for kw in ["stream", "flow", "blocked", "max_data", "max_stream"]):
            func_by_category["stream_and_flow_control"].append(f)
        elif any(kw in name_lower for kw in ["crypto", "ssl", "tls", "handshake", "cipher", "encrypt", "decrypt", "seal", "key"]):
            func_by_category["crypto_and_tls"].append(f)
        else:
            func_by_category["other_quic"].append(f)

    # Build a condensed view — full code for security functions, shorter for others
    func_text_parts = []
    for cat, funcs in func_by_category.items():
        if not funcs:
            continue
        func_text_parts.append(f"\n=== {cat.upper()} ({len(funcs)} functions) ===")
        if cat == "security_and_validation":
            # Full code for ALL security-critical functions
            for f in funcs[:15]:
                func_text_parts.append(f"\n--- {f['name']} ---\n{f['code'][:1500]}")
        elif cat == "connection_management":
            for f in funcs[:8]:
                func_text_parts.append(f"\n--- {f['name']} ---\n{f['code'][:1000]}")
        elif cat == "stream_and_flow_control":
            # Stream limits are relevant to connection limits
            for f in funcs[:6]:
                func_text_parts.append(f"\n--- {f['name']} ---\n{f['code'][:800]}")
        else:
            # Names and short snippet for others
            for f in funcs[:5]:
                func_text_parts.append(f"\n--- {f['name']} ---\n{f['code'][:300]}")

    func_text = "\n".join(func_text_parts)[:12000]

    # Pre-compute census summary for the JSON template
    census_summary = {k: len(v) for k, v in function_name_census.items()}

    # Build traffic context for cross-domain reasoning. Just present
    # the numeric stats; do not embed any rubric or attack-specific
    # rule into the prompt. The LLM reasons about activation from
    # raw traffic evidence + the binary census.
    traffic_context = ""
    if traffic_stats:
        traffic_context = f"""
TRAFFIC OBSERVATIONS (numeric stats from the network capture):
- Total connections: {traffic_stats.get('total_connections', 0)}
- Connections per second: {traffic_stats.get('connections_per_second', '?')}
- Handshake completion rate: {traffic_stats.get('handshake_completion_rate', '?')}
- Bidirectional flows: {traffic_stats.get('bidirectional_flows', '?')}
- Unidirectional flows: {traffic_stats.get('unidirectional_flows', '?')}
- Single-packet ratio: {traffic_stats.get('single_packet_ratio', '?')}
- Average packets per connection: {traffic_stats.get('avg_packets_per_connection', '?')}
- Total packets: {traffic_stats.get('total_packets', '?')}
- Capture duration (s): {traffic_stats.get('capture_duration_seconds', '?')}
"""

    system_prompt = """You are a security analyst correlating two views of a deployed
QUIC server: what defensive code is compiled into the binary, and how
the server actually behaved on the network under attack.

For each defence mechanism present in the binary, decide whether it
ACTIVATED against the observed attack, and assess the implementation's
resilience qualitatively. The interesting cases — and the contribution
finding for the paper — are SHIPPED-BUT-SILENT defences: mechanisms
that exist in the compiled binary but produced no runtime evidence of
firing against this attack.

Inputs you will receive:
  (a) BINARY MECHANISM CENSUS: defensive mechanisms with the function
      names that implement them in this binary. Presence in the
      census is authoritative — the function exists in the deployed
      binary.
  (b) DECOMPILED CODE for the most security-relevant functions.
  (c) TRAFFIC OBSERVATIONS from the actual capture.
  (d) ATTACK TYPE classified by the upstream network classifier.

REASONING RULES:
- Mechanism presence in the binary does NOT imply activation. A
  function compiled in but never called for this attack is
  "shipped but silent."
- Activation evidence comes from the traffic side. Examples:
    high attempted-vs-admitted gap        ⇒ rejection logic activated
    qlog Retry events fire (where logged) ⇒ retry-token logic activated
    flat strace deltas under sustained load ⇒ no per-packet defence work
    idle_timeout events fire              ⇒ idle-timeout logic activated
- Cross-source consistency matters. If the binary lists retry tokens
  AND qlog shows Retry events AND admission rate is below attempted,
  three views agree.
- The interesting cases are DISAGREEMENTS: binary lists the mechanism
  but traffic shows the attack succeeded. Surface those as
  shipped_but_silent.
- No dataset-derived thresholds. Protocol-grounded thresholds
  (e.g. RFC 9000 §8.1's 3× anti-amplification bound) and σ-grounded
  thresholds (when ≥3 baselines exist) are acceptable; vague
  cutoffs like "below 80%" with no protocol or σ basis are not.
- Distinguish defence purposes: (i) anti-amplification (RFC 9000
  §8.1) protects against reflection, not connection flooding;
  (ii) retry tokens (RFC 9000 §8.1.4) protect against IP spoofing,
  not connection flooding; (iii) for flooding resilience look for
  connection-count limits, rate limiting, connection rejection logic.

OUTPUT JSON (exact schema, used by the fusion agent):
{
  "agent_id": "binary_assessment",
  "implementation_name": "QUIC library/server identified",
  "attack_type": "<the attack class>",
  "mechanisms": [
    {
      "mechanism": "retry_tokens",
      "function": "QuicLibraryEvaluateSendRetryState",
      "in_binary": true,
      "activated": "yes|no|silent|uncertain",
      "evidence_for":     "specific qlog/pcap/strace observations supporting activation",
      "evidence_against": "observations consistent with no activation",
      "reasoning": "why you concluded activated/not/silent",
      "rfc_citations": ["RFC 9000 §..."]
    }
  ],
  "shipped_but_silent": [
    {"mechanism": "...", "function": "...", "evidence": "..."}
  ],
  "resilience_assessment": "qualitative paragraph; cite specific mechanism activations and silences",
  "evidence_for":     ["overall observations supporting the assessment"],
  "evidence_against": ["observations that complicate the assessment"],
  "uncertainty_notes": ["where the analysis is borderline or inconclusive"],
  "rfc_citations": ["RFC 9000 §...", "RFC 9001 §..."]
}"""

    user_prompt = f"""ATTACK TYPE: {attack_type}
{traffic_context}
=== PHASE 1: FUNCTION NAME CENSUS (scanned ALL {len(sa.get('imports', []))} imports + all function names) ===
The following defence-mechanism categories were detected by scanning every
function name in the binary. If a category has matching function names,
the mechanism DEFINITELY EXISTS in the deployed binary even if not visible
in the decompiled snippets below.

{json.dumps(function_name_census, indent=2, default=str) if function_name_census else "No mechanism indicators found in function names."}

=== PHASE 2: DECOMPILED CODE ({len(quic_functions)} functions) ===
Decompiled code from the most security-relevant QUIC functions:

{func_text}

QUIC/SSL imports ({len(quic_imports)}):
{json.dumps(quic_imports[:30])}

The function name census above is AUTHORITATIVE for mechanism existence.
A mechanism is MISSING only when it has no function name matches AND no
code evidence.

For each defence in the census, reason about whether it activated against
this attack. Use the traffic evidence to support or rule out activation.
Surface SHIPPED-BUT-SILENT defences (in_binary=true but
activated=no/silent) as a top-level list — these are the contribution
finding.

Return the JSON described in the system prompt."""

    try:
        result = llm.query_json(
            system=system_prompt,
            user=user_prompt,
            agent="binary_assessment",
        )
        result.setdefault("agent_id", "binary_assessment")
        result.setdefault("attack_type", attack_type)
        result.setdefault("evidence_for", [])
        result.setdefault("evidence_against", [])
        result.setdefault("uncertainty_notes", [])
        result.setdefault("rfc_citations", [])
        result.setdefault("shipped_but_silent", [])
        result.setdefault("mechanisms", [])
        result["usage"] = LLMProvider.usage_since(usage_checkpoint)
        nd["quic_binary_assessment"] = result
        n_silent = len(result.get("shipped_but_silent", []))
        n_mechs = len(result.get("mechanisms", []))
        cost = result["usage"].get("cost_usd", 0.0)
        return _step(
            state, nd, "quic_binary_assessment",
            f"QUIC binary assessment done — {n_mechs} mechanisms reviewed, "
            f"{n_silent} shipped-but-silent (${cost:.4f}).",
        )
    except Exception as exc:
        nd["quic_binary_assessment"] = {
            "agent_id": "binary_assessment",
            "attack_type": attack_type,
            "error": str(exc),
            "usage": LLMProvider.usage_since(usage_checkpoint),
        }
        return _step(state, nd, "quic_binary_assessment", f"QUIC binary assessment failed: {exc}")


# ── Agent: qlog Analysis ───────────────────────────────────────
#    Pure data-prep agent (no LLM call). Parses qlog .sqlog / .qlog
#    files using the existing QlogParser and aggregates per-event-type
#    counts under network_domain.qlog_features for downstream agents.

def qlog_analysis_agent(state: OrcaWorkflowState) -> Dict:
    """Parse qlog files and aggregate the per-event-type counts that
    downstream attack-specific agents (0-RTT, retry-token, CID) and
    the fusion agent consume.

    Reads from `state["qlog_dir"]` or `state["qlog_path"]`. Iterates
    every qlog file under the directory (or the single file at
    `qlog_path`), aggregates events across all files, and writes the
    feature record to `state["network_domain"]["qlog_features"]`.
    """
    from pathlib import Path
    from orca.domains.network.qlog_parser import QlogParser

    nd = state.get("network_domain") or {}
    qlog_dir = state.get("qlog_dir") or nd.get("qlog_dir")
    qlog_path = state.get("qlog_path") or nd.get("qlog_path")

    paths: List[Path] = []
    if qlog_dir:
        d = Path(qlog_dir)
        if d.is_dir():
            for ext in ("sqlog", "qlog", "jsonl"):
                paths.extend(d.rglob(f"*.{ext}"))
    if qlog_path:
        p = Path(qlog_path)
        if p.is_file():
            paths.append(p)

    if not paths:
        nd["qlog_features"] = {
            "agent_id": "qlog_analysis",
            "available": False,
            "reason": "no qlog files found at qlog_dir / qlog_path",
        }
        return _step(state, nd, "qlog_analysis", "qlog parsing skipped — no qlog files found.")

    # Aggregate events from every qlog file
    parsed_files = 0
    failed_files: List[str] = []
    all_events: List[Dict[str, Any]] = []
    for p in paths:
        try:
            parser = QlogParser(str(p))
            all_events.extend(parser.events)
            parsed_files += 1
        except Exception as exc:
            failed_files.append(f"{p.name}: {exc}")

    # Per-event-type counter
    from collections import Counter
    type_counter: Counter = Counter()
    for e in all_events:
        cat = e.get("category", "")
        typ = e.get("type", "")
        if not typ and "name" in e:
            typ = str(e["name"]).split(":")[-1]
            cat = str(e["name"]).split(":")[0] if ":" in str(e["name"]) else cat
        key = f"{cat}:{typ}" if cat else typ
        type_counter[key] += 1

    def _count_packet_received(packet_type: str) -> int:
        """Count packets of `packet_type` (case-insensitive substring match).

        qlog dialects disagree on where the packet type lives:
          - qlog draft-02+ puts it at  data.header.packet_type
          - picoquic's draft-00 puts it at  data.packet_type
        and the strings used differ ("initial" vs "Initial",
        "0rtt" vs "0RTT" vs "zero_rtt"). We accept both locations
        and use substring-match (e.g. "0rtt" matches "0RTT" and
        "zero_rtt") for cross-implementation portability.
        """
        n = 0
        target = packet_type.lower().replace("-", "").replace("_", "")
        for e in all_events:
            if e.get("type") not in ("packet_received", "packet_sent"):
                continue
            data = e.get("data", {})
            if not isinstance(data, dict):
                continue
            # try both locations
            pt = data.get("packet_type")
            if not isinstance(pt, str):
                header = data.get("header") or {}
                pt = header.get("packet_type") if isinstance(header, dict) else None
            if not isinstance(pt, str):
                continue
            pt_norm = pt.lower().replace("-", "").replace("_", "")
            if target in pt_norm or pt_norm in target:
                n += 1
        return n

    def _count_dropped_with_trigger(trigger: str) -> int:
        """Count packet_dropped events whose trigger matches.

        picoquic uses trigger strings like 'aead not ready', 'padding_packet'
        that differ from the draft-02 vocabulary ('decryption_failed',
        'unknown_connection_id'). We use substring-match in both directions.
        """
        n = 0
        target = trigger.lower().replace("_", " ")
        for e in all_events:
            if e.get("type") != "packet_dropped":
                continue
            data = e.get("data", {})
            if not isinstance(data, dict):
                continue
            trg = str(data.get("trigger") or "").lower()
            if not trg:
                continue
            # accept partial matches in either direction
            if target in trg or trg.replace(" ", "_") == trigger.lower():
                n += 1
            elif trigger.lower() == "decryption_failure" and "aead" in trg:
                # picoquic's "aead not ready" is the practical equivalent
                # of an AEAD decryption failure for an unfinished handshake.
                n += 1
        return n

    def _count_close_with_trigger(trigger: str) -> int:
        n = 0
        for e in all_events:
            if e.get("type") != "connection_closed":
                continue
            data = e.get("data", {})
            if isinstance(data, dict) and data.get("trigger", "").lower() == trigger.lower():
                n += 1
        return n

    def _count_frame_type(frame_type: str) -> int:
        """Count occurrences of a specific frame_type inside any
        packet_sent / packet_received event. picoquic emits CID issuance
        and retirement via NEW_CONNECTION_ID / RETIRE_CONNECTION_ID
        FRAMES rather than as standalone connectivity events.
        """
        target = frame_type.lower()
        n = 0
        for e in all_events:
            if e.get("type") not in ("packet_received", "packet_sent"):
                continue
            data = e.get("data", {})
            if not isinstance(data, dict):
                continue
            for fr in (data.get("frames") or []):
                if isinstance(fr, dict):
                    ft = str(fr.get("frame_type") or "").lower()
                    if ft == target:
                        n += 1
        return n

    def _count_picoquic_close_messages(needle: str) -> int:
        """picoquic logs connection lifecycle as info:message events with
        free-form text ("Clearing context on connection close (N)") rather
        than connection_closed events with structured trigger fields.
        Match by substring."""
        needle = needle.lower()
        n = 0
        for e in all_events:
            if e.get("type") != "message":
                continue
            data = e.get("data", {})
            if isinstance(data, dict):
                msg = str(data.get("message") or "").lower()
                if needle in msg:
                    n += 1
        return n

    # Initial-packets-with-token: flag any packet_received whose data.header
    # contains a non-empty token field.
    initial_with_token = 0
    for e in all_events:
        if e.get("type") not in ("packet_received", "packet_sent"):
            continue
        data = e.get("data", {})
        if not isinstance(data, dict):
            continue
        header = data.get("header", {}) if isinstance(data.get("header"), dict) else {}
        if header.get("packet_type", "").lower() == "initial" and header.get("token"):
            initial_with_token += 1

    qlog_features = {
        "agent_id": "qlog_analysis",
        "available": True,
        "files_parsed": parsed_files,
        "files_failed": failed_files,
        "total_events": len(all_events),
        "event_counts_by_name": dict(type_counter.most_common()),

        # 0-RTT-replay-relevant
        "zero_rtt_packets_received":         _count_packet_received("0rtt"),
        "early_data_accepted":               type_counter.get("security:early_data_accepted", 0)
                                              + type_counter.get("transport:early_data_accepted", 0),
        "early_data_rejected":               type_counter.get("security:early_data_rejected", 0)
                                              + type_counter.get("transport:early_data_rejected", 0),
        "duplicate_packet_number_zero_rtt":  _count_dropped_with_trigger("duplicate_packet_number"),

        # Retry-token-relevant
        "retry_packets_sent":                type_counter.get("transport:retry_packet_sent", 0)
                                              + type_counter.get("transport:retry_sent", 0),
        "retry_token_validation_failed":     type_counter.get("transport:retry_token_validation_failed", 0)
                                              + type_counter.get("security:retry_token_validation_failed", 0),
        "initial_packets_with_token":        initial_with_token,

        # CID-exhaustion-relevant. Counted both at the top-level
        # qlog-event layer (most implementations) AND inside frame
        # arrays of packet_sent/packet_received events (picoquic).
        "connection_id_issued":              type_counter.get("connectivity:connection_id_updated", 0)
                                              + type_counter.get("connectivity:new_connection_id", 0)
                                              + type_counter.get("transport:connection_id_updated", 0)
                                              + _count_frame_type("new_connection_id"),
        "connection_id_retired":             type_counter.get("connectivity:connection_id_retired", 0)
                                              + type_counter.get("transport:connection_id_retired", 0)
                                              + _count_frame_type("retire_connection_id"),
        "path_validation_started":           type_counter.get("connectivity:path_validation_started", 0)
                                              + type_counter.get("transport:path_validation", 0),
        "path_validation_succeeded":         type_counter.get("connectivity:path_validated", 0)
                                              + type_counter.get("connectivity:path_validation_succeeded", 0),
        "path_validation_failed":            type_counter.get("connectivity:path_validation_failed", 0),

        # MitM-replay-relevant (general)
        "packet_dropped_total":              type_counter.get("transport:packet_dropped", 0),
        "decryption_failure":                _count_dropped_with_trigger("decryption_failure"),
        "key_unavailable":                   _count_dropped_with_trigger("key_unavailable"),
        "unknown_connection_id":             _count_dropped_with_trigger("unknown_connection_id"),

        # Connection lifecycle. picoquic emits these as free-form
        # info:message events rather than structured connection_closed
        # events; we count both paths.
        "connection_started":                type_counter.get("connectivity:connection_started", 0),
        "connection_closed":                 type_counter.get("connectivity:connection_closed", 0)
                                              + _count_picoquic_close_messages("clearing context on connection close"),
        "idle_timeout_closes":               _count_close_with_trigger("idle_timeout")
                                              + _count_picoquic_close_messages("idle"),
        "stateless_reset_closes":            _count_close_with_trigger("stateless_reset"),
    }

    nd["qlog_features"] = qlog_features
    return _step(state, nd, "qlog_analysis",
                 f"qlog parsed — {parsed_files} files, {len(all_events)} events, "
                 f"{type_counter.get('transport:packet_dropped', 0)} drops, "
                 f"{qlog_features['retry_packets_sent']} retries, "
                 f"{qlog_features['idle_timeout_closes']} idle timeouts.")


# ── New attack-specific agents (FINE 2026: 0-RTT replay,
#    Retry-token abuse, CID exhaustion). Each extracts the qlog/PCAP
#    evidence specific to the attack class it covers and reasons
#    against the protocol-grounded signature for that class. The
#    fusion agent consumes the union of their outputs.
# ──────────────────────────────────────────────────────────────


def _qlog_features(state: OrcaWorkflowState) -> Optional[Dict[str, Any]]:
    """Return the qlog feature record if a qlog-parsing upstream agent
    has populated it; otherwise None.

    Currently `qlog_analysis_agent` is not implemented (planned per the
    refinement brief). When it lands it will populate
    `state['network_domain']['qlog_features']` with per-event-type
    counts. Until then, the attack-specific agents below degrade
    gracefully and record the missing-evidence state in
    uncertainty_notes.
    """
    nd = state.get("network_domain") or {}
    return nd.get("qlog_features")


# ── Cross-source evidence-gathering helpers ─────────────────────
# These are consumed by the three attack-specific agents below.
# Each agent receives an `evidence` dict assembled from six sources
# (pcap, qlog, strace, binary symbols, attacker-side logs, Legion
# delay-log success rate) so the LLM has structured, attack-relevant
# inputs instead of a single shallow stats blob.

import re as _re
from pathlib import Path as _Path


def _cell_dir_from_state(state: OrcaWorkflowState) -> Optional[_Path]:
    """Derive the cell artefact directory from pcap_path. The cell
    directory is the parent of attack.pcap and contains attacker_logs/,
    delay_logs/, qlog/, server.strace, etc."""
    pcap = state.get("pcap_path") or (state.get("network_domain") or {}).get("pcap_path")
    if not pcap:
        return None
    p = _Path(pcap)
    return p.parent if p.is_file() else None


def _strace_path_from_state(state: OrcaWorkflowState) -> Optional[str]:
    nd = state.get("network_domain") or {}
    return state.get("strace_path") or nd.get("strace_path")


def _pcap_summary_for_agent(state: OrcaWorkflowState) -> Dict[str, Any]:
    """Compact PCAP-side summary the agent will quote."""
    nd = state.get("network_domain") or {}
    stats = nd.get("statistics") or {}
    return {
        "total_packets":             nd.get("total_packets"),
        "udp_packets":               nd.get("udp_packets"),
        "unique_connections":        len(nd.get("connections") or []),
        "capture_duration_seconds":  nd.get("capture_duration_seconds"),
        "handshake_completion_rate": stats.get("handshake_completion_rate"),
        "single_packet_ratio":       stats.get("single_packet_ratio"),
        "bidirectional_flows":       stats.get("bidirectional_flows"),
    }


def _qlog_summary_for_agent(state: OrcaWorkflowState,
                             fields_of_interest: Optional[List[str]] = None
                             ) -> Dict[str, Any]:
    qf = (state.get("network_domain") or {}).get("qlog_features") or {}
    out: Dict[str, Any] = {
        "available":    qf.get("available", False),
        "total_events": qf.get("total_events"),
        "files_parsed": qf.get("files_parsed"),
    }
    for f in (fields_of_interest or []):
        out[f] = qf.get(f)
    counts = qf.get("event_counts_by_name") or {}
    if isinstance(counts, dict) and counts:
        out["top_event_types"] = dict(
            sorted(counts.items(), key=lambda x: -x[1])[:10]
        )
    return out


def _strace_summary_minimal(strace_path: Optional[str]) -> Dict[str, Any]:
    """Syscall histogram from server.strace. Capped to keep cheap."""
    if not strace_path:
        return {"available": False, "reason": "no strace_path"}
    p = _Path(strace_path)
    if not p.is_file() or p.stat().st_size == 0:
        return {"available": False, "reason": "strace empty or missing"}
    from collections import Counter as _Counter
    counts: _Counter = _Counter()
    total = 0
    syscall_re = _re.compile(r"\b([a-z_][a-z0-9_]*)\(")
    try:
        with p.open(errors="ignore") as fh:
            for i, line in enumerate(fh):
                if i >= 500_000:
                    break
                m = syscall_re.search(line)
                if m:
                    counts[m.group(1)] += 1
                    total += 1
    except Exception as e:
        return {"available": False, "reason": f"parse error: {e}"}
    return {
        "available":      True,
        "total_syscalls": total,
        "top10":          dict(counts.most_common(10)),
        "recvfrom":       counts.get("recvfrom", 0),
        "sendto":         counts.get("sendto", 0),
        "recvmsg":        counts.get("recvmsg", 0),
        "sendmsg":        counts.get("sendmsg", 0),
        "epoll_wait":     counts.get("epoll_wait", 0),
        "epoll_ctl":      counts.get("epoll_ctl", 0),
    }


def _attacker_observed_rate(cell_dir: Optional[_Path]) -> Dict[str, Any]:
    """Pull target/actual attack rates from attacker_logs/*.summary files.

    These are written by the attacker scripts (attacker_flood.py,
    attacker_retry_token_abuse.py, etc.) and are the authoritative
    answer to 'did the attack actually deliver at the configured rate?'
    """
    if cell_dir is None:
        return {"available": False, "reason": "no cell_dir"}
    log_dir = cell_dir / "attacker_logs"
    if not log_dir.is_dir():
        return {"available": False, "reason": "no attacker_logs dir"}
    by_level: Dict[int, Dict[str, float]] = {}
    sum_pat = _re.compile(r"target_rate=([\d.]+)/s\s+actual_rate=([\d.]+)/s")
    lvl_pat = _re.compile(r"attacker_level(\d+)")
    for f in log_dir.glob("attacker_level*.summary"):
        try:
            txt = f.read_text()
            m = sum_pat.search(txt)
            lvl_m = lvl_pat.search(f.name)
            if m and lvl_m:
                by_level[int(lvl_m.group(1))] = {
                    "target_rate": float(m.group(1)),
                    "actual_rate": float(m.group(2)),
                    "summary_text": txt.strip()[:200],
                }
        except Exception:
            pass
    if not by_level:
        return {"available": False, "reason": "no parsable summaries"}
    levels = sorted(by_level.keys())
    return {
        "available":          True,
        "levels_observed":    levels,
        "peak_target_rate":   max(b["target_rate"] for b in by_level.values()),
        "peak_actual_rate":   max(b["actual_rate"] for b in by_level.values()),
        "by_level":           {str(k): v for k, v in by_level.items()},
    }


def _legitimate_client_impact(cell_dir: Optional[_Path]) -> Dict[str, Any]:
    """Read Legion per-level .status JSONs — the legitimate-client side
    of the experiment. Returns success rate per level so the agent can
    answer 'did the defence let real clients keep working?'."""
    if cell_dir is None:
        return {"available": False, "reason": "no cell_dir"}
    log_dir = cell_dir / "delay_logs" / "legion"
    if not log_dir.is_dir():
        return {"available": False, "reason": "no delay_logs/legion dir"}
    by_level: Dict[int, Dict[str, Any]] = {}
    for f in log_dir.glob("*.status"):
        try:
            d = json.loads(f.read_text())
            lvl = d.get("level")
            if lvl is None:
                continue
            by_level[int(lvl)] = {
                "success_rate":           d.get("success_rate"),
                "mean_duration_s":        d.get("mean_duration_s"),
                "measurements_attempted": d.get("measurements_attempted"),
                "successes":              d.get("successes"),
            }
        except Exception:
            pass
    if not by_level:
        return {"available": False, "reason": "no parsable .status"}
    levels = sorted(by_level.keys())
    successes = [by_level[l]["success_rate"] for l in levels
                 if by_level[l].get("success_rate") is not None]
    return {
        "available":              True,
        "levels":                 levels,
        "baseline_success_rate":  by_level.get(0, {}).get("success_rate"),
        "peak_attack_level":      max(levels),
        "peak_attack_success_rate": by_level[max(levels)].get("success_rate"),
        "min_success_rate":       min(successes) if successes else None,
        "mean_success_rate":      sum(successes)/len(successes) if successes else None,
        "by_level":               {str(k): v for k, v in by_level.items()},
    }


def _binary_function_matches(state: OrcaWorkflowState,
                              patterns: List[str]) -> List[Dict[str, Any]]:
    """Return up to 20 binary functions whose names match any pattern
    (substring, case-insensitive)."""
    bd = state.get("binary_domain") or {}
    sa = bd.get("static_analysis") or {}
    funcs = sa.get("functions") or []
    matched: List[Dict[str, Any]] = []
    patterns_l = [p.lower() for p in patterns]
    for f in funcs:
        if isinstance(f, dict):
            nm = f.get("name", "") or ""
            callers = f.get("callers") or []
            size = f.get("size")
        elif isinstance(f, str):
            nm = f
            callers = []
            size = None
        else:
            continue
        if not nm:
            continue
        nml = nm.lower()
        if any(p in nml for p in patterns_l):
            matched.append({
                "name":         nm,
                "n_callers":    len(callers) if isinstance(callers, list) else 0,
                "size_bytes":   size,
            })
            if len(matched) >= 20:
                break
    return matched


# ── Agent: 0-RTT Replay ────────────────────────────────────────

def zero_rtt_replay_agent(state: OrcaWorkflowState) -> Dict:
    """Multi-source assessment of 0-RTT replay behaviour.

    The key question RFC 9001 §9.2 raises is whether the server has
    single-use protection on session tickets. Our attacker drives the
    server with a single saved ticket re-used 20-100 times/s; a
    compliant server accepts at most one replay, the rest must be
    rejected (early_data_rejected) or downgraded to 1-RTT.
    """
    nd = state.get("network_domain") or {}
    impl = state.get("implementation") or "unknown"
    cell_dir = _cell_dir_from_state(state)

    ev = {
        "implementation":  impl,
        "classification":  (nd.get("attack_classification") or {}).get("classification"),
        "pcap":            _pcap_summary_for_agent(state),
        "qlog":            _qlog_summary_for_agent(state, [
            "early_data_accepted",
            "early_data_rejected",
            "zero_rtt_packets_received",
            "duplicate_packet_number_zero_rtt",
        ]),
        "strace":          _strace_summary_minimal(_strace_path_from_state(state)),
        "attacker_rate":   _attacker_observed_rate(cell_dir),
        "legion_impact":   _legitimate_client_impact(cell_dir),
        "binary_defence":  _binary_function_matches(state, [
            "anti_replay", "early_data_replay", "session_ticket_replay",
            "0rtt_replay", "replay_protect", "ticket_replay",
            "session_ticket_validate", "early_data_check",
            # Also catch session-ticket store/lookup, which is where
            # single-use enforcement would live if present.
            "session_ticket", "anti_replay_db",
        ]),
    }

    usage_checkpoint = LLMProvider.usage_count()
    try:
        result = llm.query_json(
            system="""You are a QUIC security analyst evaluating 0-RTT
REPLAY behaviour for one specific server binary running under attack
on a hardware testbed. Reason against RFC 9001 §9.2 (0-RTT
anti-replay) and RFC 8446 §8 (TLS 1.3 0-RTT anti-replay strategies).

ATTACK MECHANICS:
A 0-RTT replay attacker first opens one real connection to obtain a
session ticket, then attempts many resumed connections using THE
SAME ticket and SAME early-data payload bytes. A spec-compliant
server must accept early data at most once per ticket; subsequent
replays must be rejected (downgraded to 1-RTT) or the early-data
section must be discarded. Acceptable strategies (RFC 8446 §8):
  - single-use tickets,
  - frequency-limit tracking per ticket,
  - server-side replay cache (e.g. bloom filter of accepted nonces).

The interesting question is what THIS implementation DOES with
ticket re-use. PCAP cannot see ticket identity (encrypted). qlog
events are authoritative.

EVIDENCE INTERPRETATION:

* attacker_rate.by_level shows how many resumed-connection attempts
  the attacker made at each intensity level. Compare with qlog
  early_data_accepted vs early_data_rejected ratios.
* If early_data_accepted ≈ attacker attempts and early_data_rejected
  ≈ 0, the server is accepting replays — RFC 9001 §9.2 violation.
* If early_data_accepted is ≈1 per ticket and the rest are rejected,
  the server has working anti-replay.
* zero_rtt_packets_received tells you how many 0-RTT-typed packets
  the server saw. If 0 with high attacker_rate, either the attacker
  failed to obtain a ticket or 0-RTT isn't enabled.
* duplicate_packet_number_zero_rtt > 0 directly indicates the server
  detected replay at the QUIC layer.
* binary_defence functions: presence of `anti_replay_db_add_func`,
  `tlsservercontext_get_anti_replay`, or similar means anti-replay
  code exists. ABSENCE is a strong signal the implementation lacks
  this defence.
* legion_impact: if Legion clients still succeed during attack, the
  server is not crippled even if it accepted replays — relevant for
  paper's operational-impact narrative.

Return JSON with this STRUCTURED schema (keep ALL keys):
{
  "agent_id": "zero_rtt_replay",
  "attack_confirmed": true|false,
  "attack_confirmed_evidence": [string],

  "binary_defence_implementation": {
    "is_implemented": true|false|null,
    "functions_present": [string],
    "functions_evidence": [string]
  },

  "runtime_defence_activation": {
    "activated": true|false|null,
    "early_data_accepted": int|null,
    "early_data_rejected": int|null,
    "ratio_rejected": float|null,
    "evidence": [string]
  },

  "operational_impact": {
    "legit_client_baseline_rate": float|null,
    "legit_client_min_rate_under_attack": float|null,
    "outcome": "mitigated|partial|failed|silent",
    "evidence": [string]
  },

  "rfc_compliance_verdict": {
    "compliant_9001_9_2": true|false|"unclear",
    "compliant_8446_8":  true|false|"unclear",
    "notes": [string]
  },

  "confidence": 0.0-1.0,
  "summary": "1-2 sentence executive summary for paper §IV-G",
  "rfc_citations": ["RFC 9001 §9.2", "RFC 8446 §8"],

  /* legacy keys for backward compat */
  "outcome": "resisted|accepted_replay|legit_zero_rtt|uncertain",
  "evidence_for":    [string],
  "evidence_against":[string],
  "uncertainty_notes":[string],
  "reasoning": string
}""",
            user=f"""Implementation under test: {impl}
Upstream classifier label: {ev['classification']}

— PCAP-side summary —
{json.dumps(ev['pcap'], indent=2, default=str)}

— qlog-side summary —
{json.dumps(ev['qlog'], indent=2, default=str)}

— strace-side summary —
{json.dumps(ev['strace'], indent=2, default=str)}

— Attacker-side ground truth —
{json.dumps(ev['attacker_rate'], indent=2, default=str)}

— Legitimate client impact —
{json.dumps(ev['legion_impact'], indent=2, default=str)}

— Binary symbols matching anti-replay / session-ticket patterns —
{json.dumps(ev['binary_defence'], indent=2, default=str)}

Produce the structured JSON described in the system prompt.""",
            agent="zero_rtt_replay",
        )
        result.setdefault("agent_id", "zero_rtt_replay")
        for k in ("evidence_for", "evidence_against", "uncertainty_notes",
                  "rfc_citations", "attack_confirmed_evidence"):
            result.setdefault(k, [])
        result.setdefault("binary_defence_implementation", {})
        result.setdefault("runtime_defence_activation", {})
        result.setdefault("operational_impact", {})
        result.setdefault("rfc_compliance_verdict", {})
        result["usage"] = LLMProvider.usage_since(usage_checkpoint)
        nd["zero_rtt_replay"] = result
        cost = result["usage"].get("cost_usd", 0.0)
        outcome = result.get("outcome", "?")
        return _step(state, nd, "zero_rtt_replay",
                     f"0-RTT replay assessment: {outcome} (${cost:.4f}).")
    except Exception as exc:
        nd["zero_rtt_replay"] = {
            "agent_id": "zero_rtt_replay",
            "outcome": "error",
            "error": str(exc),
            "usage": LLMProvider.usage_since(usage_checkpoint),
        }
        return _step(state, nd, "zero_rtt_replay", f"0-RTT replay assessment failed: {exc}")


# ── Agent: Retry-Token Abuse ───────────────────────────────────

def retry_token_abuse_agent(state: OrcaWorkflowState) -> Dict:
    """Multi-source assessment of retry-token-abuse behaviour.

    Gathers PCAP, qlog, strace, attacker-side, Legion-side, and binary
    symbol evidence; then asks the LLM to produce a per-mechanism
    structured verdict that answers:
      1. Did the attacker actually deliver retry-token-shaped traffic?
      2. Does the binary implement retry-token validation, and which
         functions?
      3. Did the defence activate at runtime?
      4. Did legitimate clients survive the attack?
      5. Is the implementation RFC 9000 §8.1.4 compliant?
    """
    nd = state.get("network_domain") or {}
    impl = state.get("implementation") or "unknown"
    cell_dir = _cell_dir_from_state(state)

    ev = {
        "implementation":  impl,
        "classification":  (nd.get("attack_classification") or {}).get("classification"),
        "pcap":            _pcap_summary_for_agent(state),
        "qlog":            _qlog_summary_for_agent(state, [
            "retry_packets_sent",
            "initial_packets_with_token",
            "retry_token_validation_failed",
            "packet_dropped_total",
            "decryption_failure",
        ]),
        "strace":          _strace_summary_minimal(_strace_path_from_state(state)),
        "attacker_rate":   _attacker_observed_rate(cell_dir),
        "legion_impact":   _legitimate_client_impact(cell_dir),
        "binary_defence":  _binary_function_matches(state, [
            "retry_token", "stateless_retry", "format_retry",
            "verify_retry_token", "prepare_retry_token", "queue_retry",
            "retry_packet", "validate_token", "token_check",
        ]),
    }

    usage_checkpoint = LLMProvider.usage_count()
    try:
        result = llm.query_json(
            system="""You are a QUIC security analyst evaluating
RETRY-TOKEN ABUSE behaviour for one specific server binary running
under attack on a hardware testbed. Reason against RFC 9000 §8.1.4
(Retry token semantics) and §17.2.5 (Retry packet format).

ATTACK MECHANICS:
A retry-token-abuse attacker bombards the server with Initial packets
carrying bogus 16-byte tokens drawn from /dev/urandom. A spec-compliant
server must cryptographically validate each token (typically AEAD with
a server secret); validation should be constant-cost and the server
should drop the connection attempt on validation failure.

The interesting question is not "is there an attack?" (the attacker
log proves that). The interesting question is what this specific
implementation DOES with bogus tokens — whether it accepts them
silently, whether validation cost scales with attack rate, whether
legitimate clients survive concurrently.

EVIDENCE INTERPRETATION:

* attacker_rate.peak_actual_rate is the ground truth for the attack
  intensity actually delivered. Compare to peak_target_rate to know
  if the attacker host saturated.
* qlog.retry_packets_sent > 0 means the server is in Retry-required
  mode and emitted Retry packets. = 0 with high attacker_rate means
  the server accepted Initials without forcing Retry (Retry-NOT-required
  mode) — bogus tokens are being silently dropped instead.
* qlog.retry_token_validation_failed > 0 means the server tried to
  validate tokens and rejected some. Note: this counter only exists
  if the qlog dialect emits it.
* binary_defence.functions_present lists the actual validation
  routines compiled into the binary. If empty, the implementation
  has no specific retry-token logic.
* legion_impact.min_success_rate tells you whether legitimate clients
  collapsed during the attack.
* strace.recvfrom / recvmsg measure how much the server worked.

Return JSON with this STRUCTURED schema (keep ALL keys, fill what's
known, use null for unknown):
{
  "agent_id": "retry_token_abuse",
  "attack_confirmed": true|false,
  "attack_confirmed_evidence": [string],

  "binary_defence_implementation": {
    "is_implemented": true|false|null,
    "functions_present": [string],
    "functions_evidence": [string]
  },

  "runtime_defence_activation": {
    "activated": true|false|null,
    "retry_packets_sent": int|null,
    "validation_failures_logged": int|null,
    "evidence": [string]
  },

  "operational_impact": {
    "legit_client_baseline_rate": float|null,
    "legit_client_min_rate_under_attack": float|null,
    "outcome": "mitigated|partial|failed|silent",
    "evidence": [string]
  },

  "rfc_compliance_verdict": {
    "compliant_8_1_4": true|false|"unclear",
    "compliant_17_2_5": true|false|"unclear",
    "notes": [string]
  },

  "confidence": 0.0-1.0,

  "summary": "1-2 sentence executive summary the paper §IV-G can quote",

  "rfc_citations": ["RFC 9000 §8.1.4", "RFC 9000 §17.2.5"],

  /* legacy keys for backward compat with evidence_fusion_agent */
  "outcome": "validated_correctly|accepted_invalid_tokens|silent_rejection|uncertain",
  "evidence_for":    [string],
  "evidence_against":[string],
  "uncertainty_notes":[string],
  "reasoning": string
}""",
            user=f"""Implementation under test: {impl}
Upstream classifier label: {ev['classification']}

— PCAP-side summary (server-side capture, attack.pcap) —
{json.dumps(ev['pcap'], indent=2, default=str)}

— qlog-side summary (per-connection .qlog files from server) —
{json.dumps(ev['qlog'], indent=2, default=str)}

— strace-side summary (server syscall histogram during sweep) —
{json.dumps(ev['strace'], indent=2, default=str)}

— Attacker-side ground truth (from attacker.log on C4) —
{json.dumps(ev['attacker_rate'], indent=2, default=str)}

— Legitimate client impact (Legion per-level .status JSONs) —
{json.dumps(ev['legion_impact'], indent=2, default=str)}

— Binary symbols matching retry-token mechanism patterns —
{json.dumps(ev['binary_defence'], indent=2, default=str)}

Produce the structured JSON described in the system prompt.""",
            agent="retry_token_abuse",
        )
        result.setdefault("agent_id", "retry_token_abuse")
        for k in ("evidence_for", "evidence_against", "uncertainty_notes",
                  "rfc_citations", "attack_confirmed_evidence"):
            result.setdefault(k, [])
        result.setdefault("binary_defence_implementation", {})
        result.setdefault("runtime_defence_activation", {})
        result.setdefault("operational_impact", {})
        result.setdefault("rfc_compliance_verdict", {})
        result["usage"] = LLMProvider.usage_since(usage_checkpoint)
        nd["retry_token_abuse"] = result
        cost = result["usage"].get("cost_usd", 0.0)
        outcome = result.get("outcome", "?")
        return _step(state, nd, "retry_token_abuse",
                     f"Retry-token abuse assessment: {outcome} (${cost:.4f}).")
    except Exception as exc:
        nd["retry_token_abuse"] = {
            "agent_id": "retry_token_abuse",
            "outcome": "error",
            "error": str(exc),
            "usage": LLMProvider.usage_since(usage_checkpoint),
        }
        return _step(state, nd, "retry_token_abuse", f"Retry-token abuse assessment failed: {exc}")


# ── Agent: Connection-ID Exhaustion / Migration Abuse ──────────

def cid_exhaustion_agent(state: OrcaWorkflowState) -> Dict:
    """Multi-source assessment of CID-exhaustion behaviour.

    The attacker opens many concurrent connections and asks each one
    to track up to 128 server-issued CIDs (well past RFC 9000's
    minimum of 2). A spec-compliant server CAPS its own CID issuance
    at active_connection_id_limit regardless of what the client asked
    for. We check whether picoquic/msquic/ngtcp2/quiche cap or honour.
    """
    nd = state.get("network_domain") or {}
    impl = state.get("implementation") or "unknown"
    cell_dir = _cell_dir_from_state(state)

    ev = {
        "implementation":  impl,
        "classification":  (nd.get("attack_classification") or {}).get("classification"),
        "pcap":            _pcap_summary_for_agent(state),
        "qlog":            _qlog_summary_for_agent(state, [
            "connection_id_issued",
            "connection_id_retired",
            "path_validation_started",
            "path_validation_succeeded",
            "path_validation_failed",
            "unknown_connection_id",
        ]),
        "strace":          _strace_summary_minimal(_strace_path_from_state(state)),
        "attacker_rate":   _attacker_observed_rate(cell_dir),
        "legion_impact":   _legitimate_client_impact(cell_dir),
        "binary_defence":  _binary_function_matches(state, [
            "active_connection_id_limit", "max_active_cid", "max_cids",
            "cid_pool", "connection_id_limit", "cid_table",
            "new_connection_id", "retire_connection_id",
            "create_local_cnxid", "find_local_cnxid",
        ]),
    }

    usage_checkpoint = LLMProvider.usage_count()
    try:
        result = llm.query_json(
            system="""You are a QUIC security analyst evaluating
CONNECTION-ID EXHAUSTION behaviour for one specific server binary
running under attack on a hardware testbed. Reason against
RFC 9000 §5.1 (Connection IDs), §5.1.2 (Consuming and Retiring),
§5.1.1 (Issuing), §9 (Connection Migration), §8.2 (Path Validation).

ATTACK MECHANICS:
The attacker opens N concurrent QUIC connections (default 20-100
new conn/s), each one advertising
`local_active_connection_id_limit = 128` to invite the server to
issue up to 128 CIDs per connection. Held for 60s. The hostile
intent is to force the server to track 128 × N CIDs in memory.

RFC 9000 §5.1.1 says: the server "MUST NOT" issue connection IDs
above either side's `active_connection_id_limit`. RFC 9000 §5.1.2
governs CID retirement.

KEY DISTINGUISHING SIGNAL:
- If `connection_id_issued / per_connection` ≤ 8 (or whatever the
  server's hardcoded cap is), the server is CAPPING ITS OWN
  ISSUANCE despite the client's greedy request → bounded_state.
- If `connection_id_issued / per_connection` ≈ 128 (matching the
  client's request), the server is HONOURING the greedy ask →
  state_growth_observed → potential RFC §5.1.1 violation.

EVIDENCE INTERPRETATION:
* attacker_rate.peak_actual_rate is the actual rate of new
  connections delivered.
* qlog.connection_id_issued / pcap.unique_connections gives average
  CIDs issued per connection. picoquic empirically caps at 8.
* binary_defence functions: look for an `active_connection_id_limit`
  constant or `max_cids` setter. Absence is interesting evidence
  that the implementation may not have a hard cap.
* legion_impact under cid_exhaustion: this is where the paper
  needs the operational impact narrative.

Return JSON with this STRUCTURED schema (keep ALL keys):
{
  "agent_id": "cid_exhaustion",
  "attack_confirmed": true|false,
  "attack_confirmed_evidence": [string],

  "binary_defence_implementation": {
    "is_implemented": true|false|null,
    "functions_present": [string],
    "active_connection_id_limit_cap_observed": int|null,
    "functions_evidence": [string]
  },

  "runtime_defence_activation": {
    "activated": true|false|null,
    "cids_issued_total": int|null,
    "cids_per_connection_avg": float|null,
    "cap_honoured": true|false|null,
    "evidence": [string]
  },

  "operational_impact": {
    "legit_client_baseline_rate": float|null,
    "legit_client_min_rate_under_attack": float|null,
    "outcome": "mitigated|partial|failed|silent",
    "evidence": [string]
  },

  "rfc_compliance_verdict": {
    "compliant_5_1_1": true|false|"unclear",
    "compliant_5_1_2": true|false|"unclear",
    "notes": [string]
  },

  "confidence": 0.0-1.0,
  "summary": "1-2 sentence executive summary for paper §IV-G",
  "rfc_citations": ["RFC 9000 §5.1", "RFC 9000 §5.1.1", "RFC 9000 §5.1.2"],

  /* legacy keys for backward compat */
  "outcome": "bounded_state|state_growth_observed|uncertain",
  "evidence_for":    [string],
  "evidence_against":[string],
  "uncertainty_notes":[string],
  "reasoning": string
}""",
            user=f"""Implementation under test: {impl}
Upstream classifier label: {ev['classification']}

— PCAP-side summary —
{json.dumps(ev['pcap'], indent=2, default=str)}

— qlog-side summary —
{json.dumps(ev['qlog'], indent=2, default=str)}

— strace-side summary —
{json.dumps(ev['strace'], indent=2, default=str)}

— Attacker-side ground truth (concurrent connections held, each requesting 128 CIDs) —
{json.dumps(ev['attacker_rate'], indent=2, default=str)}

— Legitimate client impact —
{json.dumps(ev['legion_impact'], indent=2, default=str)}

— Binary symbols matching CID-limit / CID-issuance patterns —
{json.dumps(ev['binary_defence'], indent=2, default=str)}

Produce the structured JSON described in the system prompt.""",
            agent="cid_exhaustion",
        )
        result.setdefault("agent_id", "cid_exhaustion")
        for k in ("evidence_for", "evidence_against", "uncertainty_notes",
                  "rfc_citations", "attack_confirmed_evidence"):
            result.setdefault(k, [])
        result.setdefault("binary_defence_implementation", {})
        result.setdefault("runtime_defence_activation", {})
        result.setdefault("operational_impact", {})
        result.setdefault("rfc_compliance_verdict", {})
        result["usage"] = LLMProvider.usage_since(usage_checkpoint)
        nd["cid_exhaustion"] = result
        cost = result["usage"].get("cost_usd", 0.0)
        outcome = result.get("outcome", "?")
        return _step(state, nd, "cid_exhaustion",
                     f"CID exhaustion assessment: {outcome} (${cost:.4f}).")
    except Exception as exc:
        nd["cid_exhaustion"] = {
            "agent_id": "cid_exhaustion",
            "outcome": "error",
            "error": str(exc),
            "usage": LLMProvider.usage_since(usage_checkpoint),
        }
        return _step(state, nd, "cid_exhaustion", f"CID exhaustion assessment failed: {exc}")


# ── Agent: Connection Flooding ─────────────────────────────────

def flood_agent(state: OrcaWorkflowState) -> Dict:
    """Multi-source assessment of connection-flooding behaviour.

    Confirms the attack and attributes it to a specific binary defence by
    correlating attacker connection rate (C4 attacker.log), server-side
    PCAP connection acceptance, qlog Retry-sent counts, syscall trace of
    the accept-path, and the Retry-token / anti-amplification symbols
    in the binary.
    """
    nd = state.get("network_domain") or {}
    impl = state.get("implementation") or "unknown"
    cell_dir = _cell_dir_from_state(state)

    ev = {
        "implementation":  impl,
        "classification":  (nd.get("attack_classification") or {}).get("classification"),
        "pcap":            _pcap_summary_for_agent(state),
        "qlog":            _qlog_summary_for_agent(state, [
            "retry_packets_sent",
            "initial_packets_received",
            "initial_packets_with_token",
            "packet_dropped_total",
            "anti_amplification_triggered",
            "connection_started",
        ]),
        "strace":          _strace_summary_minimal(_strace_path_from_state(state)),
        "attacker_rate":   _attacker_observed_rate(cell_dir),
        "legion_impact":   _legitimate_client_impact(cell_dir),
        "binary_defence":  _binary_function_matches(state, [
            "retry_token", "stateless_retry", "format_retry",
            "queue_retry", "retry_packet",
            "anti_amplification", "amplification_limit",
            "rate_limit", "accept_connection", "queue_initial",
            "max_concurrent",
        ]),
    }

    usage_checkpoint = LLMProvider.usage_count()
    try:
        result = llm.query_json(
            system="""You are a QUIC security analyst evaluating
CONNECTION-FLOODING behaviour for one specific server binary running
under attack on a hardware testbed. Reason against RFC 9000 §8.1
(address validation) and §21.1 (anti-amplification limit).

ATTACK MECHANICS:
A connection-flooding attacker sends Initial packets at high rate from
spoofable source addresses. A spec-compliant server uses two related
defences: Retry-token issuance to force the client to demonstrate a
return path before commiting state, and the anti-amplification limit
that caps server-to-client bytes at 3x client-to-server bytes on an
unvalidated path.

The interesting question is not "is there an attack?" (attacker_rate
proves it). The interesting questions are which defence the
implementation activated, at what attacker rate, and whether
legitimate clients survived.

EVIDENCE INTERPRETATION:
* attacker_rate.peak_actual_rate ground-truths the attack intensity.
* qlog.retry_packets_sent > 0 means the server entered Retry mode.
  = 0 with high attacker_rate means the server accepted Initials
  without Retry (either Retry not activated, or rate-limited).
* qlog.initial_packets_received compared against attacker_rate gives
  the admission-vs-attempt ratio.
* binary_defence.functions_present lists which Retry / amplification
  / rate-limit functions exist in the shipped binary.
* legion_impact.min_success_rate tells whether the attack hurt
  legitimate clients.
* strace.recvfrom / recvmsg measures how much work the server did.

Return JSON with this STRUCTURED schema (keep ALL keys, use null when
unknown):
{
  "agent_id": "flood",
  "attack_confirmed": true|false,
  "attack_confirmed_evidence": [string],

  "binary_defence_implementation": {
    "is_implemented": true|false|null,
    "functions_present": [string],
    "functions_evidence": [string]
  },

  "runtime_defence_activation": {
    "activated": true|false|null,
    "retry_packets_sent": int|null,
    "initial_admission_ratio": float|null,
    "evidence": [string]
  },

  "operational_impact": {
    "legit_client_baseline_rate": float|null,
    "legit_client_min_rate_under_attack": float|null,
    "outcome": "mitigated|partial|failed|silent",
    "evidence": [string]
  },

  "rfc_compliance_verdict": {
    "compliant_8_1": true|false|"unclear",
    "compliant_21_1": true|false|"unclear",
    "notes": [string]
  },

  "confidence": 0.0-1.0,
  "summary": "1-2 sentence executive summary",
  "rfc_citations": ["RFC 9000 §8.1", "RFC 9000 §21.1"],

  /* legacy keys for evidence_fusion_agent */
  "outcome": "mitigated_by_retry|mitigated_by_rate_limit|absorbed_silently|overwhelmed|uncertain",
  "evidence_for":    [string],
  "evidence_against":[string],
  "uncertainty_notes":[string],
  "reasoning": string
}""",
            user=f"""Implementation under test: {impl}
Upstream classifier label: {ev['classification']}

— PCAP-side summary (server-side capture) —
{json.dumps(ev['pcap'], indent=2, default=str)}

— qlog-side summary (per-connection .qlog from server) —
{json.dumps(ev['qlog'], indent=2, default=str)}

— strace-side summary (server syscall histogram) —
{json.dumps(ev['strace'], indent=2, default=str)}

— Attacker-side ground truth (attacker.log on C4) —
{json.dumps(ev['attacker_rate'], indent=2, default=str)}

— Legitimate client impact (Legion per-level .status JSONs) —
{json.dumps(ev['legion_impact'], indent=2, default=str)}

— Binary symbols matching flood-defence patterns —
{json.dumps(ev['binary_defence'], indent=2, default=str)}

Produce the structured JSON described in the system prompt.""",
            agent="flood",
        )
        result.setdefault("agent_id", "flood")
        for k in ("evidence_for", "evidence_against", "uncertainty_notes",
                  "rfc_citations", "attack_confirmed_evidence"):
            result.setdefault(k, [])
        result.setdefault("binary_defence_implementation", {})
        result.setdefault("runtime_defence_activation", {})
        result.setdefault("operational_impact", {})
        result.setdefault("rfc_compliance_verdict", {})
        result["usage"] = LLMProvider.usage_since(usage_checkpoint)
        nd["flood"] = result
        cost = result["usage"].get("cost_usd", 0.0)
        outcome = result.get("outcome", "?")
        return _step(state, nd, "flood",
                     f"Flood assessment: {outcome} (${cost:.4f}).")
    except Exception as exc:
        nd["flood"] = {
            "agent_id": "flood",
            "outcome": "error",
            "error": str(exc),
            "usage": LLMProvider.usage_since(usage_checkpoint),
        }
        return _step(state, nd, "flood", f"Flood assessment failed: {exc}")


# ── Agent: Slowloris (connection holding) ──────────────────────

def slowloris_agent(state: OrcaWorkflowState) -> Dict:
    """Multi-source assessment of slowloris connection-holding behaviour.

    Slowloris completes handshakes but never sends application data, so
    each held connection occupies an idle-timeout slot. A spec-compliant
    server enforces max_idle_timeout (RFC 9000 §10.1) and stream limits
    (§4.6). This agent correlates the idle-timeout / stream-limit
    symbols in the binary with qlog idle-timeout-close events and the
    syscall epoll activity to see which defence actually fired.
    """
    nd = state.get("network_domain") or {}
    impl = state.get("implementation") or "unknown"
    cell_dir = _cell_dir_from_state(state)

    ev = {
        "implementation":  impl,
        "classification":  (nd.get("attack_classification") or {}).get("classification"),
        "pcap":            _pcap_summary_for_agent(state),
        "qlog":            _qlog_summary_for_agent(state, [
            "idle_timeout_closes",
            "connection_closed",
            "max_streams_reached",
            "stream_state_updated",
            "connection_id_retired",
        ]),
        "strace":          _strace_summary_minimal(_strace_path_from_state(state)),
        "attacker_rate":   _attacker_observed_rate(cell_dir),
        "legion_impact":   _legitimate_client_impact(cell_dir),
        "binary_defence":  _binary_function_matches(state, [
            "idle_timeout", "max_idle", "connection_timeout",
            "queue_busy_packet", "adjust_max_connection",
            "close_idle", "max_streams_uni", "max_streams_bidi",
            "max_concurrent", "stream_limit",
            "connection_cleanup", "evict_connection",
        ]),
    }

    usage_checkpoint = LLMProvider.usage_count()
    try:
        result = llm.query_json(
            system="""You are a QUIC security analyst evaluating
SLOWLORIS connection-holding behaviour for one specific server binary
running under attack on a hardware testbed. Reason against RFC 9000
§10.1 (idle timeout) and §4.6 (stream concurrency limits).

ATTACK MECHANICS:
A slowloris attacker completes handshakes at a steady rate but never
sends application data, so each connection occupies server state
indefinitely. A spec-compliant server caps connection lifetime with
max_idle_timeout (§10.1) and caps concurrent open streams with the
stream-limit transport parameters (§4.6). When either limit is
reached, the server should close the idle connection or refuse new
ones.

The interesting question is whether this specific implementation
enforces those caps, at what attacker rate it starts shedding load,
and whether legitimate clients survive concurrently.

EVIDENCE INTERPRETATION:
* attacker_rate.peak_actual_rate is the attempted-hold rate.
* qlog.idle_timeout_closes > 0 means the server actually closed idle
  connections at the QUIC layer.
* qlog.connection_closed counts may include other reasons; cross-
  reference with idle_timeout_closes.
* binary_defence.functions_present lists which idle-timeout / stream
  -limit / cleanup functions exist in the shipped binary.
* legion_impact.min_success_rate is the headline impact metric.
* strace.epoll_ctl / epoll_pwait approximates how often the server
  re-armed sockets, which is a proxy for connection-table churn.

Return JSON with this STRUCTURED schema (keep ALL keys, use null when
unknown):
{
  "agent_id": "slowloris",
  "attack_confirmed": true|false,
  "attack_confirmed_evidence": [string],

  "binary_defence_implementation": {
    "is_implemented": true|false|null,
    "functions_present": [string],
    "functions_evidence": [string]
  },

  "runtime_defence_activation": {
    "activated": true|false|null,
    "idle_timeout_closes": int|null,
    "stream_limit_hits": int|null,
    "evidence": [string]
  },

  "operational_impact": {
    "legit_client_baseline_rate": float|null,
    "legit_client_min_rate_under_attack": float|null,
    "outcome": "mitigated|partial|failed|silent",
    "evidence": [string]
  },

  "rfc_compliance_verdict": {
    "compliant_10_1": true|false|"unclear",
    "compliant_4_6": true|false|"unclear",
    "notes": [string]
  },

  "confidence": 0.0-1.0,
  "summary": "1-2 sentence executive summary",
  "rfc_citations": ["RFC 9000 §10.1", "RFC 9000 §4.6"],

  /* legacy keys for evidence_fusion_agent */
  "outcome": "mitigated_by_idle_timeout|mitigated_by_stream_limit|connections_held|client_collapse|uncertain",
  "evidence_for":    [string],
  "evidence_against":[string],
  "uncertainty_notes":[string],
  "reasoning": string
}""",
            user=f"""Implementation under test: {impl}
Upstream classifier label: {ev['classification']}

— PCAP-side summary (server-side capture) —
{json.dumps(ev['pcap'], indent=2, default=str)}

— qlog-side summary —
{json.dumps(ev['qlog'], indent=2, default=str)}

— strace-side summary —
{json.dumps(ev['strace'], indent=2, default=str)}

— Attacker-side ground truth —
{json.dumps(ev['attacker_rate'], indent=2, default=str)}

— Legitimate client impact —
{json.dumps(ev['legion_impact'], indent=2, default=str)}

— Binary symbols matching slowloris-defence patterns —
{json.dumps(ev['binary_defence'], indent=2, default=str)}

Produce the structured JSON described in the system prompt.""",
            agent="slowloris",
        )
        result.setdefault("agent_id", "slowloris")
        for k in ("evidence_for", "evidence_against", "uncertainty_notes",
                  "rfc_citations", "attack_confirmed_evidence"):
            result.setdefault(k, [])
        result.setdefault("binary_defence_implementation", {})
        result.setdefault("runtime_defence_activation", {})
        result.setdefault("operational_impact", {})
        result.setdefault("rfc_compliance_verdict", {})
        result["usage"] = LLMProvider.usage_since(usage_checkpoint)
        nd["slowloris"] = result
        cost = result["usage"].get("cost_usd", 0.0)
        outcome = result.get("outcome", "?")
        return _step(state, nd, "slowloris",
                     f"Slowloris assessment: {outcome} (${cost:.4f}).")
    except Exception as exc:
        nd["slowloris"] = {
            "agent_id": "slowloris",
            "outcome": "error",
            "error": str(exc),
            "usage": LLMProvider.usage_since(usage_checkpoint),
        }
        return _step(state, nd, "slowloris", f"Slowloris assessment failed: {exc}")


# ── Agent: MitM Packet Injection ───────────────────────────────

def mitm_agent(state: OrcaWorkflowState) -> Dict:
    """Multi-source assessment of MitM packet-injection behaviour.

    A MitM attacker injects forged Initial packets at the server. A
    spec-compliant server must reject them via the AEAD integrity check
    (RFC 9001 §5.4 header protection, §5.8 AEAD limits). This agent
    correlates the AEAD/decrypt symbols in the binary with qlog
    decryption-failure / packet-dropped events and the syscall pattern
    of forged-packet rejection.
    """
    nd = state.get("network_domain") or {}
    impl = state.get("implementation") or "unknown"
    cell_dir = _cell_dir_from_state(state)

    ev = {
        "implementation":  impl,
        "classification":  (nd.get("attack_classification") or {}).get("classification"),
        "pcap":            _pcap_summary_for_agent(state),
        "qlog":            _qlog_summary_for_agent(state, [
            "decryption_failure",
            "key_unavailable",
            "packet_dropped_total",
            "unknown_connection_id",
            "header_protection_failed",
        ]),
        "strace":          _strace_summary_minimal(_strace_path_from_state(state)),
        "attacker_rate":   _attacker_observed_rate(cell_dir),
        "legion_impact":   _legitimate_client_impact(cell_dir),
        "binary_defence":  _binary_function_matches(state, [
            "aead_decrypt", "verify_packet", "header_protection",
            "decrypt_packet", "payload_decrypt", "hp_protect",
            "hp_decrypt", "unprotect", "aead_check",
            "decrypt_initial",
        ]),
    }

    usage_checkpoint = LLMProvider.usage_count()
    try:
        result = llm.query_json(
            system="""You are a QUIC security analyst evaluating
MITM PACKET INJECTION behaviour for one specific server binary running
under attack on a hardware testbed. Reason against RFC 9001 §5.4
(header protection) and §5.8 (AEAD limits), and RFC 9000 §13.4.2
(integrity protection of long-header packets).

ATTACK MECHANICS:
A MitM packet-injection attacker emits forged Initial or 1-RTT packets
at the server. The server must reject them through the AEAD integrity
check, since the attacker does not hold the AEAD key. A spec-compliant
server drops forged packets silently and does not alter connection
state on a failure.

The interesting question is which symbol path executed the rejection,
whether decryption-failure counters incremented at the expected rate,
and whether legitimate clients on the same server saw any impact from
the forged-packet processing cost.

EVIDENCE INTERPRETATION:
* attacker_rate.peak_actual_rate is the forgery rate the attacker
  achieved.
* qlog.decryption_failure > 0 confirms the AEAD check rejected
  packets. = 0 with high attacker_rate suggests forged packets are
  silently absorbed before reaching the AEAD path.
* qlog.unknown_connection_id may indicate the forged packet did not
  match an established DCID and was dropped earlier in the pipeline.
* binary_defence.functions_present lists AEAD / header-protection /
  decrypt symbols compiled in.
* legion_impact tells whether the forging cost hurt legitimate
  clients.

Return JSON with this STRUCTURED schema (keep ALL keys, use null when
unknown):
{
  "agent_id": "mitm",
  "attack_confirmed": true|false,
  "attack_confirmed_evidence": [string],

  "binary_defence_implementation": {
    "is_implemented": true|false|null,
    "functions_present": [string],
    "functions_evidence": [string]
  },

  "runtime_defence_activation": {
    "activated": true|false|null,
    "decryption_failures": int|null,
    "packets_dropped": int|null,
    "evidence": [string]
  },

  "operational_impact": {
    "legit_client_baseline_rate": float|null,
    "legit_client_min_rate_under_attack": float|null,
    "outcome": "mitigated|partial|failed|silent",
    "evidence": [string]
  },

  "rfc_compliance_verdict": {
    "compliant_9001_5_4": true|false|"unclear",
    "compliant_9001_5_8": true|false|"unclear",
    "compliant_9000_13_4_2": true|false|"unclear",
    "notes": [string]
  },

  "confidence": 0.0-1.0,
  "summary": "1-2 sentence executive summary",
  "rfc_citations": ["RFC 9001 §5.4", "RFC 9001 §5.8", "RFC 9000 §13.4.2"],

  /* legacy keys for evidence_fusion_agent */
  "outcome": "rejected_by_aead|silently_absorbed|partial_disruption|uncertain",
  "evidence_for":    [string],
  "evidence_against":[string],
  "uncertainty_notes":[string],
  "reasoning": string
}""",
            user=f"""Implementation under test: {impl}
Upstream classifier label: {ev['classification']}

— PCAP-side summary —
{json.dumps(ev['pcap'], indent=2, default=str)}

— qlog-side summary —
{json.dumps(ev['qlog'], indent=2, default=str)}

— strace-side summary —
{json.dumps(ev['strace'], indent=2, default=str)}

— Attacker-side ground truth —
{json.dumps(ev['attacker_rate'], indent=2, default=str)}

— Legitimate client impact —
{json.dumps(ev['legion_impact'], indent=2, default=str)}

— Binary symbols matching MitM/AEAD defence patterns —
{json.dumps(ev['binary_defence'], indent=2, default=str)}

Produce the structured JSON described in the system prompt.""",
            agent="mitm",
        )
        result.setdefault("agent_id", "mitm")
        for k in ("evidence_for", "evidence_against", "uncertainty_notes",
                  "rfc_citations", "attack_confirmed_evidence"):
            result.setdefault(k, [])
        result.setdefault("binary_defence_implementation", {})
        result.setdefault("runtime_defence_activation", {})
        result.setdefault("operational_impact", {})
        result.setdefault("rfc_compliance_verdict", {})
        result["usage"] = LLMProvider.usage_since(usage_checkpoint)
        nd["mitm"] = result
        cost = result["usage"].get("cost_usd", 0.0)
        outcome = result.get("outcome", "?")
        return _step(state, nd, "mitm",
                     f"MitM assessment: {outcome} (${cost:.4f}).")
    except Exception as exc:
        nd["mitm"] = {
            "agent_id": "mitm",
            "outcome": "error",
            "error": str(exc),
            "usage": LLMProvider.usage_since(usage_checkpoint),
        }
        return _step(state, nd, "mitm", f"MitM assessment failed: {exc}")


# ── Agent: Evidence Fusion (cross-source integrated assessment) ─

def evidence_fusion_agent(state: OrcaWorkflowState) -> Dict:
    """Fuse outputs from every upstream classifier-style agent into one
    integrated assessment, including the SHIPPED-BUT-SILENT finding.

    Consumes (each may be present or absent depending on inputs):
      - network_domain.attack_classification     (PCAP+qlog network classifier)
      - network_domain.anomaly_detection         (RFC violations)
      - network_domain.zero_rtt_replay           (0-RTT replay assessment)
      - network_domain.retry_token_abuse         (token validation assessment)
      - network_domain.cid_exhaustion            (CID/migration assessment)
      - network_domain.quic_binary_assessment    (per-defence activation)
      - network_domain.qlog_features             (raw qlog event counts)
      - network_domain.statistics                (PCAP stats)

    Produces (matches the standardised schema + the
    contribution-finding fields):
      {
        "agent_id": "evidence_fusion",
        "classification": <attack class>,
        "confidence": 0.0-1.0,
        "evidence_for": [...],
        "evidence_against": [...],
        "uncertainty_notes": [...],
        "reasoning": "...",
        "rfc_citations": [...],
        "shipped_but_silent": [...],   # silent-absorption finding
        "source_agreement": "all_agree|partial|conflicting",
        "winning_source": "network|binary|activation|mixed",
        "usage": {...}
      }

    No threshold rules in the prompt. Reasoning is grounded in the
    per-source visibility matrix:
      - PCAP cannot resolve MitM/replay alone (RFC 9001 §6.6).
      - Binary census shows mechanisms EXIST; activation needs runtime
        evidence (qlog or strace).
      - When two upstream agents disagree at high confidence, the
        disagreement IS the finding.
    """
    nd = state.get("network_domain") or {}

    network_cls   = nd.get("attack_classification") or {}
    anomalies     = nd.get("anomalies") or {}
    zero_rtt      = nd.get("zero_rtt_replay") or {}
    retry_token   = nd.get("retry_token_abuse") or {}
    cid_exhaust   = nd.get("cid_exhaustion") or {}
    binary_assess = nd.get("quic_binary_assessment") or {}
    qlog_features = nd.get("qlog_features") or {}
    stats         = nd.get("statistics") or {}

    if not (network_cls or binary_assess or zero_rtt or retry_token or cid_exhaust):
        return _step(state, nd, "evidence_fusion",
                     "Fusion skipped — no upstream agent outputs found.")

    usage_checkpoint = LLMProvider.usage_count()

    system_prompt = """You are the cross-source fusion analyst for the
ORCA QUIC binary-and-system integrated analysis pipeline.

Several upstream agents have produced classifications and per-defence
activation assessments from disjoint evidence streams:

  - network classifier (PCAP + qlog)
  - anomaly detector (RFC violations)
  - 0-RTT replay assessment (qlog early_data events)
  - retry-token abuse assessment (qlog token-validation events)
  - CID exhaustion assessment (qlog connection_id / path_validation)
  - binary assessment (per-mechanism activation, with binary census)

Each upstream output is structured: classification/outcome,
confidence, evidence_for, evidence_against, uncertainty_notes,
reasoning, rfc_citations.

Your job:
  1. Produce ONE integrated classification, citing which upstream
     source's evidence is strongest for the chosen label.
  2. Identify cases where sources DISAGREE and decide whether the
     disagreement resolves a silent absorption (the contribution
     finding for the paper).
  3. For each defence the binary-assessment agent flagged "silent"
     or "uncertain", decide whether the integrated evidence
     resolves: "shipped_but_silent" (binary has it, no runtime
     evidence of activation against this attack), "shipped_and_fired"
     (binary has it AND runtime evidence of activation), or
     "absent_and_attack_succeeded" (binary lacks it AND attack
     succeeded).

REASONING RULES (visibility matrix from RFC 9000 / RFC 9001):
  - PCAP CANNOT resolve MitM / replay alone — payloads are AEAD
    encrypted (RFC 9001 §6.6). Trust qlog `packet_dropped` events
    with reason `duplicate_packet_number` for replay decisions.
  - PCAP CAN resolve flooding and CID manipulation — long header is
    in clear.
  - Binary census says "exists." Activation requires runtime
    evidence (qlog event or strace delta).
  - If qlog is empty/unavailable, surface the unsoundness in
    uncertainty_notes; do NOT manufacture confidence.
  - If two upstream agents disagree at high confidence each, the
    disagreement IS the finding — record it in evidence_against and
    explain in reasoning.
  - No dataset-derived thresholds. Protocol-grounded thresholds
    (e.g. RFC 9000 §8.1's 3× anti-amplification bound) and
    σ-grounded thresholds (when ≥3 baselines exist) are acceptable.

OUTPUT JSON (standardised schema):
{
  "agent_id": "evidence_fusion",
  "classification": "NORMAL|FLOODING_DOS|SLOWLORIS_DOS|CONNECTION_ID_MANIPULATION|MAN_IN_THE_MIDDLE|ZERO_RTT_REPLAY|RETRY_TOKEN_ABUSE|CID_EXHAUSTION|UNKNOWN_ATTACK",
  "confidence": 0.0-1.0,
  "evidence_for":     ["..."],
  "evidence_against": ["..."],
  "uncertainty_notes": ["..."],
  "reasoning": "...",
  "rfc_citations": ["..."],
  "shipped_but_silent": [
    {"defence": "...", "function": "...", "evidence": "..."}
  ],
  "shipped_and_fired": [
    {"defence": "...", "function": "...", "evidence": "..."}
  ],
  "absent_and_attack_succeeded": [
    {"defence": "...", "evidence": "..."}
  ],
  "source_agreement": "all_agree|partial|conflicting",
  "winning_source": "network|binary|activation|mixed",
  "disagreement_summary": "if sources conflict, name the conflict and which evidence won"
}"""

    def _slim(d, keys):
        return {k: d.get(k) for k in keys if k in d}

    upstream_payload = {
        "network_classifier":      _slim(network_cls, [
            "agent_id", "classification", "confidence",
            "evidence_for", "evidence_against", "uncertainty_notes",
            "reasoning", "rfc_citations", "vote_distribution",
        ]),
        "anomaly_detection":       _slim(anomalies, [
            "agent_id", "anomalies", "rfc_citations", "uncertainty_notes",
        ]),
        "zero_rtt_replay":         _slim(zero_rtt, [
            "agent_id", "outcome", "confidence",
            "evidence_for", "evidence_against", "uncertainty_notes",
            "reasoning", "rfc_citations",
        ]),
        "retry_token_abuse":       _slim(retry_token, [
            "agent_id", "outcome", "confidence",
            "evidence_for", "evidence_against", "uncertainty_notes",
            "reasoning", "rfc_citations",
        ]),
        "cid_exhaustion":          _slim(cid_exhaust, [
            "agent_id", "outcome", "confidence",
            "evidence_for", "evidence_against", "uncertainty_notes",
            "reasoning", "rfc_citations",
        ]),
        "binary_assessment":       _slim(binary_assess, [
            "agent_id", "implementation_name", "attack_type",
            "mechanisms", "shipped_but_silent", "resilience_assessment",
            "evidence_for", "evidence_against", "uncertainty_notes",
            "rfc_citations",
        ]),
        "qlog_features":           _slim(qlog_features, [
            "available", "files_parsed", "total_events",
            "retry_packets_sent", "retry_token_validation_failed",
            "initial_packets_with_token",
            "early_data_accepted", "early_data_rejected",
            "zero_rtt_packets_received",
            "connection_id_issued", "connection_id_retired",
            "path_validation_started", "path_validation_succeeded",
            "path_validation_failed",
            "packet_dropped_total", "decryption_failure",
            "unknown_connection_id",
            "idle_timeout_closes",
        ]),
        "pcap_statistics":         _slim(stats, [
            "total_connections", "connections_per_second",
            "bidirectional_flows", "unidirectional_flows",
            "handshake_completion_rate", "single_packet_ratio",
            "mean_concurrent_flows", "peak_concurrent_flows",
            "long_lived_flows",
        ]),
    }

    user_prompt = f"""Fuse the following upstream agent outputs into
one integrated assessment.

Upstream outputs (per agent):
{json.dumps(upstream_payload, indent=2, default=str)[:8000]}

Reason from the per-source visibility matrix. Cite RFC sections.
Surface SHIPPED-BUT-SILENT defences as a top-level list — these are
the contribution finding for the paper.

Return the JSON described in the system prompt."""

    try:
        result = llm.query_json(
            system=system_prompt,
            user=user_prompt,
            agent="evidence_fusion",
        )
        result.setdefault("agent_id", "evidence_fusion")
        result.setdefault("evidence_for", [])
        result.setdefault("evidence_against", [])
        result.setdefault("uncertainty_notes", [])
        result.setdefault("rfc_citations", [])
        result.setdefault("shipped_but_silent", [])
        result.setdefault("shipped_and_fired", [])
        result.setdefault("absent_and_attack_succeeded", [])
        result.setdefault("source_agreement", "unknown")
        result.setdefault("winning_source", "unknown")
        result["usage"] = LLMProvider.usage_since(usage_checkpoint)
        nd["evidence_fusion"] = result
        cost = result["usage"].get("cost_usd", 0.0)
        n_silent = len(result.get("shipped_but_silent", []))
        return _step(
            state, nd, "evidence_fusion",
            f"Fusion: {result.get('classification', '?')} "
            f"(conf {result.get('confidence', 0)}, "
            f"agreement {result.get('source_agreement', '?')}, "
            f"{n_silent} silent defences, ${cost:.4f}).",
        )
    except Exception as exc:
        nd["evidence_fusion"] = {
            "agent_id": "evidence_fusion",
            "classification": "ERROR",
            "error": str(exc),
            "usage": LLMProvider.usage_since(usage_checkpoint),
        }
        return _step(state, nd, "evidence_fusion", f"Fusion failed: {exc}")


# ── Sub-graph builder ──────────────────────────────────────────

def should_continue(state: OrcaWorkflowState) -> str:
    plan = state.get("plan") or []
    step = state.get("current_step") or 0
    return plan[step] if step < len(plan) else END


def create_network_subgraph() -> StateGraph:
    g = StateGraph(OrcaWorkflowState)
    g.add_node("pcap_ingest_agent", pcap_ingest_agent)
    g.add_node("traffic_statistics_agent", traffic_statistics_agent)
    g.add_node("qlog_analysis_agent", qlog_analysis_agent)
    g.add_node("quic_handshake_agent", quic_handshake_agent)
    g.add_node("attack_classification_agent", attack_classification_agent)
    g.add_node("anomaly_detection_agent", anomaly_detection_agent)
    # FINE 2026 attack-specific evidence agents (one per attack class)
    g.add_node("zero_rtt_replay_agent", zero_rtt_replay_agent)
    g.add_node("retry_token_abuse_agent", retry_token_abuse_agent)
    g.add_node("cid_exhaustion_agent", cid_exhaustion_agent)
    g.add_node("flood_agent", flood_agent)
    g.add_node("slowloris_agent", slowloris_agent)
    g.add_node("mitm_agent", mitm_agent)
    g.add_node("evidence_fusion_agent", evidence_fusion_agent)
    g.set_entry_point("pcap_ingest_agent")

    targets = {
        "pcap_ingest": "pcap_ingest_agent",
        "traffic_statistics": "traffic_statistics_agent",
        "qlog_analysis": "qlog_analysis_agent",
        "quic_handshake": "quic_handshake_agent",
        "attack_classification": "attack_classification_agent",
        "anomaly_detection": "anomaly_detection_agent",
        "zero_rtt_replay": "zero_rtt_replay_agent",
        "retry_token_abuse": "retry_token_abuse_agent",
        "cid_exhaustion": "cid_exhaustion_agent",
        "flood": "flood_agent",
        "slowloris": "slowloris_agent",
        "mitm": "mitm_agent",
        "evidence_fusion": "evidence_fusion_agent",
        END: END,
    }
    for n in targets.values():
        if n != END:
            g.add_conditional_edges(n, should_continue, targets)
    return g

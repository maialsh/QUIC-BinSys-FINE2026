"""
ORCA QLOG Parser

Parses QLOG (RFC 9161/9162) event logs from QUIC implementations.
QLOG provides structured event data about QUIC connections including:
  - Transport events (packet_sent, packet_received, packet_lost)
  - Recovery events (metrics_updated, congestion_state_updated)
  - Security events (key_updated, key_retired)
  - HTTP/3 events (frame_created, frame_parsed)

Supports: qlog JSON and SQLOG (sequential JSON lines) formats.
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import Counter, defaultdict


class QlogParser:
    """Parse and analyse QLOG event traces."""

    def __init__(self, qlog_path: str):
        self.path = Path(qlog_path)
        self.events: List[Dict[str, Any]] = []
        self.trace_info: Dict[str, Any] = {}
        self._parse()

    def _parse(self):
        """Auto-detect format and parse.

        Three on-disk shapes are tolerated:
          1. Classic single-JSON qlog (draft-01/02): the whole file is
             one JSON object with a "traces" or "events" key.
          2. JSON-Seq sqlog per RFC 7464: each record is preceded by
             ASCII Record Separator (0x1E) and followed by LF.
          3. Newline-delimited JSON without RS: one JSON object per
             line. (Some tooling emits this dialect.)
        """
        text = self.path.read_text()
        # Strip a leading byte-order-mark if present.
        if text.startswith("﻿"):
            text = text[1:]
        # JSON-Seq files start with RS (0x1E). Detect and dispatch.
        if text.startswith("\x1e"):
            self._parse_sqlog(text)
            return
        # Classic single-object qlog: try strict JSON first regardless of
        # whether there are intervening newlines. picoquic emits a
        # multi-line single-JSON file with `"events": [ ... ]`, but its
        # qlog draft-00 output sometimes contains malformed value blocks
        # (e.g. `"version_negotiation": "chosen": ...` missing the
        # surrounding `{}`). Strict parse is attempted first; if it
        # fails, we fall through to the line-by-line salvage path which
        # scans for valid event tuples regardless of surrounding errors.
        stripped = text.lstrip()
        if stripped.startswith("{"):
            try:
                self._parse_json(text)
                if self.events:
                    return
            except json.JSONDecodeError:
                pass
            # Try the salvage parser before giving up — picoquic-style.
            salvaged = self._parse_streaming_tolerant(text)
            if salvaged:
                return
        # Default: newline-delimited.
        self._parse_sqlog(text)

    def _parse_streaming_tolerant(self, text: str) -> bool:
        """Salvage events from a malformed single-JSON qlog file.

        Used when the file looks like one big JSON object (qlog draft-00:
        `{"qlog_version": ..., "traces": [{"events": [...]}]}`) but
        strict json.loads fails because the producer emitted at least
        one malformed value block. Each line of the events array tends
        to be one self-contained event tuple — `[time, "category",
        "event", {...}]` followed by a comma — so we can extract valid
        events line-by-line and discard malformed ones.

        Returns True if any events were salvaged.
        """
        # Capture the header-ish metadata best-effort, then walk events.
        # First try to find common_fields and event_fields so downstream
        # consumers still see the same trace shape.
        m_cf = re.search(r'"common_fields"\s*:\s*(\{[^{}]*\})', text)
        m_vp = re.search(r'"vantage_point"\s*:\s*(\{[^{}]*\})', text)
        if m_cf:
            try:
                self.trace_info.update(json.loads(m_cf.group(1)))
            except json.JSONDecodeError:
                pass
        if m_vp:
            try:
                self.trace_info["vantage_point"] = json.loads(m_vp.group(1))
            except json.JSONDecodeError:
                pass

        # picoquic writes one event per line in the events array:
        #   [123, "transport", "packet_sent", { ... }],
        # Some events span multiple lines because the data object is
        # pretty-printed. We accumulate lines that start with `[` until
        # the bracket depth returns to zero, then parse the accumulated
        # buffer as one event tuple.
        salvaged = 0
        in_evt = False
        depth = 0
        buf = ""
        in_string = False
        escape = False

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not in_evt:
                # Look for the start of an event tuple — `[<number>,`.
                # Anything else (headers, "events": [, "}]}, etc) is ignored.
                if not line.startswith("["):
                    continue
                if not re.match(r'^\[\s*\d', line):
                    continue
                in_evt = True
                buf = ""
                depth = 0
                in_string = False
                escape = False

            # Append this line; update depth tracking so we know when
            # the event tuple closes.
            buf += line + "\n"
            for ch in line:
                if escape:
                    escape = False
                    continue
                if ch == "\\" and in_string:
                    escape = True
                    continue
                if ch == '"':
                    in_string = not in_string
                    continue
                if in_string:
                    continue
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1

            if depth == 0:
                # Tuple complete. Strip trailing comma and try parse.
                cand = buf.strip().rstrip(",").strip()
                try:
                    evt = json.loads(cand)
                    if (isinstance(evt, list) and len(evt) >= 3
                            and isinstance(evt[0], (int, float))
                            and isinstance(evt[1], str)
                            and isinstance(evt[2], str)):
                        self.events.append({
                            "time":     evt[0],
                            "category": evt[1],
                            "type":     evt[2],
                            "name":     f"{evt[1]}:{evt[2]}",
                            "data":     evt[3] if len(evt) > 3 else {},
                        })
                        salvaged += 1
                except json.JSONDecodeError:
                    pass  # malformed event — skip, scanner continues
                in_evt = False
                buf = ""

        return salvaged > 0

    def _parse_json(self, text: str):
        data = json.loads(text)
        # qlog draft-02+ format
        if "traces" in data:
            trace = data["traces"][0] if data["traces"] else {}
            self.trace_info = trace.get("common_fields", {})
            self.trace_info["vantage_point"] = trace.get("vantage_point", {})
            self.trace_info["title"] = trace.get("title", "")

            events_raw = trace.get("events", [])
            for evt in events_raw:
                if isinstance(evt, list) and len(evt) >= 3:
                    self.events.append({
                        "time": evt[0],
                        "category": evt[1] if len(evt) > 1 else "",
                        "type": evt[2] if len(evt) > 2 else "",
                        "data": evt[3] if len(evt) > 3 else {},
                    })
                elif isinstance(evt, dict):
                    self.events.append({
                        "time": evt.get("time", 0),
                        "category": evt.get("name", "").split(":")[0] if ":" in evt.get("name", "") else "",
                        "type": evt.get("name", "").split(":")[-1] if ":" in evt.get("name", "") else evt.get("name", ""),
                        "data": evt.get("data", {}),
                    })
        # qlog draft-01 format
        elif "events" in data:
            self.events = data["events"]

    def _parse_sqlog(self, text: str):
        """Parse JSON-Seq (RFC 7464) and newline-delimited JSON.

        JSON-Seq prefixes each record with ASCII RS (0x1E). Some
        tooling emits records separated only by newlines without RS.
        Both are handled.
        """
        # Split on RS first; if RS is present every record is preceded
        # by it (with optional trailing LF). If absent, fall back to
        # newline splitting.
        if "\x1e" in text:
            chunks = text.split("\x1e")
        else:
            chunks = text.split("\n")
        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                obj = json.loads(chunk)
            except json.JSONDecodeError:
                continue
            # The first record is typically the qlog header
            # (qlog_format, qlog_version, trace). Subsequent records
            # are events with `time` and `name`.
            if "qlog_format" in obj or "qlog_version" in obj:
                self.trace_info.update(obj)
                # Some emitters embed `trace` here with vantage_point.
                if "trace" in obj and isinstance(obj["trace"], dict):
                    self.trace_info["vantage_point"] = obj["trace"].get(
                        "vantage_point", {}
                    )
                continue
            if "header" in obj and "time" not in obj:
                self.trace_info.update(obj["header"])
                continue
            if "time" in obj or "name" in obj:
                # Normalise to the {time, category, type, data} shape
                # _parse_json uses, so downstream methods see one schema.
                name = obj.get("name", "")
                if ":" in name:
                    cat, typ = name.split(":", 1)
                else:
                    cat, typ = "", name
                self.events.append({
                    "time": obj.get("time", 0),
                    "category": cat,
                    "type": typ,
                    "name": name,
                    "data": obj.get("data", {}),
                })

    # ── Analysis Methods ───────────────────────────────────────

    def get_event_summary(self) -> Dict[str, int]:
        """Count events by type."""
        counter = Counter()
        for evt in self.events:
            key = f"{evt.get('category', '')}:{evt.get('type', '')}"
            counter[key] += 1
        return dict(counter.most_common())

    def get_packet_loss_stats(self) -> Dict[str, Any]:
        """Analyse packet loss events."""
        sent = sum(1 for e in self.events if e.get("type") in ("packet_sent",))
        received = sum(1 for e in self.events if e.get("type") in ("packet_received",))
        lost = sum(1 for e in self.events if e.get("type") in ("packet_lost",))

        return {
            "packets_sent": sent,
            "packets_received": received,
            "packets_lost": lost,
            "loss_rate": round(lost / max(sent, 1), 4),
        }

    def get_handshake_duration(self) -> Optional[float]:
        """Calculate handshake duration from first Initial to first Handshake Done."""
        initial_time = None
        handshake_done_time = None

        for evt in self.events:
            data = evt.get("data", {})
            header = data.get("header", {}) if isinstance(data, dict) else {}
            pkt_type = header.get("packet_type", "")

            if pkt_type == "initial" and initial_time is None:
                initial_time = evt.get("time", 0)
            if evt.get("type") in ("handshake_done_received", "handshake_completed"):
                handshake_done_time = evt.get("time", 0)
                break

        if initial_time is not None and handshake_done_time is not None:
            return handshake_done_time - initial_time
        return None

    def get_congestion_events(self) -> List[Dict[str, Any]]:
        """Extract congestion-related events."""
        return [
            e for e in self.events
            if e.get("type") in ("congestion_state_updated", "metrics_updated", "loss_timer_updated")
        ]

    def get_key_events(self) -> List[Dict[str, Any]]:
        """Extract key update/rotation events (security-relevant)."""
        return [
            e for e in self.events
            if e.get("type") in ("key_updated", "key_retired", "key_discarded")
            or e.get("category") == "security"
        ]

    def get_stream_activity(self) -> Dict[str, Any]:
        """Analyse stream creation and data transfer."""
        streams: Dict[str, Dict] = defaultdict(lambda: {"bytes_sent": 0, "bytes_received": 0, "frames": 0})

        for evt in self.events:
            data = evt.get("data", {})
            if not isinstance(data, dict):
                continue
            stream_id = str(data.get("stream_id", ""))
            if not stream_id:
                frames = data.get("frames", [])
                if isinstance(frames, list):
                    for f in frames:
                        if isinstance(f, dict) and "stream_id" in f:
                            sid = str(f["stream_id"])
                            streams[sid]["frames"] += 1
                            if "length" in f:
                                streams[sid]["bytes_sent"] += f["length"]
                continue

            streams[stream_id]["frames"] += 1
            if "length" in data:
                streams[stream_id]["bytes_sent"] += data["length"]

        return {
            "total_streams": len(streams),
            "streams": dict(streams),
        }

    def detect_anomalies(self) -> List[Dict[str, str]]:
        """Flag suspicious patterns in QLOG events."""
        anomalies = []
        event_summary = self.get_event_summary()
        loss = self.get_packet_loss_stats()

        # High packet loss
        if loss["loss_rate"] > 0.1:
            anomalies.append({
                "type": "high_packet_loss",
                "description": f"Packet loss rate {loss['loss_rate']:.1%} exceeds 10% threshold",
                "severity": "medium",
            })

        # Excessive key rotations
        key_events = self.get_key_events()
        if len(key_events) > 20:
            anomalies.append({
                "type": "excessive_key_rotation",
                "description": f"{len(key_events)} key events detected — may indicate key confusion attack",
                "severity": "high",
            })

        # 0-RTT data
        zero_rtt_count = sum(1 for e in self.events
                            if isinstance(e.get("data", {}), dict)
                            and e.get("data", {}).get("header", {}).get("packet_type") == "0rtt")
        if zero_rtt_count > 0:
            anomalies.append({
                "type": "0rtt_data_detected",
                "description": f"{zero_rtt_count} 0-RTT packets — potential replay risk per RFC 9001 §9.2",
                "severity": "medium",
            })

        # Connection migration
        migration_events = [e for e in self.events if "migration" in str(e.get("type", "")).lower()]
        if len(migration_events) > 5:
            anomalies.append({
                "type": "frequent_migration",
                "description": f"{len(migration_events)} connection migrations — may indicate evasion",
                "severity": "medium",
            })

        return anomalies

    def to_dict(self) -> Dict[str, Any]:
        """Full analysis as a dict for LLM consumption."""
        return {
            "trace_info": self.trace_info,
            "total_events": len(self.events),
            "event_summary": self.get_event_summary(),
            "packet_loss": self.get_packet_loss_stats(),
            "handshake_duration_ms": self.get_handshake_duration(),
            "stream_activity": self.get_stream_activity(),
            "key_events_count": len(self.get_key_events()),
            "anomalies": self.detect_anomalies(),
        }

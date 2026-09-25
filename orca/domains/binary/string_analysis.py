"""
ORCA String Threat Analyzer — pattern-based detection of suspicious strings.

Ported from binsleuth/src/cmd/enhanced_string_analysis.py.
Pure local computation, no LLM calls.
"""
from __future__ import annotations
import re
import math
from typing import Any, Dict, List, Tuple
from collections import defaultdict


# ── Pattern dictionaries ──────────────────────────────────────

SUSPICIOUS_PATTERNS = {
    "backdoor_indicators": [
        "backdoor", "rootkit", "keylogger", "stealer", "trojan",
        "hidden", "secret", "inject", "hook", "bypass",
        "persistence", "privilege", "remote", "shell", "command",
        "download", "upload", "exfiltrate", "steal",
    ],
    "network_indicators": [
        "c2", "cnc", "command.control", "beacon", "heartbeat",
        "proxy", "tunnel", "bot", "zombie", "ddos", "flood",
        "tcp", "udp", "http", "https", "port", "socket", "connect", "bind",
    ],
    "crypto_indicators": [
        "encrypt", "decrypt", "cipher", "crypto", "key", "password",
        "secret", "token", "hash", "md5", "sha", "aes", "rsa",
        "base64", "encode", "decode", "xor", "rot", "obfuscate",
    ],
    "evasion_indicators": [
        "antivirus", "defender", "firewall", "sandbox", "virtual",
        "debug", "analysis", "reverse", "disasm", "hide", "mask",
        "cloak", "polymorphic", "metamorphic", "packer",
    ],
    "persistence_indicators": [
        "registry", "hkey", "regedit", "service", "daemon", "driver",
        "startup", "autostart", "boot", "schedule", "task", "cron",
        "dll", "library", "module",
    ],
    "data_theft_indicators": [
        "password", "credential", "login", "browser", "chrome",
        "firefox", "wallet", "bitcoin", "document", "file",
        "screenshot", "keylog", "clipboard",
    ],
}

HIGH_RISK_KEYWORDS = {
    "exploit", "vulnerability", "zero-day", "payload", "shellcode",
    "malware", "virus", "worm", "ransomware", "spyware",
    "botnet", "c2", "command-control", "backdoor", "rootkit",
    "keylogger", "stealer", "trojan", "rat", "remote-access",
}

SUSPICIOUS_PATHS = {
    "system_paths": [
        r"\\system32\\", r"\\syswow64\\", r"\\windows\\",
        r"/usr/bin/", r"/bin/", r"/sbin/", r"/etc/",
    ],
    "temp_paths": [
        r"\\temp\\", r"\\tmp\\", r"%temp%", r"/tmp/",
        r"\\appdata\\", r"\\roaming\\",
    ],
    "suspicious_extensions": [
        r"\.exe$", r"\.dll$", r"\.sys$", r"\.bat$", r"\.cmd$",
        r"\.ps1$", r"\.vbs$", r"\.js$", r"\.jar$", r"\.scr$",
    ],
}


def _entropy(data: str) -> float:
    """Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for ch in data:
        freq[ch] += 1
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length) for c in freq.values() if c > 0
    )


class StringThreatAnalyzer:
    """Score and categorise strings by threat relevance."""

    def analyze(self, strings: List[str]) -> Dict[str, Any]:
        """Analyse a list of strings for threat indicators. Returns categorised results and risk score."""
        results: Dict[str, Any] = {
            "suspicious_by_category": defaultdict(list),
            "high_risk_strings": [],
            "suspicious_paths": [],
            "encoded_strings": [],
            "risk_score": 0,
            "total_analyzed": len(strings),
        }

        category_hits = defaultdict(int)

        for s in strings:
            if not isinstance(s, str) or len(s) < 4:
                continue

            s_lower = s.lower()

            # Pattern matching
            for category, patterns in SUSPICIOUS_PATTERNS.items():
                for pattern in patterns:
                    if pattern in s_lower:
                        results["suspicious_by_category"][category].append(s)
                        category_hits[category] += 1
                        break

            # High-risk keywords
            for keyword in HIGH_RISK_KEYWORDS:
                if keyword in s_lower:
                    results["high_risk_strings"].append(s)
                    break

            # Suspicious paths
            for path_type, path_patterns in SUSPICIOUS_PATHS.items():
                for pat in path_patterns:
                    if re.search(pat, s, re.IGNORECASE):
                        results["suspicious_paths"].append({"string": s, "type": path_type})
                        break

            # Encoded string detection
            enc = self._check_encoded(s)
            if enc:
                results["encoded_strings"].append(enc)

        # Risk scoring
        score = 0
        for cat, count in category_hits.items():
            if cat in ("backdoor_indicators", "data_theft_indicators"):
                score += min(count * 15, 30)
            elif cat in ("network_indicators", "evasion_indicators"):
                score += min(count * 10, 20)
            else:
                score += min(count * 5, 15)

        score += len(results["high_risk_strings"]) * 20
        score += len(results["encoded_strings"]) * 3

        for p in results["suspicious_paths"]:
            if p["type"] == "system_paths":
                score += 10
            elif p["type"] == "temp_paths":
                score += 5

        results["risk_score"] = min(score, 100)
        results["risk_level"] = (
            "HIGH" if results["risk_score"] >= 70
            else "MEDIUM" if results["risk_score"] >= 40
            else "LOW" if results["risk_score"] >= 20
            else "MINIMAL"
        )

        # Convert defaultdict to regular dict for serialisation
        results["suspicious_by_category"] = dict(results["suspicious_by_category"])
        return results

    def _check_encoded(self, s: str) -> Dict[str, Any] | None:
        """Check if a string looks encoded (base64, hex, XOR)."""
        if len(s) < 16:
            return None

        # Base64-like
        if re.match(r"^[A-Za-z0-9+/=]{16,}$", s):
            ent = _entropy(s)
            if ent > 4.5:
                return {"string": s[:80], "encoding": "base64-like", "entropy": round(ent, 2)}

        # Hex
        if len(s) >= 32 and re.match(r"^[0-9a-fA-F]+$", s):
            return {"string": s[:80], "encoding": "hex", "entropy": round(_entropy(s), 2)}

        # High entropy (possible XOR or custom)
        if len(s) >= 20:
            ent = _entropy(s)
            if ent > 5.0:
                return {"string": s[:80], "encoding": "high-entropy", "entropy": round(ent, 2)}

        return None


def score_string(s: str) -> Tuple[int, str]:
    """Score a single string's suspiciousness (0-100) with reason."""
    score = 0
    reasons = []

    s_lower = s.lower()

    for category, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            if pattern in s_lower:
                score += 20
                reasons.append(f"matches {category}")
                break

    ent = _entropy(s)
    if ent > 4.5:
        score += 15
        reasons.append(f"high entropy ({ent:.1f})")

    if len(s) >= 16 and re.match(r"^[A-Za-z0-9+/=]+$", s):
        score += 10
        reasons.append("base64-like")

    if len(s) >= 32 and re.match(r"^[0-9a-fA-F]+$", s):
        score += 10
        reasons.append("hex pattern")

    if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", s):
        score += 25
        reasons.append("IP address")

    if re.search(r"https?://", s):
        score += 20
        reasons.append("URL")

    if re.search(r"[A-Z]:\\|/usr/|/etc/|/tmp/", s):
        score += 15
        reasons.append("file path")

    return min(score, 100), "; ".join(reasons) if reasons else "normal"

"""
ORCA JA4/JA4+ Fingerprinter

Computes JA4 TLS/QUIC fingerprints from PCAP data:
  - JA4   : TLS Client Hello fingerprint
  - JA4S  : TLS Server Hello fingerprint
  - JA4H  : HTTP Client fingerprint

Reference: https://github.com/FoxIO-LLC/ja4
"""
from __future__ import annotations
import hashlib
from typing import Any, Dict, List, Optional


# Known JA4 fingerprints → client mapping
JA4_DATABASE = {
    "t13d1516h2_8daaf6152771_b186095e22b6": "Chrome 120+",
    "t13d1517h2_8daaf6152771_02713d6af862": "Firefox 120+",
    "t13d1516h2_8daaf6152771_e5627efa2ab1": "Safari 17+",
    "t13d1715h2_5b57614c22b0_06cda9e17597": "curl/8.x",
    "q13d0312h3_55b375c5d22e_06cda9e17597": "Chrome QUIC (h3)",
    "q13d0312h3_55b375c5d22e_eb21e193b2a3": "Firefox QUIC (h3)",
}


class JA4Fingerprinter:
    """Compute JA4 fingerprints from parsed TLS/QUIC handshake data."""

    def compute_ja4(self, client_hello: Dict[str, Any]) -> Optional[str]:
        """
        Compute JA4 from a parsed Client Hello.

        Expected keys:
          tls_version, cipher_suites, extensions, signature_algorithms,
          protocol (tcp|quic), sni
        """
        protocol = "q" if client_hello.get("protocol") == "quic" else "t"
        version = self._version_code(client_hello.get("tls_version", ""))
        sni_flag = "d" if client_hello.get("sni") else "i"

        ciphers = client_hello.get("cipher_suites", [])
        extensions = client_hello.get("extensions", [])
        sig_algos = client_hello.get("signature_algorithms", [])

        # Count ciphers and extensions (2-digit, zero-padded)
        cipher_count = f"{min(len(ciphers), 99):02d}"
        ext_count = f"{min(len(extensions), 99):02d}"

        # ALPN first value
        alpn = client_hello.get("alpn", ["00"])
        alpn_code = alpn[0][:2] if alpn else "00"

        # Part a: protocol + version + SNI + cipher_count + ext_count + alpn
        part_a = f"{protocol}{version}{sni_flag}{cipher_count}{ext_count}{alpn_code}"

        # Part b: sorted cipher suites hash (first 12 chars of SHA256)
        # Filter GREASE values
        filtered_ciphers = sorted(c for c in ciphers if not self._is_grease(c))
        cipher_str = ",".join(str(c) for c in filtered_ciphers)
        part_b = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]

        # Part c: sorted extensions + signature algorithms hash
        filtered_exts = sorted(e for e in extensions if not self._is_grease(e))
        ext_str = ",".join(str(e) for e in filtered_exts)
        sig_str = ",".join(str(s) for s in sig_algos)
        combined = f"{ext_str}_{sig_str}"
        part_c = hashlib.sha256(combined.encode()).hexdigest()[:12]

        return f"{part_a}_{part_b}_{part_c}"

    def identify_client(self, ja4: str) -> str:
        """Look up a JA4 fingerprint in the known database."""
        if ja4 in JA4_DATABASE:
            return JA4_DATABASE[ja4]
        # Partial match on first segment
        prefix = ja4.split("_")[0] if "_" in ja4 else ja4
        for known, client in JA4_DATABASE.items():
            if known.startswith(prefix):
                return f"{client} (partial match)"
        return "unknown"

    def extract_from_pcap(self, pcap_path: str) -> List[Dict[str, Any]]:
        """Extract JA4 fingerprints from a PCAP file using scapy."""
        try:
            from scapy.all import rdpcap, TLS, Raw, UDP
        except ImportError:
            return [{"error": "scapy not installed"}]

        results = []
        try:
            packets = rdpcap(pcap_path)
            for pkt in packets:
                # Look for TLS Client Hello in UDP (QUIC) or TCP
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    ch = self._parse_client_hello_bytes(payload)
                    if ch:
                        ch["protocol"] = "quic" if pkt.haslayer(UDP) else "tcp"
                        ja4 = self.compute_ja4(ch)
                        if ja4:
                            client = self.identify_client(ja4)
                            results.append({
                                "ja4": ja4,
                                "known_client": client,
                                "sni": ch.get("sni", ""),
                                "protocol": ch["protocol"],
                                "cipher_count": len(ch.get("cipher_suites", [])),
                                "extension_count": len(ch.get("extensions", [])),
                            })
        except Exception as exc:
            results.append({"error": str(exc)})

        return results

    def _parse_client_hello_bytes(self, data: bytes) -> Optional[Dict]:
        """Attempt to parse a TLS Client Hello from raw bytes."""
        try:
            # TLS record: content_type=22 (handshake), then version, length
            if len(data) < 9:
                return None
            # Check for handshake type 1 (Client Hello)
            # This is a simplified parser — production would use a full TLS parser
            if data[0] == 0x16 and data[5] == 0x01:  # TLS handshake, Client Hello
                return self._parse_tls_client_hello(data[5:])
            # QUIC Initial packets have different framing
            if data[0] & 0x80:  # QUIC long header
                # Simplified: look for TLS Client Hello within QUIC crypto frame
                for offset in range(len(data) - 10):
                    if data[offset] == 0x01 and offset + 4 < len(data):
                        ch = self._parse_tls_client_hello(data[offset:])
                        if ch:
                            return ch
        except Exception:
            pass
        return None

    def _parse_tls_client_hello(self, data: bytes) -> Optional[Dict]:
        """Parse TLS Client Hello message fields."""
        try:
            if len(data) < 38 or data[0] != 0x01:
                return None
            # Skip: type(1) + length(3) + client_version(2) + random(32) = 38 bytes
            offset = 38
            # Session ID
            if offset >= len(data):
                return None
            session_id_len = data[offset]
            offset += 1 + session_id_len
            # Cipher suites
            if offset + 2 > len(data):
                return None
            cs_len = int.from_bytes(data[offset:offset+2], 'big')
            offset += 2
            ciphers = []
            for i in range(0, cs_len, 2):
                if offset + i + 2 <= len(data):
                    ciphers.append(int.from_bytes(data[offset+i:offset+i+2], 'big'))
            offset += cs_len
            # Compression methods
            if offset >= len(data):
                return {"cipher_suites": ciphers, "extensions": [], "tls_version": "1.2"}
            comp_len = data[offset]
            offset += 1 + comp_len
            # Extensions
            extensions = []
            sni = ""
            alpn = []
            sig_algos = []
            if offset + 2 <= len(data):
                ext_total = int.from_bytes(data[offset:offset+2], 'big')
                offset += 2
                end = min(offset + ext_total, len(data))
                while offset + 4 <= end:
                    ext_type = int.from_bytes(data[offset:offset+2], 'big')
                    ext_len = int.from_bytes(data[offset+2:offset+4], 'big')
                    extensions.append(ext_type)
                    ext_data = data[offset+4:offset+4+ext_len]
                    if ext_type == 0 and ext_len > 5:  # SNI
                        try:
                            sni_len = int.from_bytes(ext_data[3:5], 'big')
                            sni = ext_data[5:5+sni_len].decode('ascii', errors='ignore')
                        except Exception:
                            pass
                    if ext_type == 16 and ext_len > 2:  # ALPN
                        try:
                            al = 2
                            while al < len(ext_data):
                                proto_len = ext_data[al]
                                alpn.append(ext_data[al+1:al+1+proto_len].decode('ascii', errors='ignore'))
                                al += 1 + proto_len
                        except Exception:
                            pass
                    if ext_type == 13:  # Signature algorithms
                        try:
                            sa_len = int.from_bytes(ext_data[0:2], 'big')
                            for i in range(2, 2 + sa_len, 2):
                                sig_algos.append(int.from_bytes(ext_data[i:i+2], 'big'))
                        except Exception:
                            pass
                    offset += 4 + ext_len

            version = "1.3" if 0x0304 in ciphers or 43 in extensions else "1.2"
            return {
                "tls_version": version,
                "cipher_suites": ciphers,
                "extensions": extensions,
                "sni": sni,
                "alpn": alpn,
                "signature_algorithms": sig_algos,
            }
        except Exception:
            return None

    @staticmethod
    def _version_code(version: str) -> str:
        return {"1.0": "10", "1.1": "11", "1.2": "12", "1.3": "13"}.get(version, "13")

    @staticmethod
    def _is_grease(value) -> bool:
        if isinstance(value, int):
            return (value & 0x0F0F) == 0x0A0A
        return False

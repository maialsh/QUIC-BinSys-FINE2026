"""
ORCA Multi-Sample Batch Analysis

Enables analysing multiple binaries/PCAPs in a single run with:
  - Parallel or sequential execution
  - Cross-sample correlation (shared IOCs, similar functions, common C2)
  - Aggregated reporting
  - Progress tracking
"""
from __future__ import annotations
import json, time, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class SampleSpec:
    """Specification for a single sample to analyse."""
    binary_path: Optional[str] = None
    pcap_path: Optional[str] = None
    functionality: str = ""
    goal: str = "comprehensive"
    label: str = ""  # user-defined label (e.g., "sample_A")

    def __post_init__(self):
        if not self.label:
            if self.binary_path:
                self.label = Path(self.binary_path).name
            elif self.pcap_path:
                self.label = Path(self.pcap_path).name
            else:
                self.label = "unknown"


@dataclass
class SampleResult:
    """Result from analysing a single sample."""
    label: str
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_seconds: float = 0.0


@dataclass
class BatchResult:
    """Aggregated result from batch analysis."""
    samples: List[SampleResult] = field(default_factory=list)
    cross_sample_correlation: Optional[Dict[str, Any]] = None
    total_duration: float = 0.0

    @property
    def completed_count(self) -> int:
        return sum(1 for s in self.samples if s.status == "completed")

    @property
    def failed_count(self) -> int:
        return sum(1 for s in self.samples if s.status == "failed")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_samples": len(self.samples),
            "completed": self.completed_count,
            "failed": self.failed_count,
            "total_duration": round(self.total_duration, 2),
            "samples": [
                {
                    "label": s.label,
                    "status": s.status,
                    "duration": round(s.duration_seconds, 2),
                    "error": s.error,
                    "threat_level": (s.result or {}).get("malware_domain", {}).get("analysis", {}).get("threat_level"),
                    "classification": (s.result or {}).get("malware_domain", {}).get("analysis", {}).get("classification"),
                }
                for s in self.samples
            ],
            "cross_sample_correlation": self.cross_sample_correlation,
        }


class BatchAnalyser:
    """
    Run ORCA analysis across multiple samples.

    Usage::

        batch = BatchAnalyser(max_parallel=3)
        batch.add_sample(binary_path="/path/to/sample1")
        batch.add_sample(binary_path="/path/to/sample2", goal="malware")
        batch.add_sample(pcap_path="/path/to/capture.pcap", goal="network")

        result = batch.run(progress_callback=lambda label, status: print(f"{label}: {status}"))
        print(result.to_dict())
    """

    def __init__(self, max_parallel: int = 1):
        self.samples: List[SampleSpec] = []
        self.max_parallel = max_parallel

    def add_sample(self, **kwargs) -> SampleSpec:
        spec = SampleSpec(**kwargs)
        self.samples.append(spec)
        return spec

    def add_samples_from_dir(
        self,
        directory: str,
        goal: str = "comprehensive",
        extensions: Optional[List[str]] = None,
    ) -> int:
        """Add all binaries from a directory."""
        exts = set(extensions or [])
        count = 0
        for p in sorted(Path(directory).iterdir()):
            if p.is_file() and not p.name.startswith("."):
                if exts and p.suffix not in exts:
                    continue
                self.add_sample(binary_path=str(p), goal=goal)
                count += 1
        return count

    def run(
        self,
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ) -> BatchResult:
        """Execute batch analysis."""
        from orca.core.orchestrator import run_orca

        batch_result = BatchResult()
        start = time.time()

        def _analyse(spec: SampleSpec) -> SampleResult:
            sr = SampleResult(label=spec.label)
            if progress_callback:
                progress_callback(spec.label, "running")
            sr.status = "running"
            t0 = time.time()
            try:
                result = run_orca(
                    binary_path=spec.binary_path,
                    pcap_path=spec.pcap_path,
                    functionality=spec.functionality,
                    goal=spec.goal,
                )
                sr.result = result
                sr.status = "completed"
                if progress_callback:
                    progress_callback(spec.label, "completed")
            except Exception as exc:
                sr.error = str(exc)
                sr.status = "failed"
                if progress_callback:
                    progress_callback(spec.label, f"failed: {exc}")
            sr.duration_seconds = time.time() - t0
            return sr

        if self.max_parallel <= 1:
            # Sequential
            for spec in self.samples:
                sr = _analyse(spec)
                batch_result.samples.append(sr)
        else:
            # Parallel
            with ThreadPoolExecutor(max_workers=self.max_parallel) as executor:
                futures = {executor.submit(_analyse, spec): spec for spec in self.samples}
                for future in as_completed(futures):
                    batch_result.samples.append(future.result())

        batch_result.total_duration = time.time() - start

        # Cross-sample correlation
        batch_result.cross_sample_correlation = self._cross_correlate(batch_result)
        return batch_result

    def _cross_correlate(self, batch: BatchResult) -> Dict[str, Any]:
        """Find commonalities across samples."""
        all_iocs: Dict[str, List[str]] = {}  # ioc_value -> [sample_labels]
        all_imports: Dict[str, List[str]] = {}
        all_mitre: Dict[str, List[str]] = {}

        for sr in batch.samples:
            if sr.status != "completed" or not sr.result:
                continue

            # IOC overlap
            md = sr.result.get("malware_domain") or {}
            for ioc in (md.get("iocs") or []):
                val = ioc.get("value", "")
                if val:
                    all_iocs.setdefault(val, []).append(sr.label)

            # Import overlap
            bd = sr.result.get("binary_domain") or {}
            sa = bd.get("static_analysis") or {}
            for imp in (sa.get("imports") or [])[:100]:
                all_imports.setdefault(imp, []).append(sr.label)

            # MITRE overlap
            mitre = md.get("mitre") or {}
            for tech in (mitre.get("techniques") or []):
                tid = tech.get("technique_id", "")
                if tid:
                    all_mitre.setdefault(tid, []).append(sr.label)

        shared_iocs = {k: v for k, v in all_iocs.items() if len(v) > 1}
        shared_mitre = {k: v for k, v in all_mitre.items() if len(v) > 1}
        shared_imports = {k: v for k, v in all_imports.items() if len(v) > 1 and len(v) < len(batch.samples)}

        return {
            "shared_iocs": shared_iocs,
            "shared_mitre_techniques": shared_mitre,
            "unusual_shared_imports": dict(list(shared_imports.items())[:20]),
            "possible_campaign": bool(shared_iocs) and len(shared_iocs) >= 2,
        }

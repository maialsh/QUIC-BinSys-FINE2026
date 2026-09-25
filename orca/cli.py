#!/usr/bin/env python3
"""
ORCA CLI — Unified command-line interface.

Usage:
  # Binary analysis
  python -m orca.cli -b /path/to/binary -f "DNS lookup utility" --goal capabilities

  # Malware triage
  python -m orca.cli -b /path/to/sample --goal malware

  # Network protocol analysis (QUIC)
  python -m orca.cli --pcap /path/to/capture.pcap --goal network

  # Combined binary + network
  python -m orca.cli -b /path/to/binary --pcap /path/to/capture.pcap --goal comprehensive
"""
from __future__ import annotations
import argparse, json, sys, os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        prog="orca",
        description="ORCA — Multi-Agentic Platform for Binary Analysis, Malware Triage & Network Protocol Analysis",
    )
    parser.add_argument("-b", "--binary", help="Path to binary file")
    parser.add_argument("--pcap", help="Path to PCAP file for network analysis")
    parser.add_argument("-f", "--functionality", default="", help="Declared binary functionality")
    parser.add_argument("--goal", default="comprehensive",
                        choices=["capabilities", "malware", "triage", "network", "comprehensive"],
                        help="Analysis goal")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--format", default="json", choices=["json", "html", "sarif"],
                        help="Report output format")
    parser.add_argument("--verbose", action="store_true")

    # Batch mode
    parser.add_argument("--batch-dir", help="Directory of samples for batch analysis")
    parser.add_argument("--parallel", type=int, default=1, help="Max parallel analyses in batch mode")

    # Sandbox
    parser.add_argument("--sandbox", help="Sandbox host (SSH) for remote analysis")
    parser.add_argument("--sandbox-type", choices=["cuckoo", "remnux", "custom"], default="remnux")

    args = parser.parse_args()

    if not args.binary and not args.pcap and not args.batch_dir:
        parser.error("Provide at least --binary, --pcap, or --batch-dir.")

    # Batch mode
    if args.batch_dir:
        from orca.core.batch import BatchAnalyser
        batch = BatchAnalyser(max_parallel=args.parallel)
        count = batch.add_samples_from_dir(args.batch_dir, goal=args.goal)
        print(f"\n  ORCA Batch Mode — {count} samples from {args.batch_dir}")
        result = batch.run(progress_callback=lambda l, s: print(f"  [{l}] {s}"))
        import json as _json
        output = result.to_dict()
        if args.output:
            Path(args.output).write_text(_json.dumps(output, indent=2, default=str))
            print(f"\n  Batch results saved to {args.output}")
        print(f"\n  Completed: {result.completed_count}/{len(result.samples)}, "
              f"Failed: {result.failed_count}, Duration: {result.total_duration:.1f}s")
        if result.cross_sample_correlation and result.cross_sample_correlation.get("possible_campaign"):
            print(f"  ⚠️  Possible campaign detected — shared IOCs across samples")
        return

    if args.binary and not Path(args.binary).exists():
        parser.error(f"Binary not found: {args.binary}")
    if args.pcap and not Path(args.pcap).exists():
        parser.error(f"PCAP not found: {args.pcap}")

    if args.verbose:
        os.environ["DEBUG"] = "1"

    # Run ORCA
    from orca.core.orchestrator import run_orca

    print(f"\n{'='*60}")
    print(f"  ORCA v2.0 — Multi-Agentic Security Analysis Platform")
    print(f"{'='*60}")
    if args.binary:
        print(f"  Binary : {args.binary}")
    if args.pcap:
        print(f"  PCAP   : {args.pcap}")
    print(f"  Goal   : {args.goal}")
    print(f"{'='*60}\n")

    result = run_orca(
        binary_path=args.binary,
        pcap_path=args.pcap,
        functionality=args.functionality,
        goal=args.goal,
    )

    # Serialise (strip non-serialisable objects)
    def _serialise(obj):
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        if hasattr(obj, "content"):
            return str(obj.content)
        return str(obj)

    output = {
        "binary_domain": result.get("binary_domain"),
        "malware_domain": result.get("malware_domain"),
        "network_domain": result.get("network_domain"),
        "final_report": result.get("final_report"),
        "completed_steps": result.get("completed_steps", []),
    }

    if args.output:
        from orca.core.reporting.engine import ReportEngine
        engine = ReportEngine(result)
        if args.format == "html":
            engine.to_html(args.output)
        elif args.format == "sarif":
            engine.to_sarif(args.output)
        else:
            engine.to_json(args.output)
        print(f"\nResults saved to {args.output} ({args.format})")

    # Print summary
    report = result.get("final_report") or {}
    print(f"\n{'='*60}")
    print("  ORCA ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"  Steps completed: {', '.join(result.get('completed_steps', []))}")
    if report.get("executive_summary"):
        print(f"\n  Executive Summary:\n  {report['executive_summary'][:500]}")
    if report.get("recommendations"):
        print(f"\n  Recommendations:")
        for r in report["recommendations"][:5]:
            print(f"    • {r}")
    print(f"\n{'='*60}")


if __name__ == "__main__":
    main()

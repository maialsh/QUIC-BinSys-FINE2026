"""
Per-level slicer for QUIC eval-set sweep captures.

The eval-set's per-cell capture is an 11-level intensity sweep packed into one
PCAP, one qlog directory, and one strace file. Level boundaries are recorded in
`levels.log`. This module slices those artefacts by wall-clock window so the
analysis pipeline can run per level — required for the rate-resolved activation
findings the FINE 2026 paper makes.

Three slicing strategies:

  * PCAP — `editcap -A <start_epoch> -B <end_epoch>` if available, otherwise
    a pure-Python fallback using scapy. Output is a new .pcap in a temp dir
    or an explicit out-path.
  * qlog (per-file dataset; one .sqlog per connection) — assign each file to
    the level whose [start, end) window contains the file's mtime. No
    within-file event filtering; the unit of slicing is a file, because every
    qlog-format-0.3 file uses connection-relative time and cannot be
    wall-clocked from event timestamps alone.
  * strace — line-grep by wall-clock prefix, resolving HH:MM:SS.uuuuuu
    timestamps (strace -tt) against the cell's date-from-levels.log, or
    using full-epoch timestamps directly (strace -ttt).

Design choices recorded explicitly:

  D1. Baseline strace is NOT sliced. The strace baseline comes from the
      cell's `normal` scenario at full duration; the per-level deltas are
      attack-rate / baseline-rate, not sliced-attack / sliced-baseline. The
      slicer is single-direction: it slices attack artefacts, the baseline
      stays whole.

  D2. Per-level outputs are emitted as SEPARATE cells, not a per-level array
      inside one cell. Cell key becomes `<impl>_<attack>_L<NN>` so downstream
      aggregation is one-level-per-row by default.

  D3. The slicer is pure data-prep. No LLM calls, no state mutation. It
      writes sliced files to a level-keyed output directory and returns a
      manifest. The pipeline driver consumes the manifest to schedule
      per-level pipeline passes.

This module has no LLM dependencies and is safe to run on a laptop.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Levels-log parsing ────────────────────────────────────────


_LEVEL_LINE_RE = re.compile(
    r"^level=(?P<level>\d+)\s+start=(?P<start>[\d.]+)(?:\.[A-Z])?\s+end=(?P<end>[\d.]+)(?:\.[A-Z])?\s*$"
)


@dataclass
class LevelWindow:
    level: int                  # 0, 10, 20, ..., 100
    start_epoch: float          # wall-clock seconds since 1970
    end_epoch: float
    interval_seconds: Optional[float] = None  # attacker's packet interval at this level

    @property
    def duration(self) -> float:
        return self.end_epoch - self.start_epoch


def parse_levels_log(levels_log_path: Path) -> List[LevelWindow]:
    """Parse `levels.log` into a list of LevelWindow records.

    Format observed in the eval-set:
        level=0 start=1777058350.N end=1777058412.N
        level=10 start=1777058412.N end=1777058474.N
        ...

    The trailing `.N` is the testbed's marker for nanosecond-suffix-elided
    integer epochs; we read just the integer second portion.
    """
    windows: List[LevelWindow] = []
    for raw in levels_log_path.read_text().splitlines():
        m = _LEVEL_LINE_RE.match(raw)
        if not m:
            continue
        windows.append(LevelWindow(
            level=int(m["level"]),
            start_epoch=float(m["start"]),
            end_epoch=float(m["end"]),
        ))
    windows.sort(key=lambda w: w.level)
    return windows


def annotate_with_intervals(
    windows: List[LevelWindow], flood_intervals: List[float]
) -> List[LevelWindow]:
    """Attach the metadata.json `flood_intervals` to the parsed windows in
    order, so downstream code can compute attacker-rate per level.
    """
    for w, iv in zip(windows, flood_intervals):
        w.interval_seconds = iv
    return windows


# ── PCAP slicing ──────────────────────────────────────────────


def slice_pcap(
    src: Path, dst: Path, *, start_epoch: float, end_epoch: float,
) -> Path:
    """Write a sliced PCAP at `dst` containing packets whose capture time
    falls within [start_epoch, end_epoch).

    Uses `editcap -A <utc_start> -B <utc_end>` if `editcap` is on PATH, since
    that is the standard wireshark-distributed slicer and is exact. Falls
    back to a pure-scapy filter otherwise.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)

    if shutil.which("editcap"):
        # editcap accepts ISO-8601 in UTC; convert from epoch.
        from datetime import datetime, timezone
        a = datetime.fromtimestamp(start_epoch, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S")
        b = datetime.fromtimestamp(end_epoch, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S")
        subprocess.run(
            ["editcap", "-A", a, "-B", b, str(src), str(dst)],
            check=True, capture_output=True,
        )
        return dst

    # Pure-Python fallback — slower but no system dependency.
    from scapy.all import rdpcap, wrpcap
    pkts = rdpcap(str(src))
    keep = [p for p in pkts if start_epoch <= float(p.time) < end_epoch]
    wrpcap(str(dst), keep)
    return dst


# ── qlog slicing (file-level assignment) ──────────────────────


def build_qlog_open_time_map(
    strace_path: Path, strace_date_epoch: float,
) -> Dict[str, float]:
    """Walk strace and produce {qlog_basename → wall-clock open epoch}.

    Used because qlog format 0.3 uses connection-relative time with
    reference_time=0 — there is no wall-clock anchor inside the qlog
    files themselves, and on-disk mtimes are unreliable (often stomped
    to a later post-run timestamp). The strace records every
    `openat(.../qlog/<hash>.sqlog)` with a wall-clock prefix; that is
    the authoritative anchor.

    `strace_date_epoch` must be any epoch from the same UTC day as the
    strace capture (e.g. levels[0].start_epoch).
    """
    from datetime import datetime, timezone, timedelta

    base_day = datetime.fromtimestamp(strace_date_epoch, tz=timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0,
    )

    out: Dict[str, float] = {}
    with strace_path.open("r", errors="replace") as f:
        for line in f:
            if "openat" not in line or "qlog" not in line:
                continue
            m = _STRACE_QLOG_OPEN_RE.search(line)
            if not m:
                continue
            ts: Optional[float] = None
            mt = _STRACE_TTT_RE.match(line)
            if mt:
                ts = float(mt["epoch"])
            else:
                mt = _STRACE_TT_RE.match(line)
                if mt:
                    h, mm, s = mt["hms"].split(":")
                    sec, _, usec = s.partition(".")
                    delta = timedelta(
                        hours=int(h), minutes=int(mm),
                        seconds=int(sec),
                        microseconds=int(usec.ljust(6, "0")[:6]),
                    )
                    ts = (base_day + delta).timestamp()
            if ts is None:
                continue
            basename = Path(m["path"]).name
            # Keep the FIRST open per file — server may re-open if the file
            # is recycled, but the first creation is the connection start.
            if basename not in out:
                out[basename] = ts
    return out


def assign_qlog_files_to_levels(
    qlog_dir: Path, windows: List[LevelWindow], *,
    strace_path: Optional[Path] = None,
    strace_date_epoch: Optional[float] = None,
) -> Dict[int, List[Path]]:
    """For each qlog file, decide which level window contains its
    wall-clock CREATE time. Returns {level -> [paths]}.

    Strategy:
      1. If `strace_path` is supplied and contains qlog `openat` events,
         use those as the authoritative wall-clock anchor per file
         (preferred — see build_qlog_open_time_map docstring).
      2. Otherwise fall back to file mtime (works only when the dataset
         hasn't been re-archived; on the eval-set this fallback is
         broken because every mtime is stomped to a later timestamp).
    """
    open_times: Dict[str, float] = {}
    if strace_path is not None and strace_path.exists():
        if strace_date_epoch is None and windows:
            strace_date_epoch = windows[0].start_epoch
        if strace_date_epoch is not None:
            open_times = build_qlog_open_time_map(strace_path, strace_date_epoch)

    out: Dict[int, List[Path]] = {w.level: [] for w in windows}
    for f in sorted(qlog_dir.iterdir()):
        if not f.is_file():
            continue
        if f.suffix not in {".sqlog", ".qlog", ".jsonl"}:
            continue
        ts = open_times.get(f.name)
        if ts is None:
            ts = f.stat().st_mtime  # fallback (often unreliable)
        for w in windows:
            if w.start_epoch <= ts < w.end_epoch:
                out[w.level].append(f)
                break
    return out


# ── strace slicing ────────────────────────────────────────────


# Two strace timestamp shapes seen in the eval-set:
#   `1     19:19:05.271398 epoll_pwait(...)`     ← PID-prefixed -tt (-f)
#   `19:19:05.271398 epoll_pwait(...)`           ← no-PID -tt
#   `1777058350.271398 epoll_pwait(...)`         ← -ttt (full epoch)
# The PID column is left-padded with spaces and may be multi-digit.
_STRACE_TT_RE = re.compile(
    r"^(?:\d+\s+)?(?P<hms>\d{2}:\d{2}:\d{2}\.\d+)\s"
)
_STRACE_TTT_RE = re.compile(
    r"^(?:\d+\s+)?(?P<epoch>\d{10}\.\d+)\s"
)
# qlog file open events recorded in strace, used to wall-clock-anchor each
# qlog file when the qlog itself uses connection-relative time:
#   `1  19:19:06.862529 openat(AT_FDCWD, "/runs/qlog/<hash>.sqlog", ...)`
_STRACE_QLOG_OPEN_RE = re.compile(
    r'openat\([^,]+,\s*"(?P<path>[^"]+\.sqlog|[^"]+\.qlog|[^"]+\.jsonl)"'
)


def slice_strace(
    src: Path, dst: Path, *, start_epoch: float, end_epoch: float,
    strace_date_epoch: Optional[float] = None,
) -> Path:
    """Filter strace lines to those whose timestamp falls within
    [start_epoch, end_epoch). Supports both `-tt` (HH:MM:SS) and `-ttt`
    (full epoch) formats.

    For `-tt` lines the timestamp is wall-clock-of-day and we need
    `strace_date_epoch` (any epoch from the same UTC day as the strace
    capture, e.g. the cell's first level's start_epoch) to disambiguate.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)

    if strace_date_epoch is None:
        strace_date_epoch = start_epoch

    from datetime import datetime, timezone, timedelta
    base_day = datetime.fromtimestamp(strace_date_epoch, tz=timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0,
    )

    out_lines: List[str] = []
    with src.open("r", errors="replace") as f:
        for line in f:
            ts: Optional[float] = None
            m = _STRACE_TTT_RE.match(line)
            if m:
                ts = float(m["epoch"])
            else:
                m = _STRACE_TT_RE.match(line)
                if m:
                    h, mm, s = m["hms"].split(":")
                    sec, _, usec = s.partition(".")
                    delta = timedelta(
                        hours=int(h), minutes=int(mm),
                        seconds=int(sec),
                        microseconds=int(usec.ljust(6, "0")[:6]),
                    )
                    ts = (base_day + delta).timestamp()
            if ts is None:
                # Untimestamped lines (stack traces, multi-line syscalls)
                # belong with the previous in-window line if we kept it.
                if out_lines:
                    out_lines.append(line)
                continue
            if start_epoch <= ts < end_epoch:
                out_lines.append(line)

    dst.write_text("".join(out_lines))
    return dst


# ── End-to-end manifest builder ───────────────────────────────


@dataclass
class LevelSlice:
    level: int
    start_epoch: float
    end_epoch: float
    interval_seconds: Optional[float]
    pcap_path: Path
    qlog_files: List[Path]
    strace_path: Path


def slice_cell(
    cell_dir: Path, *, out_dir: Path, levels_filter: Optional[List[int]] = None,
    flood_intervals: Optional[List[float]] = None,
) -> List[LevelSlice]:
    """Slice the entire (impl, attack) cell at `cell_dir` into one
    LevelSlice per level. Output goes to `out_dir/L<NN>/`.

    `levels_filter` lets the caller produce only specific levels (e.g.
    just level 100 for the pilot). `flood_intervals` (from metadata.json)
    is passed through onto each slice for downstream rate-attribution.
    """
    cell_dir = Path(cell_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    levels_log = cell_dir / "levels.log"
    pcap_in = cell_dir / "attack.pcap"
    strace_in = cell_dir / "server.strace"
    qlog_in = cell_dir / "qlog"

    windows = parse_levels_log(levels_log)
    if flood_intervals is not None:
        windows = annotate_with_intervals(windows, flood_intervals)

    if levels_filter is not None:
        windows = [w for w in windows if w.level in set(levels_filter)]

    qlog_assignment = assign_qlog_files_to_levels(
        qlog_in, windows,
        strace_path=strace_in if strace_in.exists() else None,
        strace_date_epoch=windows[0].start_epoch if windows else None,
    )

    slices: List[LevelSlice] = []
    for w in windows:
        ldir = out_dir / f"L{w.level:03d}"
        ldir.mkdir(parents=True, exist_ok=True)

        sliced_pcap = slice_pcap(
            pcap_in, ldir / "attack.pcap",
            start_epoch=w.start_epoch, end_epoch=w.end_epoch,
        )
        sliced_strace = slice_strace(
            strace_in, ldir / "server.strace",
            start_epoch=w.start_epoch, end_epoch=w.end_epoch,
        )

        # Materialise the per-level qlog directory by symlinking the
        # assigned files. Symlinks are cheap and let the existing
        # qlog_analysis_agent read `qlog_dir` unmodified. If symlink
        # is unavailable on the host we fall back to copying.
        qlog_subdir = ldir / "qlog"
        qlog_subdir.mkdir(exist_ok=True)
        # Clean any previous run so re-slicing is idempotent.
        for stale in qlog_subdir.iterdir():
            stale.unlink()
        for src_qf in qlog_assignment.get(w.level, []):
            link = qlog_subdir / src_qf.name
            try:
                link.symlink_to(src_qf.resolve())
            except OSError:
                shutil.copy2(src_qf, link)

        slices.append(LevelSlice(
            level=w.level,
            start_epoch=w.start_epoch,
            end_epoch=w.end_epoch,
            interval_seconds=w.interval_seconds,
            pcap_path=sliced_pcap,
            qlog_files=list(qlog_subdir.iterdir()),
            strace_path=sliced_strace,
        ))

    return slices


# ── Convenience: state-schema delta documented inline ─────────
#
# Per-level pipeline runs add three optional state fields the existing
# agents respect (with no breaking changes when the fields are absent):
#
#   level: Optional[int]                 # 0..100 for the per-level cell
#   level_window: Optional[Tuple[float,float]]  # start_epoch, end_epoch
#   level_attacker_rate_per_sec: Optional[float]
#       # 1.0 / interval_seconds when interval is finite, 0 for L0
#
# Existing agents that need to be aware:
#   - pcap_ingest_agent      → reads the sliced attack.pcap, no agent change needed
#   - traffic_statistics_agent → uses the connections list pcap_ingest produced; no agent change
#   - qlog_analysis_agent    → reads qlog_dir from state, which now points at the per-level
#                              symlinked qlog subdir; no agent change
#   - quic_handshake_agent   → no change
#   - attack_classification_agent → SHOULD include level + attacker_rate in the user prompt so
#                                   the LLM reasons over the per-level rate, not the aggregate
#   - quic_binary_assessment_agent → SHOULD also include level + attacker_rate in the
#                                    traffic_context block
#   - evidence_fusion_agent  → SHOULD include level in upstream_payload so the integrated
#                              record is level-keyed
#
# Cell key convention: <impl>_<attack>_L<NN> (separate cells per level).

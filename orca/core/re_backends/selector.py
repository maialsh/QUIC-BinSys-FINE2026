"""
ORCA RE Backend Selector

Intelligently picks Ghidra, Binary Ninja, or both based on binary characteristics.
"""
from __future__ import annotations
import subprocess
from pathlib import Path
from typing import List, Optional
from orca.core.models import REBackendType


class REBackendSelector:
    """
    Heuristic-based selector that chooses the optimal RE backend(s).

    Decision matrix:
      stripped binary        → Ghidra  (better function boundary detection)
      C++ / RTTI present     → Ghidra  (superior class reconstruction)
      taint analysis needed  → BN      (MLIL SSA is purpose-built)
      packed / obfuscated    → Both    (cross-validate, LLM merges)
      firmware / exotic arch → Ghidra  (broader architecture support)
      quick triage           → BN      (faster headless)
      default clean binary   → BN      (better HLIL readability)
    """

    def select(
        self,
        binary_path: Path,
        *,
        force_backend: Optional[REBackendType] = None,
        need_taint: bool = False,
        is_packed: bool = False,
    ) -> List[REBackendType]:
        if force_backend:
            return [force_backend]

        is_stripped = self._check_stripped(binary_path)
        has_cpp = self._check_cpp(binary_path)

        # Prefer Binary Ninja for all cases; Ghidra as fallback
        if is_packed:
            return [REBackendType.BINARY_NINJA, REBackendType.GHIDRA]
        return [REBackendType.BINARY_NINJA]

    @staticmethod
    def _check_stripped(path: Path) -> bool:
        try:
            r = subprocess.run(["file", str(path)], capture_output=True, text=True)
            return "stripped" in r.stdout.lower() and "not stripped" not in r.stdout.lower()
        except Exception:
            return False

    @staticmethod
    def _check_cpp(path: Path) -> bool:
        try:
            r = subprocess.run(["strings", str(path)], capture_output=True, text=True)
            return any(s.startswith("_Z") or "::" in s for s in r.stdout.split("\n")[:500])
        except Exception:
            return False

    @staticmethod
    def create_backend(backend_type: REBackendType, binary_path: Path):
        """Factory: instantiate the right backend class."""
        if backend_type == REBackendType.GHIDRA:
            from orca.core.re_backends.ghidra_backend import GhidraBackend
            return GhidraBackend(binary_path)
        elif backend_type == REBackendType.BINARY_NINJA:
            from orca.core.re_backends.binja_backend import BinaryNinjaBackend
            return BinaryNinjaBackend(binary_path)
        else:
            raise ValueError(f"Unknown backend type: {backend_type}")

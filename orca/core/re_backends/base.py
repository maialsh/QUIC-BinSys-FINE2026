"""
ORCA RE Backend — Abstract Protocol

Every reverse-engineering backend (Binary Ninja, Ghidra, …) implements
this protocol so the rest of ORCA is backend-agnostic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from orca.core.models import (
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    REBackendType,
    SectionInfo,
    StringCategory,
)


class REBackend(ABC):
    """
    Abstract base class that every RE backend must implement.

    Usage (as a context manager)::

        with GhidraBackend(path) as backend:
            funcs = backend.get_functions()
    """

    backend_type: REBackendType

    def __init__(self, binary_path: Path):
        self.binary_path = binary_path
        self._program: Any = None  # Opaque handle (BinaryView / Program / …)

    # ── lifecycle ──────────────────────────────────────────────

    @abstractmethod
    def open(self) -> None:
        """Load the binary and perform initial analysis."""
        ...

    @abstractmethod
    def close(self) -> None:
        """Release all resources held by the backend."""
        ...

    def __enter__(self) -> "REBackend":
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # ── queries ────────────────────────────────────────────────

    @abstractmethod
    def get_functions(self, *, include_thunks: bool = False) -> List[FunctionInfo]:
        """Return all functions discovered in the binary."""
        ...

    @abstractmethod
    def get_function_by_name(self, name: str) -> Optional[FunctionInfo]:
        """Look up a single function by name (exact or partial)."""
        ...

    @abstractmethod
    def decompile(self, function_name: str) -> Optional[str]:
        """Return decompiled C/pseudo-C for the given function."""
        ...

    @abstractmethod
    def get_assembly(self, function_name: str, *, max_lines: int = 200) -> Optional[str]:
        """Return disassembly listing for the given function."""
        ...

    @abstractmethod
    def get_imports(self) -> List[str]:
        """Return imported symbol names."""
        ...

    @abstractmethod
    def get_exports(self) -> List[str]:
        """Return exported symbol names."""
        ...

    @abstractmethod
    def get_sections(self) -> List[SectionInfo]:
        """Return information about all sections / segments."""
        ...

    @abstractmethod
    def get_strings(self, *, min_length: int = 4) -> List[str]:
        """Extract readable strings from the binary."""
        ...

    @abstractmethod
    def get_cross_references(self, symbol_name: str) -> List[str]:
        """Return function names that reference *symbol_name*."""
        ...

    # ── optional extended queries ──────────────────────────────

    def get_hlil(self, function_name: str) -> Optional[str]:
        """Binary Ninja High-Level IL (BN-only)."""
        return None

    def get_mlil(self, function_name: str) -> Optional[str]:
        """Binary Ninja Medium-Level IL / Ghidra Pcode equivalent."""
        return None

    def get_call_graph(self) -> Dict[str, List[str]]:
        """Return a dict mapping function names → list of callees."""
        functions = self.get_functions()
        return {f.name: f.callees for f in functions}

    # ── metadata helpers ───────────────────────────────────────

    @abstractmethod
    def get_architecture(self) -> str:
        """Return architecture string (e.g. 'x86_64', 'arm64')."""
        ...

    @abstractmethod
    def get_binary_format(self) -> str:
        """Return format string (e.g. 'ELF', 'PE', 'Mach-O')."""
        ...

    # ── enrichment helpers ─────────────────────────────────────

    def enrich_function(
        self,
        name: str,
        *,
        max_decompiled_chars: int = 2000,
        max_asm_lines: int = 100,
    ) -> Dict[str, Optional[str]]:
        """Retrieve decompiled code, assembly, HLIL, and MLIL for a function.

        Returns a dict with keys matching FunctionInfo optional fields.
        Truncates output to stay within token budgets.
        """
        decompiled = None
        assembly = None
        hlil = None
        mlil = None

        try:
            raw = self.decompile(name)
            if raw:
                decompiled = raw[:max_decompiled_chars]
        except Exception:
            pass

        try:
            raw = self.get_assembly(name, max_lines=max_asm_lines)
            if raw:
                assembly = raw[:3000]
        except Exception:
            pass

        try:
            raw = self.get_hlil(name)
            if raw:
                hlil = raw[:2000]
        except Exception:
            pass

        try:
            raw = self.get_mlil(name)
            if raw:
                mlil = raw[:2000]
        except Exception:
            pass

        return {
            "decompiled_code": decompiled,
            "assembly": assembly,
            "hlil": hlil,
            "mlil": mlil,
        }

    def find_string_references(
        self,
        target_string: str,
        *,
        max_results: int = 5,
    ) -> List[Dict[str, Any]]:
        """Find functions that reference *target_string*.

        Default implementation searches get_strings() then get_cross_references().
        Backends may override with more efficient native lookups.

        Returns a list of dicts: {function_name, decompiled_code, assembly}.
        """
        # Default: search for cross-refs to functions that contain the string
        # Subclasses should override with proper data-ref lookup
        return []

    # ── metadata helpers ───────────────────────────────────────

    def is_stripped(self) -> bool:
        """Heuristic: binary has very few named functions."""
        funcs = self.get_functions()
        if not funcs:
            return True
        named = sum(1 for f in funcs if not f.name.startswith("FUN_") and not f.name.startswith("sub_"))
        return named / len(funcs) < 0.3

    def has_cpp_symbols(self) -> bool:
        """Check for C++ mangled names in imports/exports."""
        all_syms = self.get_imports() + self.get_exports()
        return any(s.startswith("_Z") or "::" in s for s in all_syms)

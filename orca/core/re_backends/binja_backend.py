"""
ORCA RE Backend — Binary Ninja

Wraps Binary Ninja's Python API to implement the REBackend protocol.
Binary Ninja excels at:
  • speed — headless analysis is very fast
  • HLIL / MLIL — best intermediate representations for taint analysis
  • clean decompilation for well-formed binaries
  • BNIL (Binary Ninja IL) for data-flow and taint tracking
"""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from orca.core.models import (
    FunctionInfo,
    ParameterInfo,
    REBackendType,
    SectionInfo,
)
from orca.core.re_backends.base import REBackend

# Lazy binaryninja import — resolved at open() time
_binja_available: Optional[bool] = None


def _ensure_binja() -> None:
    """Make sure binaryninja is importable."""
    global _binja_available

    if _binja_available is True:
        return
    if _binja_available is False:
        raise RuntimeError("Binary Ninja is not available on this system.")

    # Try common install paths
    binja_paths = [
        "/Applications/Binary Ninja.app/Contents/Resources/python",
        os.path.expanduser("~/binaryninja/python"),
        os.environ.get("BINJA_PYTHON_PATH", ""),
    ]
    for p in binja_paths:
        if p and os.path.isdir(p) and p not in sys.path:
            sys.path.insert(0, p)

    try:
        import binaryninja  # noqa: F401
        _binja_available = True
    except ImportError:
        _binja_available = False
        raise RuntimeError(
            "Binary Ninja Python API not found. "
            "Set BINJA_PYTHON_PATH or install the binaryninja pip package."
        )


class BinaryNinjaBackend(REBackend):
    """Binary Ninja–based reverse-engineering backend."""

    backend_type = REBackendType.BINARY_NINJA

    def __init__(self, binary_path: Path):
        super().__init__(binary_path)

    # ── lifecycle ──────────────────────────────────────────────

    def open(self) -> None:
        _ensure_binja()
        import binaryninja

        self._program = binaryninja.load(str(self.binary_path))
        if self._program is None:
            raise RuntimeError(f"Binary Ninja could not load: {self.binary_path}")
        self._program.update_analysis_and_wait()

    def close(self) -> None:
        if self._program is not None:
            try:
                self._program.file.close()
            except Exception:
                pass
            self._program = None

    # ── queries ────────────────────────────────────────────────

    def get_functions(self, *, include_thunks: bool = False) -> List[FunctionInfo]:
        bv = self._program
        result: List[FunctionInfo] = []

        for func in bv.functions:
            if not include_thunks and func.symbol and func.symbol.type.name == "ImportedFunctionSymbol":
                continue

            callees = [
                ref.name for ref in func.callees if hasattr(ref, "name")
            ]
            callers = [
                ref.name for ref in func.callers if hasattr(ref, "name")
            ]

            params = []
            try:
                for i, p in enumerate(func.parameter_vars):
                    params.append(
                        ParameterInfo(
                            name=p.name or f"arg{i}",
                            data_type=str(p.type) if p.type else "unknown",
                            index=i,
                        )
                    )
            except Exception:
                pass

            result.append(
                FunctionInfo(
                    name=func.name,
                    address=hex(func.start),
                    size=func.total_bytes,
                    callers=callers,
                    callees=callees,
                    parameters=params,
                    is_library=func.symbol is not None
                    and func.symbol.type.name == "ImportedFunctionSymbol",
                    is_thunk=func.is_thunk if hasattr(func, "is_thunk") else False,
                    backend_used=REBackendType.BINARY_NINJA,
                )
            )

        return result

    def get_function_by_name(self, name: str) -> Optional[FunctionInfo]:
        bv = self._program
        funcs = bv.get_functions_by_name(name)
        if funcs:
            func = funcs[0]
            return self._binja_func_to_info(func)

        # Partial match fallback
        for func in bv.functions:
            if name.lower() in func.name.lower():
                return self._binja_func_to_info(func)
        return None

    def decompile(self, function_name: str) -> Optional[str]:
        bv = self._program
        funcs = bv.get_functions_by_name(function_name)
        if not funcs:
            for f in bv.functions:
                if function_name.lower() in f.name.lower():
                    funcs = [f]
                    break
        if not funcs:
            return None

        func = funcs[0]
        try:
            # Use HLIL for pseudo-C
            hlil = func.hlil
            if hlil:
                lines = []
                for line in hlil.root.lines:
                    lines.append(str(line))
                return "\n".join(lines) if lines else None
        except Exception:
            pass

        # Fallback: use linear_disassembly
        try:
            settings = bv.get_default_disassembly_settings()
            return bv.get_linear_disassembly_text(func.start, settings)
        except Exception:
            return None

    def get_assembly(self, function_name: str, *, max_lines: int = 200) -> Optional[str]:
        bv = self._program
        funcs = bv.get_functions_by_name(function_name)
        if not funcs:
            for f in bv.functions:
                if function_name.lower() in f.name.lower():
                    funcs = [f]
                    break
        if not funcs:
            return None

        func = funcs[0]
        lines: List[str] = []
        for block in func.basic_blocks:
            for tokens, addr in block.disassembly_text:
                if len(lines) >= max_lines:
                    lines.append("... (truncated)")
                    return "\n".join(lines)
                line_text = "".join(str(t) for t in tokens) if hasattr(tokens, '__iter__') else str(tokens)
                lines.append(f"0x{addr:x}: {line_text}")

        return "\n".join(lines) if lines else None

    def get_imports(self) -> List[str]:
        from binaryninja import SymbolType

        bv = self._program
        symbols = bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol)
        imports = []
        for sym in symbols:
            name = sym.name
            cleaned = name[1:] if name.startswith("_") else name
            if cleaned not in imports:
                imports.append(cleaned)
        return imports

    def get_exports(self) -> List[str]:
        from binaryninja import SymbolType

        bv = self._program
        exports = []
        for sym in bv.get_symbols_of_type(SymbolType.FunctionSymbol):
            if sym.name not in exports:
                exports.append(sym.name)
        return exports

    def get_sections(self) -> List[SectionInfo]:
        bv = self._program
        sections: List[SectionInfo] = []

        for name, section in bv.sections.items():
            # Calculate entropy for the section
            try:
                data = bv.read(section.start, min(section.length, 5 * 1024 * 1024))
                entropy = self._calculate_entropy(data) if data else None
            except Exception:
                entropy = None

            sections.append(
                SectionInfo(
                    name=name,
                    start=hex(section.start),
                    end=hex(section.end),
                    size=section.length,
                    entropy=entropy,
                    is_executable=section.semantics.name == "ReadOnlyCodeSectionSemantics"
                    or "code" in name.lower()
                    or "text" in name.lower(),
                    is_writable="data" in name.lower() or "bss" in name.lower(),
                    is_readable=True,
                    section_type=section.type if hasattr(section, "type") else "",
                )
            )

        return sections

    def get_strings(self, *, min_length: int = 4) -> List[str]:
        bv = self._program
        return [
            s.value
            for s in bv.strings
            if len(s.value) >= min_length
        ]

    def get_cross_references(self, symbol_name: str) -> List[str]:
        bv = self._program
        funcs = bv.get_functions_by_name(symbol_name)
        if not funcs:
            return []

        target_addr = funcs[0].start
        callers: List[str] = []
        for ref in bv.get_code_refs(target_addr):
            for f in bv.get_functions_containing(ref.address):
                if f.name not in callers:
                    callers.append(f.name)
        return callers

    # ── string references (BN-specific) ────────────────────────

    def find_string_references(
        self,
        target_string: str,
        *,
        max_results: int = 5,
    ) -> List[Dict[str, Any]]:
        """Find functions that reference a specific string value."""
        import binaryninja
        bv = self._program
        results = []

        # Find the string's address in the binary
        for s in bv.strings:
            if target_string in s.value:
                # Get code references to this string address
                for ref in bv.get_code_refs(s.start):
                    for func in bv.get_functions_containing(ref.address):
                        if len(results) >= max_results:
                            break
                        # Avoid duplicates
                        if any(r["function_name"] == func.name for r in results):
                            continue

                        enrichment = self.enrich_function(func.name)
                        results.append({
                            "function_name": func.name,
                            "reference_address": hex(ref.address),
                            "string_address": hex(s.start),
                            **enrichment,
                        })

                    if len(results) >= max_results:
                        break
                if len(results) >= max_results:
                    break

        return results

    # ── extended IL queries (BN-specific) ──────────────────────

    def get_hlil(self, function_name: str) -> Optional[str]:
        """Return Binary Ninja HLIL for the given function."""
        bv = self._program
        funcs = bv.get_functions_by_name(function_name)
        if not funcs:
            return None

        func = funcs[0]
        try:
            hlil = func.hlil
            if hlil:
                return str(hlil)
        except Exception:
            pass
        return None

    def get_mlil(self, function_name: str) -> Optional[str]:
        """Return Binary Ninja MLIL SSA for taint analysis."""
        bv = self._program
        funcs = bv.get_functions_by_name(function_name)
        if not funcs:
            return None

        func = funcs[0]
        try:
            mlil = func.mlil
            if mlil:
                return str(mlil)
        except Exception:
            pass
        return None

    # ── metadata ───────────────────────────────────────────────

    def get_architecture(self) -> str:
        bv = self._program
        arch = bv.arch
        return arch.name if arch else "unknown"

    def get_binary_format(self) -> str:
        bv = self._program
        return bv.view_type or "Unknown"

    # ── private helpers ────────────────────────────────────────

    def _binja_func_to_info(self, func) -> FunctionInfo:
        """Convert a binaryninja.Function to FunctionInfo."""
        callees = [ref.name for ref in func.callees if hasattr(ref, "name")]
        callers = [ref.name for ref in func.callers if hasattr(ref, "name")]

        params = []
        try:
            for i, p in enumerate(func.parameter_vars):
                params.append(
                    ParameterInfo(
                        name=p.name or f"arg{i}",
                        data_type=str(p.type) if p.type else "unknown",
                        index=i,
                    )
                )
        except Exception:
            pass

        return FunctionInfo(
            name=func.name,
            address=hex(func.start),
            size=func.total_bytes,
            callers=callers,
            callees=callees,
            parameters=params,
            is_library=func.symbol is not None
            and func.symbol.type.name == "ImportedFunctionSymbol",
            backend_used=REBackendType.BINARY_NINJA,
        )

    @staticmethod
    def _calculate_entropy(data: bytes) -> Optional[float]:
        if not data:
            return None
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        length = len(data)
        entropy = 0.0
        for c in counts:
            if c > 0:
                p = c / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

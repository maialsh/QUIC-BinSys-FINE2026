"""
ORCA RE Backend — Ghidra / pyhidra

Wraps Ghidra's Java APIs (via pyhidra bridge) to implement the REBackend
protocol.  Ghidra excels at:
  • stripped binaries (better function-boundary detection + signature matching)
  • C++ / RTTI class-hierarchy reconstruction
  • exotic architectures
  • P-Code intermediate representation
"""

from __future__ import annotations

import math
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from orca.core.models import (
    FunctionInfo,
    ParameterInfo,
    REBackendType,
    SectionInfo,
)
from orca.core.re_backends.base import REBackend

# Lazy Ghidra imports — resolved at open() time
_ghidra_available = False
_pyhidra_started = False


def _ensure_ghidra() -> None:
    """Start pyhidra and import Ghidra Java classes once."""
    global _ghidra_available, _pyhidra_started

    if _ghidra_available:
        return

    try:
        import pyhidra

        if not _pyhidra_started:
            pyhidra.start()
            _pyhidra_started = True

        # Verify we can reach Ghidra classes
        from ghidra.program.flatapi import FlatProgramAPI  # noqa: F401
        _ghidra_available = True

    except ImportError as exc:
        raise RuntimeError(
            "Ghidra backend requires pyhidra and a valid GHIDRA_INSTALL_DIR. "
            "Install: pip install pyhidra  |  export GHIDRA_INSTALL_DIR=/path/to/ghidra"
        ) from exc


class GhidraBackend(REBackend):
    """Ghidra-based reverse-engineering backend."""

    backend_type = REBackendType.GHIDRA

    def __init__(self, binary_path: Path):
        super().__init__(binary_path)
        self._pyhidra_ctx: Any = None
        self._flat_api: Any = None
        self._prepared_path: Optional[Path] = None
        self._needs_cleanup = False

    # ── lifecycle ──────────────────────────────────────────────

    def open(self) -> None:
        _ensure_ghidra()

        import pyhidra
        from ghidra.util.task import ConsoleTaskMonitor

        # Handle universal Mach-O binaries by extracting a single arch
        self._prepared_path, self._needs_cleanup = self._prepare_binary(self.binary_path)

        project_name = self._prepared_path.stem + "_orca"
        project_location = self._prepared_path.parent / ".ghidra_projects"
        project_location.mkdir(exist_ok=True)

        # Clean stale project
        existing = project_location / project_name
        if existing.exists():
            shutil.rmtree(existing, ignore_errors=True)

        self._pyhidra_ctx = pyhidra.open_program(
            str(self._prepared_path),
            project_name=project_name,
            project_location=str(project_location),
            analyze=True,
        )
        self._flat_api = self._pyhidra_ctx.__enter__()
        self._program = self._flat_api.getCurrentProgram()

        # Wait for auto-analysis
        self._wait_for_analysis()

    def close(self) -> None:
        if self._pyhidra_ctx is not None:
            try:
                self._pyhidra_ctx.__exit__(None, None, None)
            except Exception:
                pass
            self._pyhidra_ctx = None

        if self._needs_cleanup and self._prepared_path and self._prepared_path.exists():
            try:
                self._prepared_path.unlink()
            except Exception:
                pass

        self._program = None

    # ── queries ────────────────────────────────────────────────

    def get_functions(self, *, include_thunks: bool = False) -> List[FunctionInfo]:
        from ghidra.util.task import ConsoleTaskMonitor

        fm = self._program.getFunctionManager()
        monitor = ConsoleTaskMonitor()
        result: List[FunctionInfo] = []

        for func in fm.getFunctions(True):
            if not include_thunks and func.isThunk():
                continue

            name = self._resolve_function_name(func)
            body = func.getBody()
            size = body.getNumAddresses() if body else 0

            try:
                callees = [c.getName() for c in func.getCalledFunctions(monitor) if c]
            except Exception:
                callees = []

            try:
                callers = [c.getName() for c in func.getCallingFunctions(monitor) if c]
            except Exception:
                callers = []

            params = self._extract_params(func)

            result.append(
                FunctionInfo(
                    name=name,
                    address=hex(func.getEntryPoint().getOffset()),
                    size=size,
                    callers=callers,
                    callees=callees,
                    parameters=params,
                    is_library=func.isExternal(),
                    is_thunk=func.isThunk(),
                    backend_used=REBackendType.GHIDRA,
                )
            )

        return result

    def get_function_by_name(self, name: str) -> Optional[FunctionInfo]:
        for f in self.get_functions():
            if f.name == name or name.lower() in f.name.lower():
                return f
        return None

    def decompile(self, function_name: str) -> Optional[str]:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor

        func = self._find_ghidra_function(function_name)
        if func is None:
            return None

        decomp = DecompInterface()
        decomp.toggleCCode(True)
        decomp.toggleSyntaxTree(True)
        decomp.setSimplificationStyle("decompile")
        decomp.setOptions(DecompileOptions())

        if not decomp.openProgram(self._program):
            return None

        try:
            result = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
            if result and result.decompileCompleted():
                df = result.getDecompiledFunction()
                return df.getC() if df else None
        finally:
            decomp.dispose()

        return None

    def get_assembly(self, function_name: str, *, max_lines: int = 200) -> Optional[str]:
        func = self._find_ghidra_function(function_name)
        if func is None:
            return None

        listing = self._program.getListing()
        body = func.getBody()
        lines: List[str] = []

        for instr in listing.getInstructions(body, True):
            if len(lines) >= max_lines:
                lines.append("... (truncated)")
                break
            addr = instr.getAddress().toString()
            mnemonic = instr.getMnemonicString()
            ops = ", ".join(
                instr.getDefaultOperandRepresentation(i) for i in range(instr.getNumOperands())
            )
            lines.append(f"{addr}: {mnemonic} {ops}")

        return "\n".join(lines) if lines else None

    def get_imports(self) -> List[str]:
        imports: List[str] = []
        st = self._program.getSymbolTable()

        for sym in st.getExternalSymbols():
            name = sym.getName()
            # Strip leading underscore (macOS convention)
            cleaned = name[1:] if name.startswith("_") else name
            if cleaned not in imports:
                imports.append(cleaned)

        # Also check external manager
        try:
            em = self._program.getExternalManager()
            for lib in em.getExternalLibraryNames():
                for loc in em.getExternalLocations(lib):
                    label = loc.getLabel()
                    if label:
                        cleaned = label[1:] if label.startswith("_") else label
                        if cleaned not in imports:
                            imports.append(cleaned)
        except Exception:
            pass

        return imports

    def get_exports(self) -> List[str]:
        from ghidra.program.model.symbol import SymbolType

        exports: List[str] = []
        st = self._program.getSymbolTable()

        for sym in st.getAllSymbols(True):
            if sym.isExternal():
                continue
            if sym.getSymbolType() in (SymbolType.FUNCTION, SymbolType.LABEL):
                name = sym.getName()
                if name not in exports:
                    exports.append(name)

        return exports

    def get_sections(self) -> List[SectionInfo]:
        memory = self._program.getMemory()
        sections: List[SectionInfo] = []

        for block in memory.getBlocks():
            entropy = self._block_entropy(block)
            sections.append(
                SectionInfo(
                    name=block.getName(),
                    start=hex(block.getStart().getOffset()),
                    end=hex(block.getEnd().getOffset()),
                    size=int(block.getSize()),
                    entropy=entropy,
                    is_executable=block.isExecute(),
                    is_writable=block.isWrite(),
                    is_readable=block.isRead(),
                    section_type=block.getType().toString(),
                )
            )

        return sections

    def get_strings(self, *, min_length: int = 4) -> List[str]:
        strings: List[str] = []

        # Method 1 — defined data strings
        listing = self._program.getListing()
        for data in listing.getDefinedData(True):
            if data.hasStringValue():
                try:
                    val = str(data.getValue())
                    if len(val) >= min_length:
                        strings.append(val)
                except Exception:
                    continue

        # Method 2 — raw ASCII from initialised memory blocks
        memory = self._program.getMemory()
        for block in memory.getBlocks():
            if not block.isInitialized() or not block.isRead():
                continue
            try:
                block_size = min(int(block.getSize()), 1024 * 1024)
                raw_bytes = bytearray()
                for i in range(block_size):
                    try:
                        raw_bytes.append(memory.getByte(block.getStart().add(i)) & 0xFF)
                    except Exception:
                        raw_bytes.append(0)
                strings.extend(self._extract_ascii(bytes(raw_bytes), min_length))
            except Exception:
                continue

        return list(set(strings))

    def get_cross_references(self, symbol_name: str) -> List[str]:
        func = self._find_ghidra_function(symbol_name)
        if func is None:
            return []

        from ghidra.util.task import ConsoleTaskMonitor

        callers: List[str] = []
        try:
            for c in func.getCallingFunctions(ConsoleTaskMonitor()):
                if c and c.getName() not in callers:
                    callers.append(c.getName())
        except Exception:
            pass

        return callers

    def get_mlil(self, function_name: str) -> Optional[str]:
        """Ghidra P-Code as the MLIL-equivalent."""
        # P-Code extraction would require iterating PcodeOps — stub for now
        return None

    # ── metadata ───────────────────────────────────────────────

    def get_architecture(self) -> str:
        return self._program.getLanguage().getProcessor().toString()

    def get_binary_format(self) -> str:
        return self._program.getExecutableFormat() or "Unknown"

    # ── private helpers ────────────────────────────────────────

    def _find_ghidra_function(self, name: str):
        """Look up a Ghidra Function object by name."""
        fm = self._program.getFunctionManager()
        for func in fm.getFunctions(True):
            fname = func.getName()
            if fname == name or name.lower() in fname.lower():
                return func
        return None

    def _resolve_function_name(self, func) -> str:
        """Return the best available name for a Ghidra function."""
        name = func.getName()
        if name.startswith("FUN_") or name == "entry":
            st = self._program.getSymbolTable()
            sym = st.getPrimarySymbol(func.getEntryPoint())
            if sym and not sym.getName().startswith("FUN_"):
                return sym.getName()
        return name

    def _extract_params(self, func) -> List[ParameterInfo]:
        params: List[ParameterInfo] = []
        try:
            sig = func.getSignature()
            if sig:
                for i in range(sig.getParameterCount()):
                    p = sig.getParameter(i)
                    params.append(
                        ParameterInfo(
                            name=p.getName() or f"arg{i}",
                            data_type=str(p.getDataType()) if p.getDataType() else "unknown",
                            index=i,
                        )
                    )
        except Exception:
            pass
        return params

    def _wait_for_analysis(self) -> None:
        try:
            mgr = self._program.getAnalysisManager()
            if mgr and mgr.isAnalyzing():
                timeout = 120
                waited = 0.0
                while mgr.isAnalyzing() and waited < timeout:
                    time.sleep(0.2)
                    waited += 0.2
        except Exception:
            pass

    def _block_entropy(self, block) -> Optional[float]:
        try:
            size = int(block.getSize())
            if size > 5 * 1024 * 1024 or not block.isInitialized():
                return None

            memory = self._program.getMemory()
            counts = [0] * 256
            for i in range(size):
                counts[memory.getByte(block.getStart().add(i)) & 0xFF] += 1

            entropy = 0.0
            for c in counts:
                if c > 0:
                    p = c / size
                    entropy -= p * math.log2(p)
            return round(entropy, 4)
        except Exception:
            return None

    @staticmethod
    def _extract_ascii(data: bytes, min_length: int) -> List[str]:
        strings: List[str] = []
        current = ""
        for b in data:
            if 32 <= b <= 126:
                current += chr(b)
            else:
                if len(current) >= min_length:
                    strings.append(current)
                current = ""
        if len(current) >= min_length:
            strings.append(current)
        return strings

    @staticmethod
    def _prepare_binary(path: Path):
        """Extract single architecture from universal Mach-O if needed."""
        try:
            result = subprocess.run(["file", str(path)], capture_output=True, text=True)
            if "universal binary" not in result.stdout.lower():
                return path, False

            lipo = subprocess.run(["lipo", "-info", str(path)], capture_output=True, text=True)
            arch = "x86_64"
            if "x86_64" not in lipo.stdout:
                for a in ("arm64e", "arm64"):
                    if a in lipo.stdout:
                        arch = a
                        break
                else:
                    return path, False

            out = path.parent / f"{path.stem}_{arch}_extracted"
            subprocess.run(
                ["lipo", str(path), "-thin", arch, "-output", str(out)],
                capture_output=True,
                text=True,
                check=True,
            )
            return out, True

        except Exception:
            return path, False

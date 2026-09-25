"""
ORCA Reverse-Engineering Backend Abstraction

Provides a common Protocol for Binary Ninja and Ghidra,
plus an intelligent selector that picks the best backend
(or both) based on binary characteristics.
"""

from orca.core.re_backends.base import REBackend
from orca.core.re_backends.selector import REBackendSelector

__all__ = ["REBackend", "REBackendSelector"]

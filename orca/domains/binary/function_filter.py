"""
ORCA Function Filter — scores and ranks functions by security relevance.

Ported from binsleuth/src/cmd/intelligent_filter.py.
Pure local computation, no LLM calls.
"""
from __future__ import annotations
import re
import math
from typing import Any, Dict, List, Set, Tuple
from orca.core.models import FunctionInfo


# APIs that indicate security-relevant behavior
HIGH_PRIORITY_APIS: Set[str] = {
    # Network
    "socket", "connect", "bind", "listen", "accept", "send", "recv",
    "sendto", "recvfrom", "WSAStartup", "WSASocket", "InternetOpen",
    "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
    "URLDownloadToFile", "getaddrinfo", "gethostbyname",
    # Process / Thread
    "CreateProcess", "CreateThread", "CreateRemoteThread", "OpenProcess",
    "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext",
    "NtCreateThreadEx", "RtlCreateUserThread",
    "fork", "exec", "execve", "system", "popen",
    # File
    "CreateFile", "WriteFile", "ReadFile", "DeleteFile", "MoveFile",
    "open", "read", "write", "unlink", "chmod", "fopen",
    # Registry
    "RegOpenKey", "RegSetValue", "RegCreateKey", "RegDeleteKey",
    "RegOpenKeyEx", "RegSetValueEx",
    # Crypto
    "CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptGenKey",
    "CryptAcquireContext", "BCryptEncrypt", "BCryptDecrypt",
    # Anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "ptrace",
    "OutputDebugString", "QueryPerformanceCounter", "GetTickCount",
    "NtQueryInformationProcess",
    # Privilege
    "AdjustTokenPrivileges", "OpenProcessToken", "setuid", "seteuid",
    "LookupPrivilegeValue",
    # Injection
    "NtSuspendThread", "NtResumeThread", "NtSuspendProcess",
    "NtSetInformationProcess", "LoadLibrary", "GetProcAddress",
}

SUSPICIOUS_NAME_PATTERNS = [
    "crypt", "encode", "decode", "inject", "hook",
    "backdoor", "shell", "exec", "system", "payload",
    "exploit", "obfuscat", "pack", "unpack", "decrypt",
    "encrypt", "keylog", "screenshot", "download", "upload",
    "connect", "beacon", "c2", "command",
]

API_CATEGORIES = {
    "network": {"socket", "connect", "bind", "listen", "accept", "send", "recv",
                "sendto", "recvfrom", "WSAStartup", "WSASocket", "InternetOpen",
                "InternetConnect", "HttpOpenRequest", "URLDownloadToFile",
                "getaddrinfo", "gethostbyname"},
    "process": {"CreateProcess", "CreateThread", "CreateRemoteThread", "OpenProcess",
                "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext",
                "fork", "exec", "execve", "system", "popen"},
    "file": {"CreateFile", "WriteFile", "ReadFile", "DeleteFile", "MoveFile",
             "open", "read", "write", "unlink", "chmod", "fopen"},
    "registry": {"RegOpenKey", "RegSetValue", "RegCreateKey", "RegDeleteKey",
                 "RegOpenKeyEx", "RegSetValueEx"},
    "crypto": {"CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptGenKey",
               "BCryptEncrypt", "BCryptDecrypt"},
    "anti_analysis": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "ptrace",
                      "OutputDebugString", "NtQueryInformationProcess"},
    "privilege": {"AdjustTokenPrivileges", "OpenProcessToken", "setuid", "seteuid",
                  "LookupPrivilegeValue"},
    "injection": {"NtSuspendThread", "NtResumeThread", "LoadLibrary",
                  "GetProcAddress", "VirtualAllocEx", "WriteProcessMemory"},
}


def score_function(func: FunctionInfo) -> int:
    """Score a function's security relevance (0-100). No LLM calls."""
    if func.is_library or func.is_thunk:
        return 0

    score = 0

    # API calls in callees
    hp_count = sum(
        1 for callee in func.callees
        if any(api.lower() in callee.lower() for api in HIGH_PRIORITY_APIS)
    )
    score += min(hp_count * 15, 40)

    # Suspicious function name
    name_lower = func.name.lower()
    if any(p in name_lower for p in SUSPICIOUS_NAME_PATTERNS):
        score += 15

    # Function size
    if func.size > 1000:
        score += 10
    elif func.size > 500:
        score += 5

    # Call complexity
    n_callees = len(func.callees)
    if n_callees > 10:
        score += 15
    elif n_callees > 5:
        score += 10
    elif n_callees > 2:
        score += 5

    # Bonus: function has many callers (central hub)
    if len(func.callers) > 5:
        score += 5

    return min(score, 100)


def filter_functions(
    functions: List[FunctionInfo],
    top_n: int = 20,
    min_score: int = 15,
) -> List[FunctionInfo]:
    """Return the top-N most security-relevant functions with scores populated."""
    scored = []
    for func in functions:
        s = score_function(func)
        if s >= min_score:
            func.interest_score = s
            scored.append(func)

    scored.sort(key=lambda f: f.interest_score, reverse=True)

    for rank, func in enumerate(scored[:top_n], 1):
        func.interest_rank = rank

    return scored[:top_n]


def prioritize_apis(imports: List[str], top_n: int = 30) -> List[Tuple[str, str, int]]:
    """Rank imported APIs by security relevance. Returns (api, category, score)."""
    results = []
    for api in imports:
        api_lower = api.lower()
        category = "other"
        priority = 0

        for cat_name, cat_apis in API_CATEGORIES.items():
            if any(a.lower() in api_lower for a in cat_apis):
                category = cat_name
                priority = 80
                break

        # High-priority exact match
        if any(hp.lower() == api_lower for hp in HIGH_PRIORITY_APIS):
            priority = 100

        if priority > 0:
            results.append((api, category, priority))

    results.sort(key=lambda x: x[2], reverse=True)
    return results[:top_n]

"""
ORCA Configuration — YAML/JSON/env-based config management.
"""
import json, os
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_CONFIG = {
    "llm": {
        "provider": "openai",
        "model": "gpt-4o",
        "temperature": 0.1,
        "top_p": 1.0,
        "max_tokens": 2048,
        "timeout": 120,
        "retry_attempts": 7,
        "rate_limit_delay": 15,
        "requests_per_minute": 15,
        "min_delay_between_requests": 4.0,
        "max_tokens_per_request": 8000,
        "circuit_breaker_threshold": 5,
        "circuit_breaker_timeout": 90,
    },
    "analysis": {
        "max_file_size": 50 * 1024 * 1024,
        "extract_strings_min_length": 4,
        "max_functions_to_analyze": 500,
        "enable_llm_analysis": True,
        "function_filter_top_percent": 0.3,
        "function_filter_min_score": 20,
        "function_enrich_top_n": 20,
        "max_decompiled_chars": 2000,
        "max_assembly_lines": 100,
        "max_crossref_apis": 30,
        "max_crossref_functions_per_api": 3,
        "max_suspicious_strings_for_crossref": 10,
        "string_threat_min_score": 50,
    },
    "re_backend": {
        "default": "auto",  # auto | binja | ghidra
        "binja_python_path": "/Applications/Binary Ninja.app/Contents/Resources/python",
        "ghidra_install_dir": os.environ.get("GHIDRA_INSTALL_DIR", ""),
    },
    "behavior_patterns": {
        "network": ["socket", "bind", "listen", "accept", "connect", "recv", "send"],
        "process": ["exec", "fork", "spawn", "clone", "kill", "ptrace"],
        "filesystem": ["open", "read", "write", "unlink", "mkdir", "rmdir", "chmod"],
        "privilege": ["setuid", "setgid", "capset", "prctl"],
        "crypto": ["crypt", "md5", "sha1", "aes", "des", "blowfish"],
        "anti_analysis": ["ptrace", "getpid", "gettimeofday", "clock_gettime", "sysinfo"],
        "persistence": ["crontab", "systemd", "init", "rc", "bashrc", "profile"],
    },
}

class OrcaConfig:
    def __init__(self, config_path: Optional[str] = None):
        self.config: Dict[str, Any] = json.loads(json.dumps(DEFAULT_CONFIG))
        if config_path and Path(config_path).exists():
            with open(config_path) as f:
                self._deep_merge(self.config, json.load(f))
        self._load_credentials()
        self._load_env()

    def _load_credentials(self):
        try:
            agent_cfg = os.environ.get("AGENTCONFIG")
            if agent_cfg and Path(agent_cfg).exists():
                creds = json.load(open(agent_cfg))
                if "OPENAI_API_KEY" in creds:
                    os.environ.setdefault("OPENAI_API_KEY", creds["OPENAI_API_KEY"])
                if "ANTHROPIC_API_KEY" in creds:
                    os.environ.setdefault("ANTHROPIC_API_KEY", creds["ANTHROPIC_API_KEY"])
        except Exception:
            pass

    def _load_env(self):
        if m := os.environ.get("LLM_MODEL"):
            self.config["llm"]["model"] = m
        if p := os.environ.get("LLM_PROVIDER"):
            self.config["llm"]["provider"] = p

    def _deep_merge(self, target, source):
        for k, v in source.items():
            if k in target and isinstance(target[k], dict) and isinstance(v, dict):
                self._deep_merge(target[k], v)
            else:
                target[k] = v

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        result = self.config
        for k in keys:
            if isinstance(result, dict) and k in result:
                result = result[k]
            else:
                return default
        return result

    @property
    def llm(self) -> Dict[str, Any]:
        return self.config["llm"]

    @property
    def analysis(self) -> Dict[str, Any]:
        return self.config["analysis"]

# Singleton
config = OrcaConfig()

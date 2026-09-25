"""
ORCA Sandbox Integration — SSH-based remote sandbox execution.

Supports REMnux and Cuckoo sandboxes via SSH tunnel:
  - Upload sample to remote sandbox
  - Trigger analysis (detonation)
  - Poll for completion
  - Retrieve results (behavioural report, PCAP, screenshots)
"""
from __future__ import annotations
import json, os, time, tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class SandboxType(str, Enum):
    REMNUX = "remnux"
    CUCKOO = "cuckoo"
    CUSTOM = "custom"


@dataclass
class SandboxConfig:
    """SSH connection config for a remote sandbox."""
    sandbox_type: SandboxType
    host: str
    port: int = 22
    username: str = "analyst"
    key_path: Optional[str] = None
    password: Optional[str] = None
    upload_dir: str = "/tmp/orca_samples"
    results_dir: str = "/tmp/orca_results"
    timeout: int = 300
    cuckoo_api_port: int = 8090


@dataclass
class SandboxResult:
    """Results from sandbox execution."""
    status: str = "pending"
    task_id: Optional[str] = None
    report: Optional[Dict[str, Any]] = None
    pcap_path: Optional[str] = None
    screenshots: List[str] = field(default_factory=list)
    duration: float = 0.0
    error: Optional[str] = None


class SandboxConnector:
    """SSH-based connector to remote sandboxes."""

    def __init__(self, config: SandboxConfig):
        self.config = config
        self._ssh = None

    def _connect(self):
        try:
            import paramiko
        except ImportError:
            raise RuntimeError("pip install paramiko")
        if self._ssh and self._ssh.get_transport() and self._ssh.get_transport().is_active():
            return
        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {"hostname": self.config.host, "port": self.config.port,
                  "username": self.config.username}
        if self.config.key_path:
            kwargs["key_filename"] = self.config.key_path
        elif self.config.password:
            kwargs["password"] = self.config.password
        self._ssh.connect(**kwargs)

    def _exec(self, cmd: str) -> str:
        self._connect()
        _, stdout, stderr = self._ssh.exec_command(cmd, timeout=self.config.timeout)
        out = stdout.read().decode()
        err = stderr.read().decode()
        if err and "error" in err.lower():
            raise RuntimeError(err)
        return out

    def _upload(self, local_path: str, remote_path: str):
        self._connect()
        sftp = self._ssh.open_sftp()
        try:
            sftp.stat(os.path.dirname(remote_path))
        except FileNotFoundError:
            self._exec(f"mkdir -p {os.path.dirname(remote_path)}")
        sftp.put(local_path, remote_path)
        sftp.close()

    def _download(self, remote_path: str, local_path: str):
        self._connect()
        sftp = self._ssh.open_sftp()
        sftp.get(remote_path, local_path)
        sftp.close()

    def submit(self, binary_path: str) -> SandboxResult:
        """Upload and submit sample for analysis."""
        if self.config.sandbox_type == SandboxType.CUCKOO:
            return self._submit_cuckoo(binary_path)
        elif self.config.sandbox_type == SandboxType.REMNUX:
            return self._submit_remnux(binary_path)
        else:
            return self._submit_custom(binary_path)

    def _submit_cuckoo(self, binary_path: str) -> SandboxResult:
        result = SandboxResult()
        t0 = time.time()
        try:
            name = Path(binary_path).name
            remote = f"{self.config.upload_dir}/{name}"
            self._upload(binary_path, remote)
            port = self.config.cuckoo_api_port
            out = self._exec(
                f'curl -s -F file=@{remote} http://localhost:{port}/tasks/create/file'
            )
            data = json.loads(out)
            task_id = str(data.get("task_id", ""))
            result.task_id = task_id
            result.status = "submitted"
            # Poll for completion
            for _ in range(self.config.timeout // 10):
                time.sleep(10)
                status_out = self._exec(
                    f'curl -s http://localhost:{port}/tasks/view/{task_id}'
                )
                status_data = json.loads(status_out)
                task = status_data.get("task", {})
                if task.get("status") == "reported":
                    report_out = self._exec(
                        f'curl -s http://localhost:{port}/tasks/report/{task_id}'
                    )
                    result.report = json.loads(report_out)
                    result.status = "completed"
                    break
            else:
                result.status = "timeout"
        except Exception as exc:
            result.error = str(exc)
            result.status = "failed"
        result.duration = time.time() - t0
        return result

    def _submit_remnux(self, binary_path: str) -> SandboxResult:
        result = SandboxResult()
        t0 = time.time()
        try:
            name = Path(binary_path).name
            remote_sample = f"{self.config.upload_dir}/{name}"
            remote_results = f"{self.config.results_dir}/{name}"
            self._upload(binary_path, remote_sample)
            self._exec(f"mkdir -p {remote_results}")
            # Static analysis tools on REMnux
            tools_output = {}
            cmds = {
                "file": f"file {remote_sample}",
                "strings": f"strings -n 6 {remote_sample} | head -200",
                "exiftool": f"exiftool {remote_sample} 2>/dev/null || true",
                "ssdeep": f"ssdeep {remote_sample} 2>/dev/null || true",
                "yara": f"yara -r /opt/yara-rules/ {remote_sample} 2>/dev/null || true",
                "peframe": f"peframe {remote_sample} 2>/dev/null || echo 'N/A'",
                "floss": f"floss --quiet {remote_sample} 2>/dev/null | head -100 || true",
            }
            for tool_name, cmd in cmds.items():
                try:
                    tools_output[tool_name] = self._exec(cmd)[:5000]
                except Exception as e:
                    tools_output[tool_name] = f"error: {e}"
            result.report = {"tools": tools_output, "sample": name}
            result.status = "completed"
        except Exception as exc:
            result.error = str(exc)
            result.status = "failed"
        result.duration = time.time() - t0
        return result

    def _submit_custom(self, binary_path: str) -> SandboxResult:
        result = SandboxResult()
        t0 = time.time()
        try:
            name = Path(binary_path).name
            remote = f"{self.config.upload_dir}/{name}"
            self._upload(binary_path, remote)
            out = self._exec(f"ls -la {remote}")
            result.report = {"uploaded": remote, "info": out}
            result.status = "completed"
        except Exception as exc:
            result.error = str(exc)
            result.status = "failed"
        result.duration = time.time() - t0
        return result

    def close(self):
        if self._ssh:
            self._ssh.close()
            self._ssh = None

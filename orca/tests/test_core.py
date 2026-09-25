"""Tests for ORCA core infrastructure."""
import pytest


def test_config_defaults():
    from orca.core.config import OrcaConfig
    cfg = OrcaConfig()
    assert cfg.get("llm.provider") == "openai"
    assert cfg.get("analysis.max_file_size") == 50 * 1024 * 1024
    assert cfg.get("nonexistent.key", "default") == "default"


def test_config_dot_access():
    from orca.core.config import OrcaConfig
    cfg = OrcaConfig()
    assert isinstance(cfg.llm, dict)
    assert "model" in cfg.llm
    assert isinstance(cfg.analysis, dict)


def test_rate_limiter():
    from orca.core.llm.rate_limiter import RateLimiter
    rl = RateLimiter(rpm=100, min_delay=0.01)
    waited = rl.wait_if_needed()
    assert waited >= 0


def test_circuit_breaker():
    from orca.core.llm.rate_limiter import CircuitBreaker
    cb = CircuitBreaker(threshold=3, timeout=1)
    assert cb.can_attempt()
    assert cb.get_state() == "closed"
    cb.record_failure()
    cb.record_failure()
    cb.record_failure()
    assert cb.get_state() == "open"
    assert not cb.can_attempt()
    cb.record_success()
    assert cb.get_state() == "closed"


def test_token_estimator():
    from orca.core.llm.rate_limiter import TokenEstimator
    tokens = TokenEstimator.estimate_tokens("Hello world, this is a test string.")
    assert tokens > 0
    msg_tokens = TokenEstimator.estimate_messages([
        {"role": "system", "content": "You are helpful."},
        {"role": "user", "content": "Hi"},
    ])
    assert msg_tokens > tokens


def test_re_backend_selector():
    from orca.core.re_backends.selector import REBackendSelector
    from orca.core.models import REBackendType
    selector = REBackendSelector()
    result = selector.select(
        __import__("pathlib").Path("/nonexistent"),
        force_backend=REBackendType.GHIDRA,
    )
    assert result == [REBackendType.GHIDRA]


def test_re_backend_selector_auto():
    from orca.core.re_backends.selector import REBackendSelector
    from orca.core.models import REBackendType
    selector = REBackendSelector()
    result = selector.select(
        __import__("pathlib").Path("/nonexistent"),
        is_packed=True,
    )
    assert REBackendType.GHIDRA in result
    assert REBackendType.BINARY_NINJA in result

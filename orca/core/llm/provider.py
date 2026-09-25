"""
ORCA LLM Provider — unified interface to LiteLLM with rate limiting,
circuit breaking, retries, structured JSON output, and usage tracking.
"""
from __future__ import annotations
import json, os, time, random, re
from typing import Any, Dict, List, Optional
from orca.core.config import config
from orca.core.llm.rate_limiter import TokenEstimator, RateLimiter, CircuitBreaker


def _clean_json(text: str) -> str:
    """Strip markdown fences and trailing commas from LLM JSON output."""
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*$", "", text)
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return text.strip()


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Try multiple strategies to extract a JSON object from LLM output."""
    cleaned = _clean_json(text)

    # Strategy 1: direct parse
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Strategy 2: find first { ... } block
    start = cleaned.find("{")
    if start >= 0:
        depth = 0
        for i in range(start, len(cleaned)):
            if cleaned[i] == "{":
                depth += 1
            elif cleaned[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(cleaned[start:i + 1])
                    except json.JSONDecodeError:
                        break

    # Strategy 3: strip trailing commas more aggressively and retry
    aggressive = re.sub(r",\s*}", "}", cleaned)
    aggressive = re.sub(r",\s*]", "]", aggressive)
    try:
        return json.loads(aggressive)
    except json.JSONDecodeError:
        pass

    return None


# Cost per 1M tokens (USD) — update as pricing changes
MODEL_PRICING = {
    "anthropic/claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
    "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
    "anthropic/claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
    "anthropic/claude-opus-4-20250514": {"input": 15.00, "output": 75.00},
    "claude-opus-4-20250514": {"input": 15.00, "output": 75.00},
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4.1": {"input": 2.00, "output": 8.00},
    "gpt-4.1-mini": {"input": 0.40, "output": 1.60},
}


class LLMProvider:
    """
    Thin wrapper around LiteLLM with resilience features and usage tracking.

    Supports any model string LiteLLM understands:
      anthropic/claude-sonnet-4-20250514, gpt-4o, ollama/llama3, etc.

    Usage tracking is class-level so all instances share the same counters.
    """

    # Class-level usage tracking shared across all instances
    _global_usage = {
        "total_requests": 0,
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "total_tokens": 0,
        "total_cost_usd": 0.0,
        "per_request": [],
    }

    def __init__(self, model: Optional[str] = None):
        self.model = model or config.get("llm.model")
        self.temperature = config.get("llm.temperature", 0.1)
        self.max_tokens = config.get("llm.max_tokens", 4096)
        self.timeout = config.get("llm.timeout", 120)
        self._retries = config.get("llm.retry_attempts", 7)
        self._rl_delay = config.get("llm.rate_limit_delay", 15)
        self._limiter = RateLimiter(
            config.get("llm.requests_per_minute", 15),
            config.get("llm.min_delay_between_requests", 4.0),
        )
        self._breaker = CircuitBreaker(
            config.get("llm.circuit_breaker_threshold", 5),
            config.get("llm.circuit_breaker_timeout", 90),
        )

    # ── public API ─────────────────────────────────────────────

    def query(
        self,
        system: str,
        user: str,
        *,
        temperature: Optional[float] = None,
        agent: Optional[str] = None,
    ) -> str:
        """Send system+user prompt, return raw text response.

        `agent` is an optional tag (e.g. "attack_classification",
        "binary_assessment") attached to the per-request usage entry.
        Lets cost/token totals be rolled up per-agent without changing
        the call signature elsewhere.
        """
        msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        return self._send(msgs, temperature=temperature, agent=agent)

    def query_json(
        self,
        system: str,
        user: str,
        *,
        temperature: Optional[float] = None,
        agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send prompt and parse JSON response (with robust extraction and retry)."""
        raw = self.query(system, user, temperature=temperature, agent=agent)
        parsed = _extract_json(raw)
        if parsed is not None:
            return parsed

        # Retry with explicit JSON instruction
        retry_user = user + "\n\nIMPORTANT: Your response MUST be valid JSON only. No text before or after the JSON object."
        raw = self.query(system, retry_user, temperature=temperature, agent=agent)
        parsed = _extract_json(raw)
        if parsed is not None:
            return parsed

        raise ValueError(f"Could not parse JSON from LLM response: {raw[:200]}")

    @classmethod
    def get_usage(cls) -> Dict[str, Any]:
        """Return accumulated usage statistics (class-level, shared across all instances)."""
        return {
            "total_requests": cls._global_usage["total_requests"],
            "total_input_tokens": cls._global_usage["total_input_tokens"],
            "total_output_tokens": cls._global_usage["total_output_tokens"],
            "total_tokens": cls._global_usage["total_tokens"],
            "total_cost_usd": round(cls._global_usage["total_cost_usd"], 6),
        }

    @classmethod
    def get_usage_per_request(cls) -> List[Dict[str, Any]]:
        """Return per-request usage details."""
        return cls._global_usage["per_request"]

    @classmethod
    def get_usage_by_agent(cls) -> Dict[str, Dict[str, Any]]:
        """Roll up per-request usage by `agent` tag.

        Returns a dict keyed by agent name with per-agent totals:
            {
              "attack_classification": {
                "requests": 5,
                "input_tokens": 12000,
                "output_tokens": 800,
                "total_tokens": 12800,
                "cost_usd": 0.038,
              },
              ...
            }

        Untagged requests are aggregated under "_untagged".
        """
        rollup: Dict[str, Dict[str, Any]] = {}
        for entry in cls._global_usage["per_request"]:
            key = entry.get("agent") or "_untagged"
            slot = rollup.setdefault(key, {
                "requests": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "cost_usd": 0.0,
            })
            slot["requests"] += 1
            slot["input_tokens"] += entry.get("input_tokens", 0)
            slot["output_tokens"] += entry.get("output_tokens", 0)
            slot["total_tokens"] += entry.get("total_tokens", 0)
            slot["cost_usd"] += entry.get("cost_usd", 0.0)
        for slot in rollup.values():
            slot["cost_usd"] = round(slot["cost_usd"], 6)
        return rollup

    @classmethod
    def reset_usage(cls):
        """Reset usage counters (call before each binary analysis)."""
        cls._global_usage = {
            "total_requests": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_tokens": 0,
            "total_cost_usd": 0.0,
            "per_request": [],
        }

    @classmethod
    def usage_snapshot(cls) -> Dict[str, Any]:
        """Return a single dict combining totals + per-agent rollup.

        Designed to be embedded in a per-cell result JSON so each
        analysis carries its own LLM cost/token breakdown.
        """
        return {
            "totals": cls.get_usage(),
            "by_agent": cls.get_usage_by_agent(),
            "n_requests": len(cls._global_usage["per_request"]),
        }

    @classmethod
    def usage_count(cls) -> int:
        """Number of LLM requests recorded so far (class-level).

        Use as a checkpoint at agent entry; pair with `usage_since(N)`
        to get the agent's own usage delta.
        """
        return len(cls._global_usage["per_request"])

    @classmethod
    def usage_since(cls, start_index: int) -> Dict[str, Any]:
        """Aggregate per-request usage from `start_index` onwards.

        Returns:
            {
              "n_requests": int,
              "input_tokens": int,
              "output_tokens": int,
              "total_tokens": int,
              "cost_usd": float,
              "model": str | None  (the model used; None if mixed)
            }
        """
        entries = cls._global_usage["per_request"][start_index:]
        if not entries:
            return {
                "n_requests": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "cost_usd": 0.0,
                "model": None,
            }
        models = {e.get("model") for e in entries}
        return {
            "n_requests": len(entries),
            "input_tokens": sum(e.get("input_tokens", 0) for e in entries),
            "output_tokens": sum(e.get("output_tokens", 0) for e in entries),
            "total_tokens": sum(e.get("total_tokens", 0) for e in entries),
            "cost_usd": round(sum(e.get("cost_usd", 0.0) for e in entries), 6),
            "model": next(iter(models)) if len(models) == 1 else "mixed",
        }

    def _estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost in USD based on model pricing."""
        pricing = MODEL_PRICING.get(self.model, {})
        if not pricing:
            # Try without provider prefix
            short_model = self.model.split("/")[-1] if "/" in self.model else self.model
            pricing = MODEL_PRICING.get(short_model, {"input": 0, "output": 0})
        input_cost = (input_tokens / 1_000_000) * pricing.get("input", 0)
        output_cost = (output_tokens / 1_000_000) * pricing.get("output", 0)
        return input_cost + output_cost

    # ── internal ───────────────────────────────────────────────

    def _send(
        self,
        messages: List[Dict[str, str]],
        *,
        temperature: Optional[float] = None,
        agent: Optional[str] = None,
    ) -> str:
        from litellm import completion
        from litellm.exceptions import RateLimitError, ServiceUnavailableError, APIError

        if not self._breaker.can_attempt():
            raise RuntimeError(f"Circuit breaker open: {self._breaker.get_state()}")

        cur_temp = temperature if temperature is not None else self.temperature
        cur_max = self.max_tokens

        for attempt in range(1, self._retries + 1):
            try:
                self._limiter.wait_if_needed()
                resp = completion(
                    model=self.model,
                    messages=messages,
                    temperature=cur_temp,
                    max_tokens=cur_max,
                    timeout=self.timeout,
                )
                self._breaker.record_success()

                # Track usage (class-level, shared across all instances)
                usage = getattr(resp, "usage", None)
                input_tokens = getattr(usage, "prompt_tokens", 0) if usage else 0
                output_tokens = getattr(usage, "completion_tokens", 0) if usage else 0
                total_tokens = input_tokens + output_tokens
                cost = self._estimate_cost(input_tokens, output_tokens)

                LLMProvider._global_usage["total_requests"] += 1
                LLMProvider._global_usage["total_input_tokens"] += input_tokens
                LLMProvider._global_usage["total_output_tokens"] += output_tokens
                LLMProvider._global_usage["total_tokens"] += total_tokens
                LLMProvider._global_usage["total_cost_usd"] += cost
                LLMProvider._global_usage["per_request"].append({
                    "agent": agent,
                    "model": self.model,
                    "timestamp": time.time(),
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": total_tokens,
                    "cost_usd": round(cost, 6),
                })

                return resp.choices[0].message.content

            except RateLimitError:
                self._breaker.record_failure()
                cur_max = int(cur_max * 0.7)
                wait = self._rl_delay * attempt + random.uniform(0, self._rl_delay * 0.2)
                time.sleep(wait)

            except (ServiceUnavailableError, APIError):
                self._breaker.record_failure()
                time.sleep(min(2 ** attempt, 60))

            except Exception as exc:
                self._breaker.record_failure()
                raise

        raise RuntimeError(f"LLM query failed after {self._retries} attempts")

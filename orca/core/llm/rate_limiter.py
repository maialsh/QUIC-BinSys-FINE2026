"""
Rate Limiter & Circuit Breaker — carried forward from BinSleuth with minor cleanup.
"""
import time, threading, math
from collections import deque, Counter
from typing import List, Optional

class TokenEstimator:
    @staticmethod
    def estimate_tokens(text: str) -> int:
        return max(1, len(text) // 3) if text else 0

    @staticmethod
    def estimate_messages(messages: list) -> int:
        total = sum(
            TokenEstimator.estimate_tokens(m.get("content", "") if isinstance(m, dict) else str(m))
            for m in messages
        )
        return total + len(messages) * 10

class RateLimiter:
    def __init__(self, rpm: int = 20, min_delay: float = 3.0):
        self.rpm, self.min_delay = rpm, min_delay
        self._times: deque = deque()
        self._lock = threading.Lock()
        self._last = 0.0

    def wait_if_needed(self) -> float:
        with self._lock:
            now = time.time()
            waited = 0.0
            gap = self.min_delay - (now - self._last)
            if gap > 0:
                time.sleep(gap); waited += gap; now = time.time()
            cutoff = now - 60
            while self._times and self._times[0] < cutoff:
                self._times.popleft()
            if len(self._times) >= self.rpm:
                w = self._times[0] + 60 - now
                if w > 0:
                    time.sleep(w); waited += w; now = time.time()
                while self._times and self._times[0] < now - 60:
                    self._times.popleft()
            self._times.append(now); self._last = now
            return waited

class CircuitBreaker:
    def __init__(self, threshold: int = 5, timeout: int = 60):
        self.threshold, self.timeout = threshold, timeout
        self._fails = 0; self._last_fail: Optional[float] = None
        self._state = "closed"; self._lock = threading.Lock()

    def record_success(self):
        with self._lock: self._fails = 0; self._state = "closed"

    def record_failure(self):
        with self._lock:
            self._fails += 1; self._last_fail = time.time()
            if self._fails >= self.threshold:
                self._state = "open"

    def can_attempt(self) -> bool:
        with self._lock:
            if self._state == "closed": return True
            if self._state == "open" and self._last_fail:
                if time.time() - self._last_fail >= self.timeout:
                    self._state = "half_open"; return True
                return False
            return True

    def get_state(self) -> str:
        with self._lock: return self._state

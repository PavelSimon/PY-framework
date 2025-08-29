from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, Tuple
import time


class RequestRateLimiter:
    """Window-based rate limiter for requests per client (e.g., IP)."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)  # identifier -> deque[timestamps]

    def is_allowed(self, identifier: str) -> Tuple[bool, Dict[str, Any]]:
        now = time.time()
        window_start = now - self.window_seconds

        ip_requests = self.requests[identifier]
        while ip_requests and ip_requests[0] < window_start:
            ip_requests.popleft()

        if len(ip_requests) >= self.max_requests:
            reset_time = ip_requests[0] + self.window_seconds
            remaining_time = max(0, int(reset_time - now))

            return False, {
                "limit": self.max_requests,
                "remaining": 0,
                "reset": int(reset_time),
                "retry_after": remaining_time,
            }

        ip_requests.append(now)
        return True, {
            "limit": self.max_requests,
            "remaining": self.max_requests - len(ip_requests),
            "reset": int(now + self.window_seconds),
            "retry_after": 0,
        }


class LoginRateLimiter:
    """Simple rate limiter for login attempts per identifier (e.g., email/IP)."""

    def __init__(self, max_attempts: int = 5, window_minutes: int = 15):
        self.attempts: Dict[str, list[datetime]] = {}
        self.max_attempts = max_attempts
        self.window_minutes = window_minutes

    def is_rate_limited(self, identifier: str) -> bool:
        now = datetime.now()
        if identifier not in self.attempts:
            self.attempts[identifier] = []

        self.attempts[identifier] = [
            attempt
            for attempt in self.attempts[identifier]
            if now - attempt < timedelta(minutes=self.window_minutes)
        ]

        if len(self.attempts[identifier]) >= self.max_attempts:
            return True

        self.attempts[identifier].append(now)
        return False


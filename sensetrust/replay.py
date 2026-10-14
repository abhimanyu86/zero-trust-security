"""Anti-replay and rate limiting for the secure API."""

import threading
import time
from collections import OrderedDict

MAX_SKEW_S = 30


class ReplayGuard:
    """
    A request is accepted once: fresh timestamp (within MAX_SKEW_S), never-seen nonce,
    and — per sender — a strictly increasing sequence number. Nonces are remembered for
    twice the skew window, after which the timestamp check alone rejects them.
    """

    def __init__(self, clock=time.time):
        self.clock = clock
        self._nonces = OrderedDict()
        self._seq = {}
        self._lock = threading.Lock()

    def check(self, sender, nonce, ts, seq=None):
        now = self.clock()
        with self._lock:
            while self._nonces and next(iter(self._nonces.values())) < now - 2 * MAX_SKEW_S:
                self._nonces.popitem(last=False)
            if abs(now - ts) > MAX_SKEW_S:
                return False, "stale_timestamp"
            if nonce in self._nonces:
                return False, "replay"
            if seq is not None:
                if seq <= self._seq.get(sender, -1):
                    return False, "replay"
                self._seq[sender] = seq
            self._nonces[nonce] = now
            return True, "ok"


class RateLimiter:
    """Token bucket per sender."""

    def __init__(self, rate_per_s=5.0, burst=10, clock=time.time):
        self.rate, self.burst, self.clock = rate_per_s, burst, clock
        self._buckets = {}
        self._lock = threading.Lock()

    def allow(self, sender):
        now = self.clock()
        with self._lock:
            tokens, last = self._buckets.get(sender, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._buckets[sender] = (tokens, now)
                return False
            self._buckets[sender] = (tokens - 1, now)
            return True

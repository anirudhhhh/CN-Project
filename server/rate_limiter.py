# server/rate_limiter.py
import time
import threading

class TokenBucket:
    def __init__(self, rate_bytes_per_sec, capacity_bytes):
        self.rate = rate_bytes_per_sec
        self.capacity = capacity_bytes
        self.tokens = capacity_bytes
        self.last_update = time.monotonic()
        self.lock = threading.Lock()

    def wait_for_tokens(self, amount):
        """Blocks the thread until enough tokens are available."""
        # Prevent deadlock if a single packet is larger than the bucket capacity
        if amount > self.capacity:
            amount = self.capacity 
            
        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.last_update
                
                # Add new tokens based on elapsed time
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self.last_update = now

                # If we have enough tokens, consume them and proceed
                if self.tokens >= amount:
                    self.tokens -= amount
                    return
                    
            # Not enough tokens, sleep briefly to wait for refill
            time.sleep(0.01)

class RateLimiter:
    def __init__(self, rate_bytes_per_sec=1024 * 1024): # Default: 1 MB/s
        self.rate = rate_bytes_per_sec
        self.capacity = rate_bytes_per_sec * 2 # Allow a 2-second burst
        self.buckets = {}
        self.lock = threading.Lock()

    def _get_bucket(self, username, direction):
        key = (username, direction)
        with self.lock:
            if key not in self.buckets:
                self.buckets[key] = TokenBucket(self.rate, self.capacity)
            return self.buckets[key]

    def wait(self, username, direction, amount):
        """Called by the server core to limit speed."""
        if not username:
            return
        bucket = self._get_bucket(username, direction)
        bucket.wait_for_tokens(amount)
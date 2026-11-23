"""
Bounded Async Queue with Backpressure

Provides memory-safe queuing for high-throughput packet processing.
Zero unbounded memory growth guarantee.
"""

import asyncio
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Generic, Optional, TypeVar, List, Dict
import threading
import structlog

logger = structlog.get_logger(__name__)

T = TypeVar('T')


class BackpressurePolicy(str, Enum):
    """Policy when queue is full."""
    DROP_OLDEST = "drop_oldest"  # Drop oldest items (default)
    DROP_NEWEST = "drop_newest"  # Drop incoming items
    BLOCK = "block"              # Block until space available (with timeout)
    SAMPLE = "sample"            # Sample 1 in N items when full


@dataclass
class QueueStats:
    """Statistics for a bounded queue."""
    name: str
    capacity: int
    current_size: int
    total_enqueued: int = 0
    total_dequeued: int = 0
    total_dropped: int = 0
    dropped_oldest: int = 0
    dropped_newest: int = 0
    high_water_mark: int = 0
    last_enqueue_time: Optional[datetime] = None
    last_dequeue_time: Optional[datetime] = None
    avg_wait_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "capacity": self.capacity,
            "current_size": self.current_size,
            "fill_pct": round(self.current_size / self.capacity * 100, 1) if self.capacity > 0 else 0,
            "total_enqueued": self.total_enqueued,
            "total_dequeued": self.total_dequeued,
            "total_dropped": self.total_dropped,
            "dropped_oldest": self.dropped_oldest,
            "dropped_newest": self.dropped_newest,
            "high_water_mark": self.high_water_mark,
            "last_enqueue": self.last_enqueue_time.isoformat() if self.last_enqueue_time else None,
            "last_dequeue": self.last_dequeue_time.isoformat() if self.last_dequeue_time else None,
            "avg_wait_ms": round(self.avg_wait_ms, 2)
        }


class BoundedAsyncQueue(Generic[T]):
    """
    Thread-safe bounded queue with backpressure support.
    
    Features:
    - Hard capacity limit (no unbounded growth)
    - Configurable backpressure policy
    - Per-queue metrics
    - Async/await support
    - Thread-safe for producer/consumer patterns
    """
    
    def __init__(
        self,
        name: str,
        capacity: int = 1000,
        policy: BackpressurePolicy = BackpressurePolicy.DROP_OLDEST,
        sample_rate: int = 10,
        high_water_pct: float = 0.8,
        on_high_water: Optional[Callable[[], None]] = None
    ):
        self._name = name
        self._capacity = max(1, capacity)
        self._policy = policy
        self._sample_rate = max(1, sample_rate)
        self._sample_counter = 0
        
        self._queue: deque[Any] = deque(maxlen=None)  # We manage size manually
        self._lock = threading.RLock()
        self._not_empty = asyncio.Condition()
        self._not_full = asyncio.Condition()
        
        # High water mark callback
        self._high_water_threshold = int(capacity * high_water_pct)
        self._on_high_water = on_high_water
        self._high_water_triggered = False
        
        # Statistics
        self._stats = QueueStats(
            name=name,
            capacity=capacity,
            current_size=0
        )
        
        # Wait time tracking (exponential moving average)
        self._wait_times: deque[float] = deque(maxlen=100)
        
        logger.info(
            "Bounded queue created",
            name=name,
            capacity=capacity,
            policy=policy.value
        )
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def capacity(self) -> int:
        return self._capacity
    
    @property
    def size(self) -> int:
        with self._lock:
            return len(self._queue)
    
    @property
    def is_full(self) -> bool:
        return self.size >= self._capacity
    
    @property
    def is_empty(self) -> bool:
        return self.size == 0
    
    @property
    def fill_percentage(self) -> float:
        return self.size / self._capacity * 100
    
    def put_nowait(self, item: T) -> bool:
        """
        Enqueue item without blocking.
        
        Returns:
            True if item was enqueued, False if dropped
        """
        now = datetime.now(timezone.utc)
        
        with self._lock:
            self._stats.last_enqueue_time = now
            
            # Check if queue is full
            if len(self._queue) >= self._capacity:
                if self._policy == BackpressurePolicy.DROP_OLDEST:
                    # Remove oldest item
                    self._queue.popleft()
                    self._stats.dropped_oldest += 1
                    self._stats.total_dropped += 1
                    self._queue.append(item)
                    self._stats.total_enqueued += 1
                    return True
                
                elif self._policy == BackpressurePolicy.DROP_NEWEST:
                    # Drop incoming item
                    self._stats.dropped_newest += 1
                    self._stats.total_dropped += 1
                    return False
                
                elif self._policy == BackpressurePolicy.SAMPLE:
                    # Only accept 1 in N items when full
                    self._sample_counter += 1
                    if self._sample_counter >= self._sample_rate:
                        self._sample_counter = 0
                        self._queue.popleft()
                        self._stats.dropped_oldest += 1
                        self._stats.total_dropped += 1
                        self._queue.append(item)
                        self._stats.total_enqueued += 1
                        return True
                    else:
                        self._stats.dropped_newest += 1
                        self._stats.total_dropped += 1
                        return False
                
                else:  # BLOCK - can't block in nowait
                    self._stats.dropped_newest += 1
                    self._stats.total_dropped += 1
                    return False
            
            # Queue has space
            self._queue.append(item)
            self._stats.total_enqueued += 1
            
            current_size = len(self._queue)
            self._stats.current_size = current_size
            
            # Update high water mark
            if current_size > self._stats.high_water_mark:
                self._stats.high_water_mark = current_size
            
            # Check high water threshold
            if not self._high_water_triggered and current_size >= self._high_water_threshold:
                self._high_water_triggered = True
                if self._on_high_water:
                    try:
                        self._on_high_water()
                    except Exception as e:
                        logger.error("High water callback error", error=str(e))
            
            return True
    
    async def put(self, item: T, timeout: float = 1.0) -> bool:
        """
        Enqueue item with optional blocking for BLOCK policy.
        
        Args:
            item: Item to enqueue
            timeout: Max seconds to wait (for BLOCK policy)
            
        Returns:
            True if enqueued, False if dropped/timeout
        """
        if self._policy != BackpressurePolicy.BLOCK:
            return self.put_nowait(item)
        
        start = time.monotonic()
        
        async with self._not_full:
            while self.is_full:
                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0:
                    self._stats.dropped_newest += 1
                    self._stats.total_dropped += 1
                    return False
                
                try:
                    await asyncio.wait_for(
                        self._not_full.wait(),
                        timeout=remaining
                    )
                except asyncio.TimeoutError:
                    self._stats.dropped_newest += 1
                    self._stats.total_dropped += 1
                    return False
            
            # Now we have space
            wait_ms = (time.monotonic() - start) * 1000
            self._wait_times.append(wait_ms)
            self._stats.avg_wait_ms = sum(self._wait_times) / len(self._wait_times)
            
            return self.put_nowait(item)
    
    def get_nowait(self) -> Optional[T]:
        """
        Dequeue item without blocking.
        
        Returns:
            Item or None if queue is empty
        """
        with self._lock:
            if not self._queue:
                return None
            
            item = self._queue.popleft()
            self._stats.total_dequeued += 1
            self._stats.current_size = len(self._queue)
            self._stats.last_dequeue_time = datetime.now(timezone.utc)
            
            # Reset high water trigger if below threshold
            if self._high_water_triggered and len(self._queue) < self._high_water_threshold * 0.5:
                self._high_water_triggered = False
            
            return item
    
    async def get(self, timeout: float = 1.0) -> Optional[T]:
        """
        Dequeue item with optional blocking.
        
        Args:
            timeout: Max seconds to wait
            
        Returns:
            Item or None if timeout
        """
        # Try non-blocking first
        item = self.get_nowait()
        if item is not None:
            return item
        
        # Wait for item
        start = time.monotonic()
        async with self._not_empty:
            while self.is_empty:
                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0:
                    return None
                
                try:
                    await asyncio.wait_for(
                        self._not_empty.wait(),
                        timeout=remaining
                    )
                except asyncio.TimeoutError:
                    return None
            
            return self.get_nowait()
    
    def get_batch(self, max_items: int = 100) -> List[T]:
        """
        Get multiple items at once (non-blocking).
        
        Args:
            max_items: Maximum items to return
            
        Returns:
            List of items (may be empty)
        """
        items: List[Any] = []
        with self._lock:
            for _ in range(min(max_items, len(self._queue))):
                items.append(self._queue.popleft())
            
            if items:
                self._stats.total_dequeued += len(items)
                self._stats.current_size = len(self._queue)
                self._stats.last_dequeue_time = datetime.now(timezone.utc)
        
        return items
    
    def peek(self, n: int = 1) -> List[T]:
        """Peek at items without removing them."""
        with self._lock:
            return list(self._queue)[:n]
    
    def clear(self):
        """Clear all items from queue."""
        with self._lock:
            dropped = len(self._queue)
            self._queue.clear()
            self._stats.current_size = 0
            self._stats.total_dropped += dropped
            logger.info("Queue cleared", name=self._name, dropped=dropped)
    
    def get_stats(self) -> QueueStats:
        """Get queue statistics."""
        with self._lock:
            self._stats.current_size = len(self._queue)
            return self._stats
    
    def stats_dict(self) -> Dict[str, Any]:
        """Get stats as dictionary."""
        return self.get_stats().to_dict()


class BoundedSyncQueue(Generic[T]):
    """
    Synchronous version of bounded queue for thread-only usage.
    
    Used by packet capture which runs in a separate thread.
    """
    
    def __init__(
        self,
        name: str,
        capacity: int = 1000,
        policy: BackpressurePolicy = BackpressurePolicy.DROP_OLDEST
    ):
        self._name = name
        self._capacity = capacity
        self._policy = policy
        self._queue: deque[Any] = deque(maxlen=capacity if policy == BackpressurePolicy.DROP_OLDEST else None)
        self._lock = threading.Lock()
        
        self._total_enqueued = 0
        self._total_dropped = 0
    
    def put(self, item: T) -> bool:
        """Enqueue item."""
        with self._lock:
            if self._policy == BackpressurePolicy.DROP_OLDEST:
                # deque with maxlen handles this automatically
                was_full = len(self._queue) >= self._capacity
                self._queue.append(item)
                self._total_enqueued += 1
                if was_full:
                    self._total_dropped += 1
                return True
            
            elif len(self._queue) >= self._capacity:
                self._total_dropped += 1
                return False
            
            self._queue.append(item)
            self._total_enqueued += 1
            return True
    
    def get(self) -> Optional[T]:
        """Dequeue item."""
        with self._lock:
            if self._queue:
                return self._queue.popleft()
            return None
    
    def get_all(self) -> List[T]:
        """Get all items."""
        with self._lock:
            items = list(self._queue)
            self._queue.clear()
            return items
    
    @property
    def size(self) -> int:
        with self._lock:
            return len(self._queue)
    
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "name": self._name,
                "capacity": self._capacity,
                "current_size": len(self._queue),
                "total_enqueued": self._total_enqueued,
                "total_dropped": self._total_dropped
            }

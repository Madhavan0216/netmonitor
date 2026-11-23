"""
Data Storage & Retention Module

Manages data lifecycle:
- Hot data: In-memory (recent packets, active sessions)
- Warm data: SQLite/Database (historical alerts, scans)
- Retention policies: Auto-cleanup based on age/size

Note: This module uses Any type for _data to handle both Dict and deque
storage modes dynamically based on key_func parameter.
"""

import asyncio
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Generic, TypeVar, Callable
import structlog

from app.core.telemetry.metrics import metrics

logger = structlog.get_logger(__name__)

T = TypeVar('T')


@dataclass
class RetentionPolicy:
    """Data retention policy."""
    name: str
    max_age_seconds: int = 3600  # 1 hour default
    max_items: int = 10000
    cleanup_interval_seconds: int = 60
    
    # Optional: callback for custom cleanup logic
    on_expire: Optional[Callable[[Any], None]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "max_age_seconds": self.max_age_seconds,
            "max_items": self.max_items,
            "cleanup_interval_seconds": self.cleanup_interval_seconds
        }


@dataclass
class TimestampedItem(Generic[T]):
    """Item with timestamp for retention tracking."""
    data: T
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def age_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self.created_at).total_seconds()


class HotDataStore(Generic[T]):
    """
    In-memory store for hot data with automatic retention.
    
    Features:
    - Bounded size (no unbounded memory growth)
    - Time-based expiration
    - Thread-safe operations
    - Metrics integration
    """
    
    def __init__(
        self,
        name: str,
        policy: RetentionPolicy,
        key_func: Optional[Callable[[T], str]] = None
    ):
        self._name = name
        self._policy = policy
        self._key_func = key_func
        
        # Storage: either keyed dict or ordered deque
        # Using Any type to handle both storage modes - type checked at runtime via key_func
        self._data: Any
        if key_func:
            self._data = {}
        else:
            self._data = deque(maxlen=policy.max_items)
        
        self._lock = threading.RLock()
        self._cleanup_task: Optional[asyncio.Task[None]] = None
        
        # Stats
        self._total_added = 0
        self._total_expired = 0
        self._total_evicted = 0
        
        logger.info(
            "Hot data store created",
            name=name,
            max_items=policy.max_items,
            max_age=policy.max_age_seconds
        )
    
    def add(self, item: T) -> bool:
        """Add item to store."""
        with self._lock:
            timestamped = TimestampedItem(data=item)
            
            if self._key_func:
                key = self._key_func(item)
                self._data[key] = timestamped
                
                # Evict if over capacity
                while len(self._data) > self._policy.max_items:
                    oldest_key = min(self._data, key=lambda k: self._data[k].created_at)
                    del self._data[oldest_key]
                    self._total_evicted += 1
            else:
                # deque handles maxlen automatically
                if len(self._data) >= self._policy.max_items:
                    self._total_evicted += 1
                self._data.append(timestamped)
            
            self._total_added += 1
            metrics.gauge(f"store_{self._name}_size", len(self._data))
            return True
    
    def get(self, key: str) -> Optional[T]:
        """Get item by key (keyed store only)."""
        if not self._key_func:
            return None
        
        with self._lock:
            item = self._data.get(key)
            if item and item.age_seconds() <= self._policy.max_age_seconds:
                return item.data
            return None
    
    def get_recent(self, limit: int = 100, since: Optional[datetime] = None) -> List[T]:
        """Get recent items."""
        with self._lock:
            if self._key_func:
                items = sorted(
                    self._data.values(),
                    key=lambda x: x.created_at,
                    reverse=True
                )
            else:
                items = list(self._data)
                items.reverse()
            
            results: List[T] = []
            cutoff = since or datetime.min.replace(tzinfo=timezone.utc)
            max_age = self._policy.max_age_seconds
            
            for item in items[:limit]:
                if item.created_at >= cutoff and item.age_seconds() <= max_age:
                    results.append(item.data)
            
            return results
    
    def get_all(self) -> List[T]:
        """Get all valid items."""
        return self.get_recent(limit=self._policy.max_items)
    
    def size(self) -> int:
        """Get current size."""
        with self._lock:
            return len(self._data)
    
    def cleanup(self) -> int:
        """Remove expired items. Returns count removed."""
        max_age = self._policy.max_age_seconds
        removed = 0
        
        with self._lock:
            if self._key_func:
                expired_keys = [
                    k for k, v in self._data.items()
                    if v.age_seconds() > max_age
                ]
                for key in expired_keys:
                    item = self._data.pop(key)
                    if self._policy.on_expire:
                        try:
                            self._policy.on_expire(item.data)
                        except Exception as e:
                            logger.error("Expire callback error", error=str(e))
                    removed += 1
            else:
                # For deque, remove from front (oldest)
                while self._data:
                    oldest = self._data[0]
                    if oldest.age_seconds() > max_age:
                        self._data.popleft()
                        if self._policy.on_expire:
                            try:
                                self._policy.on_expire(oldest.data)
                            except Exception:
                                pass
                        removed += 1
                    else:
                        break
        
        if removed > 0:
            self._total_expired += removed
            metrics.increment(f"store_{self._name}_expired", removed)
            logger.debug("Hot store cleanup", name=self._name, removed=removed)
        
        return removed
    
    async def start_cleanup_task(self):
        """Start background cleanup task."""
        if self._cleanup_task is not None:
            return
        
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def stop_cleanup_task(self):
        """Stop background cleanup task."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
    
    async def _cleanup_loop(self):
        """Background cleanup loop."""
        while True:
            try:
                await asyncio.sleep(self._policy.cleanup_interval_seconds)
                self.cleanup()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Cleanup loop error", name=self._name, error=str(e))
    
    def stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        with self._lock:
            return {
                "name": self._name,
                "current_size": len(self._data),
                "max_items": self._policy.max_items,
                "max_age_seconds": self._policy.max_age_seconds,
                "total_added": self._total_added,
                "total_expired": self._total_expired,
                "total_evicted": self._total_evicted
            }
    
    def clear(self):
        """Clear all data."""
        with self._lock:
            if self._key_func:
                self._data.clear()
            else:
                self._data.clear()
            logger.info("Hot store cleared", name=self._name)


class DataRetentionManager:
    """
    Manages data retention across all stores.
    
    Provides:
    - Unified cleanup scheduling
    - Storage metrics
    - Policy management
    """
    
    def __init__(self):
        self._stores: Dict[str, HotDataStore[Any]] = {}
        self._policies: Dict[str, RetentionPolicy] = {}
        self._running = False
        self._cleanup_task: Optional[asyncio.Task[None]] = None
        
        # Default policies
        self._default_policies = {
            "packets": RetentionPolicy(
                name="packets",
                max_age_seconds=300,  # 5 minutes
                max_items=10000,
                cleanup_interval_seconds=30
            ),
            "alerts": RetentionPolicy(
                name="alerts",
                max_age_seconds=86400,  # 24 hours
                max_items=1000,
                cleanup_interval_seconds=300
            ),
            "flows": RetentionPolicy(
                name="flows",
                max_age_seconds=600,  # 10 minutes
                max_items=5000,
                cleanup_interval_seconds=60
            ),
            "arp_entries": RetentionPolicy(
                name="arp_entries",
                max_age_seconds=1800,  # 30 minutes
                max_items=1000,
                cleanup_interval_seconds=60
            )
        }
        
        logger.info("Data retention manager initialized")
    
    def register_store(
        self,
        name: str,
        policy: Optional[RetentionPolicy] = None,
        key_func: Optional[Callable[[Any], str]] = None
    ) -> "HotDataStore[Any]":
        """Register a new hot data store."""
        if policy is None:
            policy = self._default_policies.get(
                name,
                RetentionPolicy(name=name)
            )
        
        store: HotDataStore[Any] = HotDataStore(name=name, policy=policy, key_func=key_func)
        self._stores[name] = store
        self._policies[name] = policy
        
        return store
    
    def get_store(self, name: str) -> Optional["HotDataStore[Any]"]:
        """Get a registered store."""
        return self._stores.get(name)
    
    async def start(self):
        """Start retention management."""
        if self._running:
            return
        
        self._running = True
        
        # Start cleanup tasks for all stores
        for store in self._stores.values():
            await store.start_cleanup_task()
        
        logger.info("Data retention manager started", stores=list(self._stores.keys()))
    
    async def stop(self):
        """Stop retention management."""
        self._running = False
        
        for store in self._stores.values():
            await store.stop_cleanup_task()
        
        logger.info("Data retention manager stopped")
    
    def cleanup_all(self) -> Dict[str, int]:
        """Run cleanup on all stores."""
        results: Dict[str, int] = {}
        for name, store in self._stores.items():
            results[name] = store.cleanup()
        return results
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get stats for all stores."""
        return {
            name: store.stats()
            for name, store in self._stores.items()
        }
    
    def get_policies(self) -> Dict[str, Dict[str, Any]]:
        """Get all retention policies."""
        return {
            name: policy.to_dict()
            for name, policy in self._policies.items()
        }
    
    def update_policy(self, name: str, **kwargs: Any) -> bool:
        """Update a retention policy."""
        if name not in self._policies:
            return False
        
        policy = self._policies[name]
        for key, value in kwargs.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
        
        logger.info("Policy updated", name=name, **kwargs)
        return True


# Global retention manager
retention_manager = DataRetentionManager()

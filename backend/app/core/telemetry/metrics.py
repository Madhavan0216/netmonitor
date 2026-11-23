"""
Metrics Collector

Centralized metrics collection for internal observability.
Tracks packets/sec, drops, latencies, scan durations, etc.
"""

import time
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Callable, Tuple
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class MetricType(str, Enum):
    """Types of metrics."""
    COUNTER = "counter"      # Monotonically increasing
    GAUGE = "gauge"          # Current value
    HISTOGRAM = "histogram"  # Distribution
    RATE = "rate"           # Per-second rate


@dataclass
class RateWindow:
    """Sliding window for rate calculation."""
    window_seconds: int = 60
    buckets: "deque[Tuple[int, int]]" = field(default_factory=lambda: deque(maxlen=60))
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def record(self, count: int = 1):
        """Record events."""
        now = int(time.time())
        with self._lock:
            if self.buckets and self.buckets[-1][0] == now:
                self.buckets[-1] = (now, self.buckets[-1][1] + count)
            else:
                self.buckets.append((now, count))
    
    def rate_per_second(self) -> float:
        """Calculate rate over window."""
        now = int(time.time())
        cutoff = now - self.window_seconds
        
        with self._lock:
            total = sum(c for t, c in self.buckets if t > cutoff)
            return total / self.window_seconds


@dataclass
class HistogramBucket:
    """Histogram bucket."""
    le: float  # Less than or equal
    count: int = 0


class Histogram:
    """Histogram for latency/duration metrics."""
    
    DEFAULT_BUCKETS = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    
    def __init__(self, name: str, buckets: Optional[List[float]] = None):
        self.name = name
        self._buckets = sorted(buckets or self.DEFAULT_BUCKETS)
        self._counts: Dict[float, int] = {b: 0 for b in self._buckets}
        self._counts[float('inf')] = 0  # Overflow bucket
        self._sum = 0.0
        self._count = 0
        self._lock = threading.Lock()
    
    def observe(self, value: float):
        """Record an observation."""
        with self._lock:
            self._sum += value
            self._count += 1
            for bucket in self._buckets:
                if value <= bucket:
                    self._counts[bucket] += 1
                    break
            else:
                self._counts[float('inf')] += 1
    
    def percentile(self, p: float) -> float:
        """Estimate percentile (0-100)."""
        with self._lock:
            if self._count == 0:
                return 0.0
            
            target = self._count * (p / 100)
            cumulative = 0
            prev_bucket = 0.0
            
            for bucket in self._buckets:
                cumulative += self._counts[bucket]
                if cumulative >= target:
                    # Linear interpolation
                    return prev_bucket + (bucket - prev_bucket) * 0.5
                prev_bucket = bucket
            
            return self._buckets[-1]
    
    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "count": self._count,
                "sum": round(self._sum, 4),
                "avg": round(self._sum / self._count, 4) if self._count > 0 else 0,
                "p50": round(self.percentile(50), 4),
                "p95": round(self.percentile(95), 4),
                "p99": round(self.percentile(99), 4),
                "buckets": {str(k): v for k, v in self._counts.items()}
            }


class MetricsCollector:
    """
    Centralized metrics collection.
    
    Thread-safe, low-overhead metrics for production monitoring.
    
    Usage:
        metrics.increment("packets_captured")
        metrics.gauge("active_connections", conn_count)
        metrics.observe("packet_latency_ms", latency)
        metrics.rate("packets_per_sec", 1)
    """
    
    def __init__(self):
        self._lock = threading.RLock()
        
        # Counters (monotonically increasing)
        self._counters: Dict[str, int] = {}
        
        # Gauges (current values)
        self._gauges: Dict[str, float] = {}
        
        # Rate windows
        self._rates: Dict[str, RateWindow] = {}
        
        # Histograms
        self._histograms: Dict[str, Histogram] = {}
        
        # Service start time
        self._start_time = datetime.now(timezone.utc)
        
        # Custom metric callbacks
        self._collectors: List[Callable[[], Dict[str, Any]]] = []
        
        logger.info("Metrics collector initialized")
    
    # === Counter Operations ===
    
    def increment(self, name: str, value: int = 1) -> int:
        """Increment a counter."""
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + value
            return self._counters[name]
    
    def counter(self, name: str) -> int:
        """Get counter value."""
        with self._lock:
            return self._counters.get(name, 0)
    
    # === Gauge Operations ===
    
    def gauge(self, name: str, value: float):
        """Set a gauge value."""
        with self._lock:
            self._gauges[name] = value
    
    def gauge_increment(self, name: str, delta: float = 1.0):
        """Increment a gauge."""
        with self._lock:
            self._gauges[name] = self._gauges.get(name, 0) + delta
    
    def gauge_decrement(self, name: str, delta: float = 1.0):
        """Decrement a gauge."""
        with self._lock:
            self._gauges[name] = self._gauges.get(name, 0) - delta
    
    def get_gauge(self, name: str) -> float:
        """Get gauge value."""
        with self._lock:
            return self._gauges.get(name, 0)
    
    # === Rate Operations ===
    
    def rate(self, name: str, count: int = 1, window: int = 60):
        """Record event for rate calculation."""
        with self._lock:
            if name not in self._rates:
                self._rates[name] = RateWindow(window_seconds=window)
            self._rates[name].record(count)
    
    def get_rate(self, name: str) -> float:
        """Get rate per second."""
        with self._lock:
            if name not in self._rates:
                return 0.0
            return self._rates[name].rate_per_second()
    
    # === Histogram Operations ===
    
    def observe(self, name: str, value: float, buckets: Optional[List[float]] = None):
        """Record histogram observation."""
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = Histogram(name, buckets)
            self._histograms[name].observe(value)
    
    def get_histogram(self, name: str) -> Optional[Dict[str, Any]]:
        """Get histogram stats."""
        with self._lock:
            if name not in self._histograms:
                return None
            return self._histograms[name].to_dict()
    
    # === Timer Context Manager ===
    
    class Timer:
        """Context manager for timing operations."""
        
        def __init__(self, metrics: 'MetricsCollector', name: str):
            self._metrics = metrics
            self._name = name
            self._start: float = 0
        
        def __enter__(self) -> 'MetricsCollector.Timer':
            self._start = time.perf_counter()
            return self
        
        def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            elapsed = time.perf_counter() - self._start
            self._metrics.observe(self._name, elapsed)
    
    def timer(self, name: str) -> Timer:
        """Create a timer context manager."""
        return self.Timer(self, name)
    
    # === Custom Collectors ===
    
    def register_collector(self, collector: Callable[[], Dict[str, Any]]):
        """Register a custom metrics collector function."""
        with self._lock:
            self._collectors.append(collector)
    
    # === Export ===
    
    def get_all(self) -> Dict[str, Any]:
        """Get all metrics as dictionary."""
        with self._lock:
            uptime = (datetime.now(timezone.utc) - self._start_time).total_seconds()
            
            result: Dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "uptime_seconds": round(uptime, 1),
                "counters": dict(self._counters),
                "gauges": {k: round(v, 2) for k, v in self._gauges.items()},
                "rates": {
                    name: round(rate.rate_per_second(), 2)
                    for name, rate in self._rates.items()
                },
                "histograms": {
                    name: hist.to_dict()
                    for name, hist in self._histograms.items()
                }
            }
            
            # Collect from registered collectors
            for collector in self._collectors:
                try:
                    result.update(collector())
                except Exception as e:
                    logger.error("Collector error", error=str(e))
            
            return result
    
    def get_summary(self) -> Dict[str, Any]:
        """Get condensed metrics summary."""
        with self._lock:
            return {
                "uptime_seconds": round((datetime.now(timezone.utc) - self._start_time).total_seconds(), 1),
                "packets_captured": self._counters.get("packets_captured", 0),
                "packets_per_sec": round(self.get_rate("packets_per_sec"), 1),
                "packets_dropped": self._counters.get("packets_dropped", 0),
                "alerts_generated": self._counters.get("alerts_generated", 0),
                "active_connections": int(self._gauges.get("ws_connections", 0)),
                "memory_mb": round(self._gauges.get("memory_mb", 0), 1)
            }
    
    def reset(self):
        """Reset all metrics (for testing)."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._rates.clear()
            self._histograms.clear()
            self._start_time = datetime.now(timezone.utc)


# Global metrics instance
metrics = MetricsCollector()


# === Predefined Metric Names ===
class MetricNames:
    """Standard metric names for consistency."""
    
    # Packet capture
    PACKETS_CAPTURED = "packets_captured"
    PACKETS_DROPPED = "packets_dropped"
    PACKETS_PER_SEC = "packets_per_sec"
    BYTES_CAPTURED = "bytes_captured"
    
    # Detection
    ALERTS_GENERATED = "alerts_generated"
    RULES_EVALUATED = "rules_evaluated"
    DETECTION_LATENCY = "detection_latency_ms"
    
    # WebSocket
    WS_CONNECTIONS = "ws_connections"
    WS_MESSAGES_SENT = "ws_messages_sent"
    WS_MESSAGES_DROPPED = "ws_messages_dropped"
    WS_BROADCAST_LATENCY = "ws_broadcast_latency_ms"
    
    # Scanner
    SCANS_STARTED = "scans_started"
    SCANS_COMPLETED = "scans_completed"
    SCAN_DURATION = "scan_duration_sec"
    HOSTS_DISCOVERED = "hosts_discovered"
    
    # System
    MEMORY_MB = "memory_mb"
    CPU_PERCENT = "cpu_percent"
    QUEUE_SIZE = "queue_size"
    
    # Network interfaces
    IFACE_RX_BYTES = "iface_rx_bytes"
    IFACE_TX_BYTES = "iface_tx_bytes"
    IFACE_RX_PACKETS = "iface_rx_packets"
    IFACE_TX_PACKETS = "iface_tx_packets"
    IFACE_RX_ERRORS = "iface_rx_errors"
    IFACE_TX_ERRORS = "iface_tx_errors"

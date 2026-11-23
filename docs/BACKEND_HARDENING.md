# Backend Hardening - Telemetry & Observability

This document describes the backend hardening features implemented to make NetMonitor a rock-solid security telemetry platform.

## Overview

The hardening includes:
1. **Bounded Queues** - Memory-safe queuing with backpressure
2. **Metrics Collection** - Internal observability 
3. **Interface Monitoring** - RX/TX stats, state changes
4. **ARP Monitoring** - Arpwatch-like functionality
5. **Gateway Detection** - Network gateway discovery
6. **Health Endpoints** - Kubernetes-style probes
7. **Data Retention** - Hot/warm data management
8. **Export Capabilities** - PCAP-lite, JSON, CSV, SIEM

---

## 1. Bounded Queues & Backpressure

**Location:** `app/core/telemetry/bounded_queue.py`

### Features
- Hard capacity limits (no unbounded growth)
- Configurable backpressure policies:
  - `DROP_OLDEST` - Remove oldest items (default)
  - `DROP_NEWEST` - Reject new items
  - `BLOCK` - Wait for space
  - `SAMPLE` - Statistical sampling

### Usage

```python
from app.core.telemetry import BoundedAsyncQueue, BackpressurePolicy

# Create queue with 10k capacity
queue = BoundedAsyncQueue(
    name="packets",
    max_size=10000,
    policy=BackpressurePolicy.DROP_OLDEST,
    high_water_mark=0.8  # Alert at 80% full
)

# Non-blocking put
success = await queue.put_nowait(packet)

# Check stats
stats = queue.get_stats()
print(f"Fill: {stats.fill_pct}%, Drops: {stats.drops}")
```

### Metrics Tracked
- `queue.{name}.size` - Current queue size
- `queue.{name}.drops` - Dropped items count
- `queue.{name}.puts` - Total put operations

---

## 2. Metrics Collection

**Location:** `app/core/telemetry/metrics.py`

### Metric Types
- **Counters** - Monotonically increasing (packets captured)
- **Gauges** - Current values (memory usage, queue fill)
- **Rates** - Per-second calculations (packets/sec)
- **Histograms** - Distributions with percentiles

### Standard Metric Names

```python
class MetricNames:
    # Capture
    PACKETS_CAPTURED = "capture.packets_captured"
    PACKETS_DROPPED = "capture.packets_dropped"
    BYTES_CAPTURED = "capture.bytes_captured"
    PACKETS_PER_SEC = "capture.packets_per_sec"
    
    # Detection
    ALERTS_GENERATED = "detection.alerts_generated"
    RULES_MATCHED = "detection.rules_matched"
    DETECTION_LATENCY = "detection.latency_ms"
    
    # Scans
    SCANS_COMPLETED = "scanner.scans_completed"
    HOSTS_DISCOVERED = "scanner.hosts_discovered"
    SCAN_DURATION = "scanner.duration_ms"
    
    # System
    MEMORY_MB = "system.memory_mb"
    CPU_PERCENT = "system.cpu_percent"
```

### Usage

```python
from app.core.telemetry.metrics import metrics, MetricNames

# Counter
metrics.increment(MetricNames.PACKETS_CAPTURED)
metrics.increment(MetricNames.BYTES_CAPTURED, size)

# Gauge
metrics.gauge("capture.buffer_fill_pct", 75.5)

# Rate
metrics.rate(MetricNames.PACKETS_PER_SEC, 1)

# Histogram (timing)
with metrics.timer("detection.latency_ms"):
    result = engine.analyze(packet)
```

---

## 3. Interface Monitoring

**Location:** `app/core/interfaces/interface_monitor.py`

### Features
- Per-interface statistics (RX/TX bytes, packets, errors)
- Rate calculations (bytes/sec, packets/sec)
- State change detection (up/down events)
- Cross-platform: Linux native + Windows psutil fallback

### Data Model

```python
@dataclass
class InterfaceStats:
    name: str
    is_up: bool
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_errors: int
    tx_errors: int
    rx_dropped: int
    tx_dropped: int
    
    # Rates (calculated)
    rx_bytes_per_sec: float
    tx_bytes_per_sec: float
    rx_packets_per_sec: float
    tx_packets_per_sec: float
```

### Events
- `interface_up` - Interface came online
- `interface_down` - Interface went offline
- Broadcasts via WebSocket on channel "stats"

---

## 4. ARP Monitoring (Arpwatch-like)

**Location:** `app/core/interfaces/arp_monitor.py`

### Features
- ARP table monitoring (like arpwatch)
- Detects:
  - **New hosts** on the network
  - **MAC changes** (potential spoofing)
  - **IP conflicts** (same IP, different MACs)
  - **Flip-flops** (rapid MAC alternations)
  - **Gratuitous ARP** (potential attack)
  - **Host gone** (stale entry removed)

### Event Types & Severity

| Event Type | Severity | Description |
|------------|----------|-------------|
| `NEW_HOST` | info | New IP/MAC discovered |
| `MAC_CHANGE` | warning | MAC address changed for IP |
| `IP_CONFLICT` | critical | Multiple MACs claiming same IP |
| `FLIP_FLOP` | warning | MAC alternating rapidly |
| `GRATUITOUS_ARP` | warning | Self-announcement detected |
| `HOST_GONE` | info | Entry expired |

### Alerts
- Critical/warning events broadcast via WebSocket on "alerts" channel
- Includes previous/current MAC, vendor info

---

## 5. Gateway Detection

**Location:** `app/core/interfaces/gateway.py`

### Features
- Parses system routing tables
- Identifies default gateway(s)
- ICMP verification (optional)
- Cross-platform: Linux `ip route` / Windows `route print`

### Data Model

```python
@dataclass
class GatewayInfo:
    ip_address: str
    interface: str
    is_default: bool
    metric: int
    is_reachable: Optional[bool]
    last_check: datetime
```

### Integration
- Gateway IP set in topology service for visualization
- Used to identify edge of monitored network

---

## 6. Health Endpoints

**Location:** `app/api/health.py`

### Endpoints

#### `GET /api/health` - Liveness Probe
Indicates if the service is alive.

```json
{
  "status": "healthy|degraded|unhealthy",
  "service": "NetMonitor",
  "version": "1.0.0",
  "uptime_seconds": 3600,
  "timestamp": "2024-01-01T00:00:00Z",
  "checks": {
    "database": {"status": "ok"},
    "capture": {"status": "ok", "running": true},
    "detection": {"status": "ok"},
    "websocket": {"status": "ok", "connections": 5}
  }
}
```

#### `GET /api/ready` - Readiness Probe
Indicates if the service is ready to serve traffic.

```json
{
  "ready": true,
  "checks": { ... }
}
```

#### `GET /api/metrics` - Internal Metrics
Returns all collected metrics.

```json
{
  "timestamp": "2024-01-01T00:00:00Z",
  "uptime_seconds": 3600,
  "counters": {
    "capture.packets_captured": 150000,
    "capture.packets_dropped": 0
  },
  "gauges": {
    "system.memory_mb": 256.5,
    "capture.buffer_fill_pct": 45.2
  },
  "rates": {
    "capture.packets_per_sec": 250.0
  },
  "histograms": {
    "detection.latency_ms": {
      "count": 1000,
      "sum": 450.5,
      "p50": 0.3,
      "p90": 0.8,
      "p99": 2.1
    }
  }
}
```

#### `GET /api/metrics/prometheus` - Prometheus Format
Metrics in Prometheus exposition format for scraping.

---

## 7. Data Retention

**Location:** `app/core/storage/`

### Hot Data Store (In-Memory)
- TTL-based expiration
- Size limits
- Background cleanup
- Per-store metrics

```python
from app.core.storage import hot_store, RetentionPolicy

# Store with 5-minute TTL, max 10k items
hot_store.create_store(
    "recent_packets",
    RetentionPolicy(max_age_seconds=300, max_items=10000)
)

hot_store.put("recent_packets", "key1", packet_data)
data = hot_store.get("recent_packets", "key1")
```

### Database Retention (Warm Data)
- Configurable retention periods:
  - Alerts: 30 days (default)
  - Scans: 90 days (default)
- Background cleanup loop
- Respects foreign key constraints

---

## 8. Export Capabilities

**Location:** `app/core/export/`, `app/api/export.py`

### Formats

#### PCAP-lite (JSON Lines, gzipped)
Compact packet archive for analysis.

```
GET /api/export/packets/pcaplite?limit=1000
Content-Type: application/gzip
```

#### JSON Export
Full structured export of packets, alerts, topology.

```
GET /api/export/packets/json?limit=100
GET /api/export/alerts/json?start_date=2024-01-01
GET /api/export/topology/json
```

#### CSV Export
Tabular export for spreadsheets/analysis.

```
GET /api/export/packets/csv
GET /api/export/alerts/csv
```

#### CEF (Common Event Format)
Basic SIEM compatibility.

```
GET /api/export/alerts/cef
```

### SIEM Compatibility

See `GET /api/export/siem-compatibility` for:
- Supported formats
- Field mappings (CEF, LEEF, JSON)
- Integration guidelines for:
  - Splunk
  - Elastic SIEM
  - Azure Sentinel
  - IBM QRadar
  - Sumo Logic

---

## Configuration

All new features respect existing configuration in `app/core/config.py`:

```python
# Buffer sizes
CAPTURE_BUFFER_SIZE: int = 10000
WS_MAX_CONNECTIONS: int = 100

# Retention (add these)
ALERT_RETENTION_DAYS: int = 30
SCAN_RETENTION_DAYS: int = 90
HOT_DATA_TTL_SECONDS: int = 300
```

---

## Architecture Notes

### Thread Safety
- All stores use `threading.RLock()` for concurrent access
- Metrics collection is thread-safe
- Interface/ARP monitors run in background tasks

### Memory Management
- Bounded queues prevent unbounded growth
- Hot data stores auto-evict old entries
- Packet buffer is circular (deque with maxlen)

### Platform Support
- **Linux**: Native access to `/proc`, `/sys`, `ip` commands
- **Windows**: Fallback to `psutil`, `arp -a`, `route print`

### Error Handling
- All monitors have graceful degradation
- Errors logged but don't crash the service
- Health endpoints report component status

---

## Future Enhancements

1. **PostgreSQL support** for production deployments
2. **Time-series database** for metrics (InfluxDB/TimescaleDB)
3. **Syslog forwarding** for SIEM integration
4. **SNMP traps** for network monitoring integration
5. **Grafana dashboards** for metrics visualization

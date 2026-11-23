# NetMonitor: Production-Grade Network Security Command Center
## Complete System Design Specification

**Version:** 2.0  
**Author:** Principal Security Architect  
**Date:** January 2026  
**Status:** Ready for Implementation

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
3. [Backend Design](#3-backend-design)
4. [Frontend Design](#4-frontend-design)
5. [Feature Modules](#5-feature-modules)
6. [Threat Detection Engine](#6-threat-detection-engine)
7. [Security & Safety Design](#7-security--safety-design)
8. [Plugin Architecture](#8-plugin-architecture)
9. [API Specification](#9-api-specification)
10. [Deployment Strategy](#10-deployment-strategy)
11. [Limitations & Non-Goals](#11-limitations--non-goals)

---

## 1. Executive Summary

### 1.1 Product Vision

NetMonitor is a browser-based **Network Security Command Center** designed for defensive network monitoring. It combines:

- **Wireshark's** packet inspection depth (metadata-first, no raw payloads by default)
- **Nmap's** discovery capabilities (safe, rate-limited scan profiles)
- **EtherApe's** visual network topology (real-time animated graphs)
- **Kismet's** wireless visibility concepts (passive, read-only)
- **Linux tooling** philosophy (iftop, tcpdump, arpwatch philosophy)

### 1.2 Design Principles

| Principle | Implementation |
|-----------|----------------|
| **Safety First** | Local scope enforcement, CIDR limits, rate caps, privilege separation |
| **Explainable Detection** | No ML black boxes; every alert includes plain-English explanation |
| **Metadata Over Payload** | Packet headers by default; payload inspection opt-in with warnings |
| **Progressive Disclosure** | Simple dashboard for beginners, expert depth available |
| **Minimal Attack Surface** | Read-only operations default; destructive actions require explicit confirmation |

### 1.3 Target Users

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER SPECTRUM                                   │
├─────────────────┬──────────────────┬─────────────────┬─────────────────────┤
│  Home Lab User  │  Security Student│  Network Admin  │    SOC Analyst      │
├─────────────────┼──────────────────┼─────────────────┼─────────────────────┤
│ Dashboard view  │ Learning mode    │ Full monitoring │ Alert investigation │
│ Basic alerts    │ Packet analysis  │ Scan scheduling │ Forensic export     │
│ Device list     │ Detection labs   │ Report generation│ Integration APIs   │
└─────────────────┴──────────────────┴─────────────────┴─────────────────────┘
```

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│                                 BROWSER (React)                                     │
│  ┌──────────────────────────────────────────────────────────────────────────────┐  │
│  │                         PRESENTATION LAYER                                    │  │
│  │  ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌─────────┐ ┌────────┐ │  │
│  │  │Dashboard│ │ Network  │ │  Packet   │ │ Scanner  │ │ Alerts  │ │Wireless│ │  │
│  │  │         │ │   Map    │ │ Explorer  │ │          │ │   Feed  │ │Overview│ │  │
│  │  └────┬────┘ └────┬─────┘ └─────┬─────┘ └────┬─────┘ └────┬────┘ └───┬────┘ │  │
│  │       └───────────┴─────────────┴────────────┴────────────┴──────────┘      │  │
│  │                                    │                                          │  │
│  │              ┌─────────────────────┴───────────────────────┐                 │  │
│  │              │           STATE MANAGEMENT (Zustand)        │                 │  │
│  │              └─────────────────────┬───────────────────────┘                 │  │
│  └────────────────────────────────────┼──────────────────────────────────────────┘  │
│                                       │                                             │
│         ┌─────────────────────────────┼─────────────────────────────────┐          │
│         │            REST API         │        WebSocket                 │          │
│         │         (HTTPS:8000)        │       (WSS:8000/ws)             │          │
└─────────┴─────────────────────────────┴─────────────────────────────────┴──────────┘
                                        │
┌───────────────────────────────────────┴────────────────────────────────────────────┐
│                              API GATEWAY (FastAPI)                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐            │   │
│  │  │Rate Limiter│  │Auth (JWT)  │  │Input Valid.│  │Audit Logger│            │   │
│  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘            │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                       │                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                          CORE SERVICES LAYER                                 │   │
│  │  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐   │   │
│  │  │    Packet     │ │   Network     │ │  Detection    │ │    Alert      │   │   │
│  │  │   Capture     │ │   Scanner     │ │   Engine      │ │   Manager     │   │   │
│  │  │   Service     │ │   Service     │ │               │ │               │   │   │
│  │  └───────┬───────┘ └───────┬───────┘ └───────┬───────┘ └───────┬───────┘   │   │
│  │          │                 │                 │                 │           │   │
│  │  ┌───────┴─────────────────┴─────────────────┴─────────────────┴───────┐   │   │
│  │  │                      EVENT BUS (asyncio Queue)                       │   │   │
│  │  └─────────────────────────────────────────────────────────────────────┘   │   │
│  │                                     │                                       │   │
│  │  ┌─────────────────────────────────────────────────────────────────────┐   │   │
│  │  │                       PLUGIN SYSTEM                                  │   │   │
│  │  │    ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────────┐   │   │   │
│  │  │    │Hook Mgr │  │ Loader  │  │Sandboxer│  │ Built-in Plugins    │   │   │   │
│  │  │    └─────────┘  └─────────┘  └─────────┘  └─────────────────────┘   │   │   │
│  │  └─────────────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────────┘
                                        │
         ┌──────────────────────────────┼──────────────────────────────┐
         ▼                              ▼                              ▼
┌─────────────────┐         ┌─────────────────────┐        ┌──────────────────┐
│ PRIVILEGED AGENT│         │   DATA LAYER        │        │  EXTERNAL TOOLS  │
│  (Root/CAP_NET) │         │   (SQLite/Postgres) │        │                  │
│  ┌───────────┐  │         │  ┌────────────────┐ │        │  ┌────────────┐  │
│  │ Scapy     │  │         │  │ Packets (ring) │ │        │  │   Nmap     │  │
│  │ Capture   │  │         │  │ Alerts         │ │        │  │  (subprocess)│ │
│  ├───────────┤  │         │  │ Hosts          │ │        │  ├────────────┤  │
│  │ Interface │  │         │  │ Scans          │ │        │  │  tshark    │  │
│  │ Control   │  │         │  │ Users          │ │        │  │ (optional) │  │
│  ├───────────┤  │         │  │ Rules          │ │        │  ├────────────┤  │
│  │ ARP Cache │  │         │  │ Sessions       │ │        │  │  iw/iwconfig│ │
│  │ Reader    │  │         │  └────────────────┘ │        │  │ (read-only)│  │
│  └───────────┘  │         └─────────────────────┘        │  └────────────┘  │
└─────────────────┘                                        └──────────────────┘
```

### 2.2 Trust Boundaries

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                           TRUST BOUNDARY DIAGRAM                                │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│    UNTRUSTED ZONE                    │         TRUSTED ZONE                     │
│    (Browser/User Input)              │         (Backend Services)              │
│                                      │                                          │
│    ┌────────────────┐                │    ┌────────────────────────────────┐   │
│    │ User Browser   │ ═══════════════╪═══▶│ Input Validation Layer         │   │
│    │                │                │    │ • JWT verification             │   │
│    │ • Form inputs  │                │    │ • Schema validation            │   │
│    │ • API calls    │                │    │ • Rate limiting                │   │
│    │ • WebSocket    │                │    │ • Scope enforcement            │   │
│    └────────────────┘                │    └────────────┬───────────────────┘   │
│                                      │                 │                        │
│                                      │                 ▼                        │
│                                      │    ┌────────────────────────────────┐   │
│                                      │    │ Application Logic              │   │
│                                      │    │ (User-space, non-privileged)   │   │
│                                      │    └────────────┬───────────────────┘   │
│                                      │                 │                        │
│                                      │    ─────────────┼─────────────────────   │
│                                      │    PRIVILEGE BOUNDARY                    │
│                                      │    ─────────────┼─────────────────────   │
│                                      │                 ▼                        │
│                                      │    ┌────────────────────────────────┐   │
│                                      │    │ Privileged Agent               │   │
│                                      │    │ (Minimal, audited code)        │   │
│                                      │    │ • CAP_NET_RAW for capture      │   │
│                                      │    │ • Socket-based IPC only        │   │
│                                      │    │ • Allowlist of operations      │   │
│                                      │    └────────────────────────────────┘   │
│                                      │                                          │
└────────────────────────────────────────────────────────────────────────────────┘
```

### 2.3 Data Flow

```
                              DATA FLOW ARCHITECTURE

┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Network    │     │   Packet     │     │  Detection   │     │    Alert     │
│  Interface   │────▶│   Parser     │────▶│   Engine     │────▶│   Manager    │
│              │     │              │     │              │     │              │
│ Raw frames   │     │ Structured   │     │ Analyzed     │     │ Prioritized  │
│ (promiscuous)│     │ PacketInfo   │     │ with context │     │ alerts       │
└──────────────┘     └──────┬───────┘     └──────────────┘     └──────┬───────┘
                           │                                          │
                           │                                          │
           ┌───────────────┴───────────────┐           ┌─────────────┴────────┐
           │         PACKET BUS            │           │      ALERT BUS       │
           │  (async queue, ring buffer)   │           │   (priority queue)   │
           └───────────────┬───────────────┘           └─────────────┬────────┘
                           │                                          │
        ┌──────────────────┼──────────────────────────────────────────┤
        │                  │                                          │
        ▼                  ▼                                          ▼
┌──────────────┐   ┌──────────────┐                           ┌──────────────┐
│  Ring Buffer │   │   Database   │                           │  WebSocket   │
│  (in-memory) │   │  (SQLite)    │                           │  Broadcast   │
│              │   │              │                           │              │
│ Last 10K     │   │ Persistent   │                           │ Real-time    │
│ packets      │   │ storage      │                           │ to UI        │
└──────────────┘   └──────────────┘                           └──────────────┘
```

### 2.4 Performance Considerations

| Component | Target | Strategy |
|-----------|--------|----------|
| Packet throughput | 10K pps | Ring buffer, batch processing, sampling on overload |
| WebSocket latency | <100ms | Debounced broadcasts, subscription filtering |
| UI responsiveness | 60fps | WebGL rendering, virtual scrolling, incremental updates |
| Memory footprint | <500MB | Bounded queues, TTL eviction, lazy loading |
| Database writes | Batched | 1s flush interval, async writes |

---

## 3. Backend Design

### 3.1 Service Architecture

```
backend/
├── app/
│   ├── main.py                    # FastAPI entry point, lifespan management
│   ├── core/
│   │   ├── config.py              # Pydantic settings, env loading
│   │   ├── events.py              # Event bus implementation
│   │   ├── capture/
│   │   │   ├── packet_capture.py  # Scapy-based capture service
│   │   │   ├── packet_parser.py   # Protocol dissection
│   │   │   └── interface_mgr.py   # NIC enumeration, state tracking
│   │   ├── scanner/
│   │   │   ├── network_scanner.py # Nmap wrapper with safety limits
│   │   │   ├── port_profiles.py   # Safe scan profiles
│   │   │   └── arp_monitor.py     # ARP table watcher
│   │   ├── detection/
│   │   │   ├── engine.py          # Rule orchestration
│   │   │   ├── rules/             # Individual detection rules
│   │   │   │   ├── port_scan.py
│   │   │   │   ├── arp_spoof.py
│   │   │   │   ├── dns_tunnel.py
│   │   │   │   ├── flood.py
│   │   │   │   └── new_device.py
│   │   │   └── correlator.py      # Multi-event correlation
│   │   ├── alerting/
│   │   │   ├── alert_manager.py   # Alert lifecycle
│   │   │   ├── enrichment.py      # GeoIP, vendor lookup
│   │   │   └── notifications.py   # Optional external alerts
│   │   ├── wireless/
│   │   │   ├── interface_scan.py  # Wireless interface discovery
│   │   │   ├── channel_hop.py     # Read-only channel info
│   │   │   └── ap_tracker.py      # BSSID/SSID tracking
│   │   └── topology/
│   │       ├── graph_builder.py   # Network graph construction
│   │       └── traffic_matrix.py  # Host-to-host traffic stats
│   ├── api/
│   │   ├── auth.py                # JWT authentication
│   │   ├── packets.py             # Packet capture endpoints
│   │   ├── scanner.py             # Scan management
│   │   ├── alerts.py              # Alert CRUD
│   │   ├── dashboard.py           # Aggregated stats
│   │   ├── network.py             # Topology, hosts
│   │   ├── wireless.py            # Wireless overview
│   │   ├── reports.py             # Export generation
│   │   └── plugins.py             # Plugin management
│   ├── database/
│   │   ├── models.py              # SQLAlchemy models
│   │   ├── session.py             # Async session factory
│   │   └── migrations/            # Alembic migrations
│   ├── websocket/
│   │   ├── manager.py             # Connection manager
│   │   └── channels.py            # Channel subscriptions
│   └── plugins/
│       ├── loader.py              # Plugin discovery/loading
│       ├── hooks.py               # Hook definitions
│       └── sandbox.py             # Execution isolation
├── privileged_agent/              # Runs with CAP_NET_RAW
│   ├── agent.py                   # Minimal privileged process
│   └── ipc.py                     # Unix socket IPC
├── requirements.txt
├── pyproject.toml
└── Dockerfile
```

### 3.2 Core Service Responsibilities

#### 3.2.1 Packet Capture Service

```python
# Responsibilities:
# - Interface selection and management
# - BPF filter compilation and application
# - Raw packet capture via Scapy
# - Protocol dissection (metadata extraction)
# - Ring buffer management
# - Callback dispatch for downstream services

class PacketCaptureService:
    """
    Thread-safe packet capture with backpressure handling.
    
    Safety features:
    - Configurable capture rate limit
    - Automatic sampling under load (1:N sampling)
    - Memory-bounded ring buffer
    - Graceful degradation (drops oldest packets)
    """
    
    async def start(self, interface: str, bpf_filter: str = "") -> CaptureSession
    async def stop() -> CaptureStats
    
    def get_packets(self, 
                    limit: int = 100,
                    protocol: str = None,
                    time_range: tuple = None) -> List[PacketInfo]
    
    def get_interfaces() -> List[InterfaceInfo]
    
    # Event hooks for plugin system
    on_packet_captured: List[Callable[[PacketInfo], None]]
```

#### 3.2.2 Network Scanner Service

```python
# Responsibilities:
# - Target validation (CIDR limits, local-only by default)
# - Scan rate enforcement
# - Nmap subprocess management
# - Result parsing and enrichment
# - Concurrent scan limiting

class NetworkScannerService:
    """
    Safe network scanning with guardrails.
    
    Safety features:
    - CIDR limit: /24 maximum (256 hosts)
    - Rate limit: 100 packets/second default
    - Local network enforcement (RFC1918 by default)
    - Scan timeout: 5 minutes max
    - Concurrent scan limit: 3
    """
    
    SAFE_PROFILES = {
        "ping": ScanProfile(
            nmap_args="-sn",
            description="Host discovery only, no port scan",
            risk_level="low"
        ),
        "quick": ScanProfile(
            nmap_args="-T4 -F --max-rate 100",
            description="Top 100 ports, fast timing",
            risk_level="low"
        ),
        "standard": ScanProfile(
            nmap_args="-sT -T3 --top-ports 1000",
            description="Top 1000 ports, connect scan",
            risk_level="medium"
        ),
        "service": ScanProfile(
            nmap_args="-sV -sC --version-light",
            description="Service version detection",
            risk_level="medium"
        )
    }
    
    async def start_scan(self, 
                         target: str,
                         profile: str = "ping") -> ScanJob
    
    async def cancel_scan(self, scan_id: str) -> bool
    
    def get_scan_status(self, scan_id: str) -> ScanStatus
    
    def validate_target(self, target: str) -> ValidationResult
```

#### 3.2.3 Detection Engine

```python
# Responsibilities:
# - Rule registration and lifecycle
# - Packet/event analysis dispatch
# - State management (sliding windows, caches)
# - Alert generation with explanations
# - Detection cooldowns (avoid alert storms)

class DetectionEngine:
    """
    Rule-based threat detection with explainable outputs.
    
    Every detection includes:
    - rule_id: Unique identifier for the rule
    - severity: info | warning | critical
    - title: Human-readable title
    - description: Technical description
    - explanation: Plain English explanation for non-experts
    - evidence: Data that triggered the detection
    - recommended_action: What the user should do
    """
    
    def register_rule(self, rule: DetectionRule)
    def unregister_rule(self, rule_id: str)
    
    async def analyze_packet(self, packet: PacketInfo)
    async def analyze_event(self, event: SystemEvent)
    
    def get_rule_status() -> Dict[str, RuleStats]
```

### 3.3 Privileged Agent Design

The privileged agent runs with `CAP_NET_RAW` capability and communicates with the main application via Unix socket IPC.

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRIVILEGED AGENT (cap_net_raw)               │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    ALLOWLIST ONLY                        │   │
│  │                                                          │   │
│  │  Allowed Operations:                                     │   │
│  │  ├── capture.start(interface, filter)                   │   │
│  │  ├── capture.stop()                                     │   │
│  │  ├── interfaces.list()                                  │   │
│  │  ├── interfaces.get_stats(name)                         │   │
│  │  └── arp.read_cache()                                   │   │
│  │                                                          │   │
│  │  DENIED Operations:                                      │   │
│  │  ├── Any file system access outside /proc/net           │   │
│  │  ├── Network connections (outbound)                     │   │
│  │  ├── Process spawning                                   │   │
│  │  └── Any syscall not in allowlist                       │   │
│  │                                                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              UNIX SOCKET IPC (/run/netmonitor.sock)      │   │
│  │              • Request/Response protocol                 │   │
│  │              • JSON message framing                      │   │
│  │              • Authentication via peer credentials       │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 3.4 Database Schema

```sql
-- Core tables for persistence

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'viewer',  -- 'admin' | 'operator' | 'viewer'
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE TABLE hosts (
    id INTEGER PRIMARY KEY,
    ip_address TEXT UNIQUE NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    vendor TEXT,
    os_guess TEXT,
    device_type TEXT,  -- 'router' | 'server' | 'workstation' | 'iot' | 'unknown'
    is_gateway BOOLEAN DEFAULT FALSE,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    notes TEXT
);

CREATE TABLE ports (
    id INTEGER PRIMARY KEY,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    state TEXT,  -- 'open' | 'closed' | 'filtered'
    service TEXT,
    version TEXT,
    last_seen TIMESTAMP,
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,  -- 'info' | 'warning' | 'critical'
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    explanation TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    port INTEGER,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by INTEGER REFERENCES users(id),
    acknowledged_at TIMESTAMP,
    notes TEXT
);

CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    scan_id TEXT UNIQUE NOT NULL,
    scan_type TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT DEFAULT 'pending',  -- 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
    progress INTEGER DEFAULT 0,
    hosts_found INTEGER DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    initiated_by INTEGER REFERENCES users(id),
    result JSON
);

CREATE TABLE traffic_stats (
    id INTEGER PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    packets INTEGER DEFAULT 0,
    bytes INTEGER DEFAULT 0,
    -- Aggregated per minute
    UNIQUE(timestamp, source_ip, destination_ip, protocol)
);

CREATE TABLE detection_rules (
    id INTEGER PRIMARY KEY,
    rule_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    severity TEXT DEFAULT 'warning',
    config JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE
);

-- Indexes for performance
CREATE INDEX idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX idx_alerts_severity ON alerts(severity, acknowledged);
CREATE INDEX idx_hosts_last_seen ON hosts(last_seen DESC);
CREATE INDEX idx_traffic_timestamp ON traffic_stats(timestamp DESC);
```

---

## 4. Frontend Design

### 4.1 Technology Stack

| Layer | Technology | Rationale |
|-------|------------|-----------|
| Framework | React 18 + TypeScript | Type safety, ecosystem, developer experience |
| Build | Vite | Fast HMR, ESM-native, simple config |
| State | Zustand | Minimal boilerplate, hooks-based, TypeScript support |
| Routing | React Router v6 | Standard, nested routes, lazy loading |
| Styling | Tailwind CSS | Utility-first, dark mode, rapid prototyping |
| Network Graph | Cytoscape.js | Mature, performant, extensive layout algorithms |
| Charts | Recharts | React-native, composable, good TypeScript support |
| Virtual Scroll | @tanstack/react-virtual | Required for 10K+ packet lists |
| WebSocket | Native WebSocket + reconnection wrapper | Simpler than Socket.IO for this use case |

### 4.2 Application Structure

```
frontend/
├── src/
│   ├── main.tsx                   # Entry point
│   ├── App.tsx                    # Router setup
│   ├── index.css                  # Tailwind imports
│   │
│   ├── components/
│   │   ├── common/
│   │   │   ├── Button.tsx
│   │   │   ├── Card.tsx
│   │   │   ├── Modal.tsx
│   │   │   ├── Badge.tsx
│   │   │   ├── Spinner.tsx
│   │   │   └── VirtualList.tsx
│   │   │
│   │   ├── layout/
│   │   │   ├── Layout.tsx         # Main app shell
│   │   │   ├── Sidebar.tsx        # Navigation
│   │   │   ├── Header.tsx         # Top bar, user menu
│   │   │   └── Footer.tsx         # Status bar
│   │   │
│   │   ├── dashboard/
│   │   │   ├── SecurityScore.tsx  # Circular gauge
│   │   │   ├── StatCard.tsx       # KPI cards
│   │   │   ├── AlertsFeed.tsx     # Recent alerts
│   │   │   ├── TrafficChart.tsx   # Protocol distribution
│   │   │   └── TopTalkers.tsx     # High-traffic hosts
│   │   │
│   │   ├── network/
│   │   │   ├── NetworkGraph.tsx   # Cytoscape wrapper
│   │   │   ├── NodeDetails.tsx    # Host detail panel
│   │   │   ├── EdgeDetails.tsx    # Connection details
│   │   │   ├── GraphControls.tsx  # Zoom, layout, filters
│   │   │   └── Legend.tsx         # Protocol colors
│   │   │
│   │   ├── packets/
│   │   │   ├── PacketTable.tsx    # Virtual scrolling table
│   │   │   ├── PacketDetail.tsx   # Expanded packet view
│   │   │   ├── PacketFilters.tsx  # BPF-like filtering
│   │   │   ├── ProtocolTree.tsx   # Layer breakdown
│   │   │   └── HexView.tsx        # Optional payload view
│   │   │
│   │   ├── scanner/
│   │   │   ├── ScanForm.tsx       # Target, profile selection
│   │   │   ├── ScanProgress.tsx   # Progress bar, live hosts
│   │   │   ├── ScanResults.tsx    # Discovered hosts table
│   │   │   └── HostCard.tsx       # Individual host details
│   │   │
│   │   ├── alerts/
│   │   │   ├── AlertList.tsx      # Filterable alert list
│   │   │   ├── AlertCard.tsx      # Individual alert
│   │   │   ├── AlertDetail.tsx    # Full explanation modal
│   │   │   └── AlertFilters.tsx   # Severity, time, rule
│   │   │
│   │   └── wireless/
│   │       ├── APList.tsx         # Access point list
│   │       ├── ChannelChart.tsx   # Channel utilization
│   │       └── SignalStrength.tsx # RSSI visualization
│   │
│   ├── pages/
│   │   ├── Dashboard.tsx
│   │   ├── NetworkMap.tsx
│   │   ├── PacketCapture.tsx
│   │   ├── NetworkScanner.tsx
│   │   ├── Alerts.tsx
│   │   ├── WirelessOverview.tsx
│   │   ├── InterfaceManager.tsx
│   │   ├── Reports.tsx
│   │   ├── Settings.tsx
│   │   └── Login.tsx
│   │
│   ├── services/
│   │   ├── api.ts                 # REST client (axios)
│   │   ├── websocket.ts           # WebSocket manager
│   │   └── storage.ts             # Local storage helpers
│   │
│   ├── stores/
│   │   ├── authStore.ts           # User session
│   │   ├── packetStore.ts         # Captured packets
│   │   ├── alertStore.ts          # Alerts state
│   │   ├── networkStore.ts        # Hosts, topology
│   │   ├── scanStore.ts           # Scan jobs
│   │   └── settingsStore.ts       # User preferences
│   │
│   ├── hooks/
│   │   ├── useWebSocket.ts        # WebSocket connection
│   │   ├── usePacketStream.ts     # Real-time packets
│   │   ├── useAlertStream.ts      # Real-time alerts
│   │   └── useDebounce.ts
│   │
│   └── types/
│       ├── packet.ts
│       ├── host.ts
│       ├── alert.ts
│       ├── scan.ts
│       └── api.ts
│
├── public/
│   └── favicon.ico
├── package.json
├── vite.config.ts
├── tailwind.config.js
└── tsconfig.json
```

### 4.3 Screen-by-Screen UI Layout

#### 4.3.1 Dashboard (Home)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  ☰  NetMonitor                                            🔔 3   👤 admin   ⚙   │
├────────┬────────────────────────────────────────────────────────────────────────┤
│        │                                                                         │
│  NAV   │   ┌────────────────┐  ┌────────────────┐  ┌────────────────┐           │
│        │   │ SECURITY SCORE │  │ PACKETS TODAY  │  │ ACTIVE HOSTS   │           │
│ Dashboard │ │                │  │                │  │                │           │
│ Network   │ │      85        │  │    24,531      │  │      14        │           │
│ Packets   │ │   ████████░░   │  │   ↑ 12%        │  │   ↓ 2          │           │
│ Scanner   │ │     Good       │  │                │  │                │           │
│ Alerts    │ └────────────────┘  └────────────────┘  └────────────────┘           │
│ Wireless  │                                                                      │
│ Interfaces│  ┌─────────────────────────────────────┐ ┌────────────────────────┐  │
│ Reports   │  │        TRAFFIC DISTRIBUTION          │ │    RECENT ALERTS       │  │
│           │  │                                      │ │                        │  │
│           │  │   ████████████████  TCP 54%         │ │  🔴 Port Scan Detected │  │
│           │  │   ██████████       UDP 31%          │ │     192.168.1.50       │  │
│           │  │   ████             DNS 8%           │ │     2 min ago          │  │
│           │  │   ██               Other 7%         │ │                        │  │
│           │  │                                      │ │  🟡 New Device         │  │
│           │  └─────────────────────────────────────┘ │     192.168.1.105      │  │
│           │                                          │     15 min ago         │  │
│           │  ┌─────────────────────────────────────┐ │                        │  │
│           │  │          TOP TALKERS                 │ │  🟢 High Traffic       │  │
│           │  │  ┌─────────────────────────────────┐│ │     192.168.1.10       │  │
│ ───────── │  │  │ 192.168.1.100  ████████  2.3GB ││ │     1 hour ago         │  │
│ Settings  │  │  │ 192.168.1.1    ██████    1.8GB ││ └────────────────────────┘  │
│           │  │  │ 192.168.1.50   ████      892MB ││                             │
│           │  │  └─────────────────────────────────┘│                             │
│           │  └─────────────────────────────────────┘                             │
└────────┴─────────────────────────────────────────────────────────────────────────┘
│                          Capture: ● Running on eth0 │ 125 pkt/s │ 14 hosts      │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### 4.3.2 Network Map (EtherApe-Inspired)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  ☰  NetMonitor > Network Map                                    🔔   👤   ⚙    │
├────────┬────────────────────────────────────────────────────────────────────────┤
│        │  ┌──────────────────────────────────────────────────────────────────┐  │
│  NAV   │  │  Filters: [TCP] [UDP] [ARP] [DNS] [ICMP]    Timeframe: [Live ▼]  │  │
│        │  │  Layout: [Force ▼]  [🔍+] [🔍-] [⬜] [Fit]  Animation: [● On]   │  │
│        │  └──────────────────────────────────────────────────────────────────┘  │
│        │                                                                         │
│        │  ┌────────────────────────────────────────────────┐ ┌───────────────┐  │
│        │  │                                                │ │ NODE DETAILS  │  │
│        │  │                    ┌───┐                       │ │               │  │
│        │  │                    │🌐 │ gateway               │ │ 192.168.1.1   │  │
│        │  │                    │.1 │                       │ │ Router        │  │
│        │  │                    └─┬─┘                       │ │               │  │
│        │  │          ┌──────────┼──────────┐               │ │ MAC: aa:bb:.. │  │
│        │  │          │          │          │               │ │ Vendor: Cisco │  │
│        │  │       ╔══╧══╗    ╔══╧══╗    ╔══╧══╗           │ │               │  │
│        │  │       ║ 💻  ║────║ 🖥️  ║────║ 📱  ║           │ │ Open Ports:   │  │
│        │  │       ║.100 ║    ║ .50 ║    ║.105 ║           │ │ 22 SSH        │  │
│        │  │       ╚══╤══╝    ╚══╤══╝    ╚═════╝           │ │ 80 HTTP       │  │
│        │  │          │          │                          │ │ 443 HTTPS     │  │
│        │  │          │    ══════╧═══════                   │ │               │  │
│        │  │          │    ║   🖥️       ║                   │ │ Traffic:      │  │
│        │  │          └────║   .10      ║                   │ │ ↑ 1.2 MB/s    │  │
│        │  │               ║  server    ║                   │ │ ↓ 3.4 MB/s    │  │
│        │  │               ══════════════                   │ │               │  │
│        │  │                                                │ │ [View Details]│  │
│        │  │  Legend:  ───── TCP  ═════ UDP  ┄┄┄┄┄ ARP    │ │ [Start Scan]  │  │
│        │  │  Edge thickness = traffic volume               │ └───────────────┘  │
│        │  └────────────────────────────────────────────────┘                    │
│        │                                                                         │
│        │  ┌──────────────────────────────────────────────────────────────────┐  │
│        │  │ Timeline: [|◀] [◀] [▶|]   ════════════════════════●══════       │  │
│        │  │                          10:00    10:15    10:30    10:45 (now)   │  │
│        │  └──────────────────────────────────────────────────────────────────┘  │
└────────┴─────────────────────────────────────────────────────────────────────────┘
```

**Visual Design Notes:**

- **Node sizing**: Based on traffic volume (more traffic = larger node)
- **Edge thickness**: Proportional to bytes transferred
- **Edge animation**: Flowing dots indicate direction and rate
- **Colors**:
  - TCP: Blue (#3B82F6)
  - UDP: Green (#10B981)
  - DNS: Purple (#8B5CF6)
  - ARP: Yellow (#F59E0B)
  - ICMP: Cyan (#06B6D4)
  - Suspicious: Red (#EF4444)

#### 4.3.3 Packet Explorer (Wireshark-lite)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  ☰  NetMonitor > Packet Capture                                 🔔   👤   ⚙    │
├────────┬────────────────────────────────────────────────────────────────────────┤
│        │  ┌──────────────────────────────────────────────────────────────────┐  │
│  NAV   │  │ [▶ Start] [⏹ Stop] Interface: [eth0 ▼]                          │  │
│        │  │                                                                   │  │
│        │  │ Filter: [tcp port 80 or dns                              ] [Apply]│  │
│        │  │ Quick: [HTTP] [DNS] [SSH] [Clear]       Showing 1,247 / 24,531   │  │
│        │  └──────────────────────────────────────────────────────────────────┘  │
│        │                                                                         │
│        │  ┌──────────────────────────────────────────────────────────────────┐  │
│        │  │ # │ Time     │ Source        │ Destination   │Proto│ Len│ Info   │  │
│        │  ├───┼──────────┼───────────────┼───────────────┼─────┼────┼────────┤  │
│        │  │ 1 │ 10:45:01 │ 192.168.1.100 │ 8.8.8.8       │ DNS │ 74 │ A goo..│  │
│        │  │ 2 │ 10:45:01 │ 8.8.8.8       │ 192.168.1.100 │ DNS │ 90 │ A 142..│  │
│        │  │►3 │ 10:45:02 │ 192.168.1.100 │ 142.250.185.78│ TCP │ 74 │ 443 SYN│  │
│        │  │ 4 │ 10:45:02 │ 142.250.185.78│ 192.168.1.100 │ TCP │ 74 │ SYN,ACK│  │
│        │  │ 5 │ 10:45:02 │ 192.168.1.100 │ 142.250.185.78│ TCP │ 66 │ ACK    │  │
│        │  │ 6 │ 10:45:02 │ 192.168.1.100 │ 142.250.185.78│ TLS │1514│ Client │  │
│        │  │   │          │               │               │     │    │ Hello  │  │
│        │  │ ▼ more rows (virtual scroll)                                      │  │
│        │  └──────────────────────────────────────────────────────────────────┘  │
│        │                                                                         │
│        │  ┌─────────────────────────────────┐ ┌────────────────────────────────┐│
│        │  │ PACKET DETAILS                  │ │ PROTOCOL LAYERS                ││
│        │  │                                 │ │                                ││
│        │  │ Packet #3                       │ │ ▼ Ethernet II                  ││
│        │  │ Captured: 2026-01-24 10:45:02   │ │   Src: aa:bb:cc:dd:ee:ff      ││
│        │  │ Length: 74 bytes                │ │   Dst: 11:22:33:44:55:66      ││
│        │  │                                 │ │   Type: IPv4 (0x0800)         ││
│        │  │ Source: 192.168.1.100:54321     │ │                                ││
│        │  │ Destination: 142.250.185.78:443 │ │ ▼ IPv4                         ││
│        │  │ Protocol: TCP                   │ │   Version: 4                   ││
│        │  │ Flags: SYN                      │ │   TTL: 64                      ││
│        │  │ Seq: 0x12345678                 │ │   Protocol: TCP (6)            ││
│        │  │ Window: 65535                   │ │                                ││
│        │  │                                 │ │ ▼ TCP                          ││
│        │  │ [Copy] [Export] [Follow Stream] │ │   Src Port: 54321              ││
│        │  └─────────────────────────────────┘ │   Dst Port: 443 (HTTPS)        ││
│        │                                      │   Flags: SYN                   ││
│        │                                      │   Seq: 305419896               ││
│        │                                      └────────────────────────────────┘│
└────────┴─────────────────────────────────────────────────────────────────────────┘
```

#### 4.3.4 Network Scanner

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  ☰  NetMonitor > Network Scanner                                🔔   👤   ⚙    │
├────────┬────────────────────────────────────────────────────────────────────────┤
│        │  ┌──────────────────────────────────────────────────────────────────┐  │
│  NAV   │  │ NEW SCAN                                                         │  │
│        │  │                                                                   │  │
│        │  │ Target: [192.168.1.0/24          ]  ⚠️ Local networks only       │  │
│        │  │                                                                   │  │
│        │  │ Profile: ○ Ping Sweep (fast, host discovery only)                │  │
│        │  │          ● Quick Scan (common ports, low impact)                 │  │
│        │  │          ○ Standard Scan (top 1000 ports)                        │  │
│        │  │          ○ Service Detection (version fingerprinting)            │  │
│        │  │                                                                   │  │
│        │  │ ⚙️ Advanced: Ports [22,80,443,8080] Rate [100 pkt/s]            │  │
│        │  │                                                                   │  │
│        │  │                                        [Start Scan]              │  │
│        │  │                                                                   │  │
│        │  │ ⚠️ DISCLAIMER: Only scan networks you own or have permission to  │  │
│        │  │    scan. Unauthorized scanning may be illegal in your jurisdiction.│ │
│        │  └──────────────────────────────────────────────────────────────────┘  │
│        │                                                                         │
│        │  ┌──────────────────────────────────────────────────────────────────┐  │
│        │  │ SCAN IN PROGRESS                                     [Cancel]    │  │
│        │  │                                                                   │  │
│        │  │ Target: 192.168.1.0/24   Profile: Quick Scan   ETA: 2:34        │  │
│        │  │ ████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░  47%            │  │
│        │  │                                                                   │  │
│        │  │ Discovered: 12 hosts    Open Ports: 34                           │  │
│        │  └──────────────────────────────────────────────────────────────────┘  │
│        │                                                                         │
│        │  ┌──────────────────────────────────────────────────────────────────┐  │
│        │  │ DISCOVERED HOSTS                                [Export ▼]       │  │
│        │  │                                                                   │  │
│        │  │ ┌─────────────────────────────────────────────────────────────┐ │  │
│        │  │ │ 🌐 192.168.1.1    │ gateway.local │ Cisco    │ Router      │ │  │
│        │  │ │    Ports: 22, 80, 443                                       │ │  │
│        │  │ └─────────────────────────────────────────────────────────────┘ │  │
│        │  │ ┌─────────────────────────────────────────────────────────────┐ │  │
│        │  │ │ 🖥️ 192.168.1.10   │ server01      │ Dell     │ Server      │ │  │
│        │  │ │    Ports: 22 SSH, 80 nginx/1.18, 443 nginx/1.18, 5432 Postgres││
│        │  │ └─────────────────────────────────────────────────────────────┘ │  │
│        │  └──────────────────────────────────────────────────────────────────┘  │
└────────┴─────────────────────────────────────────────────────────────────────────┘
```

#### 4.3.5 Alerts View

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  ☰  NetMonitor > Alerts                                         🔔 3 👤   ⚙    │
├────────┬────────────────────────────────────────────────────────────────────────┤
│        │  ┌──────────────────────────────────────────────────────────────────┐  │
│  NAV   │  │ Filters: [All Severities ▼] [All Rules ▼] [All Time ▼]          │  │
│        │  │          [☑ Show acknowledged]                    [Export]       │  │
│        │  └──────────────────────────────────────────────────────────────────┘  │
│        │                                                                         │
│        │  ┌──────────────────────────────────────────────────────────────────┐  │
│        │  │ 🔴 CRITICAL │ Port Scan Detected                    2 min ago    │  │
│        │  │                                                                   │  │
│        │  │ IP 192.168.1.50 connected to 23 different ports in 60 seconds   │  │
│        │  │                                                                   │  │
│        │  │ 💡 WHAT THIS MEANS:                                              │  │
│        │  │ Port scanning is often the first step in an attack. Attackers   │  │
│        │  │ scan ports to find which services are running and potentially   │  │
│        │  │ vulnerable. Normal applications typically connect to 1-3 ports. │  │
│        │  │                                                                   │  │
│        │  │ 🎯 RECOMMENDED ACTION:                                           │  │
│        │  │ • If this is a known security scanner, acknowledge this alert   │  │
│        │  │ • If unexpected, investigate the source device immediately      │  │
│        │  │ • Consider blocking this IP if unauthorized                      │  │
│        │  │                                                                   │  │
│        │  │ [Acknowledge] [Investigate] [View Packets]          Rule: PS001  │  │
│        │  └──────────────────────────────────────────────────────────────────┘  │
│        │                                                                         │
│        │  ┌──────────────────────────────────────────────────────────────────┐  │
│        │  │ 🟡 WARNING  │ ARP Table Change                      15 min ago   │  │
│        │  │                                                                   │  │
│        │  │ Gateway IP 192.168.1.1 MAC changed: aa:bb:cc → 11:22:33         │  │
│        │  │                                                                   │  │
│        │  │ 💡 WHAT THIS MEANS: [Click to expand]                            │  │
│        │  │                                                                   │  │
│        │  │ [Acknowledge] [View Details]                        Rule: ARP001 │  │
│        │  └──────────────────────────────────────────────────────────────────┘  │
│        │                                                                         │
│        │  ┌──────────────────────────────────────────────────────────────────┐  │
│        │  │ 🟢 INFO     │ New Device Detected                   1 hour ago   │  │
│        │  │                                                                   │  │
│        │  │ New host appeared: 192.168.1.105 (Apple Inc.)                   │  │
│        │  │                                                    ✓ Acknowledged │  │
│        │  └──────────────────────────────────────────────────────────────────┘  │
└────────┴─────────────────────────────────────────────────────────────────────────┘
```

### 4.4 Color System

```css
/* NetMonitor Dark Theme */
:root {
  /* Background layers */
  --bg-primary: #0D1117;      /* Main background */
  --bg-secondary: #161B22;    /* Cards, panels */
  --bg-tertiary: #21262D;     /* Hover states */
  
  /* Text */
  --text-primary: #F0F6FC;
  --text-secondary: #8B949E;
  --text-muted: #484F58;
  
  /* Borders */
  --border-default: #30363D;
  --border-muted: #21262D;
  
  /* Protocol colors */
  --proto-tcp: #3B82F6;       /* Blue */
  --proto-udp: #10B981;       /* Green */
  --proto-dns: #8B5CF6;       /* Purple */
  --proto-arp: #F59E0B;       /* Amber */
  --proto-icmp: #06B6D4;      /* Cyan */
  --proto-http: #EC4899;      /* Pink */
  --proto-https: #14B8A6;     /* Teal */
  
  /* Severity colors */
  --severity-critical: #EF4444;
  --severity-warning: #F59E0B;
  --severity-info: #3B82F6;
  --severity-success: #10B981;
  
  /* Accent */
  --accent-primary: #58A6FF;
  --accent-hover: #79C0FF;
}
```

---

## 5. Feature Modules

### 5.1 Packet Explorer (Wireshark-lite)

| Aspect | Details |
|--------|---------|
| **Purpose** | Real-time packet inspection with protocol decoding, filtering, and export |
| **Linux Inspiration** | Wireshark, tcpdump, tshark |
| **Backend Logic** | Scapy captures frames → parses headers → extracts metadata → stores in ring buffer |
| **Safety** | No raw payload by default; BPF filters applied at capture level |

**Backend Implementation:**

```python
class PacketExplorerModule:
    """
    Wireshark-lite functionality.
    
    Key differences from Wireshark:
    - Metadata-first: No raw payload stored by default
    - Web-native: Stream via WebSocket, not file-based
    - Safety limits: Buffer size, rate limiting
    - Simplified protocol tree: Common protocols only
    """
    
    SUPPORTED_PROTOCOLS = {
        'ethernet': EthernetParser,
        'ipv4': IPv4Parser,
        'ipv6': IPv6Parser,
        'tcp': TCPParser,
        'udp': UDPParser,
        'icmp': ICMPParser,
        'dns': DNSParser,
        'http': HTTPParser,  # Basic request/response metadata
        'tls': TLSParser,    # Handshake metadata only
        'arp': ARPParser,
        'dhcp': DHCPParser,
    }
    
    def parse_packet(self, raw_frame: bytes) -> PacketInfo:
        """Parse raw frame into structured metadata."""
        layers = []
        remaining = raw_frame
        
        for proto, parser in self._detect_stack(raw_frame):
            layer_data, remaining = parser.parse(remaining)
            layers.append(layer_data)
        
        return PacketInfo(
            timestamp=datetime.utcnow(),
            size=len(raw_frame),
            layers=layers,
            summary=self._generate_summary(layers)
        )
```

**UI Features:**

- Virtual scrolling for 100K+ packets
- BPF-like filter syntax with autocomplete
- Color-coded protocol highlighting
- Collapsible protocol tree view
- Stream following (TCP reassembly for same connection)
- Export: JSON, CSV (metadata), PCAP (if payload capture enabled)

### 5.2 Network Scanner (Nmap-safe)

| Aspect | Details |
|--------|---------|
| **Purpose** | Host discovery, port scanning, service fingerprinting with safety limits |
| **Linux Inspiration** | Nmap, netdiscover, arp-scan |
| **Backend Logic** | Validate target → spawn Nmap subprocess with safe args → parse XML output |
| **Safety** | CIDR /24 max, rate limits, local-only by default, timeout enforcement |

**Safe Scan Profiles:**

```python
SCAN_PROFILES = {
    "ping": {
        "name": "Host Discovery",
        "description": "Find live hosts without port scanning",
        "nmap_args": "-sn -n",
        "rate_limit": 200,
        "timeout": 120,
        "risk": "minimal",
        "use_case": "Initial reconnaissance, network inventory"
    },
    "quick": {
        "name": "Quick Scan",
        "description": "Top 100 ports, fast timing",
        "nmap_args": "-T4 -F --max-rate 100",
        "rate_limit": 100,
        "timeout": 180,
        "risk": "low",
        "use_case": "Regular security audits"
    },
    "standard": {
        "name": "Standard Scan",
        "description": "Top 1000 ports, normal timing",
        "nmap_args": "-sT -T3 --top-ports 1000 --max-rate 50",
        "rate_limit": 50,
        "timeout": 300,
        "risk": "medium",
        "use_case": "Comprehensive port survey"
    },
    "service": {
        "name": "Service Detection",
        "description": "Version fingerprinting, script scanning",
        "nmap_args": "-sV -sC --version-light --max-rate 30",
        "rate_limit": 30,
        "timeout": 600,
        "risk": "medium",
        "use_case": "Vulnerability assessment prep",
        "requires_confirmation": True
    }
}
```

**UI Features:**

- Target validation with visual feedback
- Profile selection with risk indicators
- Real-time progress with discovered hosts
- Result cards with expandable port details
- Scan history with re-run capability
- Export: JSON, CSV, PDF report

### 5.3 Live Network Map (EtherApe-Inspired)

| Aspect | Details |
|--------|---------|
| **Purpose** | Real-time animated network topology visualization |
| **Linux Inspiration** | EtherApe, ntopng topology view |
| **Backend Logic** | Build host graph from traffic → calculate edge weights → emit via WebSocket |
| **Rendering** | Cytoscape.js with force-directed layout, WebGL for edge animations |

**Graph Construction:**

```python
class TopologyBuilder:
    """
    Constructs network graph from observed traffic.
    
    Node types:
    - Gateway: Identified by ARP, default route analysis
    - Server: High fan-in, consistent services
    - Workstation: Mixed traffic, client behavior
    - IoT: Limited port usage, periodic beacons
    - Unknown: Insufficient data
    """
    
    def update_from_packet(self, packet: PacketInfo):
        """Update graph based on new packet."""
        src = self._ensure_node(packet.source_ip)
        dst = self._ensure_node(packet.destination_ip)
        
        edge = self._ensure_edge(src, dst)
        edge.update_metrics(
            packets=1,
            bytes=packet.size,
            protocol=packet.protocol,
            timestamp=packet.timestamp
        )
    
    def get_topology(self) -> NetworkGraph:
        """Return current graph state for visualization."""
        return NetworkGraph(
            nodes=[n.to_dict() for n in self.nodes.values()],
            edges=[e.to_dict() for e in self.edges.values()],
            metadata=self._calculate_metadata()
        )
```

**Visualization Features:**

- Force-directed layout with physics simulation
- Node size proportional to traffic volume
- Edge thickness based on bytes transferred
- Edge animation: flowing particles showing direction
- Protocol color coding on edges
- Click node → show details panel
- Timeline scrubbing for historical replay (buffered data)
- Zoom, pan, fit-to-screen controls
- Multiple layout algorithms (force, hierarchical, circle)

### 5.4 Wireless Overview (Kismet-style)

| Aspect | Details |
|--------|---------|
| **Purpose** | Passive visibility into wireless environment (read-only) |
| **Linux Inspiration** | Kismet, airodump-ng (passive mode), iw |
| **Backend Logic** | Query wireless interfaces → read beacon frames → track APs and clients |
| **Safety** | Read-only, no injection, no deauth, requires explicit mode enable |

**Implementation Notes:**

```python
class WirelessOverviewModule:
    """
    Passive wireless monitoring.
    
    IMPORTANT LIMITATIONS:
    - Does NOT put interface into monitor mode automatically
    - Does NOT perform any injection or deauthentication
    - Only reads information available in managed mode by default
    - Monitor mode features require explicit admin action outside the app
    
    Features available in MANAGED mode:
    - List nearby APs (via scan results)
    - Current connection details
    - Signal strength monitoring
    - Channel information
    
    Features requiring MONITOR mode (manual setup):
    - All 802.11 frames (not just beacons)
    - Client tracking
    - Probe request observation
    - Hidden SSID detection
    """
    
    def get_wireless_interfaces(self) -> List[WirelessInterface]:
        """List wireless interfaces and their capabilities."""
        # Uses 'iw dev' and 'iw phy' to enumerate
        pass
    
    def get_nearby_networks(self, interface: str) -> List[AccessPoint]:
        """Get APs from last scan (managed mode compatible)."""
        # Uses 'iw dev <iface> scan dump' - requires recent scan
        pass
    
    def get_current_connection(self, interface: str) -> ConnectionInfo:
        """Get current association details."""
        # Uses 'iw dev <iface> link' and 'iw dev <iface> station dump'
        pass
```

**UI Features:**

- AP list with SSID, BSSID, channel, signal strength
- Channel utilization chart (2.4 GHz / 5 GHz bands)
- Signal strength over time graph
- Connected clients (if monitor mode enabled)
- Security status indicators (WPA3/WPA2/Open)

### 5.5 Alerts & Anomaly Feed

| Aspect | Details |
|--------|---------|
| **Purpose** | Centralized view of all security events with explanations |
| **Backend Logic** | Alert manager receives from detection engine → enriches → persists → broadcasts |
| **UI Focus** | Explainability, actionability, context |

**Alert Lifecycle:**

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Detection  │────▶│  Enrichment  │────▶│  Broadcast   │────▶│    Store     │
│   Triggered  │     │  (GeoIP,     │     │  (WebSocket) │     │  (Database)  │
│              │     │   Vendor)    │     │              │     │              │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                                                │
                                                ▼
                                         ┌──────────────┐
                                         │     UI       │
                                         │  Notification│
                                         └──────────────┘
```

**Alert Structure:**

```python
@dataclass
class Alert:
    id: str
    rule_id: str
    severity: Literal["info", "warning", "critical"]
    title: str
    description: str           # Technical description
    explanation: str           # Plain English for non-experts
    recommended_action: str    # What the user should do
    evidence: Dict[str, Any]   # Supporting data
    
    source_ip: Optional[str]
    destination_ip: Optional[str]
    protocol: Optional[str]
    
    created_at: datetime
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    notes: Optional[str] = None
```

### 5.6 Interface Manager

| Aspect | Details |
|--------|---------|
| **Purpose** | View and manage network interfaces, start/stop capture |
| **Backend Logic** | Read from /sys/class/net, parse interface stats, track state |

**UI Features:**

- List all interfaces (wired, wireless, virtual)
- Real-time RX/TX counters
- Up/down status indicators
- Capture button per interface
- MTU, MAC address, IP addresses
- Driver information
- Error counters (drops, errors, overruns)

### 5.7 Scan History & Reports

| Aspect | Details |
|--------|---------|
| **Purpose** | Historical record of scans, exportable reports |
| **Backend Logic** | Store scan results → generate reports on demand |

**Report Formats:**

- JSON (machine-readable, full data)
- CSV (spreadsheet-compatible hosts/ports)
- PDF (formatted report with charts)
- HTML (self-contained web report)

**Report Contents:**

```
NETWORK SCAN REPORT
Generated: 2026-01-24 10:45:00
Target: 192.168.1.0/24
Profile: Standard Scan

EXECUTIVE SUMMARY
─────────────────────────────────────────────
Hosts Discovered: 14
Open Ports Found: 47
Critical Findings: 2
Warnings: 5

HOST INVENTORY
─────────────────────────────────────────────
[Detailed host list with ports and services]

SECURITY OBSERVATIONS
─────────────────────────────────────────────
⚠️ Telnet (port 23) open on 192.168.1.1 - insecure protocol
⚠️ Default SSH port (22) exposed on 5 hosts
...
```

---

## 6. Threat Detection Engine

### 6.1 Detection Philosophy

**Principles:**

1. **Explainable**: Every alert includes human-readable explanation
2. **Tunable**: All thresholds are configurable
3. **Low false positive**: Conservative defaults, err on side of silence
4. **Transparent**: No ML black boxes, rule logic is visible
5. **Contextual**: Consider network baseline, time of day, device history

### 6.2 Built-in Detection Rules

#### 6.2.1 Port Scan Detection

```python
class PortScanRule:
    """
    Detects hosts connecting to many ports in short time.
    
    Logic:
    1. Track unique (source_ip, dest_port) pairs per destination
    2. Use sliding window (default: 60 seconds)
    3. Alert if unique ports > threshold (default: 10)
    
    Tuning:
    - Higher threshold for networks with scanning tools
    - Longer window for slower scanners
    - Exclude known scanners by IP
    """
    
    rule_id = "port_scan"
    default_threshold = 10
    default_window = 60  # seconds
    severity = "warning"  # Escalate to critical if > 100 ports
    
    explanation_template = """
    Port scanning is typically the first step in an attack. An attacker 
    scans many ports to discover which services are running and potentially 
    vulnerable. Normal applications connect to only 1-3 specific ports.
    
    This alert was triggered because {source_ip} connected to {port_count} 
    different ports on {dest_ip} within {window} seconds.
    
    If this is a legitimate security scanner or network discovery tool, 
    you can acknowledge this alert. Otherwise, investigate the source device.
    """
```

#### 6.2.2 ARP Spoofing Detection

```python
class ARPSpoofRule:
    """
    Detects IP-to-MAC mapping changes that may indicate ARP poisoning.
    
    Logic:
    1. Maintain cache of IP → MAC mappings
    2. When ARP reply received, compare to cache
    3. Alert if MAC changed for known IP (especially gateway)
    
    Special handling:
    - Gateway IP changes: Always critical
    - Other IPs: Warning with cooldown
    - Grace period for DHCP environments
    """
    
    rule_id = "arp_spoof"
    severity_gateway = "critical"
    severity_other = "warning"
    cooldown = 300  # seconds before re-alerting same IP
    
    explanation_template = """
    ARP spoofing (ARP poisoning) is a man-in-the-middle attack where an 
    attacker sends fake ARP messages to link their MAC address with another 
    host's IP address. This allows them to intercept, modify, or stop traffic.
    
    This alert was triggered because the MAC address for {ip} changed from 
    {old_mac} to {new_mac}. {gateway_warning}
    
    Legitimate causes include:
    - Network equipment replacement
    - Virtual machine migrations
    - DHCP lease changes
    
    If unexpected, this could indicate an active attack on your network.
    """
```

#### 6.2.3 DNS Tunneling Detection

```python
class DNSTunnelRule:
    """
    Detects data exfiltration or C2 via DNS.
    
    Logic:
    1. Check DNS packet size (> 512 bytes suspicious)
    2. Check query name entropy (high entropy = encoded data)
    3. Check query frequency to single domain
    4. Check for unusual record types (TXT, NULL)
    
    Thresholds:
    - Size: > 512 bytes
    - Entropy: > 3.5 bits per character
    - Frequency: > 100 queries/minute to same domain
    """
    
    rule_id = "dns_tunnel"
    size_threshold = 512
    entropy_threshold = 3.5
    frequency_threshold = 100
    
    explanation_template = """
    DNS tunneling encodes data inside DNS queries to bypass firewalls. 
    Attackers use this to exfiltrate stolen data or establish command-and-
    control channels that evade traditional security tools.
    
    This alert was triggered because: {trigger_reason}
    
    Legitimate services that may cause this:
    - DNSSEC validation responses
    - DNS-over-HTTPS queries
    - SPF/DKIM/DMARC TXT record lookups
    
    If this domain ({domain}) is unfamiliar, investigate further.
    """
```

#### 6.2.4 Packet Flood Detection

```python
class FloodRule:
    """
    Detects denial-of-service attempts via packet flooding.
    
    Logic:
    1. Count packets per source IP in sliding window
    2. Alert if count exceeds threshold
    3. Differentiate by protocol (SYN flood, UDP flood, ICMP flood)
    
    Protocol-specific thresholds:
    - TCP SYN: 1000/10s (SYN without ACK)
    - UDP: 5000/10s
    - ICMP: 500/10s
    """
    
    rule_id = "packet_flood"
    
    thresholds = {
        "tcp_syn": 1000,
        "udp": 5000,
        "icmp": 500,
        "general": 10000
    }
    window = 10  # seconds
```

#### 6.2.5 New Device Detection

```python
class NewDeviceRule:
    """
    Alerts when previously unseen device appears on network.
    
    Logic:
    1. Maintain database of known MAC addresses
    2. When new MAC seen, create info alert
    3. Enrich with vendor lookup (OUI database)
    
    Configuration:
    - Can be set to warning for high-security environments
    - Optional auto-acknowledgment for home networks
    """
    
    rule_id = "new_device"
    severity = "info"  # Configurable to warning
```

#### 6.2.6 Suspicious Port Activity

```python
class SuspiciousPortRule:
    """
    Detects traffic on ports commonly used by malware.
    
    Monitored ports:
    - 4444: Metasploit default listener
    - 5555: Android debug bridge
    - 6666-6669: IRC (botnet C2)
    - 31337: Back Orifice, "elite" backdoors
    - 12345: NetBus trojan
    - 65535: Various malware
    
    Logic:
    1. Check destination port against known-bad list
    2. Check if connection established (not just SYN)
    3. Exclude if destination is known legitimate service
    """
```

### 6.3 Detection Correlation

```python
class EventCorrelator:
    """
    Correlates multiple low-severity events into high-severity alerts.
    
    Example correlations:
    
    1. Reconnaissance Chain:
       port_scan + service_probe + exploit_attempt → attack_in_progress
    
    2. Lateral Movement:
       new_device + port_scan_from_device + auth_failures → compromised_device
    
    3. Data Exfiltration:
       high_traffic_spike + dns_tunnel_activity → exfiltration_attempt
    """
    
    def correlate(self, events: List[DetectionEvent]) -> Optional[CorrelatedAlert]:
        for pattern in self.patterns:
            if pattern.matches(events):
                return pattern.generate_alert(events)
        return None
```

---

## 7. Security & Safety Design

### 7.1 Safety Limits

| Limit | Default | Configurable | Rationale |
|-------|---------|--------------|-----------|
| CIDR max size | /24 (256 hosts) | Yes, min /24 | Prevent accidental internet scans |
| Scan rate | 100 pkt/s | Yes, max 500 | Avoid network disruption |
| Scan timeout | 5 minutes | Yes, max 30 | Prevent runaway scans |
| Concurrent scans | 3 | Yes, max 5 | Resource management |
| Packet buffer | 10,000 | Yes | Memory bounds |
| Target scope | RFC1918 only | Yes (explicit override) | Prevent external scanning |
| Payload capture | Off | Opt-in | Privacy protection |

### 7.2 Access Control

```python
class Role(Enum):
    VIEWER = "viewer"      # Read-only: dashboards, alerts, reports
    OPERATOR = "operator"  # Can start captures/scans, acknowledge alerts
    ADMIN = "admin"        # Full access: settings, users, unsafe operations

PERMISSIONS = {
    "dashboard.view": [Role.VIEWER, Role.OPERATOR, Role.ADMIN],
    "packets.view": [Role.VIEWER, Role.OPERATOR, Role.ADMIN],
    "packets.capture_start": [Role.OPERATOR, Role.ADMIN],
    "packets.capture_stop": [Role.OPERATOR, Role.ADMIN],
    "scanner.start": [Role.OPERATOR, Role.ADMIN],
    "scanner.cancel": [Role.OPERATOR, Role.ADMIN],
    "alerts.view": [Role.VIEWER, Role.OPERATOR, Role.ADMIN],
    "alerts.acknowledge": [Role.OPERATOR, Role.ADMIN],
    "settings.view": [Role.ADMIN],
    "settings.modify": [Role.ADMIN],
    "users.manage": [Role.ADMIN],
    "payload.enable": [Role.ADMIN],  # Requires explicit confirmation
    "external_scan.enable": [Role.ADMIN],  # Requires explicit confirmation
}
```

### 7.3 UI Safety Features

**Disclaimers:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ ⚠️ IMPORTANT DISCLAIMER                                                     │
│                                                                             │
│ This tool performs network scanning and packet capture. Only use it on     │
│ networks you own or have explicit written permission to test.              │
│                                                                             │
│ Unauthorized scanning may be illegal in your jurisdiction and could        │
│ result in civil or criminal penalties.                                     │
│                                                                             │
│ [ ] I confirm I have authorization to monitor this network                 │
│                                                                             │
│                                              [Cancel] [I Understand]       │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Confirmation Dialogs for Dangerous Operations:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ ⚠️ ENABLE PAYLOAD CAPTURE?                                                  │
│                                                                             │
│ You are about to enable raw payload capture. This will:                    │
│                                                                             │
│ • Record actual packet contents (not just metadata)                        │
│ • Significantly increase storage requirements                              │
│ • Potentially capture sensitive information                                │
│ • May have legal/compliance implications                                   │
│                                                                             │
│ Only enable this if you understand the implications and have               │
│ appropriate data handling procedures in place.                             │
│                                                                             │
│ Type "ENABLE PAYLOAD" to confirm: [                    ]                   │
│                                                                             │
│                                              [Cancel] [Enable]             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.4 Audit Logging

```python
@dataclass
class AuditEvent:
    """All security-relevant actions are logged."""
    timestamp: datetime
    user_id: int
    action: str
    resource: str
    details: Dict[str, Any]
    ip_address: str
    user_agent: str
    success: bool
    error_message: Optional[str] = None

# Logged actions:
# - login_attempt (success/failure)
# - scan_started (target, profile)
# - scan_cancelled
# - capture_started (interface, filter)
# - capture_stopped
# - alert_acknowledged (alert_id, notes)
# - settings_changed (setting_name, old_value, new_value)
# - user_created
# - user_deleted
# - role_changed
# - payload_capture_enabled
# - external_scan_enabled
```

### 7.5 Input Validation

```python
class TargetValidator:
    """Validates scan targets with strict rules."""
    
    def validate(self, target: str, allow_external: bool = False) -> ValidationResult:
        # 1. Parse target (IP, CIDR, range, hostname)
        parsed = self._parse_target(target)
        
        # 2. Check for injection attempts
        if self._contains_injection(target):
            return ValidationResult(
                valid=False,
                error="Invalid characters in target"
            )
        
        # 3. Check network size
        if parsed.num_hosts > 256:
            return ValidationResult(
                valid=False,
                error="Network too large. Maximum /24 (256 hosts)."
            )
        
        # 4. Check scope (RFC1918 by default)
        if not allow_external:
            if not self._is_private_network(parsed):
                return ValidationResult(
                    valid=False,
                    error="External networks require explicit permission. "
                          "Only RFC1918 addresses allowed by default."
                )
        
        # 5. Check against blocklist
        if self._is_blocklisted(parsed):
            return ValidationResult(
                valid=False,
                error="Target is blocklisted."
            )
        
        return ValidationResult(valid=True, parsed=parsed)
```

---

## 8. Plugin Architecture

### 8.1 Plugin System Design

```
plugins/
├── builtin/
│   ├── geo_enrichment/          # GeoIP lookup for IPs
│   │   ├── __init__.py
│   │   ├── plugin.py
│   │   └── GeoLite2-City.mmdb
│   │
│   ├── vendor_lookup/           # MAC vendor identification
│   │   ├── __init__.py
│   │   ├── plugin.py
│   │   └── oui.txt
│   │
│   └── slack_alerts/            # Send alerts to Slack
│       ├── __init__.py
│       └── plugin.py
│
├── custom/                       # User-installed plugins
│   └── .gitkeep
│
└── README.md                     # Plugin development guide
```

### 8.2 Plugin Interface

```python
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class PluginMetadata:
    """Plugin identification and requirements."""
    name: str
    version: str
    author: str
    description: str
    hooks: List[str]  # Which hooks this plugin uses
    config_schema: Dict[str, Any]  # JSON Schema for configuration


class PluginBase(ABC):
    """Base class for all plugins."""
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        pass
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize plugin with configuration. Return True on success."""
        pass
    
    @abstractmethod
    def shutdown(self) -> None:
        """Clean up plugin resources."""
        pass


class PacketPlugin(PluginBase):
    """Plugin that processes packets."""
    
    @abstractmethod
    def on_packet(self, packet: 'PacketInfo') -> Optional['PacketInfo']:
        """
        Called for each captured packet.
        
        Can:
        - Enrich packet with additional data (return modified packet)
        - Trigger custom alerts
        - Log to external systems
        
        Return None to drop packet, or modified PacketInfo to continue.
        """
        pass


class AlertPlugin(PluginBase):
    """Plugin that processes alerts."""
    
    @abstractmethod
    def on_alert(self, alert: 'Alert') -> None:
        """
        Called when new alert is generated.
        
        Use cases:
        - Send to Slack/Teams/Discord
        - Push to SIEM
        - Trigger automated response
        """
        pass


class HostPlugin(PluginBase):
    """Plugin that processes host discovery events."""
    
    @abstractmethod
    def on_host_discovered(self, host: 'DiscoveredHost') -> Optional['DiscoveredHost']:
        """
        Called when new host is discovered.
        
        Can enrich with:
        - GeoIP data
        - Vendor information
        - Asset database lookup
        """
        pass
```

### 8.3 Event Hooks

```python
class HookManager:
    """Manages plugin hook registration and dispatch."""
    
    AVAILABLE_HOOKS = {
        # Packet lifecycle
        "packet_captured": "Called for each raw packet captured",
        "packet_parsed": "Called after packet is parsed into PacketInfo",
        
        # Host events
        "host_discovered": "Called when new host appears",
        "host_updated": "Called when host info changes",
        "host_disappeared": "Called when host stops responding",
        
        # Scan events
        "scan_started": "Called when scan begins",
        "scan_completed": "Called when scan finishes",
        "port_discovered": "Called for each open port found",
        
        # Alert events
        "alert_generated": "Called when detection engine creates alert",
        "alert_acknowledged": "Called when user acknowledges alert",
        
        # System events
        "capture_started": "Called when packet capture begins",
        "capture_stopped": "Called when packet capture ends",
        "application_startup": "Called on application start",
        "application_shutdown": "Called on application shutdown",
    }
    
    def register(self, hook: str, callback: Callable) -> str:
        """Register a callback for a hook. Returns registration ID."""
        pass
    
    def unregister(self, registration_id: str) -> bool:
        """Unregister a callback."""
        pass
    
    async def dispatch(self, hook: str, *args, **kwargs) -> List[Any]:
        """Dispatch event to all registered callbacks."""
        pass
```

### 8.4 Example Plugin: Slack Alerts

```python
# plugins/builtin/slack_alerts/plugin.py

import httpx
from typing import Dict, Any, Optional


class SlackAlertsPlugin(AlertPlugin):
    """Send critical alerts to Slack."""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Slack Alerts",
            version="1.0.0",
            author="NetMonitor Team",
            description="Send critical alerts to a Slack channel",
            hooks=["alert_generated"],
            config_schema={
                "type": "object",
                "properties": {
                    "webhook_url": {
                        "type": "string",
                        "description": "Slack Incoming Webhook URL"
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": ["info", "warning", "critical"],
                        "default": "critical"
                    },
                    "channel": {
                        "type": "string",
                        "description": "Override channel (optional)"
                    }
                },
                "required": ["webhook_url"]
            }
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.webhook_url = config["webhook_url"]
        self.min_severity = config.get("min_severity", "critical")
        self.channel = config.get("channel")
        self.client = httpx.AsyncClient()
        return True
    
    def shutdown(self) -> None:
        self.client.close()
    
    async def on_alert(self, alert: 'Alert') -> None:
        if self._severity_meets_threshold(alert.severity):
            await self._send_to_slack(alert)
    
    async def _send_to_slack(self, alert: 'Alert'):
        payload = {
            "text": f"🚨 *{alert.severity.upper()}*: {alert.title}",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🚨 {alert.title}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": alert.description
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"Severity: *{alert.severity}* | Rule: `{alert.rule_id}` | Source: {alert.source_ip or 'N/A'}"
                        }
                    ]
                }
            ]
        }
        
        if self.channel:
            payload["channel"] = self.channel
        
        await self.client.post(self.webhook_url, json=payload)
```

---

## 9. API Specification

### 9.1 REST API Endpoints

#### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Authenticate, receive JWT |
| POST | `/api/auth/logout` | Invalidate token |
| GET | `/api/auth/me` | Get current user info |
| POST | `/api/auth/change-password` | Change password |

#### Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard/summary` | System overview stats |
| GET | `/api/dashboard/security-score` | Calculated security score |
| GET | `/api/dashboard/traffic-stats` | Protocol distribution |
| GET | `/api/dashboard/top-talkers` | High-traffic hosts |

#### Packet Capture

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/packets/interfaces` | List network interfaces |
| POST | `/api/packets/capture/start` | Start capture |
| POST | `/api/packets/capture/stop` | Stop capture |
| GET | `/api/packets/capture/status` | Capture status |
| GET | `/api/packets/packets` | Get captured packets |
| GET | `/api/packets/stats` | Capture statistics |
| GET | `/api/packets/export` | Export packets |

#### Network Scanner

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/scanner/profiles` | List scan profiles |
| POST | `/api/scanner/scan` | Start scan |
| GET | `/api/scanner/scan/{id}` | Get scan status |
| DELETE | `/api/scanner/scan/{id}` | Cancel scan |
| GET | `/api/scanner/history` | Scan history |

#### Network Topology

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/network/hosts` | List discovered hosts |
| GET | `/api/network/hosts/{id}` | Host details |
| GET | `/api/network/topology` | Graph data |
| GET | `/api/network/traffic-matrix` | Host-to-host traffic |

#### Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | List alerts (filterable) |
| GET | `/api/alerts/{id}` | Alert details |
| POST | `/api/alerts/{id}/acknowledge` | Acknowledge alert |
| GET | `/api/alerts/rules` | List detection rules |
| PUT | `/api/alerts/rules/{id}` | Update rule config |

#### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/reports` | List reports |
| POST | `/api/reports/generate` | Generate report |
| GET | `/api/reports/{id}/download` | Download report |

### 9.2 WebSocket Channels

```
WebSocket URL: ws://localhost:8000/ws

Connection with auth:
ws://localhost:8000/ws?token=<jwt_token>

CHANNELS:
─────────────────────────────────────────────

Channel: "packets"
  Description: Real-time packet stream
  Message format:
  {
    "type": "packet",
    "data": {
      "timestamp": "2026-01-24T10:45:02Z",
      "source_ip": "192.168.1.100",
      "destination_ip": "8.8.8.8",
      "protocol": "UDP",
      "source_port": 54321,
      "destination_port": 53,
      "size": 74,
      "info": "DNS Query A google.com"
    }
  }

Channel: "alerts"
  Description: Real-time alert stream
  Message format:
  {
    "type": "alert",
    "data": {
      "id": "alert_123",
      "rule_id": "port_scan",
      "severity": "warning",
      "title": "Port Scan Detected",
      "description": "...",
      "explanation": "...",
      "source_ip": "192.168.1.50",
      "timestamp": "2026-01-24T10:45:02Z"
    }
  }

Channel: "stats"
  Description: Periodic statistics updates (every 1s)
  Message format:
  {
    "type": "stats",
    "data": {
      "packets_per_second": 125,
      "bytes_per_second": 95000,
      "active_connections": 42,
      "protocol_distribution": {
        "TCP": 54,
        "UDP": 31,
        "DNS": 8,
        "Other": 7
      }
    }
  }

Channel: "topology"
  Description: Network graph updates
  Message format:
  {
    "type": "topology_update",
    "data": {
      "event": "edge_updated",
      "source": "192.168.1.100",
      "target": "192.168.1.1",
      "metrics": {
        "packets": 15,
        "bytes": 12500,
        "protocol": "TCP"
      }
    }
  }

SUBSCRIPTION:
─────────────────────────────────────────────

Subscribe to channels:
{
  "action": "subscribe",
  "channels": ["packets", "alerts"]
}

Unsubscribe:
{
  "action": "unsubscribe", 
  "channels": ["packets"]
}

Apply filter (packets channel):
{
  "action": "filter",
  "channel": "packets",
  "filter": {
    "protocols": ["TCP", "UDP"],
    "source_ip": "192.168.1.100"
  }
}
```

### 9.3 API Error Responses

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid target format",
    "details": {
      "field": "target",
      "reason": "CIDR /16 exceeds maximum allowed /24"
    }
  }
}
```

**Error Codes:**

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `AUTH_REQUIRED` | 401 | Missing or invalid token |
| `AUTH_EXPIRED` | 401 | Token expired |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 400 | Invalid input |
| `RATE_LIMITED` | 429 | Too many requests |
| `SCAN_IN_PROGRESS` | 409 | Scan already running |
| `CAPTURE_RUNNING` | 409 | Capture already active |
| `INTERNAL_ERROR` | 500 | Server error |

---

## 10. Deployment Strategy

### 10.1 Docker Deployment (Recommended)

```dockerfile
# Dockerfile.backend
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    nmap \
    iproute2 \
    wireless-tools \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash netmonitor

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY backend/ ./backend/

# Switch to non-root user
USER netmonitor

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s \
    CMD curl -f http://localhost:8000/health || exit 1

# Run with uvicorn
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```dockerfile
# Dockerfile.frontend
FROM node:20-alpine AS builder

WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

```yaml
# docker-compose.yml
version: "3.9"

services:
  backend:
    build:
      context: .
      dockerfile: Dockerfile.backend
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - /var/run/docker.sock:/var/run/docker.sock:ro  # For container scanning
    cap_add:
      - NET_RAW      # Required for packet capture
      - NET_ADMIN    # Required for interface management
    network_mode: host  # Required for full network visibility
    environment:
      - DATABASE_URL=sqlite+aiosqlite:///./data/netmonitor.db
      - SECRET_KEY=${SECRET_KEY}
      - DEBUG=false
    restart: unless-stopped

  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend
    ports:
      - "80:80"
    depends_on:
      - backend
    restart: unless-stopped

  # Optional: Prometheus metrics
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    profiles:
      - monitoring

  # Optional: Grafana dashboards
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    profiles:
      - monitoring
```

### 10.2 Production Checklist

```markdown
## Pre-Deployment Checklist

### Security
- [ ] Change default admin password
- [ ] Generate strong SECRET_KEY
- [ ] Enable HTTPS (reverse proxy with TLS)
- [ ] Configure firewall rules (restrict access to trusted IPs)
- [ ] Review and adjust CORS origins
- [ ] Enable audit logging
- [ ] Set appropriate file permissions

### Performance
- [ ] Set appropriate buffer sizes for expected traffic
- [ ] Configure log rotation
- [ ] Set up monitoring (Prometheus/Grafana)
- [ ] Plan database maintenance (SQLite vacuum, or migrate to Postgres)

### Network
- [ ] Verify interface permissions (CAP_NET_RAW)
- [ ] Test packet capture on target interface
- [ ] Verify Nmap installation and permissions
- [ ] Test WebSocket connectivity

### Compliance
- [ ] Review local laws regarding network monitoring
- [ ] Obtain written authorization for monitored networks
- [ ] Configure appropriate data retention policies
- [ ] Document deployed configuration
```

### 10.3 Environment Variables

```bash
# .env.example

# Application
SECRET_KEY=generate-a-strong-random-key-here
DEBUG=false
LOG_LEVEL=INFO

# Database
DATABASE_URL=sqlite+aiosqlite:///./data/netmonitor.db
# For production, consider:
# DATABASE_URL=postgresql+asyncpg://user:pass@localhost/netmonitor

# Authentication
ACCESS_TOKEN_EXPIRE_MINUTES=30
DEFAULT_ADMIN_PASSWORD=changeme  # Only used on first run

# CORS (comma-separated)
CORS_ORIGINS=https://netmonitor.example.com

# Capture Settings
CAPTURE_INTERFACE=eth0
CAPTURE_BUFFER_SIZE=10000

# Scanner Settings
SCAN_RATE_LIMIT=100
SCAN_TIMEOUT=300
MAX_CONCURRENT_SCANS=3

# Detection
DETECTION_WINDOW_SECONDS=60
PORT_SCAN_THRESHOLD=10
FLOOD_THRESHOLD=1000

# External (optional)
GEOIP_DATABASE_PATH=/app/data/GeoLite2-City.mmdb
```

---

## 11. Limitations & Non-Goals

### 11.1 Explicit Non-Goals

| Feature | Reason |
|---------|--------|
| **Offensive capabilities** | This is a defensive tool. No exploit modules, no password cracking, no packet injection |
| **Full Wireshark replacement** | We provide metadata inspection; full payload analysis needs Wireshark |
| **Enterprise SIEM** | Not a log aggregation platform; use Splunk/Elastic for that |
| **IDS/IPS** | Detection only, no automatic blocking |
| **Wireless attacks** | No deauth, no WPA cracking, no evil twin |
| **Cloud/SaaS monitoring** | Focused on local network; use cloud-native tools for AWS/Azure/GCP |
| **Multi-tenant** | Single organization deployment |
| **Mobile app** | Web-only for simplicity |

### 11.2 Known Limitations

| Limitation | Mitigation |
|------------|------------|
| **Root/CAP_NET_RAW required** | Docker with capabilities; document manual setup |
| **Linux-primary** | Windows support limited; WSL2 recommended |
| **10K pps throughput ceiling** | Sampling mode for high-traffic networks |
| **Single-node** | Horizontal scaling not supported; one instance per network segment |
| **WebSocket scalability** | ~100 concurrent clients max; add Redis pub/sub for more |
| **SQLite for persistence** | Fine for small deployments; document Postgres migration for scale |

### 11.3 Future Roadmap (Out of Scope for v1)

```
v1.0 - Current Specification
├── Core packet capture
├── Basic network scanning
├── Rule-based detection
├── Real-time network map
└── WebSocket streaming

v1.1 - Planned
├── Wireless interface support (read-only)
├── Plugin marketplace
├── Scheduled scans
└── Email alerting

v2.0 - Future Consideration
├── Multi-node deployment
├── Kubernetes operator
├── STIX/TAXII threat intel integration
├── Automated response playbooks
└── Mobile companion app
```

---

## Appendix A: Quick Reference

### A.1 Technology Summary

| Component | Technology |
|-----------|------------|
| Backend Framework | FastAPI (Python 3.11+) |
| Packet Capture | Scapy |
| Network Scanning | python-nmap (wrapping Nmap) |
| Database | SQLite (dev) / PostgreSQL (prod) |
| ORM | SQLAlchemy 2.0 (async) |
| Frontend Framework | React 18 + TypeScript |
| Build Tool | Vite |
| State Management | Zustand |
| Network Graph | Cytoscape.js |
| Charts | Recharts |
| Styling | Tailwind CSS |
| Real-time | WebSocket (native) |
| Auth | JWT (python-jose) |
| Deployment | Docker + docker-compose |

### A.2 Default Ports

| Service | Port |
|---------|------|
| Frontend (dev) | 5173 |
| Frontend (prod) | 80/443 |
| Backend API | 8000 |
| WebSocket | 8000/ws |
| Prometheus (optional) | 9090 |
| Grafana (optional) | 3000 |

### A.3 Key Files

```
netmonitor/
├── backend/
│   ├── app/main.py                 # Entry point
│   └── app/core/config.py          # All settings
├── frontend/
│   ├── src/App.tsx                 # Router
│   └── src/services/api.ts         # API client
├── docker-compose.yml              # Deployment
├── .env                            # Configuration
└── docs/
    ├── DESIGN_SPECIFICATION.md     # This document
    ├── API.md                      # API reference
    └── DETECTION_RULES.md          # Rule documentation
```

---

## Appendix B: Implementation Priority

### Phase 1: Foundation (Week 1-2)
1. ✅ FastAPI backend skeleton
2. ✅ SQLite database models
3. ✅ JWT authentication
4. ✅ Basic packet capture (Scapy)
5. ✅ WebSocket manager
6. ✅ React frontend shell

### Phase 2: Core Features (Week 3-4)
1. ✅ Packet Explorer UI
2. ✅ Network Scanner integration
3. ✅ Detection engine framework
4. ✅ Alert system
5. Dashboard components

### Phase 3: Visualization (Week 5-6)
1. Network Map (Cytoscape.js)
2. Traffic charts
3. Timeline scrubbing
4. Edge animations

### Phase 4: Polish (Week 7-8)
1. Plugin system
2. Export functionality
3. Documentation
4. Security hardening
5. Performance optimization

---

**Document End**

*This specification provides sufficient detail for a small team to begin implementation immediately. Technical decisions have been made; implementation should follow the patterns established herein.*

# Network Safety Monitor - Architecture

## System Overview

The Network Safety Monitor is a full-stack web application for network security monitoring, combining packet inspection capabilities with network scanning features.

```
┌─────────────────────────────────────────────────────────────────┐
│                        React Frontend                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │Dashboard │ │ Packets  │ │ Scanner  │ │  Alerts  │            │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘            │
│       └────────────┴────────────┴────────────┘                   │
│                          │                                       │
│                    REST API / WebSocket                          │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────────────┐
│                      FastAPI Backend                             │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    API Layer                              │    │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ │    │
│  │  │  Auth  │ │Packets │ │Scanner │ │ Alerts │ │Network │ │    │
│  │  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘ │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   Core Services                          │    │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐     │    │
│  │  │PacketCapture │ │NetworkScanner│ │  Detection   │     │    │
│  │  │   (Scapy)    │ │ (python-nmap)│ │   Engine     │     │    │
│  │  └──────────────┘ └──────────────┘ └──────────────┘     │    │
│  │                         │                                │    │
│  │                  ┌──────────────┐                        │    │
│  │                  │AlertManager  │                        │    │
│  │                  └──────────────┘                        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   Data Layer                             │    │
│  │        SQLAlchemy ORM + SQLite (aiosqlite)              │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
netmonitor/
├── backend/
│   └── app/
│       ├── main.py              # FastAPI application entry point
│       ├── core/
│       │   ├── config.py        # Application settings
│       │   ├── capture/
│       │   │   └── packet_capture.py  # Scapy packet capture
│       │   ├── scanner/
│       │   │   └── network_scanner.py # Nmap scanning
│       │   ├── detection/
│       │   │   └── engine.py    # Threat detection rules
│       │   └── alerting/
│       │       └── alert_manager.py   # Alert generation
│       ├── api/
│       │   ├── auth.py          # Authentication routes
│       │   ├── packets.py       # Packet capture routes
│       │   ├── scanner.py       # Network scanner routes
│       │   ├── alerts.py        # Alert management routes
│       │   ├── dashboard.py     # Dashboard data routes
│       │   └── network.py       # Network topology routes
│       ├── database/
│       │   ├── models.py        # SQLAlchemy models
│       │   ├── session.py       # Database session
│       │   └── init_db.py       # Database initialization
│       └── websocket/
│           └── manager.py       # WebSocket connection manager
├── frontend/
│   ├── src/
│   │   ├── App.tsx              # React router setup
│   │   ├── main.tsx             # Entry point
│   │   ├── pages/               # Page components
│   │   ├── components/          # Reusable components
│   │   ├── services/            # API client
│   │   └── stores/              # Zustand state stores
│   ├── package.json
│   └── vite.config.ts
├── docs/
│   ├── API.md
│   ├── ARCHITECTURE.md
│   └── DETECTION_RULES.md
├── requirements.txt
└── README.md
```

---

## Backend Components

### 1. FastAPI Application (`main.py`)

The main entry point that:
- Initializes the FastAPI application with lifespan management
- Configures CORS for frontend communication
- Mounts all API routers
- Provides health check and disclaimer endpoints

### 2. Packet Capture Service

**File:** `core/capture/packet_capture.py`

Uses Scapy for real-time packet capture:

```python
class PacketCaptureService:
    - start_capture(interface, bpf_filter)
    - stop_capture()
    - get_packets(limit, protocol_filter)
    - get_stats()
```

**Features:**
- Thread-safe packet buffer
- BPF filter support
- Protocol parsing (TCP, UDP, ICMP, DNS, HTTP, ARP)
- Callback system for real-time processing

### 3. Network Scanner Service

**File:** `core/scanner/network_scanner.py`

Wraps python-nmap for safe network scanning:

```python
class NetworkScannerService:
    - start_scan(target, scan_type, ports)
    - get_scan_status(scan_id)
    - cancel_scan(scan_id)
    - validate_target(target)
```

**Safety Features:**
- Target validation (no external IPs by default)
- CIDR size limits (/24 maximum)
- Rate limiting (100 packets/sec)
- Scan timeout enforcement

### 4. Detection Engine

**File:** `core/detection/engine.py`

Analyzes packets for security threats:

```python
class DetectionEngine:
    - analyze_packet(packet)
    - register_callback(callback)
    - get_stats()
```

**Detection Rules:**
- Port scanning (configurable threshold)
- ARP spoofing (MAC/IP inconsistency)
- DNS tunneling (large query/response)
- Packet floods (rate-based)
- Suspicious ports (known malware ports)
- ICMP sweeps (host discovery)

### 5. Alert Manager

**File:** `core/alerting/alert_manager.py`

Manages security alerts:

```python
class AlertManager:
    - create_alert(severity, title, description, ...)
    - get_alerts(filters)
    - acknowledge_alert(alert_id)
    - get_stats()
```

**Features:**
- Alert rate limiting to prevent spam
- Plain English explanations
- Severity levels (info, warning, critical)

---

## Frontend Components

### Technology Stack
- **React 18** with TypeScript
- **Vite** for fast development/building
- **Tailwind CSS** for styling (dark theme)
- **Zustand** for state management
- **Chart.js** for visualizations
- **Lucide React** for icons

### Page Components

| Page | Description |
|------|-------------|
| `Dashboard` | Overview with security score, stats, traffic chart |
| `PacketCapture` | Real-time packet inspection with filtering |
| `NetworkScanner` | Network discovery and port scanning |
| `Alerts` | Security alert management and acknowledgment |
| `NetworkMap` | Visual network topology |
| `Settings` | User profile, password, detection rules |

### State Management

```typescript
// Auth Store (Zustand + persist)
interface AuthState {
  token: string | null
  user: User | null
  isAuthenticated: boolean
  login(token, user)
  logout()
}
```

---

## Data Models

### User
```sql
- id: Integer (PK)
- username: String (unique)
- hashed_password: String
- role: Enum (admin, viewer)
- is_active: Boolean
```

### Alert
```sql
- id: Integer (PK)
- severity: Enum (info, warning, critical)
- title: String
- description: Text
- explanation: Text
- source_ip: String (nullable)
- destination_ip: String (nullable)
- protocol: String (nullable)
- port: Integer (nullable)
- rule_id: String (nullable)
- is_acknowledged: Boolean
- acknowledged_by: String (nullable)
- created_at: DateTime
```

### NetworkScan
```sql
- id: String (UUID, PK)
- target: String
- scan_type: String
- status: Enum (pending, running, completed, failed, cancelled)
- started_at: DateTime
- completed_at: DateTime (nullable)
- results: JSON
- error_message: String (nullable)
```

### DiscoveredHost
```sql
- id: Integer (PK)
- ip_address: String
- mac_address: String (nullable)
- hostname: String (nullable)
- os_info: String (nullable)
- device_type: String (nullable)
- is_gateway: Boolean
- first_seen: DateTime
- last_seen: DateTime
- ports: JSON
```

### DetectionRule
```sql
- id: String (PK)
- name: String
- description: Text
- severity: Enum
- is_enabled: Boolean
- threshold: Integer (nullable)
- time_window: Integer (nullable)
```

---

## Security Architecture

### Authentication
- JWT tokens with configurable expiration
- bcrypt password hashing
- Role-based access control (admin/viewer)

### Network Safety
- Local network scanning only by default
- Private IP validation
- CIDR size restrictions
- Scan rate limiting

### Data Privacy
- No raw packet payloads stored by default
- Sensitive data redaction options
- Local SQLite database (no cloud)

---

## Communication Flow

### REST API Flow
```
Frontend → HTTP Request → FastAPI Router → Service → Database
         ← HTTP Response ←              ←        ←
```

### WebSocket Flow
```
Frontend ←──────┐
                │
Backend:        │
  PacketCapture ├──→ WebSocket Manager ──→ Connected Clients
  AlertManager ─┤
  Detection    ─┘
```

### Packet Analysis Pipeline
```
Network Interface
       │
       ▼
  Scapy Capture (thread)
       │
       ▼
  Protocol Parser
       │
       ├──→ Packet Buffer (for display)
       │
       ▼
  Detection Engine
       │
       ├──→ Alert Manager (if threat detected)
       │
       ▼
  WebSocket Broadcast
```

---

## Deployment

### Development
```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

### Production
```bash
# Backend with Gunicorn
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker

# Frontend build
npm run build
# Serve dist/ with nginx or similar
```

### Requirements
- Python 3.9+
- Node.js 18+
- Nmap installed on system
- Root/Admin privileges for raw packet capture

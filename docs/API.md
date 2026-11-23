# Network Safety Monitor - API Documentation

## Overview

The Network Safety Monitor provides a RESTful API built with FastAPI. All endpoints (except auth) require JWT authentication.

**Base URL:** `http://localhost:8000/api`

---

## Authentication

### POST `/auth/login`
Authenticate and receive a JWT token.

**Request Body (form-data):**
```
username: string
password: string
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer"
}
```

### GET `/auth/me`
Get current user information.

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "id": 1,
  "username": "admin",
  "role": "admin",
  "is_active": true
}
```

### POST `/auth/change-password`
Change the current user's password.

**Request Body:**
```json
{
  "current_password": "string",
  "new_password": "string"
}
```

---

## Dashboard

### GET `/dashboard/summary`
Get system overview statistics.

**Response:**
```json
{
  "total_packets_captured": 15234,
  "active_connections": 42,
  "alerts_today": 5,
  "hosts_discovered": 12,
  "capture_status": "running",
  "uptime_seconds": 3600
}
```

### GET `/dashboard/security-score`
Get the current security score (0-100).

**Response:**
```json
{
  "score": 85,
  "factors": {
    "unacknowledged_alerts": -10,
    "critical_alerts": -5,
    "open_ports": 0
  },
  "recommendations": [
    "Review 3 unacknowledged alerts"
  ]
}
```

### GET `/dashboard/traffic-stats`
Get protocol distribution statistics.

**Response:**
```json
{
  "protocols": {
    "TCP": 8500,
    "UDP": 4200,
    "ICMP": 534,
    "Other": 1000
  },
  "total": 14234
}
```

### GET `/dashboard/top-talkers`
Get hosts with most traffic.

**Query Parameters:**
- `limit` (int, default: 10): Number of results

**Response:**
```json
[
  {
    "ip": "192.168.1.100",
    "packets_sent": 5000,
    "packets_received": 3200,
    "bytes_total": 4500000
  }
]
```

---

## Packet Capture

### GET `/packets/interfaces`
List available network interfaces.

**Response:**
```json
[
  {
    "name": "eth0",
    "description": "Ethernet adapter",
    "addresses": ["192.168.1.100"]
  }
]
```

### POST `/packets/start`
Start packet capture.

**Request Body:**
```json
{
  "interface": "eth0",
  "bpf_filter": "tcp port 80"
}
```

**Response:**
```json
{
  "status": "started",
  "interface": "eth0",
  "filter": "tcp port 80"
}
```

### POST `/packets/stop`
Stop packet capture.

**Response:**
```json
{
  "status": "stopped",
  "packets_captured": 1520
}
```

### GET `/packets/status`
Get capture status.

**Response:**
```json
{
  "is_capturing": true,
  "interface": "eth0",
  "filter": "tcp port 80",
  "packets_captured": 1520,
  "started_at": "2026-01-24T10:00:00Z"
}
```

### GET `/packets/packets`
Get captured packets.

**Query Parameters:**
- `limit` (int, default: 100): Max packets to return
- `protocol` (string, optional): Filter by protocol
- `source_ip` (string, optional): Filter by source IP

**Response:**
```json
[
  {
    "timestamp": "2026-01-24T10:05:23Z",
    "source_ip": "192.168.1.100",
    "destination_ip": "8.8.8.8",
    "protocol": "UDP",
    "source_port": 54321,
    "destination_port": 53,
    "length": 64,
    "info": "DNS Query"
  }
]
```

### GET `/packets/stats`
Get capture statistics.

**Response:**
```json
{
  "total_packets": 15234,
  "protocols": {"TCP": 8500, "UDP": 4200},
  "packets_per_second": 125.5,
  "bytes_captured": 12500000
}
```

---

## Network Scanner

### POST `/scanner/scan`
Start a network scan.

**Request Body:**
```json
{
  "target": "192.168.1.0/24",
  "scan_type": "quick",
  "ports": "22,80,443"
}
```

**Scan Types:**
- `ping`: Host discovery only
- `quick`: Common ports scan
- `syn`: SYN stealth scan (requires root)
- `connect`: TCP connect scan
- `service`: Service version detection

**Response:**
```json
{
  "scan_id": "abc123",
  "status": "running",
  "target": "192.168.1.0/24",
  "scan_type": "quick"
}
```

### GET `/scanner/scan/{scan_id}`
Get scan results.

**Response:**
```json
{
  "scan_id": "abc123",
  "status": "completed",
  "target": "192.168.1.0/24",
  "hosts_found": 12,
  "started_at": "2026-01-24T10:00:00Z",
  "completed_at": "2026-01-24T10:02:30Z",
  "results": [
    {
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "state": "up",
      "ports": [
        {"port": 80, "state": "open", "service": "http"}
      ]
    }
  ]
}
```

### GET `/scanner/scans`
List all scans.

**Query Parameters:**
- `status` (string, optional): Filter by status (running, completed, failed)

### POST `/scanner/scan/{scan_id}/cancel`
Cancel a running scan.

### GET `/scanner/validate-target`
Validate a scan target.

**Query Parameters:**
- `target` (string): Target to validate

**Response:**
```json
{
  "valid": true,
  "target_type": "cidr",
  "host_count": 254,
  "warnings": []
}
```

---

## Alerts

### GET `/alerts/`
List alerts.

**Query Parameters:**
- `limit` (int, default: 100): Max results
- `severity` (string, optional): Filter by severity (info, warning, critical)
- `acknowledged` (bool, optional): Filter by acknowledgment status

**Response:**
```json
[
  {
    "id": 1,
    "severity": "warning",
    "title": "Port Scan Detected",
    "description": "Multiple ports probed from 192.168.1.50",
    "explanation": "This may indicate reconnaissance activity...",
    "source_ip": "192.168.1.50",
    "is_acknowledged": false,
    "created_at": "2026-01-24T10:15:00Z"
  }
]
```

### GET `/alerts/stats`
Get alert statistics.

**Response:**
```json
{
  "total_alerts": 150,
  "info_count": 100,
  "warning_count": 40,
  "critical_count": 10,
  "unacknowledged_count": 25
}
```

### POST `/alerts/{alert_id}/acknowledge`
Acknowledge an alert.

### POST `/alerts/acknowledge-all`
Acknowledge all alerts.

**Request Body:**
```json
{
  "severity": "warning"
}
```

### DELETE `/alerts/{alert_id}`
Delete an alert.

### POST `/alerts/clear`
Clear alerts.

**Query Parameters:**
- `acknowledged_only` (bool, default: true): Only clear acknowledged

### GET `/alerts/rules/list`
List detection rules.

**Response:**
```json
[
  {
    "id": "port_scan",
    "name": "Port Scan Detection",
    "description": "Detects scanning of multiple ports",
    "severity": "warning",
    "is_enabled": true,
    "threshold": 10,
    "time_window": 60
  }
]
```

### PATCH `/alerts/rules/{rule_id}`
Update a detection rule.

**Request Body:**
```json
{
  "is_enabled": false,
  "threshold": 20
}
```

---

## Network

### GET `/network/hosts`
Get discovered hosts.

**Response:**
```json
[
  {
    "id": 1,
    "ip_address": "192.168.1.1",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "hostname": "router.local",
    "is_gateway": true,
    "ports": [{"port": 80, "service": "http"}]
  }
]
```

### GET `/network/topology`
Get network topology for visualization.

**Response:**
```json
{
  "nodes": [
    {"id": "192.168.1.1", "label": "router", "type": "gateway"}
  ],
  "edges": [
    {"source": "192.168.1.100", "target": "192.168.1.1"}
  ]
}
```

### GET `/network/local-info`
Get local machine network info.

**Response:**
```json
{
  "hostname": "my-laptop",
  "local_ip": "192.168.1.100",
  "gateway": "192.168.1.1",
  "dns_servers": ["8.8.8.8", "8.8.4.4"]
}
```

---

## WebSocket

### WS `/ws`
Real-time updates connection.

**Query Parameters:**
- `token`: JWT authentication token

**Channels:**
- `packets`: Real-time packet data
- `alerts`: New alert notifications
- `stats`: Periodic statistics updates

**Message Format:**
```json
{
  "channel": "alerts",
  "data": {
    "id": 1,
    "severity": "warning",
    "title": "Port Scan Detected"
  }
}
```

---

## Error Responses

All endpoints return standard error responses:

```json
{
  "detail": "Error message describing what went wrong"
}
```

**HTTP Status Codes:**
- `400`: Bad Request - Invalid parameters
- `401`: Unauthorized - Missing or invalid token
- `403`: Forbidden - Insufficient permissions
- `404`: Not Found - Resource doesn't exist
- `422`: Validation Error - Invalid request body
- `500`: Internal Server Error

# NetMonitor - Production Setup & Verification Guide

## Quick Start

### Prerequisites

#### Windows
1. **Install Npcap** (REQUIRED for packet capture):
   - Download from: https://npcap.com/#download
   - During installation, CHECK "WinPcap API-compatible Mode"
   - Restart your computer after installation

2. **Install Python 3.10+**:
   ```powershell
   winget install Python.Python.3.11
   ```

3. **Install Node.js 18+**:
   ```powershell
   winget install OpenJS.NodeJS.LTS
   ```

4. **Install nmap** (for network scanning):
   ```powershell
   winget install Insecure.Nmap
   ```

#### Linux
```bash
# Debian/Ubuntu
sudo apt install python3 python3-pip nodejs npm nmap tcpdump libpcap-dev

# Fedora/RHEL
sudo dnf install python3 python3-pip nodejs npm nmap tcpdump libpcap-devel
```

#### macOS
```bash
brew install python node nmap
# libpcap is included with macOS
```

---

## Installation

### 1. Backend Setup
```powershell
cd backend
python -m venv venv

# Windows
.\venv\Scripts\Activate.ps1

# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Frontend Setup
```powershell
cd frontend
npm install
```

---

## Running the Application

### Start Backend (REQUIRES ADMIN/ROOT for packet capture)

**Windows (Run as Administrator):**
```powershell
cd backend
.\venv\Scripts\Activate.ps1
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Linux/macOS (with sudo):**
```bash
cd backend
source venv/bin/activate
sudo $(which uvicorn) app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Start Frontend
```powershell
cd frontend
npm run dev
```

---

## Verification Checklist

### ✅ Step 1: Backend Health
Open: http://localhost:8000/api/health

Expected response:
```json
{
  "status": "healthy",
  "database": "connected",
  "capture": "available"
}
```

### ✅ Step 2: Interface Enumeration
Open: http://localhost:8000/api/docs

Navigate to: `GET /api/packets/interfaces`

Expected: List of interfaces with friendly names, IPs, and MAC addresses (not just NPF GUIDs)

### ✅ Step 3: Login
Open: http://localhost:5173

Default credentials:
- Username: `admin`
- Password: `admin`

### ✅ Step 4: Start Packet Capture
1. Go to "Packet Explorer" page
2. Select your active network interface (should show friendly name + IP)
3. Click "Start Capture"
4. The status should show "Capturing on [interface]"
5. WebSocket indicator should show "Live streaming" (green)

### ✅ Step 5: Generate Traffic
Open a new browser tab and:
- Browse to any website (YouTube, Google)
- Run: `ping google.com` in terminal

### ✅ Step 6: Verify Packets Flow
In Packet Explorer:
- Packets should appear in real-time
- Protocol colors should show (TCP=blue, UDP=green, DNS=purple)
- Stats should update (Total, TCP, UDP counts)

### ✅ Step 7: Verify Network Map
Go to "Network Map" page:
- Your gateway should appear as central node
- Connected hosts should appear as traffic flows
- WebSocket indicator should show "Live"

### ✅ Step 8: Verify Alerts
Go to "Alerts" page:
- WebSocket indicator should show "Live"
- If you run a port scan or flood, alerts should appear in real-time

### ✅ Step 9: Network Scanner
Go to "Network Scanner" page:
1. Enter your local subnet (e.g., 192.168.1.0/24)
2. Select "Ping Sweep" scan type
3. Click "Start Scan"
4. Hosts should be discovered

---

## Troubleshooting

### Packet Capture Not Working

**Windows:**
- Ensure Npcap is installed with WinPcap compatibility mode
- Run PowerShell as Administrator
- Check Npcap service: `Get-Service npcap`

**Linux:**
- Run with sudo or configure capabilities:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip $(which python)
  ```

### Interfaces Show Only NPF GUIDs (Windows)
- This means psutil couldn't resolve friendly names
- Verify psutil is installed: `pip show psutil`
- The capture should still work with NPF names

### WebSocket Not Connecting
- Check browser console for errors
- Ensure backend is running on port 8000
- Check CORS settings in backend

### No Packets Appearing
1. Verify capture is started (green indicator)
2. Check you selected the correct interface
3. Ensure you have network traffic (browse a website)
4. Check backend logs for capture errors

### Scanner Not Finding Hosts
- Ensure nmap is installed and in PATH
- Verify target is a valid private IP range
- Run scanner from admin/root terminal

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend                             │
│  React + TypeScript + Vite (localhost:5173)                │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ PacketCapture │ NetworkMap │ Alerts │ Scanner │ ...  │  │
│  └──────────────────────────────────────────────────────┘  │
│              │ WebSocket                    │ REST API      │
└──────────────┼──────────────────────────────┼───────────────┘
               │                              │
               ▼                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        Backend                              │
│  FastAPI + Scapy + python-nmap (localhost:8000)            │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────────────┐  │
│  │ Packet      │  │ Detection   │  │ WebSocket         │  │
│  │ Capture     │──│ Engine      │──│ Manager           │  │
│  │ (Scapy)     │  │             │  │ (Broadcasts)      │  │
│  └─────────────┘  └─────────────┘  └───────────────────┘  │
│         │                │                  │              │
│         ▼                ▼                  ▼              │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────────────┐  │
│  │ Topology    │  │ Alert       │  │ Network           │  │
│  │ Service     │  │ Manager     │  │ Scanner (nmap)    │  │
│  └─────────────┘  └─────────────┘  └───────────────────┘  │
└─────────────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│                    Network Interface                        │
│  Npcap (Windows) / libpcap (Linux/macOS)                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Fixes Applied

1. **Interface Enumeration**: Now merges Scapy + psutil data for friendly names, IPs, MACs
2. **Packet → WebSocket Wiring**: Packets now stream to frontend in real-time
3. **Detection → Alert Wiring**: Detection events broadcast to WebSocket
4. **Frontend WebSocket Integration**: All pages now support real-time updates
5. **Type Safety**: All TypeScript errors resolved

---

## Legal Notice

This tool is for **defensive and educational purposes only**. 
Only use on networks you own or have explicit written authorization to monitor.
Unauthorized network monitoring may violate local, state, and federal laws.

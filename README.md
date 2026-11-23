# NetMonitor - Network Security Command Center

A production-grade, browser-based defensive network monitoring platform combining:
- **Wireshark-inspired** packet inspection & protocol decoding
- **Nmap-inspired** host discovery & port scanning
- **EtherApe-inspired** real-time animated network topology
- **Kismet-inspired** wireless visibility (read-only)

## 🛡️ Overview

NetMonitor is a **defensive cybersecurity platform** for:
- 📊 Real-time network traffic monitoring and visualization
- 🔍 Safe network scanning with rate limiting and scope enforcement
- 🚨 Explainable threat detection with plain-English alerts
- 🗺️ Interactive animated network maps
- 📚 Security education with beginner-friendly UI

**Target Users:** Network admins, SOC analysts, cybersecurity students, home lab enthusiasts.

**This is NOT a hacking tool.** It's designed for legitimate defensive monitoring only.

## ⚖️ Legal & Ethical Disclaimer

> ⚠️ **IMPORTANT:** Only use this tool on networks you own or have explicit written permission to monitor/scan.

- Unauthorized network monitoring may violate laws (CFAA, GDPR, etc.)
- Always obtain written permission before scanning third-party networks
- This tool is for defensive and educational purposes only
- Users are responsible for compliance with local laws and regulations

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [DESIGN_SPECIFICATION.md](docs/DESIGN_SPECIFICATION.md) | Complete system design, architecture, and implementation guide |
| [ARCHITECTURE_DIAGRAMS.md](docs/ARCHITECTURE_DIAGRAMS.md) | ASCII architecture diagrams and data flows |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component overview and directory structure |
| [API.md](docs/API.md) | REST and WebSocket API reference |
| [DETECTION_RULES.md](docs/DETECTION_RULES.md) | Threat detection rules and tuning guide |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Frontend (React)                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │Dashboard │ │ Network  │ │  Alerts  │ │  Scan    │           │
│  │  View    │ │   Map    │ │   Feed   │ │ History  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
└─────────────────────────────┬───────────────────────────────────┘
                              │ REST API / WebSocket
┌─────────────────────────────┴───────────────────────────────────┐
│                      Backend (FastAPI)                           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                      API Layer                              │ │
│  │  • REST Endpoints  • WebSocket Handler  • Auth Middleware  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ Packet   │ │  Scan    │ │Detection │ │ Alerting │           │
│  │ Capture  │ │  Engine  │ │  Engine  │ │  System  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│       │             │            │             │                 │
│  ┌────┴─────────────┴────────────┴─────────────┴────┐          │
│  │              Database (SQLite/PostgreSQL)         │          │
│  └───────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Features

### Packet Monitoring
- Real-time packet capture using Scapy/tshark
- Protocol analysis (TCP, UDP, ICMP, DNS, HTTP, HTTPS)
- Traffic visualization with live graphs
- Privacy-first: No raw payload display by default

### Network Scanning
- Host discovery (ping sweep)
- TCP SYN scan
- Open port detection
- Service fingerprinting
- Rate-limited to prevent abuse

### Threat Detection
- Port scanning detection
- ARP spoofing indicators
- DNS tunneling patterns
- Packet flood detection
- Failed connection monitoring

### Alerts & Insights
- Real-time alerts with severity levels (Info, Warning, Critical)
- Plain English explanations
- Actionable recommendations

## 📋 Prerequisites

### System Requirements
- Python 3.9+
- Node.js 18+
- Nmap installed on system
- Admin/root privileges for packet capture

### Windows
```powershell
# Install Nmap from https://nmap.org/download.html
# Install Npcap from https://npcap.com/

# Verify installation
nmap --version
```

### Linux
```bash
sudo apt update
sudo apt install nmap libpcap-dev python3-dev
```

### macOS
```bash
brew install nmap
```

## 🛠️ Installation

### Backend Setup
```bash
cd backend
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

### Frontend Setup
```bash
cd frontend
npm install
```

### Database Setup
```bash
cd backend
python -m app.database.init_db
```

## ▶️ Running the Application

### Development Mode

**Terminal 1 - Backend:**
```bash
cd backend
.\venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/macOS
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

### Production Mode
```bash
# Backend
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4

# Frontend
cd frontend
npm run build
npm run preview
```

## 🔐 Default Credentials

- Username: `admin`
- Password: `changeme123`

**⚠️ Change these immediately after first login!**

## 📁 Project Structure

```
netmonitor/
├── backend/
│   ├── app/
│   │   ├── api/              # REST API routes
│   │   ├── core/             # Core modules
│   │   │   ├── capture/      # Packet capture
│   │   │   ├── scanner/      # Network scanning
│   │   │   ├── detection/    # Threat detection
│   │   │   └── alerting/     # Alert system
│   │   ├── database/         # Database models
│   │   ├── websocket/        # Real-time updates
│   │   └── main.py           # FastAPI app
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/       # React components
│   │   ├── pages/            # Page views
│   │   ├── hooks/            # Custom hooks
│   │   ├── services/         # API services
│   │   └── App.tsx
│   └── package.json
└── docs/
    ├── API.md
    ├── ARCHITECTURE.md
    └── DETECTION_RULES.md
```

## 📚 Documentation

- [API Reference](docs/API.md)
- [Architecture Guide](docs/ARCHITECTURE.md)
- [Detection Rules](docs/DETECTION_RULES.md)
- [Security Considerations](docs/SECURITY.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## ⚠️ Responsible Use

This tool is provided for **defensive and educational purposes only**. The developers:
- Do not condone unauthorized network monitoring
- Are not responsible for misuse of this software
- Recommend consulting legal counsel before deployment in production environments

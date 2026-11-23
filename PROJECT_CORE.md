# NetMonitor - Project Core

## 1. Project Summary
NetMonitor is a defensive network monitoring platform that combines packet capture, safe network scanning, threat detection, topology visualization, and alert triage in one browser-based console. It is built for authorized environments such as home labs, internal security teams, and training use, with explicit guardrails around capture, scanning, authentication, and legal consent.

The system uses a FastAPI backend for orchestration and a React/Vite frontend for the operator experience. Real-time state is pushed through WebSockets so the dashboard, packet explorer, alert center, and network map stay synchronized with the backend runtime.

## 2. Core Architecture

| Component | Main Files | What It Does |
|---|---|---|
| Application bootstrap | [backend/app/main.py](backend/app/main.py) | Creates the FastAPI app, initializes services during lifespan startup, wires callbacks, and exposes all routes. |
| Authentication | [backend/app/api/auth.py](backend/app/api/auth.py), [frontend/src/stores/authStore.ts](frontend/src/stores/authStore.ts) | Issues JWT tokens, validates the current user, and persists auth state in the browser. |
| Packet capture | [backend/app/core/capture/packet_capture.py](backend/app/core/capture/packet_capture.py), [backend/app/api/packets.py](backend/app/api/packets.py) | Captures live traffic with Scapy, parses metadata, buffers packets, and exposes capture control endpoints. |
| Safe scanning | [backend/app/core/scanner/network_scanner.py](backend/app/core/scanner/network_scanner.py), [backend/app/api/scanner.py](backend/app/api/scanner.py) | Runs constrained Nmap-backed scans with RFC1918 enforcement, target validation, and rate limits. |
| Detection engine | [backend/app/core/detection/engine.py](backend/app/core/detection/engine.py), [backend/app/core/detection/rules.py](backend/app/core/detection/rules.py), [backend/app/core/detection/correlation.py](backend/app/core/detection/correlation.py) | Detects port scans, floods, ARP spoofing, DNS tunneling, suspicious ports, and correlated attack chains. |
| Alerting | [backend/app/core/alerting/alert_manager.py](backend/app/core/alerting/alert_manager.py), [backend/app/api/alerts.py](backend/app/api/alerts.py) | Stores alerts in memory, rate-limits noisy rules, supports acknowledgement, deletion, and summaries. |
| Topology and device intelligence | [backend/app/core/topology/topology_service.py](backend/app/core/topology/topology_service.py), [backend/app/core/topology/device_classifier.py](backend/app/core/topology/device_classifier.py), [backend/app/core/topology/traffic_aggregator.py](backend/app/core/topology/traffic_aggregator.py) | Builds live nodes/edges, classifies devices, and aggregates flows for the network map. |
| Interface and gateway monitoring | [backend/app/core/interfaces/interface_monitor.py](backend/app/core/interfaces/interface_monitor.py), [backend/app/core/interfaces/arp_monitor.py](backend/app/core/interfaces/arp_monitor.py), [backend/app/core/interfaces/gateway.py](backend/app/core/interfaces/gateway.py) | Watches interface state, ARP changes, and default gateway discovery. |
| WebSocket transport | [backend/app/websocket/manager.py](backend/app/websocket/manager.py) | Manages channels for packets, alerts, stats, topology, and scans with broadcast fanout. |
| Telemetry and retention | [backend/app/core/telemetry/metrics.py](backend/app/core/telemetry/metrics.py), [backend/app/core/storage/db_retention.py](backend/app/core/storage/db_retention.py), [backend/app/core/telemetry/bounded_queue.py](backend/app/core/telemetry/bounded_queue.py) | Tracks metrics, enforces bounded queues, and cleans old database rows. |
| Persistence | [backend/app/database/models.py](backend/app/database/models.py), [backend/app/database/session.py](backend/app/database/session.py), [backend/app/database/init_db.py](backend/app/database/init_db.py) | Defines ORM models, async sessions, and database bootstrapping with default admin and rules. |
| Frontend shell | [frontend/src/App.tsx](frontend/src/App.tsx), [frontend/src/components/Layout.tsx](frontend/src/components/Layout.tsx), [frontend/src/main.tsx](frontend/src/main.tsx) | Sets up routing, protected navigation, global error handling, and the app shell. |
| Frontend pages | [frontend/src/pages/Dashboard.tsx](frontend/src/pages/Dashboard.tsx), [frontend/src/pages/PacketCapture.tsx](frontend/src/pages/PacketCapture.tsx), [frontend/src/pages/NetworkScanner.tsx](frontend/src/pages/NetworkScanner.tsx), [frontend/src/pages/Alerts.tsx](frontend/src/pages/Alerts.tsx), [frontend/src/pages/NetworkMap.tsx](frontend/src/pages/NetworkMap.tsx), [frontend/src/pages/Settings.tsx](frontend/src/pages/Settings.tsx), [frontend/src/pages/Login.tsx](frontend/src/pages/Login.tsx) | Implements the operator workflows for monitoring, scanning, alert triage, topology, settings, and login. |
| Shared UI and state | [frontend/src/design-system.ts](frontend/src/design-system.ts), [frontend/src/components/ui/index.tsx](frontend/src/components/ui/index.tsx), [frontend/src/stores/uiStore.ts](frontend/src/stores/uiStore.ts) | Provides the semantic design system, reusable primitives, and persistent UI preferences. |
| API client and realtime hook | [frontend/src/services/api.ts](frontend/src/services/api.ts), [frontend/src/hooks/useWebSocket.ts](frontend/src/hooks/useWebSocket.ts) | Centralizes REST requests and live socket subscriptions. |
| Compliance and safety UX | [frontend/src/components/LegalConsentBanner.tsx](frontend/src/components/LegalConsentBanner.tsx) | Forces legal acknowledgment before use. |

## 3. Tech Stack

### Backend

| Category | Libraries / Tools |
|---|---|
| Language | Python |
| Web framework | FastAPI |
| ASGI server | Uvicorn |
| Validation / settings | Pydantic, pydantic-settings |
| ORM / migrations | SQLAlchemy, Alembic, aiosqlite |
| Authentication | python-jose, passlib, bcrypt |
| Packet capture | Scapy |
| Network scanning | python-nmap, Nmap system install |
| Realtime | websockets, asyncio |
| Observability | structlog, psutil |
| Testing | pytest, pytest-asyncio, httpx |
| File / async helpers | aiofiles |
| Rate limiting | slowapi |
| Environment config | python-dotenv |

### Frontend

| Category | Libraries / Tools |
|---|---|
| Language | TypeScript |
| UI library | React 18 |
| Routing | react-router-dom |
| Build tool | Vite |
| Styling | Tailwind CSS, PostCSS, Autoprefixer |
| State management | Zustand |
| Charts | chart.js, react-chartjs-2 |
| Icons | lucide-react |
| API client | axios |
| Utilities | clsx, tailwind-merge, date-fns |
| Type definitions | @types/react, @types/react-dom |
| Linting / type tooling | ESLint, @typescript-eslint/parser, @typescript-eslint/eslint-plugin, eslint-plugin-react-hooks, eslint-plugin-react-refresh, TypeScript |

### Infrastructure / Project Tools

| Category | Tools / Artifacts |
|---|---|
| OS support | Windows-focused launchers, PowerShell scripts, batch files |
| Database | SQLite default runtime database (`backend/netmonitor.db`) |
| Workspace config | `.vscode/settings.json` |
| Startup / shutdown | `start.bat`, `stop.bat`, `scripts/start_project.ps1`, `scripts/run.bat` |
| Logging / diagnostics | `scripts/error_logger.py`, `error.txt` |
| Documentation | `README.md`, `SETUP_GUIDE.md`, `docs/*.md` |

## 4. Key Features

- JWT-based authentication with persisted browser session state.
- Protected route shell that blocks anonymous access to operational pages.
- Live packet capture with protocol parsing, metadata extraction, and circular buffering.
- Interface enumeration with platform-aware display names and capture selection.
- Safe network scanning with CIDR and hostname validation, RFC1918-only defaults, and rate limits.
- Scan history, progress tracking, cancellation, and audit logging.
- Threat detection for port scans, packet floods, ARP spoofing, DNS tunneling, suspicious ports, and ICMP sweeps.
- Advanced detection for lateral movement, beaconing, broadcast abuse, and new-device risk scoring.
- Correlation engine that links multiple detections into attack chains.
- Alert creation, acknowledgement, deletion, clearing, and summary reporting.
- Real-time WebSocket delivery for packets, alerts, stats, topology, and scan updates.
- Passive network discovery from observed traffic.
- Live topology rendering with node classification, edge aggregation, and activity levels.
- Dashboard summaries for capture, alerts, traffic, detection, and health.
- Export support for packets, alerts, topology, and SIEM-friendly formats.
- Health, readiness, and metrics endpoints for operational monitoring.
- Beginner/expert UI mode with keyboard shortcuts and explanatory UI helpers.
- Legal consent gate before the application can be used.
- Password change and detection rule management in settings.
- Error boundary protection in the frontend so runtime faults do not blank the entire app.

## 5. How It Works

1. The user opens the app and sees the legal consent banner if consent has not already been stored.
2. After accepting the terms, the user signs in through the login page.
3. The backend verifies credentials in [backend/app/api/auth.py](backend/app/api/auth.py), issues a JWT, and the frontend stores it in Zustand/localStorage.
4. The protected application shell mounts and loads the dashboard by default.
5. [backend/app/main.py](backend/app/main.py) initializes database tables, creates the capture engine, detection engine, alert manager, topology service, WebSocket manager, interface monitor, ARP monitor, and gateway detector.
6. Packet capture, interface monitoring, ARP monitoring, and retention jobs start in the background.
7. When packets arrive, [backend/app/core/capture/packet_capture.py](backend/app/core/capture/packet_capture.py) parses metadata, updates telemetry, pushes packets to the capture buffer, and forwards them to detection and topology services.
8. The detection engine evaluates each packet against rules in [backend/app/core/detection/engine.py](backend/app/core/detection/engine.py) and the advanced modules in [backend/app/core/detection/rules.py](backend/app/core/detection/rules.py).
9. If a detection fires, the alert manager turns the detection into an alert and the WebSocket manager streams it to the frontend.
10. The topology service updates nodes and edges, while the frontend network map draws the current graph state.
11. The dashboard polls summary endpoints while also benefiting from live realtime data for packets, alerts, and topology changes.
12. The packet explorer can either stream live packets over WebSocket or fall back to polling if realtime is unavailable.
13. The scanner page validates a target, enforces safety rules, and starts a background Nmap job.
14. Alert operators can acknowledge, delete, clear, or filter alerts; settings can change the password and toggle detection rules.
15. On shutdown, background services are stopped cleanly and retention workers are halted.

### Runtime Flow Diagram

```text
User Action
   ↓
Frontend Route / Widget / Form
   ↓
Axios REST Call or WebSocket Channel
   ↓
FastAPI Route / WebSocket Handler
   ↓
Core Service (capture, scan, detection, alerting, topology)
   ↓
Telemetry / Database / In-memory state
   ↓
Response or broadcast back to UI
```

## 6. Current Status

| Area | Status |
|---|---|
| Backend service wiring | Working |
| Authentication and protected routing | Working |
| Packet capture pipeline | Working |
| Safe network scanning pipeline | Working |
| Detection and alerting | Working |
| Topology and network visualization | Working |
| WebSocket real-time update path | Working |
| Dashboard and page-level UI | Working |
| Export endpoints | Working |
| Health/readiness/metrics endpoints | Working |
| Frontend validation | Working; workspace checker reported no syntax/type errors |
| Documentation consistency | Partially incomplete |
| Generated artifacts in repo | Present; `backend/venv`, `backend/netmonitor.db`, and `frontend/package-lock.json` are checked in artifacts rather than source |
| API doc alignment | Inconsistent in a few places; for example, some docs mention `/auth/login` while the implementation exposes `/api/auth/token` |
| Production hardening | In progress; the project has strong guardrails, but some runtime state is still in-memory and would need external persistence for horizontal scale |
| Privileged capture boundary | Present as an abstraction, but the production IPC separation is not implemented in this repo |

### What is incomplete or fragile

- Several subsystems still keep state in memory, which is fine for local use but not ideal for distributed deployment.
- The default database is SQLite, which is practical for development but not a long-term high-concurrency backend.
- Some docs are slightly stale relative to the implementation, especially around endpoint names and response shapes.
- The repository contains generated/runtime files, which complicate source hygiene and can mislead file counts.

### What is broken

- No code errors were reported by the workspace checker in the current state.
- No major syntax, type, or import failures were detected during this analysis pass.
- The main “broken” issues are documentation drift and repository hygiene, not runtime compilation failures.

## 7. Unique / Interesting Parts

- The architecture is intentionally event-driven. Packet capture, interface changes, ARP changes, detection events, and topology changes all fan out through callbacks rather than being recomputed from scratch.
- The detection pipeline is explainability-first. Alerts are not just labels; they include evidence, thresholds, confidence, false-positive context, and recommended actions.
- The project has a dual-mode UX. Beginner mode hides complexity; expert mode exposes shortcuts, denser controls, and more technical data.
- The topology layer is more than a graph renderer. It combines passive device classification, traffic aggregation, activity scoring, and change events to produce a meaningful network map.
- The scanner is safety-constrained by design. It validates target scope, enforces local-only behavior by default, caps host count, and limits rate and concurrency.
- The frontend uses a semantic design system rather than ad hoc classes. Severity, protocol, and risk states are encoded consistently in [frontend/src/design-system.ts](frontend/src/design-system.ts).
- The WebSocket manager supports channel subscriptions and rate-limited broadcasts, which keeps realtime traffic organized and prevents a single unstructured event stream.
- The bounded queue and retention modules show careful attention to memory safety and long-running operation.
- The login and legal-consent workflow make the tool’s intended defensive use explicit before access is granted.

## 8. Entry Point

### Backend

```bash
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python -m app.database.init_db
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Full local run on Windows

```bash
.\start.bat
```

### Stop services

```bash
.\stop.bat
```

### Other useful commands

```bash
cd frontend
npm run build
npm run preview

cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Notes

- The backend expects the Python environment and dependencies to be installed under the project root.
- The frontend assumes the backend is reachable through the configured local API base URL.
- On Windows, the provided batch and PowerShell scripts are the intended operator-friendly entry points.

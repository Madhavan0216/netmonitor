"""
NetMonitor - Network Safety Monitoring Tool
Main FastAPI Application Entry Point

Enhanced with:
- Telemetry & Metrics
- Interface Monitoring
- ARP Monitoring
- Gateway Detection
- Data Retention
- Export Capabilities
"""

import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import structlog

from app.core.config import settings
from app.api import auth, packets, scanner, alerts, dashboard, network, topology
from app.api import health as health_api
from app.api import export as export_api
from app.websocket.manager import router as ws_router, ConnectionManager
from app.database.session import engine, Base
from app.core.capture.packet_capture import PacketCaptureService
from app.core.detection.engine import DetectionEngine
from app.core.alerting.alert_manager import AlertManager
from app.core.topology.topology_service import TopologyService
from app.core.telemetry.metrics import metrics, MetricNames
from app.core.interfaces.interface_monitor import InterfaceMonitor
from app.core.interfaces.arp_monitor import ARPMonitor
from app.core.interfaces.gateway import GatewayDetector
from app.core.storage import retention_manager
from app.core.storage.db_retention import db_retention

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Global service instances
packet_capture_service: PacketCaptureService | None = None
detection_engine: DetectionEngine | None = None
alert_manager: AlertManager | None = None
topology_service: TopologyService | None = None
ws_manager: ConnectionManager | None = None
interface_monitor: InterfaceMonitor | None = None
arp_monitor: ARPMonitor | None = None
gateway_detector: GatewayDetector | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle manager."""
    global packet_capture_service, detection_engine, alert_manager, topology_service, ws_manager
    global interface_monitor, arp_monitor, gateway_detector
    
    logger.info("Starting NetMonitor services...")
    
    # Create database tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Initialize core services
    alert_manager = AlertManager()
    detection_engine = DetectionEngine(alert_manager)
    topology_service = TopologyService(stale_threshold_seconds=300)
    packet_capture_service = PacketCaptureService(detection_engine, topology_service)
    ws_manager = ConnectionManager()
    
    # Initialize interface monitoring
    def on_interface_state_change(change):
        """Handle interface state changes."""
        logger.warning(
            "Interface state changed",
            interface=change.interface,
            event=change.to_dict()["event"]
        )
        asyncio.create_task(ws_manager.broadcast_stats({
            "event": "interface_state_change",
            **change.to_dict()
        }))
    
    interface_monitor = InterfaceMonitor(
        poll_interval=2.0,
        on_state_change=on_interface_state_change
    )
    
    # Initialize ARP monitoring
    def on_arp_event(event):
        """Handle ARP events."""
        if event.severity in ("warning", "critical"):
            logger.warning("ARP event", **event.to_dict())
            asyncio.create_task(ws_manager.broadcast_alert({
                "event": "arp_event",
                **event.to_dict()
            }))
    
    arp_monitor = ARPMonitor(
        poll_interval=10.0,
        stale_threshold=300,
        on_event=on_arp_event
    )
    
    # Initialize gateway detector
    gateway_detector = GatewayDetector()
    
    # Wire up topology changes to WebSocket broadcasts
    def on_topology_change(change):
        """Broadcast topology changes to connected clients."""
        asyncio.create_task(ws_manager.broadcast_topology({
            "event": "change",
            **change.to_dict()
        }))
    
    topology_service.on_change(on_topology_change)
    
    # CRITICAL: Wire up packet capture to WebSocket broadcasts
    async def on_packet_captured(packet_info):
        """Broadcast captured packets to connected clients in real-time."""
        await ws_manager.broadcast_packet(packet_info)
    
    packet_capture_service.add_callback(on_packet_captured)
    logger.info("Packet capture callback registered for WebSocket streaming")
    
    # Wire up detection engine alerts to WebSocket broadcasts
    def on_detection_event(detection_event):
        """Broadcast detection events/alerts to connected clients."""
        alert_data = {
            "id": detection_event.id,
            "type": detection_event.type,
            "severity": detection_event.severity,
            "title": detection_event.title,
            "description": detection_event.description,
            "source_ip": detection_event.source_ip,
            "destination_ip": detection_event.destination_ip,
            "timestamp": detection_event.timestamp.isoformat(),
            "evidence": detection_event.evidence
        }
        asyncio.create_task(ws_manager.broadcast_alert(alert_data))
        logger.info("Detection event broadcast", type=detection_event.type, severity=detection_event.severity)
    
    detection_engine.add_callback(on_detection_event)
    
    # Register metrics collector for system stats
    def collect_system_metrics():
        try:
            import psutil
            mem = psutil.virtual_memory()
            metrics.gauge(MetricNames.MEMORY_MB, mem.used / 1024 / 1024)
            metrics.gauge(MetricNames.CPU_PERCENT, psutil.cpu_percent())
        except ImportError:
            pass
        return {}
    
    metrics.register_collector(collect_system_metrics)
    
    # Start background services
    await interface_monitor.start()
    await arp_monitor.start()
    await retention_manager.start()
    await db_retention.start()
    
    # Detect gateways
    gateways = await gateway_detector.detect()
    if gateways:
        default_gw = gateway_detector.get_default_gateway()
        if default_gw:
            topology_service.set_gateway(default_gw.ip_address)
            logger.info("Default gateway detected", ip=default_gw.ip_address)
    
    # Store services in app state for access in routes
    app.state.packet_capture = packet_capture_service
    app.state.detection_engine = detection_engine
    app.state.alert_manager = alert_manager
    app.state.topology_service = topology_service
    app.state.ws_manager = ws_manager
    app.state.interface_monitor = interface_monitor
    app.state.arp_monitor = arp_monitor
    app.state.gateway_detector = gateway_detector
    app.state.metrics = metrics
    
    logger.info("NetMonitor services started successfully")
    
    yield
    
    # Cleanup on shutdown
    logger.info("Shutting down NetMonitor services...")
    
    await interface_monitor.stop()
    await arp_monitor.stop()
    await retention_manager.stop()
    await db_retention.stop()
    
    if packet_capture_service:
        await packet_capture_service.stop()
    
    logger.info("NetMonitor shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="NetMonitor",
    description="Network Safety Monitoring Tool - Defensive cybersecurity application",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(packets.router, prefix="/api/packets", tags=["Packet Capture"])
app.include_router(scanner.router, prefix="/api/scanner", tags=["Network Scanner"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(network.router, prefix="/api/network", tags=["Network"])
app.include_router(topology.router, prefix="/api/topology", tags=["Topology"])
app.include_router(health_api.router, prefix="/api", tags=["Health"])
app.include_router(export_api.router, prefix="/api/export", tags=["Export"])
app.include_router(ws_router, prefix="/ws", tags=["WebSocket"])


@app.get("/api/disclaimer")
async def get_disclaimer():
    """Return legal and ethical disclaimer."""
    return {
        "title": "Legal & Ethical Disclaimer",
        "message": (
            "This tool is for defensive and educational purposes only. "
            "Only use on networks you own or have explicit written permission to monitor. "
            "Unauthorized network monitoring may violate local, state, and federal laws. "
            "Users are solely responsible for ensuring compliance with all applicable laws and regulations."
        ),
        "accepted_use": [
            "Monitoring your own home or business network",
            "Security auditing with written authorization",
            "Educational purposes in controlled lab environments",
            "Incident response on authorized systems"
        ],
        "prohibited_use": [
            "Monitoring networks without authorization",
            "Attacking or exploiting discovered vulnerabilities",
            "Intercepting private communications",
            "Any illegal activities"
        ]
    }

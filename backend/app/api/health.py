"""
Health & Readiness API

Provides Kubernetes-style health endpoints:
- /health - Liveness probe (is the service alive?)
- /ready - Readiness probe (is the service ready to serve traffic?)
- /metrics - Internal metrics for monitoring
"""

import platform
import os
from datetime import datetime, timezone
from typing import Dict, Any, List
from fastapi import APIRouter, Request, Response
from pydantic import BaseModel
import structlog

from app.core.telemetry.metrics import metrics

logger = structlog.get_logger(__name__)

router = APIRouter()


class HealthStatus(BaseModel):
    """Health check response."""
    status: str  # healthy, degraded, unhealthy
    timestamp: str
    version: str
    uptime_seconds: float
    checks: Dict[str, Any]


class ReadinessStatus(BaseModel):
    """Readiness check response."""
    ready: bool
    timestamp: str
    checks: Dict[str, Any]


class MetricsResponse(BaseModel):
    """Metrics response."""
    timestamp: str
    uptime_seconds: float
    counters: Dict[str, int]
    gauges: Dict[str, float]
    rates: Dict[str, float]
    histograms: Dict[str, Any]


async def check_database(request: Request) -> Dict[str, Any]:
    """Check database connectivity."""
    try:
        from app.database.session import engine
        from sqlalchemy import text
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"status": "ok", "latency_ms": 0}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def check_capture_service(request: Request) -> Dict[str, Any]:
    """Check packet capture service."""
    try:
        capture = request.app.state.packet_capture
        if capture is None:
            return {"status": "not_initialized"}
        
        return {
            "status": "ok",
            "running": capture.is_running,
            "interface": capture.interface,
            "packets_captured": capture.stats.total_packets
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def check_detection_engine(request: Request) -> Dict[str, Any]:
    """Check detection engine."""
    try:
        engine = request.app.state.detection_engine
        if engine is None:
            return {"status": "not_initialized"}
        
        return {
            "status": "ok",
            "rules_loaded": len(engine.rules) if hasattr(engine, 'rules') else 0
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def check_websocket(request: Request) -> Dict[str, Any]:
    """Check WebSocket manager."""
    try:
        ws_manager = request.app.state.ws_manager
        if ws_manager is None:
            return {"status": "not_initialized"}
        
        return {
            "status": "ok",
            "connections": ws_manager.connection_count,
            "max_connections": ws_manager._max_connections
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def get_system_info() -> Dict[str, Any]:
    """Get system information."""
    try:
        import psutil  # type: ignore[import-not-found]
        mem = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=0.1)
        
        return {
            "platform": platform.system(),
            "python_version": platform.python_version(),
            "cpu_percent": cpu,
            "memory_percent": mem.percent,
            "memory_available_mb": round(mem.available / 1024 / 1024, 1),
            "pid": os.getpid()
        }
    except ImportError:
        return {
            "platform": platform.system(),
            "python_version": platform.python_version(),
            "pid": os.getpid()
        }


@router.get("/health", response_model=HealthStatus)
async def health_check(request: Request):
    """
    Liveness probe - is the service alive?
    
    Returns 200 if the service is running, even if some components are degraded.
    Returns 503 if the service is unhealthy and should be restarted.
    """
    checks: Dict[str, Any] = {}
    
    # Database check
    db_check = await check_database(request)
    checks["database"] = db_check
    
    # Capture service check
    capture_check = await check_capture_service(request)
    checks["capture"] = capture_check
    
    # Detection engine check
    detection_check = await check_detection_engine(request)
    checks["detection"] = detection_check
    
    # WebSocket check
    ws_check = await check_websocket(request)
    checks["websocket"] = ws_check
    
    # System info
    checks["system"] = get_system_info()
    
    # Determine overall status
    errors: List[str] = [k for k, v in checks.items() 
                         if isinstance(v, dict) and v.get("status") == "error"]  # type: ignore[union-attr]
    
    if errors:
        status = "degraded" if len(errors) < 3 else "unhealthy"
    else:
        status = "healthy"
    
    uptime = metrics.get_all().get("uptime_seconds", 0)
    
    response = HealthStatus(
        status=status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        version="1.0.0",
        uptime_seconds=uptime,
        checks=checks
    )
    
    # Return appropriate status code
    if status == "unhealthy":
        return Response(
            content=response.model_dump_json(),
            status_code=503,
            media_type="application/json"
        )
    
    return response


@router.get("/ready", response_model=ReadinessStatus)
async def readiness_check(request: Request):
    """
    Readiness probe - is the service ready to serve traffic?
    
    Returns 200 if all critical components are ready.
    Returns 503 if the service should not receive traffic.
    """
    checks: Dict[str, Any] = {}
    
    # Database must be available
    db_check = await check_database(request)
    checks["database"] = db_check
    
    # Capture service must be initialized
    capture_check = await check_capture_service(request)
    checks["capture"] = capture_check
    
    # Detection engine must be initialized
    detection_check = await check_detection_engine(request)
    checks["detection"] = detection_check
    
    # Determine readiness
    critical_ok = all([
        checks.get("database", {}).get("status") == "ok",
        checks.get("capture", {}).get("status") in ("ok", "not_initialized"),
        checks.get("detection", {}).get("status") in ("ok", "not_initialized")
    ])
    
    response = ReadinessStatus(
        ready=critical_ok,
        timestamp=datetime.now(timezone.utc).isoformat(),
        checks=checks
    )
    
    if not critical_ok:
        return Response(
            content=response.model_dump_json(),
            status_code=503,
            media_type="application/json"
        )
    
    return response


@router.get("/metrics", response_model=MetricsResponse)
async def get_metrics(request: Request):
    """
    Get internal metrics.
    
    Returns all collected metrics including:
    - Counters (packets, alerts, etc.)
    - Gauges (connections, memory, etc.)
    - Rates (packets/sec, etc.)
    - Histograms (latencies, durations, etc.)
    """
    all_metrics = metrics.get_all()
    
    return MetricsResponse(
        timestamp=all_metrics.get("timestamp", datetime.now(timezone.utc).isoformat()),
        uptime_seconds=all_metrics.get("uptime_seconds", 0),
        counters=all_metrics.get("counters", {}),
        gauges=all_metrics.get("gauges", {}),
        rates=all_metrics.get("rates", {}),
        histograms=all_metrics.get("histograms", {})
    )


@router.get("/metrics/summary")
async def get_metrics_summary(request: Request):
    """Get condensed metrics summary."""
    return metrics.get_summary()


@router.get("/metrics/prometheus")
async def get_prometheus_metrics(request: Request):
    """
    Get metrics in Prometheus exposition format.
    
    Compatible with Prometheus scraping.
    """
    all_metrics = metrics.get_all()
    lines: List[str] = []
    
    # Counters
    for name, value in all_metrics.get("counters", {}).items():
        lines.append(f"netmonitor_{name}_total {value}")
    
    # Gauges
    for name, value in all_metrics.get("gauges", {}).items():
        lines.append(f"netmonitor_{name} {value}")
    
    # Rates
    for name, value in all_metrics.get("rates", {}).items():
        lines.append(f"netmonitor_{name}_per_second {value}")
    
    # Histograms
    for name, hist in all_metrics.get("histograms", {}).items():
        lines.append(f'netmonitor_{name}_count {hist.get("count", 0)}')
        lines.append(f'netmonitor_{name}_sum {hist.get("sum", 0)}')
        for bucket, count in hist.get("buckets", {}).items():
            if bucket != "inf":
                lines.append(f'netmonitor_{name}_bucket{{le="{bucket}"}} {count}')
    
    return Response(
        content="\n".join(lines),
        media_type="text/plain"
    )

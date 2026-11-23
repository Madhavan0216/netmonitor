"""
Export API Routes

Provides endpoints for data export:
- PCAP-lite export
- JSON export
- CSV export
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Request, Query, Response, Depends

from app.api.auth import get_current_active_user
from app.database.models import User
from app.core.export import (
    PCAPLiteExporter,
    JSONExporter,
    CSVExporter,
    SIEMExporter,
    SIEM_COMPATIBILITY_DOC
)

router = APIRouter()


@router.get("/packets/pcaplite")
async def export_packets_pcaplite(
    request: Request,
    limit: int = Query(1000, ge=1, le=10000, description="Max packets to export"),
    compress: bool = Query(True, description="Gzip compress output"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Export recent packets in PCAP-lite format (JSON Lines).
    
    PCAP-lite is a simplified packet format containing metadata only:
    - Timestamps
    - Source/destination IPs and ports
    - Protocol
    - Size
    - Flags/info
    
    Returns gzipped JSON Lines by default.
    """
    capture = request.app.state.packet_capture
    if not capture:
        return Response(
            content='{"error": "Packet capture not available"}',
            status_code=503,
            media_type="application/json"
        )
    
    packets = capture.get_recent_packets(limit=limit)
    
    exporter = PCAPLiteExporter()
    exporter.add_packets(packets)
    
    data = exporter.export_jsonl(compress=compress)
    
    filename = f"netmonitor_packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if compress:
        filename += ".jsonl.gz"
        media_type = "application/gzip"
    else:
        filename += ".jsonl"
        media_type = "application/x-ndjson"
    
    return Response(
        content=data,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )


@router.get("/packets/json")
async def export_packets_json(
    request: Request,
    limit: int = Query(1000, ge=1, le=10000),
    pretty: bool = Query(False),
    current_user: User = Depends(get_current_active_user)
):
    """Export recent packets as JSON."""
    capture = request.app.state.packet_capture
    if not capture:
        return {"error": "Packet capture not available"}
    
    packets = capture.get_recent_packets(limit=limit)
    
    exporter = JSONExporter(pretty=pretty)
    content = exporter.export_statistics({"packets": packets})
    
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="packets_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
        }
    )


@router.get("/packets/csv")
async def export_packets_csv(
    request: Request,
    limit: int = Query(1000, ge=1, le=10000),
    current_user: User = Depends(get_current_active_user)
):
    """Export recent packets as CSV."""
    capture = request.app.state.packet_capture
    if not capture:
        return {"error": "Packet capture not available"}
    
    packets = capture.get_recent_packets(limit=limit)
    
    exporter = CSVExporter()
    content = exporter.export_packets(packets)
    
    return Response(
        content=content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="packets_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        }
    )


@router.get("/alerts/json")
async def export_alerts_json(
    request: Request,
    limit: int = Query(1000, ge=1, le=10000),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    pretty: bool = Query(False),
    current_user: User = Depends(get_current_active_user)
):
    """Export alerts as JSON."""
    from app.database.session import AsyncSession, engine
    from app.database.models import Alert
    from sqlalchemy import select, desc
    
    async with AsyncSession(engine) as session:
        query = select(Alert).order_by(desc(Alert.created_at)).limit(limit)
        
        if severity:
            from app.database.models import AlertSeverity
            query = query.where(Alert.severity == AlertSeverity(severity))
        
        result = await session.execute(query)
        alerts = result.scalars().all()
        
        alert_dicts: List[Dict[str, Any]] = []
        for alert in alerts:
            alert_dicts.append({
                "id": alert.id,
                "severity": alert.severity.value,
                "title": alert.title,
                "description": alert.description,
                "explanation": alert.explanation,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "protocol": alert.protocol,
                "port": alert.port,
                "rule_id": alert.rule_id,
                "created_at": alert.created_at.isoformat() if alert.created_at else None
            })
    
    exporter = JSONExporter(pretty=pretty)
    content = exporter.export_alerts(alert_dicts)
    
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="alerts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
        }
    )


@router.get("/alerts/csv")
async def export_alerts_csv(
    request: Request,
    limit: int = Query(1000, ge=1, le=10000),
    current_user: User = Depends(get_current_active_user)
):
    """Export alerts as CSV."""
    from app.database.session import AsyncSession, engine
    from app.database.models import Alert
    from sqlalchemy import select, desc
    
    async with AsyncSession(engine) as session:
        result = await session.execute(
            select(Alert).order_by(desc(Alert.created_at)).limit(limit)
        )
        alerts = result.scalars().all()
        
        alert_dicts: List[Dict[str, Any]] = []
        for alert in alerts:
            alert_dicts.append({
                "id": alert.id,
                "severity": alert.severity.value,
                "title": alert.title,
                "description": alert.description,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "protocol": alert.protocol,
                "port": alert.port,
                "rule_id": alert.rule_id,
                "created_at": alert.created_at.isoformat() if alert.created_at else None
            })
    
    exporter = CSVExporter()
    content = exporter.export_alerts(alert_dicts)
    
    return Response(
        content=content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="alerts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        }
    )


@router.get("/topology/json")
async def export_topology_json(
    request: Request,
    pretty: bool = Query(False),
    current_user: User = Depends(get_current_active_user)
):
    """Export current topology as JSON."""
    topology_service = request.app.state.topology_service
    if not topology_service:
        return {"error": "Topology service not available"}
    
    snapshot = topology_service.get_snapshot()
    
    nodes = [n.to_dict() for n in snapshot.nodes]
    edges = [e.to_dict() for e in snapshot.edges]
    
    exporter = JSONExporter(pretty=pretty)
    content = exporter.export_topology(nodes, edges)
    
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="topology_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
        }
    )


@router.get("/alerts/cef")
async def export_alerts_cef(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_active_user)
):
    """
    Export alerts in CEF (Common Event Format).
    
    Compatible with ArcSight, QRadar, and other SIEM platforms.
    """
    from app.database.session import AsyncSession, engine
    from app.database.models import Alert
    from sqlalchemy import select, desc
    
    async with AsyncSession(engine) as session:
        result = await session.execute(
            select(Alert).order_by(desc(Alert.created_at)).limit(limit)
        )
        alerts = result.scalars().all()
    
    exporter = SIEMExporter()
    lines: List[str] = []
    
    for alert in alerts:
        alert_dict: Dict[str, Any] = {
            "severity": alert.severity.value,
            "title": alert.title,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "source_port": None,  # Would need to parse from extra_data
            "destination_port": alert.port,
            "protocol": alert.protocol,
            "rule_id": alert.rule_id
        }
        lines.append(exporter.format_cef(alert_dict))
    
    content = "\n".join(lines)
    
    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="alerts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.cef"'
        }
    )


@router.get("/siem-compatibility")
async def get_siem_compatibility():
    """Get SIEM integration documentation."""
    return Response(
        content=SIEM_COMPATIBILITY_DOC,
        media_type="text/markdown"
    )

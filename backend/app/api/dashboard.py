"""
Dashboard API routes.

Normalized API responses per DESIGN_SPECIFICATION.md Section 5.2.
"""

from typing import Optional, List, Generic, TypeVar, Dict
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.api.auth import get_current_active_user
from app.database.models import User

router = APIRouter()


# =============================================================================
# Generic API Response Wrapper
# =============================================================================

T = TypeVar('T')


class APIResponse(BaseModel, Generic[T]):
    """Standardized API response wrapper."""
    success: bool
    data: Optional[T] = None
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# =============================================================================
# Dashboard Data Models
# =============================================================================

class CaptureStatusData(BaseModel):
    """Capture status for dashboard."""
    is_running: bool
    interface: Optional[str] = None
    total_packets: int
    total_bytes: int
    unique_hosts: int


class AlertSummaryData(BaseModel):
    """Alert summary for dashboard."""
    total: int
    critical: int
    warning: int
    info: int
    unacknowledged: int
    critical_unacknowledged: int


class TrafficSummaryData(BaseModel):
    """Traffic summary for dashboard."""
    tcp_percentage: float
    udp_percentage: float
    icmp_percentage: float
    http_packets: int
    https_packets: int
    dns_packets: int


class DetectionBreakdown(BaseModel):
    """Detection breakdown by type."""
    port_scans: int
    arp_spoofs: int
    floods: int
    dns_tunnels: int
    suspicious_traffic: int


class DetectionSummaryData(BaseModel):
    """Detection summary for dashboard."""
    total_analyzed: int
    threats_detected: int
    breakdown: DetectionBreakdown


class ServiceStatus(BaseModel):
    """Service status information."""
    capture: str  # running | stopped
    detection: str  # active | inactive
    alerting: str  # active | inactive


class SystemStatusData(BaseModel):
    """System status for dashboard."""
    services: ServiceStatus
    uptime: Optional[str] = None
    health: str  # healthy | degraded | unhealthy


class DashboardSummaryData(BaseModel):
    """Comprehensive dashboard summary."""
    capture_status: CaptureStatusData
    alert_summary: AlertSummaryData
    traffic_summary: TrafficSummaryData
    detection_summary: DetectionSummaryData
    system_status: SystemStatusData


class ProtocolStat(BaseModel):
    """Protocol statistics."""
    count: int
    percentage: float


class TrafficStatsData(BaseModel):
    """Detailed traffic statistics."""
    total_packets: int
    total_bytes: int
    protocols: Dict[str, ProtocolStat]
    unique_sources: int
    unique_destinations: int
    capture_start: Optional[str] = None


class TalkerInfo(BaseModel):
    """IP address talker information."""
    ip: str
    packet_count: int


class TopTalkersData(BaseModel):
    """Top talkers response data."""
    top_sources: List[TalkerInfo]
    top_destinations: List[TalkerInfo]
    sample_size: int


class ActivityItem(BaseModel):
    """Activity feed item."""
    type: str  # alert | packet
    severity: Optional[str] = None
    title: str
    description: str
    timestamp: str
    source_ip: Optional[str] = None


class RecentActivityData(BaseModel):
    """Recent activity feed data."""
    activity: List[ActivityItem]
    recent_packets_count: int
    alert_count: int


class SecurityFactors(BaseModel):
    """Factors affecting security score."""
    critical_alerts: int
    warning_alerts: int
    info_alerts: int


class SecurityScoreData(BaseModel):
    """Security score data."""
    score: int
    status: str  # good | warning | critical
    message: str
    factors: SecurityFactors


# =============================================================================
# Dashboard Endpoints
# =============================================================================

@router.get("/summary", response_model=APIResponse[DashboardSummaryData])
async def get_dashboard_summary(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get comprehensive dashboard summary.
    
    Returns aggregated information about:
    - Packet capture status and statistics
    - Alert counts and severity breakdown
    - Traffic statistics
    - Detection engine statistics
    """
    try:
        capture_service = request.app.state.packet_capture
        alert_manager = request.app.state.alert_manager
        detection_engine = request.app.state.detection_engine
        
        # Capture status
        capture_stats = capture_service.get_stats()
        capture_status = CaptureStatusData(
            is_running=capture_service.is_capture_running(),
            interface=capture_service.interface,
            total_packets=capture_stats.get("total_packets", 0),
            total_bytes=capture_stats.get("total_bytes", 0),
            unique_hosts=capture_stats.get("unique_sources", 0) + capture_stats.get("unique_destinations", 0)
        )
        
        # Alert summary
        alert_stats = alert_manager.get_stats()
        alert_summary = AlertSummaryData(
            total=alert_stats.get("current_count", 0),
            critical=alert_stats.get("critical_count", 0),
            warning=alert_stats.get("warning_count", 0),
            info=alert_stats.get("info_count", 0),
            unacknowledged=alert_stats.get("unacknowledged_count", 0),
            critical_unacknowledged=alert_stats.get("critical_unacknowledged", 0)
        )
        
        # Traffic summary
        traffic_summary = TrafficSummaryData(
            tcp_percentage=_safe_percentage(capture_stats.get("tcp_packets", 0), capture_stats.get("total_packets", 0)),
            udp_percentage=_safe_percentage(capture_stats.get("udp_packets", 0), capture_stats.get("total_packets", 0)),
            icmp_percentage=_safe_percentage(capture_stats.get("icmp_packets", 0), capture_stats.get("total_packets", 0)),
            http_packets=capture_stats.get("http_packets", 0),
            https_packets=capture_stats.get("https_packets", 0),
            dns_packets=capture_stats.get("dns_packets", 0)
        )
        
        # Detection summary
        detection_stats = detection_engine.get_stats()
        detection_summary = DetectionSummaryData(
            total_analyzed=detection_stats.get("total_analyzed", 0),
            threats_detected=sum([
                detection_stats.get("port_scans_detected", 0),
                detection_stats.get("arp_spoofs_detected", 0),
                detection_stats.get("floods_detected", 0),
                detection_stats.get("dns_tunnels_detected", 0),
                detection_stats.get("suspicious_traffic_detected", 0)
            ]),
            breakdown=DetectionBreakdown(
                port_scans=detection_stats.get("port_scans_detected", 0),
                arp_spoofs=detection_stats.get("arp_spoofs_detected", 0),
                floods=detection_stats.get("floods_detected", 0),
                dns_tunnels=detection_stats.get("dns_tunnels_detected", 0),
                suspicious_traffic=detection_stats.get("suspicious_traffic_detected", 0)
            )
        )
        
        # System status
        system_status = SystemStatusData(
            services=ServiceStatus(
                capture="running" if capture_service.is_capture_running() else "stopped",
                detection="active",
                alerting="active"
            ),
            uptime=capture_stats.get("start_time"),
            health="healthy"
        )
        
        return APIResponse(
            success=True,
            data=DashboardSummaryData(
                capture_status=capture_status,
                alert_summary=alert_summary,
                traffic_summary=traffic_summary,
                detection_summary=detection_summary,
                system_status=system_status
            )
        )
    except Exception as e:
        return APIResponse(success=False, error=str(e))


@router.get("/traffic-stats", response_model=APIResponse[TrafficStatsData])
async def get_traffic_stats(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """Get detailed traffic statistics."""
    try:
        capture_service = request.app.state.packet_capture
        stats = capture_service.get_stats()
        
        total = stats.get("total_packets", 0)
        
        return APIResponse(
            success=True,
            data=TrafficStatsData(
                total_packets=total,
                total_bytes=stats.get("total_bytes", 0),
                protocols={
                    "TCP": ProtocolStat(count=stats.get("tcp_packets", 0), percentage=_safe_percentage(stats.get("tcp_packets", 0), total)),
                    "UDP": ProtocolStat(count=stats.get("udp_packets", 0), percentage=_safe_percentage(stats.get("udp_packets", 0), total)),
                    "ICMP": ProtocolStat(count=stats.get("icmp_packets", 0), percentage=_safe_percentage(stats.get("icmp_packets", 0), total)),
                    "ARP": ProtocolStat(count=stats.get("arp_packets", 0), percentage=_safe_percentage(stats.get("arp_packets", 0), total)),
                    "DNS": ProtocolStat(count=stats.get("dns_packets", 0), percentage=_safe_percentage(stats.get("dns_packets", 0), total)),
                    "HTTP": ProtocolStat(count=stats.get("http_packets", 0), percentage=_safe_percentage(stats.get("http_packets", 0), total)),
                    "HTTPS": ProtocolStat(count=stats.get("https_packets", 0), percentage=_safe_percentage(stats.get("https_packets", 0), total)),
                    "Other": ProtocolStat(count=stats.get("other_packets", 0), percentage=_safe_percentage(stats.get("other_packets", 0), total))
                },
                unique_sources=stats.get("unique_sources", 0),
                unique_destinations=stats.get("unique_destinations", 0),
                capture_start=stats.get("start_time")
            )
        )
    except Exception as e:
        return APIResponse(success=False, error=str(e))


@router.get("/top-talkers", response_model=APIResponse[TopTalkersData])
async def get_top_talkers(
    request: Request,
    limit: int = 10,
    current_user: User = Depends(get_current_active_user)
):
    """Get top talkers (most active IPs)."""
    try:
        capture_service = request.app.state.packet_capture
        packets = capture_service.get_recent_packets(limit=1000)
        
        # Count packets per source IP
        source_counts = {}
        dest_counts = {}
        
        for packet in packets:
            src = packet.get("source_ip", "N/A")
            dst = packet.get("destination_ip", "N/A")
            
            if src != "N/A":
                source_counts[src] = source_counts.get(src, 0) + 1
            if dst != "N/A":
                dest_counts[dst] = dest_counts.get(dst, 0) + 1
        
        # Sort and limit
        top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        top_destinations = sorted(dest_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        
        return APIResponse(
            success=True,
            data=TopTalkersData(
                top_sources=[TalkerInfo(ip=ip, packet_count=count) for ip, count in top_sources],
                top_destinations=[TalkerInfo(ip=ip, packet_count=count) for ip, count in top_destinations],
                sample_size=len(packets)
            )
        )
    except Exception as e:
        return APIResponse(success=False, error=str(e))


@router.get("/recent-activity", response_model=APIResponse[RecentActivityData])
async def get_recent_activity(
    request: Request,
    limit: int = 20,
    current_user: User = Depends(get_current_active_user)
):
    """Get recent network activity (alerts + notable packets)."""
    try:
        alert_manager = request.app.state.alert_manager
        capture_service = request.app.state.packet_capture
        
        # Get recent alerts
        alerts = alert_manager.get_alerts(limit=limit)
        
        # Get recent packets summary
        packets = capture_service.get_recent_packets(limit=50)
        
        # Build activity feed
        activity = []
        
        for alert in alerts[:limit]:
            activity.append(ActivityItem(
                type="alert",
                severity=alert["severity"],
                title=alert["title"],
                description=alert["description"],
                timestamp=alert["created_at"],
                source_ip=alert.get("source_ip")
            ))
        
        # Sort by timestamp
        activity.sort(key=lambda x: x.timestamp, reverse=True)
        
        return APIResponse(
            success=True,
            data=RecentActivityData(
                activity=activity[:limit],
                recent_packets_count=len(packets),
                alert_count=len(alerts)
            )
        )
    except Exception as e:
        return APIResponse(success=False, error=str(e))


@router.get("/security-score", response_model=APIResponse[SecurityScoreData])
async def get_security_score(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Calculate a simple security score based on current alerts and threats.
    
    Score ranges from 0-100, where:
    - 100 = No threats detected
    - 0 = Critical security issues
    """
    try:
        alert_manager = request.app.state.alert_manager
        detection_engine = request.app.state.detection_engine
        
        stats = alert_manager.get_stats()
        
        # Base score
        score = 100
        
        # Deduct for unacknowledged alerts
        critical_unack = stats.get("critical_unacknowledged", 0)
        warning_count = stats.get("warning_count", 0)
        info_count = stats.get("info_count", 0)
        
        # Critical alerts are serious
        score -= min(critical_unack * 20, 50)
        
        # Warnings are concerning
        score -= min(warning_count * 5, 25)
        
        # Ensure score stays in bounds
        score = max(0, min(100, score))
        
        # Determine status
        if score >= 80:
            status = "good"
            message = "Your network appears secure. Continue monitoring for changes."
        elif score >= 50:
            status = "warning"
            message = "Some security concerns detected. Review alerts and take appropriate action."
        else:
            status = "critical"
            message = "Significant security threats detected. Immediate attention required."
        
        return APIResponse(
            success=True,
            data=SecurityScoreData(
                score=score,
                status=status,
                message=message,
                factors=SecurityFactors(
                    critical_alerts=critical_unack,
                    warning_alerts=warning_count,
                    info_alerts=info_count
                )
            )
        )
    except Exception as e:
        return APIResponse(success=False, error=str(e))


def _safe_percentage(value: int, total: int) -> float:
    """Calculate percentage safely."""
    if total == 0:
        return 0.0
    return round((value / total) * 100, 2)

"""
Alerts API routes.

Normalized API responses per DESIGN_SPECIFICATION.md Section 5.2.
"""

from typing import Optional, List, Generic, TypeVar
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
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
# Alert Data Models
# =============================================================================

class AlertData(BaseModel):
    """Alert detail data."""
    id: int
    severity: str
    title: str
    description: str
    explanation: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    rule_id: Optional[str] = None
    evidence: dict = Field(default_factory=dict)
    recommended_action: Optional[str] = None
    confidence: Optional[float] = None
    false_positive_likelihood: Optional[str] = None
    is_acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None
    created_at: str


class AlertListData(BaseModel):
    """Alert list response data."""
    alerts: List[AlertData]
    total: int
    filtered: int


class AlertStatsData(BaseModel):
    """Alert statistics data."""
    total_alerts: int
    info_count: int
    warning_count: int
    critical_count: int
    acknowledged_count: int
    unacknowledged_count: int
    critical_unacknowledged: int
    current_count: int


class AlertSummaryData(BaseModel):
    """Alert summary data."""
    total: int
    by_severity: dict
    by_rule: dict
    top_sources: List[tuple]
    period_hours: int


class AcknowledgeRequest(BaseModel):
    """Request to acknowledge alerts."""
    severity: Optional[str] = None


class AcknowledgeResult(BaseModel):
    """Result of acknowledge operation."""
    status: str
    alert_id: Optional[int] = None
    count: Optional[int] = None


# =============================================================================
# Alert Endpoints
# =============================================================================

@router.get("/", response_model=APIResponse[AlertListData])
async def get_alerts(
    request: Request,
    limit: int = 100,
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    source_ip: Optional[str] = None,
    rule_id: Optional[str] = None,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get security alerts with optional filtering.
    
    **Severity Levels:**
    - `info`: Informational, may warrant attention
    - `warning`: Potential security concern
    - `critical`: Serious security threat requiring immediate attention
    """
    try:
        alert_manager = request.app.state.alert_manager
        
        alerts = alert_manager.get_alerts(
            limit=min(limit, 500),
            severity=severity,
            acknowledged=acknowledged,
            source_ip=source_ip,
            rule_id=rule_id
        )
        
        alert_list = [AlertData(**alert) for alert in alerts]
        
        return APIResponse(
            success=True,
            data=AlertListData(
                alerts=alert_list,
                total=len(alert_list),
                filtered=len(alert_list)
            )
        )
    except Exception as e:
        return APIResponse(success=False, error=str(e))


@router.get("/stats", response_model=APIResponse[AlertStatsData])
async def get_alert_stats(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """Get alert statistics."""
    try:
        alert_manager = request.app.state.alert_manager
        stats = alert_manager.get_stats()
        return APIResponse(
            success=True,
            data=AlertStatsData(**stats)
        )
    except Exception as e:
        return APIResponse(success=False, error=str(e))


@router.get("/summary", response_model=APIResponse[AlertSummaryData])
async def get_alert_summary(
    request: Request,
    hours: int = 24,
    current_user: User = Depends(get_current_active_user)
):
    """Get alert summary for the last N hours."""
    try:
        alert_manager = request.app.state.alert_manager
        summary = alert_manager.get_recent_summary(hours=min(hours, 168))  # Max 1 week
        return APIResponse(
            success=True,
            data=AlertSummaryData(**summary)
        )
    except Exception as e:
        return APIResponse(success=False, error=str(e))


@router.get("/{alert_id}", response_model=APIResponse[AlertData])
async def get_alert(
    request: Request,
    alert_id: int,
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific alert by ID."""
    alert_manager = request.app.state.alert_manager
    alert = alert_manager.get_alert_by_id(alert_id)
    
    if not alert:
        return APIResponse(success=False, error="Alert not found")
    
    return APIResponse(success=True, data=AlertData(**alert))


@router.post("/{alert_id}/acknowledge", response_model=APIResponse[AcknowledgeResult])
async def acknowledge_alert(
    request: Request,
    alert_id: int,
    current_user: User = Depends(get_current_active_user)
):
    """Acknowledge a specific alert."""
    alert_manager = request.app.state.alert_manager
    
    success = alert_manager.acknowledge_alert(alert_id, current_user.username)
    
    if not success:
        return APIResponse(success=False, error="Alert not found")
    
    return APIResponse(
        success=True,
        data=AcknowledgeResult(status="acknowledged", alert_id=alert_id)
    )


@router.post("/acknowledge-all", response_model=APIResponse[AcknowledgeResult])
async def acknowledge_all_alerts(
    request: Request,
    ack_request: AcknowledgeRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Acknowledge all alerts, optionally filtered by severity."""
    alert_manager = request.app.state.alert_manager
    
    count = alert_manager.acknowledge_all(
        username=current_user.username,
        severity=ack_request.severity
    )
    
    return APIResponse(
        success=True,
        data=AcknowledgeResult(
            status="acknowledged",
            count=count
        )
    )


class DeleteResult(BaseModel):
    """Result of delete operation."""
    status: str
    alert_id: Optional[int] = None
    count: Optional[int] = None


class ClearResult(BaseModel):
    """Result of clear operation."""
    status: str
    count: int
    acknowledged_only: bool


class DetectionRuleInfo(BaseModel):
    """Detection rule information."""
    rule_id: str
    name: str
    description: str
    category: str
    severity: str
    is_enabled: bool


class RulesListData(BaseModel):
    """Rules list response data."""
    rules: List[DetectionRuleInfo]
    total: int


@router.delete("/{alert_id}", response_model=APIResponse[DeleteResult])
async def delete_alert(
    request: Request,
    alert_id: int,
    current_user: User = Depends(get_current_active_user)
):
    """Delete a specific alert."""
    alert_manager = request.app.state.alert_manager
    
    success = alert_manager.delete_alert(alert_id)
    
    if not success:
        return APIResponse(success=False, error="Alert not found")
    
    return APIResponse(
        success=True,
        data=DeleteResult(status="deleted", alert_id=alert_id)
    )


@router.post("/clear", response_model=APIResponse[ClearResult])
async def clear_alerts(
    request: Request,
    acknowledged_only: bool = True,
    current_user: User = Depends(get_current_active_user)
):
    """
    Clear alerts.
    
    By default, only clears acknowledged alerts. Set `acknowledged_only=false` to clear all.
    """
    alert_manager = request.app.state.alert_manager
    
    count = alert_manager.clear_alerts(acknowledged_only=acknowledged_only)
    
    return APIResponse(
        success=True,
        data=ClearResult(
            status="cleared",
            count=count,
            acknowledged_only=acknowledged_only
        )
    )


@router.get("/rules/list", response_model=APIResponse[RulesListData])
async def list_detection_rules(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """List all detection rules."""
    # For now, return built-in rules from detection engine
    rules = [
        DetectionRuleInfo(
            rule_id="PORT_SCAN_DETECTION",
            name="Port Scan Detection",
            description="Detects when a single source IP attempts to connect to multiple ports",
            category="reconnaissance",
            severity="warning",
            is_enabled=True
        ),
        DetectionRuleInfo(
            rule_id="ARP_SPOOF_DETECTION", 
            name="ARP Spoofing Detection",
            description="Detects potential ARP spoofing attacks",
            category="mitm",
            severity="critical",
            is_enabled=True
        ),
        DetectionRuleInfo(
            rule_id="DNS_TUNNEL_DETECTION",
            name="DNS Tunneling Detection",
            description="Detects potential DNS tunneling by monitoring for unusual DNS queries",
            category="exfiltration",
            severity="warning",
            is_enabled=True
        ),
        DetectionRuleInfo(
            rule_id="PACKET_FLOOD_DETECTION",
            name="Packet Flood Detection",
            description="Detects potential DoS attacks by monitoring packet rates",
            category="dos",
            severity="critical",
            is_enabled=True
        ),
        DetectionRuleInfo(
            rule_id="FAILED_CONN_DETECTION",
            name="Failed Connection Detection",
            description="Detects repeated failed connection attempts",
            category="reconnaissance",
            severity="info",
            is_enabled=True
        ),
        DetectionRuleInfo(
            rule_id="ICMP_SWEEP_DETECTION",
            name="ICMP Sweep Detection",
            description="Detects ICMP-based host discovery sweeps",
            category="reconnaissance",
            severity="info",
            is_enabled=True
        ),
        DetectionRuleInfo(
            rule_id="SUSPICIOUS_PORT",
            name="Suspicious Port Traffic",
            description="Detects connections to known suspicious ports",
            category="exfiltration",
            severity="warning",
            is_enabled=True
        )
    ]
    
    return APIResponse(
        success=True,
        data=RulesListData(rules=rules, total=len(rules))
    )

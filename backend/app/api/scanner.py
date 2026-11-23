"""
Network Scanner API routes.

Provides REST endpoints for network scanning with safety guardrails.
All responses use standardized format per DESIGN_SPECIFICATION.md.
"""

from datetime import datetime
from typing import Any, Dict, Generic, List, Optional, TypeVar
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.auth import get_current_active_user
from app.database.models import User
from app.core.scanner.network_scanner import NetworkScannerService
from app.core.audit import get_audit_logger, AuditEventType

router = APIRouter()

# Global scanner instance with RFC1918 enforcement enabled
scanner_service = NetworkScannerService(local_only=True)

# Audit logger
audit_logger = get_audit_logger()


# =============================================================================
# Response Models (Normalized)
# =============================================================================

T = TypeVar("T")


class APIResponse(BaseModel, Generic[T]):
    """Standardized API response wrapper."""
    success: bool = True
    data: Optional[T] = None
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ScanRequest(BaseModel):
    """Request model for starting a scan."""
    target: str = Field(..., description="Target IP, CIDR, or hostname")
    scan_type: str = Field(
        default="ping",
        description="Type of scan: ping, quick, connect, service, syn"
    )
    ports: Optional[str] = Field(
        None,
        description="Port specification (e.g., 22, 22-80, 22,80,443)"
    )
    local_only: bool = Field(
        default=True,
        description="Enforce RFC1918 private network addresses only"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "target": "192.168.1.0/24",
                "scan_type": "ping",
                "ports": None,
                "local_only": True
            }
        }


class ScanResultData(BaseModel):
    """Scan result data model."""
    scan_id: str
    scan_type: str
    target: str
    status: str
    progress: int
    hosts: List[dict]
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    error: Optional[str] = None
    statistics: dict = Field(default_factory=dict)
    is_local_only: bool = True
    target_host_count: int = 0
    rate_limit: int = 100


class HostData(BaseModel):
    """Host data model."""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    state: str = "unknown"
    os_guess: Optional[str] = None
    open_ports: List[dict] = Field(default_factory=list)
    services: List[dict] = Field(default_factory=list)
    is_gateway: bool = False


class ScanTypeInfo(BaseModel):
    """Scan type information."""
    id: str
    name: str
    description: str
    risk_level: str
    requires_root: bool
    typical_duration: str
    use_case: str


class ValidationResult(BaseModel):
    """Target validation result."""
    valid: bool
    error: Optional[str] = None
    normalized_target: Optional[str] = None
    host_count: int = 0
    is_private: bool = False
    local_only_mode: bool = True


class SafetyLimits(BaseModel):
    """Current safety limits."""
    max_hosts_per_scan: int
    max_ports_per_scan: int
    max_scan_timeout_seconds: int
    max_concurrent_scans: int
    rate_limit_pps: int
    local_only_mode: bool
    allowed_private_ranges: List[str]


# =============================================================================
# API Endpoints
# =============================================================================

@router.post("/scan", response_model=APIResponse[ScanResultData])
async def start_scan(
    scan_request: ScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Start a network scan.
    
    **Scan Types:**
    - `ping`: Host discovery (ping sweep) - fastest, discovers live hosts
    - `quick`: Top 100 ports, fast timing
    - `connect`: TCP connect scan - reliable, no special privileges needed
    - `service`: Service version detection - slowest, most detailed
    - `syn`: TCP SYN scan - stealthy, requires elevated privileges
    
    **Safety Limits:**
    - Maximum network size: /24 (256 addresses)
    - Rate limit: 100 packets/second
    - Only RFC1918 private networks by default
    - Scan timeout: 5 minutes
    
    **Returns:**
    Standardized response with scan job information.
    """
    result = await scanner_service.start_scan(
        target=scan_request.target,
        scan_type=scan_request.scan_type,
        ports=scan_request.ports,
        local_only=scan_request.local_only
    )
    
    if result.status == "failed":
        # Log the failed attempt
        audit_logger.log(
            event_type=AuditEventType.SCAN_FAILED,
            user_id=str(current_user.id),
            username=current_user.username,
            resource_type="scan",
            success=False,
            error_message=result.error,
            target=scan_request.target,
            scan_type=scan_request.scan_type
        )
        
        return APIResponse(
            success=False,
            error=result.error,
            data=None
        )
    
    # Log successful scan start
    audit_logger.log_scan_started(
        scan_id=result.scan_id,
        target=scan_request.target,
        scan_type=scan_request.scan_type,
        user_id=str(current_user.id),
        username=current_user.username,
        local_only=scan_request.local_only
    )
    
    return APIResponse(
        success=True,
        data=ScanResultData(**result.to_dict())
    )


@router.get("/scan/{scan_id}", response_model=APIResponse[ScanResultData])
async def get_scan_result(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get the result of a specific scan."""
    result = scanner_service.get_scan_result(scan_id)
    
    if not result:
        return APIResponse(
            success=False,
            error=f"Scan '{scan_id}' not found"
        )
    
    return APIResponse(
        success=True,
        data=ScanResultData(**result.to_dict())
    )


@router.get("/scans", response_model=APIResponse[List[ScanResultData]])
async def list_scans(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=500, description="Maximum results"),
    current_user: User = Depends(get_current_active_user)
):
    """List all scans with optional status filter."""
    scans = scanner_service.get_all_scans(status=status)
    
    # Sort by start_time descending
    scans = sorted(scans, key=lambda x: x.get("start_time") or "", reverse=True)
    
    return APIResponse(
        success=True,
        data=[ScanResultData(**s) for s in scans[:limit]]
    )


@router.post("/scan/{scan_id}/cancel", response_model=APIResponse[Dict[str, str]])
async def cancel_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Cancel a running scan."""
    success = scanner_service.cancel_scan(scan_id)
    
    if not success:
        return APIResponse(
            success=False,
            error="Cannot cancel scan (not found or not running)"
        )
    
    # Log cancellation
    audit_logger.log(
        event_type=AuditEventType.SCAN_CANCELLED,
        user_id=str(current_user.id),
        username=current_user.username,
        resource_type="scan",
        resource_id=scan_id
    )
    
    return APIResponse(
        success=True,
        data={"status": "cancelled", "scan_id": scan_id}
    )


@router.get("/scan-types", response_model=APIResponse[List[ScanTypeInfo]])
async def get_scan_types(
    current_user: User = Depends(get_current_active_user)
):
    """Get available scan types with descriptions and safety metadata."""
    scan_types = [
        ScanTypeInfo(
            id="ping",
            name="Host Discovery",
            description="Discover live hosts using ICMP ping sweep. Fastest and safest scan type.",
            risk_level="low",
            requires_root=False,
            typical_duration="10-30 seconds",
            use_case="Initial network mapping"
        ),
        ScanTypeInfo(
            id="quick",
            name="Quick Scan",
            description="Fast scan of top 100 ports with rate limiting.",
            risk_level="low",
            requires_root=False,
            typical_duration="30 seconds - 1 minute",
            use_case="Quick security check"
        ),
        ScanTypeInfo(
            id="connect",
            name="TCP Connect Scan",
            description="Full TCP connection to discover open ports. Reliable, no special privileges.",
            risk_level="medium",
            requires_root=False,
            typical_duration="1-5 minutes",
            use_case="Port discovery"
        ),
        ScanTypeInfo(
            id="service",
            name="Service Detection",
            description="Identify running services and versions on open ports. Most detailed.",
            risk_level="medium",
            requires_root=False,
            typical_duration="2-10 minutes",
            use_case="Vulnerability assessment preparation"
        ),
        ScanTypeInfo(
            id="syn",
            name="TCP SYN Scan",
            description="Half-open scan using TCP SYN packets. Stealthier but requires privileges.",
            risk_level="medium",
            requires_root=True,
            typical_duration="30 seconds - 2 minutes",
            use_case="Stealthy port discovery"
        )
    ]
    
    return APIResponse(success=True, data=scan_types)


@router.get("/common-ports", response_model=APIResponse[Dict[str, List[int]]])
async def get_common_ports(
    current_user: User = Depends(get_current_active_user)
):
    """Get lists of common ports organized by category."""
    return APIResponse(
        success=True,
        data=scanner_service.get_common_ports()
    )


@router.get("/validate-target", response_model=APIResponse[ValidationResult])
async def validate_target(
    target: str = Query(..., description="Target to validate"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Validate a scan target without starting a scan.
    
    Returns validation status, normalized target, and host count.
    Useful for UI validation before submitting scan request.
    """
    result = scanner_service.validate_target(target)
    
    return APIResponse(
        success=True,
        data=ValidationResult(**result)
    )


@router.get("/safety-limits", response_model=APIResponse[SafetyLimits])
async def get_safety_limits(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current safety limits for network scanning.
    
    Returns the configured safety guardrails that protect against
    accidental network disruption.
    """
    limits = scanner_service.get_safety_limits()
    
    return APIResponse(
        success=True,
        data=SafetyLimits(**limits)
    )
    valid, error = scanner_service._validate_target(target)
    return {
        "target": target,
        "is_valid": valid,
        "error": error if not valid else None
    }

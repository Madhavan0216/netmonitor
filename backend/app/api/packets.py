"""
Packet Capture API routes.

Provides REST endpoints for packet capture with safety controls.
All responses use standardized format per DESIGN_SPECIFICATION.md.
"""

from datetime import datetime
from typing import Any, Dict, Generic, List, Optional, TypeVar
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.api.auth import get_current_active_user
from app.database.models import User
from app.core.audit import get_audit_logger, AuditEventType

router = APIRouter()

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


class CaptureStartRequest(BaseModel):
    """Request model for starting packet capture."""
    interface: Optional[str] = Field(
        None,
        description="Network interface to capture on (None = all)"
    )
    bpf_filter: Optional[str] = Field(
        None,
        description="BPF filter expression (e.g., 'tcp port 80')"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "interface": "eth0",
                "bpf_filter": "tcp port 80"
            }
        }


class InterfaceInfo(BaseModel):
    """Network interface information."""
    name: str
    display_name: Optional[str] = None  # Made optional - Windows NPF interfaces may not have friendly names
    description: str = ""
    ip_addresses: List[str] = Field(default_factory=list)
    mac_address: Optional[str] = None
    is_up: bool = False
    is_loopback: bool = False
    
    def model_post_init(self, __context):
        """Set display_name to name if not provided."""
        if self.display_name is None:
            object.__setattr__(self, 'display_name', self.name)


class CaptureStatusData(BaseModel):
    """Capture status data."""
    is_running: bool
    interface: Optional[str] = None
    filter: Optional[str] = None
    stats: Dict[str, Any] = Field(default_factory=dict)


class PacketData(BaseModel):
    """Packet data model."""
    timestamp: str
    source_ip: str
    destination_ip: str
    source_mac: Optional[str] = None
    destination_mac: Optional[str] = None
    protocol: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    size: int
    flags: Optional[str] = None
    info: str = ""
    layer: str = "network"


class CaptureStats(BaseModel):
    """Capture statistics."""
    total_packets: int = 0
    packets_per_second: float = 0.0
    bytes_captured: int = 0
    start_time: Optional[str] = None
    duration_seconds: float = 0.0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    arp_packets: int = 0
    dns_packets: int = 0
    http_packets: int = 0
    https_packets: int = 0
    other_packets: int = 0
    buffer_usage_percent: float = 0.0


class ProtocolStats(BaseModel):
    """Protocol distribution statistics."""
    protocols: Dict[str, Dict[str, Any]]
    total: int


# =============================================================================
# API Endpoints
# =============================================================================

@router.get("/interfaces", response_model=APIResponse[List[InterfaceInfo]])
async def get_interfaces(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get available network interfaces for capture.
    
    Returns list of interfaces with their properties (IP, MAC, status).
    Windows Note: NPF device names are normalized to friendly display names.
    """
    capture_service = request.app.state.packet_capture
    
    try:
        interfaces = capture_service.get_interfaces()
    except Exception as e:
        # Return empty list on failure instead of 500
        import structlog
        structlog.get_logger(__name__).warning("Failed to enumerate interfaces", error=str(e))
        return APIResponse(success=True, data=[])
    
    # Convert to normalized format with safe defaults
    interface_list = []
    for iface in interfaces:
        try:
            if isinstance(iface, dict):
                # Extract name safely
                name = iface.get("name", "unknown")
                display_name = iface.get("display_name") or iface.get("description") or name
                description = iface.get("description", "")
                ip_addresses = iface.get("ip_addresses", [])
                mac_address = iface.get("mac_address")
                is_up = iface.get("is_up", False)
                is_loopback = iface.get("is_loopback", False)
                
                interface_list.append(InterfaceInfo(
                    name=name,
                    display_name=display_name,
                    description=description,
                    ip_addresses=ip_addresses if isinstance(ip_addresses, list) else [],
                    mac_address=mac_address,
                    is_up=bool(is_up),
                    is_loopback=bool(is_loopback)
                ))
            elif isinstance(iface, str):
                # Simple string interface name (common on Windows)
                interface_list.append(InterfaceInfo(
                    name=iface,
                    display_name=iface,
                    description=iface
                ))
        except Exception:
            # Skip malformed interface entries
            continue
    
    return APIResponse(success=True, data=interface_list)


@router.post("/start", response_model=APIResponse[CaptureStatusData])
async def start_capture(
    request: Request,
    capture_request: CaptureStartRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Start packet capture.
    
    **Parameters:**
    - `interface`: Network interface (None for all)
    - `bpf_filter`: Berkeley Packet Filter expression
    
    **Safety Notes:**
    - Capture runs in promiscuous mode
    - Only packet metadata is captured by default
    - Buffer size is limited to prevent memory issues
    """
    capture_service = request.app.state.packet_capture
    
    success = await capture_service.start(
        interface=capture_request.interface,
        bpf_filter=capture_request.bpf_filter
    )
    
    if not success:
        audit_logger.log(
            event_type=AuditEventType.CAPTURE_FAILED,
            user_id=str(current_user.id),
            username=current_user.username,
            resource_type="capture",
            success=False,
            error_message="Failed to start capture",
            interface=capture_request.interface
        )
        
        return APIResponse(
            success=False,
            error="Failed to start packet capture. Check interface and permissions."
        )
    
    # Log successful capture start
    audit_logger.log_capture_started(
        interface=capture_request.interface or "all",
        bpf_filter=capture_request.bpf_filter,
        user_id=str(current_user.id)
    )
    
    return APIResponse(
        success=True,
        data=CaptureStatusData(
            is_running=True,
            interface=capture_service.interface,
            filter=capture_service.bpf_filter,
            stats=capture_service.get_stats()
        )
    )


@router.post("/stop", response_model=APIResponse[CaptureStatusData])
async def stop_capture(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """Stop packet capture."""
    capture_service = request.app.state.packet_capture
    
    stats = capture_service.get_stats()
    interface = capture_service.interface
    
    await capture_service.stop()
    
    # Log capture stop
    audit_logger.log_capture_stopped(
        interface=interface or "all",
        packets_captured=stats.get("total_packets", 0),
        duration_seconds=stats.get("duration_seconds", 0)
    )
    
    return APIResponse(
        success=True,
        data=CaptureStatusData(
            is_running=False,
            interface=None,
            filter=None,
            stats=stats
        )
    )


@router.get("/status", response_model=APIResponse[CaptureStatusData])
async def get_capture_status(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """Get packet capture status."""
    capture_service = request.app.state.packet_capture
    
    return APIResponse(
        success=True,
        data=CaptureStatusData(
            is_running=capture_service.is_capture_running(),
            interface=capture_service.interface,
            filter=capture_service.bpf_filter,
            stats=capture_service.get_stats()
        )
    )


@router.get("/packets", response_model=APIResponse[List[PacketData]])
async def get_recent_packets(
    request: Request,
    limit: int = Query(100, ge=1, le=1000, description="Maximum packets to return"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    destination_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get recent captured packets.
    
    Returns packets from the ring buffer (newest first).
    Apply filters to narrow results.
    """
    capture_service = request.app.state.packet_capture
    
    packets = capture_service.get_recent_packets(limit=min(limit, 1000))
    
    # Apply filters
    if protocol:
        packets = [p for p in packets if p.get("protocol", "").upper() == protocol.upper()]
    
    if source_ip:
        packets = [p for p in packets if p.get("source_ip") == source_ip]
    
    if destination_ip:
        packets = [p for p in packets if p.get("destination_ip") == destination_ip]
    
    # Convert to normalized format
    packet_list = []
    for p in packets:
        packet_list.append(PacketData(
            timestamp=p.get("timestamp", ""),
            source_ip=p.get("source_ip", "unknown"),
            destination_ip=p.get("destination_ip", "unknown"),
            source_mac=p.get("source_mac"),
            destination_mac=p.get("destination_mac"),
            protocol=p.get("protocol", "unknown"),
            source_port=p.get("source_port"),
            destination_port=p.get("destination_port"),
            size=p.get("size", 0),
            flags=p.get("flags"),
            info=p.get("info", ""),
            layer=p.get("layer", "network")
        ))
    
    return APIResponse(success=True, data=packet_list)


@router.get("/stats", response_model=APIResponse[CaptureStats])
async def get_capture_stats(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """Get packet capture statistics."""
    capture_service = request.app.state.packet_capture
    stats = capture_service.get_stats()
    
    return APIResponse(
        success=True,
        data=CaptureStats(**stats)
    )


@router.post("/clear", response_model=APIResponse[Dict[str, str]])
async def clear_packet_buffer(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """Clear the packet buffer."""
    capture_service = request.app.state.packet_capture
    capture_service.clear_buffer()
    
    return APIResponse(
        success=True,
        data={"status": "cleared", "message": "Packet buffer cleared"}
    )


@router.get("/protocols", response_model=APIResponse[ProtocolStats])
async def get_protocol_stats(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """Get packet distribution by protocol."""
    capture_service = request.app.state.packet_capture
    stats = capture_service.get_stats()
    
    total = stats.get("total_packets", 0)
    
    protocols = {
        "TCP": stats.get("tcp_packets", 0),
        "UDP": stats.get("udp_packets", 0),
        "ICMP": stats.get("icmp_packets", 0),
        "ARP": stats.get("arp_packets", 0),
        "DNS": stats.get("dns_packets", 0),
        "HTTP": stats.get("http_packets", 0),
        "HTTPS": stats.get("https_packets", 0),
        "Other": stats.get("other_packets", 0)
    }
    
    # Calculate percentages
    protocol_stats = {
        proto: {
            "count": count,
            "percentage": round((count / total) * 100, 2) if total > 0 else 0
        }
        for proto, count in protocols.items()
    }
    
    return APIResponse(
        success=True,
        data=ProtocolStats(protocols=protocol_stats, total=total)
    )

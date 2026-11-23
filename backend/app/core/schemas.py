"""
Core Pydantic schemas for type safety and validation.
Follows DESIGN_SPECIFICATION.md Section 3.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Generic, List, Optional, TypeVar, cast

from pydantic import BaseModel, Field, field_validator, model_validator


# =============================================================================
# Enums
# =============================================================================

class AlertSeverity(str, Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class ScanStatus(str, Enum):
    """Scan job status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ScanType(str, Enum):
    """Safe scan types with risk levels."""
    PING = "ping"          # Host discovery only
    QUICK = "quick"        # Top 100 ports
    STANDARD = "standard"  # Top 1000 ports
    SERVICE = "service"    # Version detection


class CaptureStatus(str, Enum):
    """Packet capture status."""
    IDLE = "idle"
    CAPTURING = "capturing"
    STOPPING = "stopping"
    ERROR = "error"


class Protocol(str, Enum):
    """Supported network protocols."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ARP = "ARP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    OTHER = "Other"


# =============================================================================
# Generic Response Wrapper
# =============================================================================

T = TypeVar("T")


class APIResponse(BaseModel, Generic[T]):
    """
    Standardized API response wrapper.
    All API endpoints return this shape for consistency.
    """
    success: bool = True
    data: Optional[T] = None
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    @classmethod
    def ok(cls, data: T) -> "APIResponse[T]":
        """Create a successful response."""
        return cls(success=True, data=data)
    
    @classmethod
    def fail(cls, error: str) -> "APIResponse[None]":
        """Create a failure response."""
        return cast("APIResponse[None]", cls(success=False, error=error))


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper."""
    items: List[T]
    total: int
    page: int = 1
    page_size: int = 50
    has_more: bool = False


# =============================================================================
# Network Validation Schemas
# =============================================================================

class CIDRTarget(BaseModel):
    """
    Validated CIDR target for scanning.
    Enforces safety limits as per DESIGN_SPECIFICATION.md Section 7.
    """
    target: str
    network: Optional[ipaddress.IPv4Network] = None
    is_local: bool = False
    host_count: int = 0
    
    # Safety limits
    MAX_HOSTS: int = 256  # /24 maximum
    
    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Validate and normalize the target."""
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        return v
    
    @model_validator(mode="after")
    def validate_network(self) -> "CIDRTarget":
        """Validate network range and compute properties."""
        try:
            # Handle single IP
            if "/" not in self.target:
                ip = ipaddress.IPv4Address(self.target)
                self.network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
            else:
                self.network = ipaddress.IPv4Network(self.target, strict=False)
            
            # Compute host count
            self.host_count = self.network.num_addresses
            
            # Enforce CIDR limit
            if self.host_count > self.MAX_HOSTS:
                raise ValueError(
                    f"Target range too large: {self.host_count} hosts. "
                    f"Maximum allowed: {self.MAX_HOSTS} hosts (/24 or smaller)"
                )
            
            # Check if local (RFC1918)
            self.is_local = self.network.is_private
            
        except ipaddress.AddressValueError as e:
            raise ValueError(f"Invalid IP address: {e}")
        except ipaddress.NetmaskValueError as e:
            raise ValueError(f"Invalid network mask: {e}")
        
        return self
    
    def enforce_local_only(self) -> None:
        """
        Enforce that target is within RFC1918 private ranges.
        Called when local_only mode is enabled.
        """
        if not self.is_local:
            raise ValueError(
                f"Target {self.target} is not a private network. "
                "Only RFC1918 ranges allowed (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)"
            )


class PortRange(BaseModel):
    """Validated port range specification."""
    ports: str
    parsed_ports: List[int] = Field(default_factory=lambda: [])
    
    MAX_PORTS: int = 10000
    
    @model_validator(mode="after")
    def validate_ports(self) -> "PortRange":
        """Parse and validate port specification."""
        if not self.ports or self.ports == "-":
            # All ports requested - cap it
            raise ValueError(f"Cannot scan all ports. Maximum: {self.MAX_PORTS}")
        
        ports_set: set[int] = set()
        
        for part in self.ports.split(","):
            part = part.strip()
            if "-" in part:
                # Range
                try:
                    start, end = part.split("-")
                    start_port = int(start)
                    end_port = int(end)
                    
                    if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                        raise ValueError(f"Port out of range: {part}")
                    
                    if start_port > end_port:
                        raise ValueError(f"Invalid port range: {part}")
                    
                    for p in range(start_port, end_port + 1):
                        ports_set.add(p)
                except ValueError:
                    raise ValueError(f"Invalid port range: {part}")
            else:
                # Single port
                try:
                    port = int(part)
                    if not (1 <= port <= 65535):
                        raise ValueError(f"Port out of range: {port}")
                    ports_set.add(port)
                except ValueError:
                    raise ValueError(f"Invalid port: {part}")
        
        if len(ports_set) > self.MAX_PORTS:
            raise ValueError(f"Too many ports: {len(ports_set)}. Maximum: {self.MAX_PORTS}")
        
        self.parsed_ports = sorted(ports_set)
        return self


# =============================================================================
# Packet Schemas
# =============================================================================

class PacketInfo(BaseModel):
    """
    Structured packet information.
    Metadata-first approach per DESIGN_SPECIFICATION.md.
    """
    id: str
    timestamp: datetime
    protocol: Protocol
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: int
    info: str = ""
    
    # Optional deep fields (only populated when requested)
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    ttl: Optional[int] = None
    flags: Optional[str] = None
    
    # DNS specific
    dns_query: Optional[str] = None
    dns_response: Optional[List[str]] = None
    
    # ARP specific
    arp_op: Optional[str] = None
    arp_sender_ip: Optional[str] = None
    arp_target_ip: Optional[str] = None


class CaptureStats(BaseModel):
    """Packet capture statistics."""
    total_packets: int = 0
    packets_per_second: float = 0.0
    bytes_captured: int = 0
    start_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    protocol_breakdown: dict[str, int] = Field(default_factory=dict)
    dropped_packets: int = 0
    buffer_usage_percent: float = 0.0


class InterfaceInfo(BaseModel):
    """Network interface information."""
    name: str
    display_name: str
    description: str = ""
    mac_address: Optional[str] = None
    ip_addresses: List[str] = Field(default_factory=list)
    is_up: bool = False
    is_loopback: bool = False
    is_wireless: bool = False


class CaptureRequest(BaseModel):
    """Request to start packet capture."""
    interface: Optional[str] = None
    bpf_filter: Optional[str] = ""
    buffer_size: int = Field(default=10000, ge=100, le=100000)
    
    @field_validator("bpf_filter")
    @classmethod
    def validate_bpf_filter(cls, v: Optional[str]) -> str:
        """Basic BPF filter validation."""
        if v is None:
            return ""
        
        v = v.strip()
        
        # Block potentially dangerous filters
        dangerous_patterns = ["load", "write", "exec"]
        for pattern in dangerous_patterns:
            if pattern in v.lower():
                raise ValueError(f"BPF filter contains disallowed pattern: {pattern}")
        
        return v


# =============================================================================
# Scanner Schemas
# =============================================================================

class ScanRequest(BaseModel):
    """Request to start a network scan."""
    target: str
    scan_type: ScanType = ScanType.PING
    ports: Optional[str] = None
    local_only: bool = True  # Enforce RFC1918 by default
    
    @model_validator(mode="after")
    def validate_request(self) -> "ScanRequest":
        """Validate the scan request."""
        # Validate target as CIDR
        cidr = CIDRTarget(target=self.target)
        
        # Enforce local-only if enabled
        if self.local_only:
            cidr.enforce_local_only()
        
        # Validate ports if provided
        if self.ports:
            PortRange(ports=self.ports)
        
        return self


class ScanResult(BaseModel):
    """Network scan result."""
    scan_id: str
    target: str
    scan_type: ScanType
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    hosts_found: int = 0
    hosts_scanned: int = 0
    progress_percent: int = 0
    error: Optional[str] = None


class DiscoveredHost(BaseModel):
    """Host discovered by network scan."""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    os_info: Optional[str] = None
    device_type: Optional[str] = None
    vendor: Optional[str] = None
    is_gateway: bool = False
    first_seen: datetime
    last_seen: datetime
    ports: List["PortInfo"] = Field(default_factory=lambda: [])


class PortInfo(BaseModel):
    """Information about an open port."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


# =============================================================================
# Alert Schemas
# =============================================================================

class AlertCreate(BaseModel):
    """Data for creating an alert."""
    rule_id: str
    severity: AlertSeverity
    title: str
    description: str
    explanation: str  # Plain English for non-experts
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommended_action: str = ""


class AlertResponse(BaseModel):
    """Alert response model."""
    id: int
    rule_id: str
    severity: AlertSeverity
    title: str
    description: str
    explanation: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommended_action: str = ""
    created_at: datetime
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None


class AlertStats(BaseModel):
    """Alert statistics."""
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    unacknowledged: int = 0
    last_24h: int = 0
    last_hour: int = 0


# =============================================================================
# Detection Schemas
# =============================================================================

class DetectionEvent(BaseModel):
    """
    Event generated by the detection engine.
    Always includes explanation per DESIGN_SPECIFICATION.md.
    """
    rule_id: str
    severity: AlertSeverity
    title: str
    description: str
    explanation: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    recommended_action: str = ""
    
    # Detection metadata
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    false_positive_likelihood: str = "low"  # low, medium, high


class DetectionRule(BaseModel):
    """Detection rule configuration."""
    id: str
    name: str
    description: str
    severity: AlertSeverity
    enabled: bool = True
    threshold: Optional[int] = None
    window_seconds: int = 60
    cooldown_seconds: int = 60


# =============================================================================
# Network Topology Schemas
# =============================================================================

class TopologyNode(BaseModel):
    """Node in network topology graph."""
    id: str
    ip: str
    label: Optional[str] = None
    mac: Optional[str] = None
    device_type: Optional[str] = None
    is_gateway: bool = False
    is_local: bool = False
    ports_open: int = 0
    last_seen: Optional[datetime] = None


class TopologyEdge(BaseModel):
    """Edge in network topology graph."""
    source: str
    target: str
    packets: int = 0
    bytes: int = 0
    protocols: List[str] = Field(default_factory=lambda: [])
    last_activity: Optional[datetime] = None


class NetworkTopology(BaseModel):
    """Complete network topology."""
    nodes: List[TopologyNode] = Field(default_factory=lambda: [])
    edges: List[TopologyEdge] = Field(default_factory=lambda: [])
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# WebSocket Schemas
# =============================================================================

class WSMessage(BaseModel):
    """WebSocket message format."""
    channel: str
    event: str
    data: Any = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WSSubscription(BaseModel):
    """WebSocket subscription request."""
    channels: List[str] = Field(default_factory=lambda: [])
    
    ALLOWED_CHANNELS = {"packets", "alerts", "stats", "topology", "scans"}
    
    @field_validator("channels")
    @classmethod
    def validate_channels(cls, v: List[str]) -> List[str]:
        """Validate channel names."""
        invalid = set(v) - cls.ALLOWED_CHANNELS
        if invalid:
            raise ValueError(f"Invalid channels: {invalid}. Allowed: {cls.ALLOWED_CHANNELS}")
        return v


# Forward references for nested models
DiscoveredHost.model_rebuild()

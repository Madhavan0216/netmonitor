"""
Network API routes.
Handles network discovery, topology, and ARP cache.

Normalized API responses per DESIGN_SPECIFICATION.md Section 5.2.
"""

from typing import Optional, List, Generic, TypeVar, Set
from datetime import datetime
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
import socket

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
# Network Data Models
# =============================================================================

class DiscoveredHost(BaseModel):
    """Discovered network host."""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    packet_count: int
    protocols: List[str]
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    is_local: bool


class HostListData(BaseModel):
    """Host list response data."""
    hosts: List[DiscoveredHost]
    total_hosts: int
    local_hosts: int
    external_hosts: int


class ARPEntryData(BaseModel):
    """ARP cache entry."""
    ip_address: str
    mac_address: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class ARPCacheData(BaseModel):
    """ARP cache response data."""
    entries: List[ARPEntryData]
    total: int


class ConnectionData(BaseModel):
    """Network connection data."""
    source_ip: str
    destination_ip: str
    destination_port: Optional[int] = None
    protocol: str
    packet_count: int
    total_bytes: int
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class ConnectionListData(BaseModel):
    """Connection list response data."""
    connections: List[ConnectionData]
    total_unique_connections: int


class TopologyNode(BaseModel):
    """Network topology node (host)."""
    id: str
    label: str
    type: str  # local | external
    packet_count: int


class TopologyEdge(BaseModel):
    """Network topology edge (connection)."""
    source: str
    target: str
    packet_count: int
    protocols: List[str]


class TopologyStats(BaseModel):
    """Topology statistics."""
    total_nodes: int
    total_edges: int
    local_nodes: int
    external_nodes: int


class TopologyData(BaseModel):
    """Network topology for visualization."""
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]
    stats: TopologyStats


class PrivateRangeInfo(BaseModel):
    """Private IP range information."""
    range: str
    description: str


class LocalNetworkInfo(BaseModel):
    """Local network information."""
    hostname: str
    local_ip: str
    common_private_ranges: List[PrivateRangeInfo]


# =============================================================================
# Network Endpoints
# =============================================================================

@router.get("/hosts", response_model=APIResponse[HostListData])
async def get_discovered_hosts(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get list of discovered hosts from packet capture.
    
    Hosts are discovered passively through network traffic analysis.
    For active discovery, use the scanner API.
    """
    try:
        capture_service = request.app.state.packet_capture
        detection_engine = request.app.state.detection_engine
        
        # Get unique hosts from packet buffer
        packets = capture_service.get_recent_packets(limit=1000)
        
        hosts = {}
        for packet in packets:
            src_ip = packet.get("source_ip", "N/A")
            dst_ip = packet.get("destination_ip", "N/A")
            
            for ip in [src_ip, dst_ip]:
                if ip != "N/A" and ip not in hosts:
                    hosts[ip] = {
                        "ip_address": ip,
                        "mac_address": packet.get("source_mac") if ip == src_ip else packet.get("destination_mac"),
                        "packet_count": 0,
                        "protocols": set(),
                        "first_seen": packet.get("timestamp"),
                        "last_seen": packet.get("timestamp")
                    }
                
                if ip in hosts:
                    hosts[ip]["packet_count"] += 1
                    hosts[ip]["protocols"].add(packet.get("protocol", "UNKNOWN"))
                    hosts[ip]["last_seen"] = packet.get("timestamp")
        
        # Get ARP cache for MAC addresses
        arp_cache = detection_engine.get_arp_cache()
        for ip, data in arp_cache.items():
            if ip in hosts:
                hosts[ip]["mac_address"] = data.get("mac")
        
        # Convert to list and add hostname lookups
        host_list = []
        for ip, data in hosts.items():
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
            
            host_list.append(DiscoveredHost(
                ip_address=ip,
                hostname=hostname,
                mac_address=data.get("mac_address"),
                packet_count=data["packet_count"],
                protocols=list(data["protocols"]),
                first_seen=data.get("first_seen"),
                last_seen=data.get("last_seen"),
                is_local=_is_local_ip(ip)
            ))
        
        # Sort by packet count
        host_list.sort(key=lambda x: x.packet_count, reverse=True)
        
        return APIResponse(
            success=True,
            data=HostListData(
                hosts=host_list,
                total_hosts=len(host_list),
                local_hosts=sum(1 for h in host_list if h.is_local),
                external_hosts=sum(1 for h in host_list if not h.is_local)
            )
        )
    except Exception as e:
        return APIResponse(success=False, error=str(e))


@router.get("/arp-cache", response_model=APIResponse[ARPCacheData])
async def get_arp_cache(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get the ARP cache built from observed traffic.
    
    Useful for detecting ARP spoofing - watch for IP addresses
    that change their MAC address unexpectedly.
    """
    try:
        detection_engine = request.app.state.detection_engine
        arp_cache = detection_engine.get_arp_cache()
        
        entries = []
        for ip, data in arp_cache.items():
            entries.append(ARPEntryData(
                ip_address=ip,
                mac_address=data.get("mac"),
                first_seen=data.get("first_seen").isoformat() if data.get("first_seen") else None,
                last_seen=data.get("last_seen").isoformat() if data.get("last_seen") else None
            ))
        
        return APIResponse(
            success=True,
            data=ARPCacheData(entries=entries, total=len(entries))
        )
    except Exception as e:
        return APIResponse(success=False, error=str(e))


@router.get("/connections", response_model=APIResponse[ConnectionListData])
async def get_active_connections(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get active network connections observed in traffic.
    
    Shows source-destination pairs with protocol and port information.
    """
    try:
        capture_service = request.app.state.packet_capture
        packets = capture_service.get_recent_packets(limit=500)
        
        connections = {}
        for packet in packets:
            src_ip = packet.get("source_ip", "N/A")
            dst_ip = packet.get("destination_ip", "N/A")
            protocol = packet.get("protocol", "UNKNOWN")
            dst_port = packet.get("destination_port")
            
            if src_ip == "N/A" or dst_ip == "N/A":
                continue
            
            # Create connection key
            key = f"{src_ip}->{dst_ip}:{dst_port or 'any'}/{protocol}"
            
            if key not in connections:
                connections[key] = {
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "destination_port": dst_port,
                    "protocol": protocol,
                    "packet_count": 0,
                    "total_bytes": 0,
                    "first_seen": packet.get("timestamp"),
                    "last_seen": packet.get("timestamp")
                }
            
            connections[key]["packet_count"] += 1
            connections[key]["total_bytes"] += packet.get("size", 0)
            connections[key]["last_seen"] = packet.get("timestamp")
        
        # Convert to list and sort by packet count
        conn_list = [ConnectionData(**c) for c in connections.values()]
        conn_list.sort(key=lambda x: x.packet_count, reverse=True)
        
        return APIResponse(
            success=True,
            data=ConnectionListData(
                connections=conn_list[:100],  # Limit to top 100
                total_unique_connections=len(conn_list)
            )
        )
    except Exception as e:
        return APIResponse(success=False, error=str(e))


@router.get("/topology", response_model=APIResponse[TopologyData])
async def get_network_topology(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get network topology for visualization.
    
    Returns nodes (hosts) and edges (connections) suitable for
    graph visualization libraries like D3.js or vis.js.
    """
    try:
        capture_service = request.app.state.packet_capture
        packets = capture_service.get_recent_packets(limit=1000)
        
        # Build nodes (unique IPs)
        nodes = {}
        edges = {}
        
        for packet in packets:
            src_ip = packet.get("source_ip", "N/A")
            dst_ip = packet.get("destination_ip", "N/A")
            
            if src_ip == "N/A" or dst_ip == "N/A":
                continue
            
            # Add source node
            if src_ip not in nodes:
                nodes[src_ip] = {
                    "id": src_ip,
                    "label": src_ip,
                    "type": "local" if _is_local_ip(src_ip) else "external",
                    "packet_count": 0
                }
            nodes[src_ip]["packet_count"] += 1
            
            # Add destination node
            if dst_ip not in nodes:
                nodes[dst_ip] = {
                    "id": dst_ip,
                    "label": dst_ip,
                    "type": "local" if _is_local_ip(dst_ip) else "external",
                    "packet_count": 0
                }
            nodes[dst_ip]["packet_count"] += 1
            
            # Add edge
            edge_key = f"{src_ip}-{dst_ip}"
            if edge_key not in edges:
                edges[edge_key] = {
                    "source": src_ip,
                    "target": dst_ip,
                    "packet_count": 0,
                    "protocols": set()
                }
            edges[edge_key]["packet_count"] += 1
            edges[edge_key]["protocols"].add(packet.get("protocol", "UNKNOWN"))
        
        # Convert to lists
        node_list = [TopologyNode(**n) for n in nodes.values()]
        edge_list = [
            TopologyEdge(
                source=edge["source"],
                target=edge["target"],
                packet_count=edge["packet_count"],
                protocols=list(edge["protocols"])
            )
            for edge in edges.values()
        ]
        
        return APIResponse(
            success=True,
            data=TopologyData(
                nodes=node_list,
                edges=edge_list,
                stats=TopologyStats(
                    total_nodes=len(node_list),
                    total_edges=len(edge_list),
                    local_nodes=sum(1 for n in node_list if n.type == "local"),
                    external_nodes=sum(1 for n in node_list if n.type == "external")
                )
            )
        )
    except Exception as e:
        return APIResponse(success=False, error=str(e))


@router.get("/local-info", response_model=APIResponse[LocalNetworkInfo])
async def get_local_network_info(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get information about the local network.
    """
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except:
        hostname = "unknown"
        local_ip = "127.0.0.1"
    
    return APIResponse(
        success=True,
        data=LocalNetworkInfo(
            hostname=hostname,
            local_ip=local_ip,
            common_private_ranges=[
                PrivateRangeInfo(range="10.0.0.0/8", description="Class A Private Network"),
                PrivateRangeInfo(range="172.16.0.0/12", description="Class B Private Network"),
                PrivateRangeInfo(range="192.168.0.0/16", description="Class C Private Network")
            ]
        )
    )


def _is_local_ip(ip: str) -> bool:
    """Check if IP is a private/local address."""
    if ip == "N/A":
        return False
    
    try:
        parts = [int(p) for p in ip.split(".")]
        
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        
        # 127.0.0.0/8 (loopback)
        if parts[0] == 127:
            return True
        
        return False
    except:
        return False

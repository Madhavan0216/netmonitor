"""
Topology API Routes

REST endpoints for network topology data.
Provides data for Cytoscape.js visualization.

All responses follow APIResponse[T] pattern.
"""

from typing import Optional, List, Generic, TypeVar, Dict, Any, cast
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Query
from pydantic import BaseModel, Field

from app.api.auth import get_current_active_user
from app.database.models import User

router = APIRouter()


# =============================================================================
# Response Models
# =============================================================================

T = TypeVar('T')


class APIResponse(BaseModel, Generic[T]):
    """Standardized API response wrapper."""
    success: bool
    data: Optional[T] = None
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NodeData(BaseModel):
    """Node data for API response."""
    id: str
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    device_type: str
    device_role: str
    classification_confidence: float
    vendor: Optional[str] = None
    os_hint: Optional[str] = None
    services: List[str]
    is_local: bool
    is_gateway: bool
    packet_count: int
    byte_count: int
    connection_count: int
    first_seen: str
    last_seen: str
    activity_level: float
    alert_count: int
    is_active: bool


class EdgeData(BaseModel):
    """Edge data for API response."""
    id: str
    source: str
    target: str
    total_packets: int
    total_bytes: int
    bandwidth_kbps: float
    protocols: List[str]
    services: List[str]
    ports: List[int]
    direction: str
    packets_forward: int
    packets_reverse: int
    first_seen: str
    last_seen: str
    activity_level: float
    thickness: float
    is_active: bool


class TopologyStats(BaseModel):
    """Topology statistics."""
    total_nodes: int
    total_edges: int
    active_nodes: int
    active_edges: int
    local_nodes: int
    external_nodes: int


class TopologySnapshotData(BaseModel):
    """Complete topology snapshot."""
    nodes: List[NodeData]
    edges: List[EdgeData]
    timestamp: str
    stats: TopologyStats


class ClassificationEvidence(BaseModel):
    """Evidence for device classification."""
    factor: str
    weight: float
    observation: str
    timestamp: str


class AlternativeType(BaseModel):
    """Alternative device type classification."""
    type: str
    confidence: float


class DeviceClassificationData(BaseModel):
    """Device classification details."""
    device_type: str
    role: str
    confidence: float
    explanation: str
    evidence: List[ClassificationEvidence]
    alternative_types: List[AlternativeType]
    os_hint: Optional[str] = None
    vendor: Optional[str] = None
    services: List[str]


class NodeDetailsData(BaseModel):
    """Detailed node information."""
    node: NodeData
    classification: DeviceClassificationData
    connections: List[EdgeData]


class TopologyServiceStats(BaseModel):
    """Topology service statistics."""
    total_nodes: int
    known_ips: int
    gateway_ip: Optional[str] = None
    aggregator_stats: Dict[str, Any]
    classifications: Dict[str, int]


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/snapshot", response_model=APIResponse[TopologySnapshotData])
async def get_topology_snapshot(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get complete topology snapshot.
    
    Returns all nodes and edges with current metrics.
    Suitable for initial load and full refresh.
    """
    try:
        topology_service = request.app.state.topology_service
        snapshot = topology_service.get_snapshot()
        
        return APIResponse(
            success=True,
            data=TopologySnapshotData(
                nodes=[NodeData(**n.to_dict()) for n in snapshot.nodes],
                edges=[EdgeData(**e.to_dict()) for e in snapshot.edges],
                timestamp=snapshot.timestamp.isoformat(),
                stats=TopologyStats(
                    total_nodes=snapshot.total_nodes,
                    total_edges=snapshot.total_edges,
                    active_nodes=snapshot.active_nodes,
                    active_edges=snapshot.active_edges,
                    local_nodes=snapshot.local_nodes,
                    external_nodes=snapshot.external_nodes
                )
            )
        )
    except Exception as e:
        return cast("APIResponse[None]", APIResponse(success=False, error=str(e)))


@router.get("/active", response_model=APIResponse[TopologySnapshotData])
async def get_active_topology(
    request: Request,
    window_seconds: int = Query(60, ge=10, le=600, description="Activity window in seconds"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get only recently active nodes and edges.
    
    Filters to devices/connections with traffic in the specified window.
    Useful for focusing on current activity.
    """
    try:
        topology_service = request.app.state.topology_service
        snapshot = topology_service.get_active_topology(window_seconds)
        snapshot.calculate_stats()
        
        return APIResponse(
            success=True,
            data=TopologySnapshotData(
                nodes=[NodeData(**n.to_dict()) for n in snapshot.nodes],
                edges=[EdgeData(**e.to_dict()) for e in snapshot.edges],
                timestamp=snapshot.timestamp.isoformat(),
                stats=TopologyStats(
                    total_nodes=snapshot.total_nodes,
                    total_edges=snapshot.total_edges,
                    active_nodes=snapshot.active_nodes,
                    active_edges=snapshot.active_edges,
                    local_nodes=snapshot.local_nodes,
                    external_nodes=snapshot.external_nodes
                )
            )
        )
    except Exception as e:
        return cast("APIResponse[None]", APIResponse(success=False, error=str(e)))


@router.get("/nodes", response_model=APIResponse[List[NodeData]])
async def get_nodes(
    request: Request,
    device_type: Optional[str] = Query(None, description="Filter by device type"),
    is_local: Optional[bool] = Query(None, description="Filter by local/external"),
    min_packets: int = Query(0, ge=0, description="Minimum packet count"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get topology nodes with optional filtering.
    """
    try:
        topology_service = request.app.state.topology_service
        snapshot = topology_service.get_snapshot()
        
        nodes = snapshot.nodes
        
        # Apply filters
        if device_type:
            nodes = [n for n in nodes if n.device_type.value == device_type]
        if is_local is not None:
            nodes = [n for n in nodes if n.is_local == is_local]
        if min_packets > 0:
            nodes = [n for n in nodes if n.packet_count >= min_packets]
        
        return APIResponse(
            success=True,
            data=[NodeData(**n.to_dict()) for n in nodes]
        )
    except Exception as e:
        return cast("APIResponse[None]", APIResponse(success=False, error=str(e)))


@router.get("/nodes/{ip}", response_model=APIResponse[NodeDetailsData])
async def get_node_details(
    request: Request,
    ip: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get detailed information about a specific node.
    
    Includes:
    - Node metadata
    - Classification with evidence and explanation
    - All connections to/from this node
    """
    try:
        topology_service = request.app.state.topology_service
        details = topology_service.get_node_details(ip)
        
        if not details:
            return cast("APIResponse[None]", APIResponse(success=False, error=f"Node {ip} not found"))
        
        return APIResponse(
            success=True,
            data=NodeDetailsData(
                node=NodeData(**details["node"]),
                classification=DeviceClassificationData(**details["classification"]),
                connections=[EdgeData(**e) for e in details["connections"]]
            )
        )
    except Exception as e:
        return cast("APIResponse[None]", APIResponse(success=False, error=str(e)))


@router.get("/edges", response_model=APIResponse[List[EdgeData]])
async def get_edges(
    request: Request,
    min_packets: int = Query(1, ge=1, description="Minimum packet count"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get topology edges with optional filtering.
    """
    try:
        topology_service = request.app.state.topology_service
        snapshot = topology_service.get_snapshot()
        
        edges = snapshot.edges
        
        # Apply filters
        if min_packets > 1:
            edges = [e for e in edges if e.total_packets >= min_packets]
        if protocol:
            edges = [e for e in edges if protocol.upper() in [p.upper() for p in e.protocols]]
        
        return APIResponse(
            success=True,
            data=[EdgeData(**e.to_dict()) for e in edges]
        )
    except Exception as e:
        return cast("APIResponse[None]", APIResponse(success=False, error=str(e)))


@router.get("/stats", response_model=APIResponse[TopologyServiceStats])
async def get_topology_stats(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get topology service statistics.
    
    Includes node counts by device type, aggregator stats, etc.
    """
    try:
        topology_service = request.app.state.topology_service
        stats = topology_service.get_stats()
        
        return APIResponse(
            success=True,
            data=TopologyServiceStats(**stats)
        )
    except Exception as e:
        return cast("APIResponse[None]", APIResponse(success=False, error=str(e)))


@router.post("/cleanup", response_model=APIResponse[Dict[str, Any]])
async def cleanup_stale_topology(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Trigger cleanup of stale nodes and edges.
    
    Removes entries older than the configured threshold.
    """
    try:
        topology_service = request.app.state.topology_service
        removed = topology_service.cleanup_stale()
        
        return APIResponse(
            success=True,
            data={"removed_count": removed}
        )
    except Exception as e:
        return cast("APIResponse[None]", APIResponse(success=False, error=str(e)))


@router.post("/clear", response_model=APIResponse[Dict[str, Any]])
async def clear_topology(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Clear all topology data.
    
    Use with caution - removes all discovered nodes and edges.
    """
    try:
        topology_service = request.app.state.topology_service
        topology_service.clear()
        
        return APIResponse(
            success=True,
            data={"status": "cleared"}
        )
    except Exception as e:
        return cast("APIResponse[None]", APIResponse(success=False, error=str(e)))


@router.post("/set-gateway", response_model=APIResponse[Dict[str, Any]])
async def set_gateway(
    request: Request,
    gateway_ip: str = Query(..., description="Gateway IP address"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Set the network gateway IP.
    
    This helps the classifier correctly identify the gateway device.
    """
    try:
        topology_service = request.app.state.topology_service
        topology_service.set_gateway(gateway_ip)
        
        return APIResponse(
            success=True,
            data={"gateway_ip": gateway_ip, "status": "set"}
        )
    except Exception as e:
        return cast("APIResponse[None]", APIResponse(success=False, error=str(e)))

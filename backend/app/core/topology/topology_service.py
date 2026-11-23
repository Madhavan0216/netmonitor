"""
Topology Service

Central service coordinating device classification, traffic aggregation,
and topology state management for real-time network visualization.

Integrates with:
- PacketCapture for real-time packet data
- DeviceClassifier for node classification  
- TrafficAggregator for edge metrics
- WebSocketManager for real-time updates

Design: Event-driven, minimal latency, SOC-grade.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Callable, Any
from enum import Enum
import threading
import structlog

from app.core.topology.device_classifier import (
    DeviceClassifier, DeviceType, DeviceRole
)
from app.core.topology.traffic_aggregator import (
    TrafficAggregator, AggregatedEdge, FlowDirection
)

logger = structlog.get_logger(__name__)


class TopologyChangeType(str, Enum):
    """Types of topology changes for real-time updates."""
    NODE_ADDED = "node_added"
    NODE_UPDATED = "node_updated"
    NODE_REMOVED = "node_removed"
    EDGE_ADDED = "edge_added"
    EDGE_UPDATED = "edge_updated"
    EDGE_REMOVED = "edge_removed"
    FULL_REFRESH = "full_refresh"


@dataclass
class TopologyNode:
    """
    A node in the network topology.
    
    Enriched with classification, activity metrics,
    and visualization hints.
    """
    id: str  # IP address
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    
    # Classification
    device_type: DeviceType = DeviceType.UNKNOWN
    device_role: DeviceRole = DeviceRole.ENDPOINT
    classification_confidence: float = 0.0
    vendor: Optional[str] = None
    os_hint: Optional[str] = None
    services: List[str] = field(default_factory=lambda: [])
    
    # Network position
    is_local: bool = True
    is_gateway: bool = False
    subnet: Optional[str] = None
    
    # Activity metrics
    packet_count: int = 0
    byte_count: int = 0
    connection_count: int = 0
    
    # Timing
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Visualization hints
    activity_level: float = 0.0  # 0-1, for pulsing animation
    alert_count: int = 0  # For threat highlighting
    
    def calculate_activity(self, window_seconds: int = 30) -> float:
        """Calculate activity level for visualization."""
        age = (datetime.now(timezone.utc) - self.last_seen).total_seconds()
        if age > window_seconds:
            self.activity_level = 0.0
        else:
            self.activity_level = 1.0 - (age / window_seconds)
        return self.activity_level
    
    def to_dict(self) -> Dict[str, Any]:
        self.calculate_activity()
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "device_type": self.device_type.value,
            "device_role": self.device_role.value,
            "classification_confidence": round(self.classification_confidence, 2),
            "vendor": self.vendor,
            "os_hint": self.os_hint,
            "services": self.services[:5],
            "is_local": self.is_local,
            "is_gateway": self.is_gateway,
            "subnet": self.subnet,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "connection_count": self.connection_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "activity_level": round(self.activity_level, 2),
            "alert_count": self.alert_count,
            "is_active": self.activity_level > 0.1
        }


@dataclass
class TopologyEdge:
    """
    An edge in the network topology.
    
    Wraps AggregatedEdge with visualization metadata.
    """
    id: str  # "{source}-{target}"
    source: str
    target: str
    
    # Metrics (from TrafficAggregator)
    total_packets: int = 0
    total_bytes: int = 0
    bandwidth_kbps: float = 0.0
    
    # Protocol info
    protocols: List[str] = field(default_factory=lambda: [])
    services: List[str] = field(default_factory=lambda: [])
    ports: List[int] = field(default_factory=lambda: [])
    
    # Direction
    direction: FlowDirection = FlowDirection.BIDIRECTIONAL
    packets_forward: int = 0
    packets_reverse: int = 0
    
    # Timing
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Visualization
    activity_level: float = 0.0
    thickness: float = 1.0  # Normalized 1-10 based on traffic
    
    @classmethod
    def from_aggregated(cls, agg: AggregatedEdge) -> "TopologyEdge":
        """Create from AggregatedEdge."""
        edge = cls(
            id=f"{agg.source}-{agg.target}",
            source=agg.source,
            target=agg.target,
            total_packets=agg.total_packets,
            total_bytes=agg.total_bytes,
            protocols=list(agg.protocols),
            services=agg.services[:5],
            ports=sorted(list(agg.ports))[:10],
            direction=agg.direction,
            packets_forward=agg.packets_src_to_dst,
            packets_reverse=agg.packets_dst_to_src,
            first_seen=agg.first_seen,
            last_seen=agg.last_seen,
            activity_level=agg.activity_level
        )
        edge._calculate_bandwidth()
        return edge
    
    def _calculate_bandwidth(self):
        """Calculate bandwidth and thickness."""
        duration = max((self.last_seen - self.first_seen).total_seconds(), 1)
        self.bandwidth_kbps = round((self.total_bytes * 8 / 1000) / duration, 2)
        
        # Thickness: log scale, 1-10
        import math
        self.thickness = min(10, max(1, 1 + math.log10(max(self.total_packets, 1))))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "bandwidth_kbps": self.bandwidth_kbps,
            "protocols": self.protocols,
            "services": self.services,
            "ports": self.ports,
            "direction": self.direction.value,
            "packets_forward": self.packets_forward,
            "packets_reverse": self.packets_reverse,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "activity_level": round(self.activity_level, 2),
            "thickness": round(self.thickness, 1),
            "is_active": self.activity_level > 0.1
        }


@dataclass
class TopologySnapshot:
    """Complete topology state at a point in time."""
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Summary stats
    total_nodes: int = 0
    total_edges: int = 0
    active_nodes: int = 0
    active_edges: int = 0
    local_nodes: int = 0
    external_nodes: int = 0
    
    def calculate_stats(self):
        """Calculate summary statistics."""
        self.total_nodes = len(self.nodes)
        self.total_edges = len(self.edges)
        self.active_nodes = sum(1 for n in self.nodes if n.activity_level > 0.1)
        self.active_edges = sum(1 for e in self.edges if e.activity_level > 0.1)
        self.local_nodes = sum(1 for n in self.nodes if n.is_local)
        self.external_nodes = self.total_nodes - self.local_nodes
    
    def to_dict(self) -> Dict[str, Any]:
        self.calculate_stats()
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "timestamp": self.timestamp.isoformat(),
            "stats": {
                "total_nodes": self.total_nodes,
                "total_edges": self.total_edges,
                "active_nodes": self.active_nodes,
                "active_edges": self.active_edges,
                "local_nodes": self.local_nodes,
                "external_nodes": self.external_nodes
            }
        }


@dataclass
class TopologyChange:
    """A change event for real-time updates."""
    change_type: TopologyChangeType
    node: Optional[TopologyNode] = None
    edge: Optional[TopologyEdge] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "type": self.change_type.value,
            "timestamp": self.timestamp.isoformat()
        }
        if self.node:
            data["node"] = self.node.to_dict()
        if self.edge:
            data["edge"] = self.edge.to_dict()
        return data


class TopologyService:
    """
    Central topology management service.
    
    Responsibilities:
    - Maintain current topology state
    - Process packet events
    - Classify devices
    - Aggregate traffic
    - Emit change events for WebSocket
    - Provide snapshots for API
    """
    
    def __init__(
        self,
        stale_threshold_seconds: int = 300,
        update_interval_seconds: float = 1.0
    ):
        self._classifier = DeviceClassifier()
        self._aggregator = TrafficAggregator(stale_threshold_seconds)
        
        self._nodes: Dict[str, TopologyNode] = {}
        self._known_ips: Set[str] = set()
        self._gateway_ip: Optional[str] = None
        
        self._lock = threading.RLock()
        self._change_callbacks: List[Callable[[TopologyChange], None]] = []
        self._update_interval = update_interval_seconds
        
        # Pending changes buffer (for batched updates)
        self._pending_changes: List[TopologyChange] = []
        
        logger.info(
            "Topology service initialized",
            stale_threshold=stale_threshold_seconds,
            update_interval=update_interval_seconds
        )
    
    def set_gateway(self, ip: str):
        """Set the known gateway IP."""
        self._gateway_ip = ip
        if ip in self._nodes:
            self._nodes[ip].is_gateway = True
            self._nodes[ip].device_type = DeviceType.GATEWAY
    
    def on_change(self, callback: Callable[[TopologyChange], None]):
        """Register a callback for topology changes."""
        self._change_callbacks.append(callback)
    
    def process_packet(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        size: int,
        src_mac: Optional[str] = None,
        dst_mac: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        tcp_flags: Optional[str] = None
    ):
        """
        Process a packet and update topology.
        
        This is the main ingestion point, called for every captured packet.
        Optimized for high throughput.
        """
        with self._lock:
            # Update traffic aggregator
            self._aggregator.record_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                size=size,
                src_port=src_port,
                dst_port=dst_port,
                tcp_flags=tcp_flags
            )
            
            # Update source node
            src_is_new = src_ip not in self._known_ips
            self._update_node(
                ip=src_ip,
                mac=src_mac,
                protocol=protocol,
                as_source=True,
                port=src_port,
                size=size
            )
            if src_is_new:
                self._emit_change(TopologyChange(
                    change_type=TopologyChangeType.NODE_ADDED,
                    node=self._nodes[src_ip]
                ))
            
            # Update destination node
            dst_is_new = dst_ip not in self._known_ips
            self._update_node(
                ip=dst_ip,
                mac=dst_mac,
                protocol=protocol,
                as_source=False,
                port=dst_port,
                size=size
            )
            if dst_is_new:
                self._emit_change(TopologyChange(
                    change_type=TopologyChangeType.NODE_ADDED,
                    node=self._nodes[dst_ip]
                ))
    
    def _update_node(
        self,
        ip: str,
        mac: Optional[str],
        protocol: str,
        as_source: bool,
        port: Optional[int],
        size: int
    ):
        """Update or create a node."""
        now = datetime.now(timezone.utc)
        
        if ip not in self._nodes:
            self._nodes[ip] = TopologyNode(
                id=ip,
                ip_address=ip,
                is_local=self._is_local_ip(ip),
                first_seen=now
            )
            self._known_ips.add(ip)
        
        node = self._nodes[ip]
        node.last_seen = now
        node.packet_count += 1
        node.byte_count += size
        
        if mac and not node.mac_address:
            node.mac_address = mac
        
        # Update classifier profile
        src_ports = {port} if as_source and port else None
        dst_ports = {port} if not as_source and port else None
        
        self._classifier.update_profile(
            ip=ip,
            mac=mac,
            src_ports=src_ports,
            dst_ports=dst_ports,
            protocols={protocol},
            packet_count=1,
            bytes_sent=size if as_source else 0,
            bytes_received=0 if as_source else size,
            is_gateway_candidate=(ip == self._gateway_ip)
        )
        
        # Check if gateway
        if ip == self._gateway_ip:
            node.is_gateway = True
    
    def reclassify_all(self):
        """Reclassify all nodes with current data."""
        with self._lock:
            for ip, node in self._nodes.items():
                classification = self._classifier.classify(ip)
                node.device_type = classification.device_type
                node.device_role = classification.role
                node.classification_confidence = classification.confidence
                node.vendor = classification.vendor
                node.os_hint = classification.os_hint
                node.services = classification.services
    
    def get_snapshot(self) -> TopologySnapshot:
        """Get current topology snapshot."""
        with self._lock:
            # Reclassify nodes
            self.reclassify_all()
            
            # Build node list
            nodes = list(self._nodes.values())
            
            # Build edge list from aggregator
            agg_edges = self._aggregator.get_edges(min_packets=1)
            edges = [TopologyEdge.from_aggregated(e) for e in agg_edges]
            
            # Update node connection counts
            for node in nodes:
                node.connection_count = sum(
                    1 for e in edges 
                    if e.source == node.ip_address or e.target == node.ip_address
                )
            
            return TopologySnapshot(nodes=nodes, edges=edges)
    
    def get_node(self, ip: str) -> Optional[TopologyNode]:
        """Get a specific node."""
        with self._lock:
            return self._nodes.get(ip)
    
    def get_node_details(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get detailed node info including classification explanation."""
        with self._lock:
            node = self._nodes.get(ip)
            if not node:
                return None
            
            classification = self._classifier.classify(ip)
            edges = self._aggregator.get_edges_for_node(ip)
            
            return {
                "node": node.to_dict(),
                "classification": classification.to_dict(),
                "connections": [TopologyEdge.from_aggregated(e).to_dict() for e in edges],
                "profile": self._classifier.get_profile(ip)
            }
    
    def get_active_topology(self, window_seconds: int = 60) -> TopologySnapshot:
        """Get only recently active nodes and edges."""
        with self._lock:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
            
            active_nodes = [
                n for n in self._nodes.values()
                if n.last_seen > cutoff
            ]
            
            active_edges = [
                TopologyEdge.from_aggregated(e)
                for e in self._aggregator.get_active_edges(window_seconds)
            ]
            
            return TopologySnapshot(nodes=active_nodes, edges=active_edges)
    
    def cleanup_stale(self) -> int:
        """Remove stale nodes and flows."""
        with self._lock:
            removed = self._aggregator.cleanup_stale()
            
            # Remove stale nodes
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=self._aggregator._stale_threshold)  # type: ignore[access-private-usage]
            stale_ips = [
                ip for ip, node in self._nodes.items()
                if node.last_seen < cutoff
            ]
            
            for ip in stale_ips:
                node = self._nodes.pop(ip)
                self._known_ips.discard(ip)
                self._emit_change(TopologyChange(
                    change_type=TopologyChangeType.NODE_REMOVED,
                    node=node
                ))
                removed += 1
            
            return removed
    
    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics."""
        with self._lock:
            return {
                "total_nodes": len(self._nodes),
                "known_ips": len(self._known_ips),
                "gateway_ip": self._gateway_ip,
                "aggregator_stats": self._aggregator.get_stats(),
                "classifications": {
                    t.value: sum(
                        1 for n in self._nodes.values()
                        if n.device_type == t
                    )
                    for t in DeviceType
                }
            }
    
    def _emit_change(self, change: TopologyChange):
        """Emit a topology change to callbacks."""
        for callback in self._change_callbacks:
            try:
                callback(change)
            except Exception as e:
                logger.error("Topology change callback error", error=str(e))
    
    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is local/private."""
        try:
            parts = [int(p) for p in ip.split(".")]
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
            return False
        except:
            return False
    
    def clear(self):
        """Clear all topology data."""
        with self._lock:
            self._nodes.clear()
            self._known_ips.clear()
            self._classifier.clear()
            self._aggregator.clear()
            logger.info("Topology cleared")

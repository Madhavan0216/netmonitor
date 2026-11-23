"""
Traffic Flow Aggregator

Aggregates network traffic into flows for visualization.
Provides metrics for edge thickness, bandwidth calculation,
and protocol distribution per connection.

Design Goals:
- Real-time flow tracking
- Efficient memory usage (sliding windows)
- Rich metrics for visualization
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum
import threading
import structlog

logger = structlog.get_logger(__name__)


class FlowDirection(str, Enum):
    """Flow direction classification."""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BIDIRECTIONAL = "bidirectional"
    INTERNAL = "internal"


class ConnectionState(str, Enum):
    """TCP connection state tracking."""
    NEW = "new"
    ESTABLISHED = "established"
    CLOSING = "closing"
    CLOSED = "closed"
    UNKNOWN = "unknown"


@dataclass
class FlowKey:
    """Unique identifier for a network flow."""
    src_ip: str
    dst_ip: str
    protocol: str
    dst_port: Optional[int] = None
    
    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.protocol, self.dst_port))
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FlowKey):
            return False
        return (self.src_ip == other.src_ip and 
                self.dst_ip == other.dst_ip and
                self.protocol == other.protocol and
                self.dst_port == other.dst_port)
    
    def reversed(self) -> "FlowKey":
        """Get the reverse flow key."""
        return FlowKey(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            protocol=self.protocol,
            dst_port=self.dst_port
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "dst_port": self.dst_port
        }


@dataclass
class FlowMetrics:
    """Metrics for a single flow."""
    packet_count: int = 0
    byte_count: int = 0
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Per-second rates (calculated)
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    
    # Protocol breakdown
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    other_packets: int = 0
    
    # TCP flags seen (for state tracking)
    tcp_flags_seen: Set[str] = field(default_factory=lambda: set())
    
    # Connection state
    connection_state: ConnectionState = ConnectionState.UNKNOWN
    
    def update_rates(self):
        """Recalculate per-second rates."""
        duration = (self.last_seen - self.first_seen).total_seconds()
        if duration > 0:
            self.packets_per_second = self.packet_count / duration
            self.bytes_per_second = self.byte_count / duration
    
    def to_dict(self) -> Dict[str, Any]:
        self.update_rates()
        return {
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "packets_per_second": round(self.packets_per_second, 2),
            "bytes_per_second": round(self.bytes_per_second, 2),
            "bandwidth_kbps": round(self.bytes_per_second * 8 / 1000, 2),
            "protocol_breakdown": {
                "tcp": self.tcp_packets,
                "udp": self.udp_packets,
                "icmp": self.icmp_packets,
                "other": self.other_packets
            },
            "connection_state": self.connection_state.value
        }


@dataclass 
class AggregatedEdge:
    """
    Aggregated edge for visualization.
    
    Combines bidirectional flows between two hosts.
    """
    source: str
    target: str
    
    # Aggregate metrics
    total_packets: int = 0
    total_bytes: int = 0
    
    # Directional metrics
    packets_src_to_dst: int = 0
    packets_dst_to_src: int = 0
    bytes_src_to_dst: int = 0
    bytes_dst_to_src: int = 0
    
    # Protocols used
    protocols: Set[str] = field(default_factory=lambda: set())
    
    # Ports used
    ports: Set[int] = field(default_factory=lambda: set())
    
    # Services detected
    services: List[str] = field(default_factory=lambda: [])
    
    # Timing
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Activity level (for animation)
    activity_level: float = 0.0  # 0.0 to 1.0
    
    # Flow direction
    direction: FlowDirection = FlowDirection.BIDIRECTIONAL
    
    def calculate_activity(self, window_seconds: int = 10) -> float:
        """Calculate recent activity level (0-1)."""
        now = datetime.now(timezone.utc)
        age = (now - self.last_seen).total_seconds()
        
        if age > window_seconds:
            return 0.0
        
        # Decay based on recency
        recency_factor = 1.0 - (age / window_seconds)
        
        # Scale by packet rate (normalize to reasonable range)
        duration = max((self.last_seen - self.first_seen).total_seconds(), 1)
        pps = self.total_packets / duration
        rate_factor = min(pps / 100, 1.0)  # Cap at 100 pps
        
        self.activity_level = recency_factor * (0.5 + 0.5 * rate_factor)
        return self.activity_level
    
    def to_dict(self) -> Dict[str, Any]:
        self.calculate_activity()
        
        return {
            "source": self.source,
            "target": self.target,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "bandwidth_kbps": self._calculate_bandwidth(),
            "packets_src_to_dst": self.packets_src_to_dst,
            "packets_dst_to_src": self.packets_dst_to_src,
            "bytes_src_to_dst": self.bytes_src_to_dst,
            "bytes_dst_to_src": self.bytes_dst_to_src,
            "protocols": list(self.protocols),
            "ports": sorted(list(self.ports))[:10],  # Limit for display
            "services": self.services[:5],
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "activity_level": round(self.activity_level, 2),
            "direction": self.direction.value,
            "is_active": self.activity_level > 0.1
        }
    
    def _calculate_bandwidth(self) -> float:
        """Calculate bandwidth in kbps."""
        duration = max((self.last_seen - self.first_seen).total_seconds(), 1)
        return round((self.total_bytes * 8 / 1000) / duration, 2)


# =============================================================================
# Port to Service Mapping
# =============================================================================

PORT_SERVICES: Dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 5060: "SIP", 554: "RTSP"
}


class TrafficAggregator:
    """
    Aggregates network traffic into flows and edges for visualization.
    
    Features:
    - Real-time flow tracking
    - Bidirectional flow merging
    - Automatic stale flow cleanup
    - Activity level calculation for animations
    """
    
    def __init__(self, stale_threshold_seconds: int = 300):
        self._flows: Dict[FlowKey, FlowMetrics] = {}
        self._edges: Dict[Tuple[str, str], AggregatedEdge] = {}  # (min_ip, max_ip) -> edge
        self._stale_threshold = stale_threshold_seconds
        self._lock = threading.Lock()
        
        # Statistics
        self._total_packets = 0
        self._total_bytes = 0
        
        logger.info("Traffic aggregator initialized", stale_threshold=stale_threshold_seconds)
    
    def record_packet(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        size: int,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        tcp_flags: Optional[str] = None
    ):
        """Record a packet and update flow/edge metrics."""
        now = datetime.now(timezone.utc)
        
        with self._lock:
            self._total_packets += 1
            self._total_bytes += size
            
            # === Update Flow ===
            flow_key = FlowKey(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                dst_port=dst_port
            )
            
            if flow_key not in self._flows:
                self._flows[flow_key] = FlowMetrics(first_seen=now)
            
            flow = self._flows[flow_key]
            flow.packet_count += 1
            flow.byte_count += size
            flow.last_seen = now
            
            # Protocol breakdown
            proto_upper = protocol.upper()
            if proto_upper == "TCP":
                flow.tcp_packets += 1
                if tcp_flags:
                    flow.tcp_flags_seen.add(tcp_flags)
                    flow.connection_state = self._infer_tcp_state(flow.tcp_flags_seen)
            elif proto_upper == "UDP":
                flow.udp_packets += 1
            elif proto_upper == "ICMP":
                flow.icmp_packets += 1
            else:
                flow.other_packets += 1
            
            # === Update Edge (bidirectional) ===
            edge_key: Tuple[str, str] = (min(src_ip, dst_ip), max(src_ip, dst_ip))
            
            if edge_key not in self._edges:
                self._edges[edge_key] = AggregatedEdge(
                    source=edge_key[0],
                    target=edge_key[1],
                    first_seen=now
                )
            
            edge = self._edges[edge_key]
            edge.total_packets += 1
            edge.total_bytes += size
            edge.last_seen = now
            edge.protocols.add(protocol)
            
            if dst_port:
                edge.ports.add(dst_port)
                if dst_port in PORT_SERVICES:
                    service = PORT_SERVICES[dst_port]
                    if service not in edge.services:
                        edge.services.append(service)
            
            # Directional tracking
            if src_ip == edge_key[0]:
                edge.packets_src_to_dst += 1
                edge.bytes_src_to_dst += size
            else:
                edge.packets_dst_to_src += 1
                edge.bytes_dst_to_src += size
            
            # Determine direction type
            if edge.packets_src_to_dst > 0 and edge.packets_dst_to_src > 0:
                edge.direction = FlowDirection.BIDIRECTIONAL
            elif edge.packets_src_to_dst > edge.packets_dst_to_src:
                edge.direction = FlowDirection.OUTBOUND
            else:
                edge.direction = FlowDirection.INBOUND
    
    def _infer_tcp_state(self, flags_seen: Set[str]) -> ConnectionState:
        """Infer TCP connection state from observed flags."""
        if "S" in flags_seen and "A" in flags_seen and "F" not in flags_seen:
            return ConnectionState.ESTABLISHED
        elif "F" in flags_seen or "R" in flags_seen:
            return ConnectionState.CLOSED
        elif "S" in flags_seen and "A" not in flags_seen:
            return ConnectionState.NEW
        return ConnectionState.UNKNOWN
    
    def get_edges(self, min_packets: int = 1) -> List[AggregatedEdge]:
        """Get all edges with at least min_packets."""
        with self._lock:
            return [
                edge for edge in self._edges.values()
                if edge.total_packets >= min_packets
            ]
    
    def get_edges_for_node(self, ip: str) -> List[AggregatedEdge]:
        """Get all edges connected to a specific node."""
        with self._lock:
            return [
                edge for key, edge in self._edges.items()
                if ip in key
            ]
    
    def get_active_edges(self, window_seconds: int = 30) -> List[AggregatedEdge]:
        """Get edges with recent activity."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        with self._lock:
            return [
                edge for edge in self._edges.values()
                if edge.last_seen > cutoff
            ]
    
    def get_flow(self, flow_key: FlowKey) -> Optional[FlowMetrics]:
        """Get metrics for a specific flow."""
        with self._lock:
            return self._flows.get(flow_key)
    
    def get_all_flows(self) -> Dict[FlowKey, FlowMetrics]:
        """Get all flows."""
        with self._lock:
            return self._flows.copy()
    
    def get_top_talkers(self, limit: int = 10) -> List[Tuple[str, int, int]]:
        """Get top talking IPs by packet count. Returns [(ip, packets, bytes)]."""
        ip_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
        
        with self._lock:
            for edge in self._edges.values():
                ip_stats[edge.source]["packets"] += edge.packets_src_to_dst
                ip_stats[edge.source]["bytes"] += edge.bytes_src_to_dst
                ip_stats[edge.target]["packets"] += edge.packets_dst_to_src
                ip_stats[edge.target]["bytes"] += edge.bytes_dst_to_src
        
        sorted_ips = sorted(
            ip_stats.items(),
            key=lambda x: x[1]["packets"],
            reverse=True
        )
        
        return [
            (ip, stats["packets"], stats["bytes"])
            for ip, stats in sorted_ips[:limit]
        ]
    
    def cleanup_stale(self) -> int:
        """Remove stale flows and edges. Returns count removed."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self._stale_threshold)
        removed = 0
        
        with self._lock:
            # Clean flows
            stale_flows = [
                key for key, flow in self._flows.items()
                if flow.last_seen < cutoff
            ]
            for key in stale_flows:
                del self._flows[key]
                removed += 1
            
            # Clean edges
            stale_edges = [
                key for key, edge in self._edges.items()
                if edge.last_seen < cutoff
            ]
            for key in stale_edges:
                del self._edges[key]
                removed += 1
        
        if removed > 0:
            logger.debug("Cleaned stale traffic data", removed=removed)
        
        return removed
    
    def get_stats(self) -> Dict[str, Any]:
        """Get aggregator statistics."""
        with self._lock:
            return {
                "total_packets": self._total_packets,
                "total_bytes": self._total_bytes,
                "active_flows": len(self._flows),
                "active_edges": len(self._edges),
                "stale_threshold_seconds": self._stale_threshold
            }
    
    def clear(self):
        """Clear all data."""
        with self._lock:
            self._flows.clear()
            self._edges.clear()
            self._total_packets = 0
            self._total_bytes = 0

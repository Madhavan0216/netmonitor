# Topology service module
"""
Network Topology Subsystem

Provides real-time network visualization data:
- TopologyService: Central coordinator for nodes, edges, and state
- DeviceClassifier: Passive device fingerprinting (MAC OUI, port analysis, traffic patterns)
- TrafficAggregator: Flow aggregation with edge metrics and bandwidth calculation
"""

from app.core.topology.topology_service import (
    TopologyService,
    TopologyNode,
    TopologyEdge,
    TopologySnapshot,
    TopologyChange,
    TopologyChangeType
)
from app.core.topology.device_classifier import (
    DeviceClassifier,
    DeviceType,
    DeviceRole,
    DeviceClassification,
    ClassificationEvidence
)
from app.core.topology.traffic_aggregator import (
    TrafficAggregator,
    FlowDirection,
    ConnectionState,
    AggregatedEdge,
    FlowMetrics
)

__all__ = [
    # Topology Service
    "TopologyService",
    "TopologyNode",
    "TopologyEdge",
    "TopologySnapshot",
    "TopologyChange",
    "TopologyChangeType",
    # Device Classification
    "DeviceClassifier",
    "DeviceType",
    "DeviceRole",
    "DeviceClassification",
    "ClassificationEvidence",
    # Traffic Aggregation
    "TrafficAggregator",
    "FlowDirection",
    "ConnectionState",
    "AggregatedEdge",
    "FlowMetrics"
]

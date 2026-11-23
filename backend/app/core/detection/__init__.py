"""
Detection Engine Module

Provides explainable, trustworthy threat detection.

Core components:
- DetectionEngine: Main engine orchestrating all detections
- DetectionEvent: Structured alert with evidence

Advanced rules:
- LateralMovementDetector: Internal-to-internal admin port scanning
- BeaconingDetector: C2 callback pattern detection
- BroadcastAbuseDetector: Broadcast storm and rogue DHCP detection
- NewDeviceScorer: Risk assessment for new devices

Correlation:
- CorrelationEngine: Multi-signal attack chain detection

Evidence model:
- DetectionEvidence: Complete evidence package
- EvidenceItem: Individual evidence pieces
- ConfidenceScore: Calculated, justified confidence
"""

from app.core.detection.engine import (
    DetectionEngine,
    DetectionEvent,
    DetectionSeverity,
    FalsePositiveLikelihood,
    SlidingWindowCounter
)

from app.core.detection.evidence import (
    EvidenceItem,
    EvidenceType,
    TimeWindow,
    ConfidenceScore,
    FalsePositiveAssessment,
    FalsePositiveReason,
    AdminAction,
    DetectionEvidence,
    build_threshold_evidence,
    build_scan_evidence,
    build_timing_evidence,
    calculate_confidence
)

from app.core.detection.rules import (
    LateralMovementDetector,
    BeaconingDetector,
    BroadcastAbuseDetector,
    NewDeviceScorer
)

from app.core.detection.correlation import (
    CorrelationEngine,
    AttackChain,
    AttackPhase,
    correlation_engine
)

__all__ = [
    # Core
    "DetectionEngine",
    "DetectionEvent",
    "DetectionSeverity",
    "FalsePositiveLikelihood",
    "SlidingWindowCounter",
    
    # Evidence
    "EvidenceItem",
    "EvidenceType",
    "TimeWindow",
    "ConfidenceScore",
    "FalsePositiveAssessment",
    "FalsePositiveReason",
    "AdminAction",
    "DetectionEvidence",
    "build_threshold_evidence",
    "build_scan_evidence",
    "build_timing_evidence",
    "calculate_confidence",
    
    # Advanced Rules
    "LateralMovementDetector",
    "BeaconingDetector",
    "BroadcastAbuseDetector",
    "NewDeviceScorer",
    
    # Correlation
    "CorrelationEngine",
    "AttackChain",
    "AttackPhase",
    "correlation_engine"
]

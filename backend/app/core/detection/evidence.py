"""
Evidence Model for Explainable Detections

Every detection MUST include structured evidence that justifies the alert.
No hidden heuristics. No "AI decided." Everything is auditable.

Design principles:
1. Evidence objects are immutable snapshots
2. Time windows are explicit
3. Thresholds are documented
4. Confidence is calculated, not guessed
5. False-positive likelihood is based on observable factors
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
import hashlib


class EvidenceType(str, Enum):
    """Types of evidence that support a detection."""
    PACKET_COUNT = "packet_count"           # Number of packets matching criteria
    UNIQUE_TARGETS = "unique_targets"       # Unique destination IPs/ports
    TIME_PATTERN = "time_pattern"           # Timing-based evidence (intervals)
    THRESHOLD_BREACH = "threshold_breach"   # Value exceeded threshold
    STATE_CHANGE = "state_change"           # Something changed (MAC, etc.)
    BEHAVIORAL = "behavioral"               # Pattern of behavior over time
    CORRELATION = "correlation"             # Multiple signals combined
    STATISTICAL = "statistical"             # Statistical anomaly


class ConfidenceFactors(str, Enum):
    """Factors that affect confidence in a detection."""
    SAMPLE_SIZE = "sample_size"             # More samples = more confidence
    TIME_WINDOW = "time_window"             # Longer observation = more confidence
    BASELINE_DEVIATION = "baseline_deviation"  # How far from normal
    CORROBORATING_EVIDENCE = "corroborating_evidence"  # Multiple indicators
    KNOWN_PATTERN = "known_pattern"         # Matches known attack signature


@dataclass
class EvidenceItem:
    """
    A single piece of evidence supporting a detection.
    
    Example:
        EvidenceItem(
            type=EvidenceType.PACKET_COUNT,
            key="syn_packets",
            value=150,
            threshold=100,
            description="SYN packets without ACK",
            raw_data={"packet_hashes": [...]}
        )
    """
    type: EvidenceType
    key: str                                # What was measured
    value: Any                              # The measured value
    threshold: Optional[Any] = None         # The threshold (if applicable)
    unit: str = ""                          # Unit of measurement
    description: str = ""                   # Human-readable description
    raw_data: Dict[str, Any] = field(default_factory=lambda: {})  # Supporting data
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value if type(self.type) is EvidenceType else self.type,
            "key": self.key,
            "value": self.value,
            "threshold": self.threshold,
            "unit": self.unit,
            "description": self.description,
            "raw_data": self.raw_data
        }
    
    def exceeds_threshold(self) -> bool:
        """Check if value exceeds threshold."""
        if self.threshold is None:
            return False
        try:
            return self.value >= self.threshold
        except TypeError:
            return False


@dataclass
class TimeWindow:
    """
    Explicit time window for a detection.
    
    Every detection must specify when the suspicious activity occurred.
    """
    start: datetime
    end: datetime
    duration_seconds: int = field(init=False)
    
    def __post_init__(self):
        self.duration_seconds = int((self.end - self.start).total_seconds())
    
    @classmethod
    def last_n_seconds(cls, seconds: int) -> 'TimeWindow':
        """Create a time window for the last N seconds."""
        end = datetime.now(timezone.utc)
        start = end - timedelta(seconds=seconds)
        return cls(start=start, end=end)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "duration_seconds": self.duration_seconds
        }


@dataclass
class ConfidenceScore:
    """
    Calculated confidence score with justification.
    
    Confidence is NOT a magic number. It's calculated from observable factors:
    - Base confidence from rule design (how reliable is this detection type?)
    - Adjustments based on evidence quality
    - Adjustments based on corroboration
    
    Final score is clamped to [0.0, 1.0]
    """
    base_score: float                       # Starting confidence (from rule design)
    adjustments: List[Tuple[str, float]] = field(default_factory=lambda: [])
    final_score: float = field(init=False)
    
    # Limits for sanity
    MIN_CONFIDENCE = 0.1
    MAX_CONFIDENCE = 0.99
    
    def __post_init__(self):
        score = self.base_score
        for _, adjustment in self.adjustments:
            score += adjustment
        self.final_score = max(self.MIN_CONFIDENCE, min(self.MAX_CONFIDENCE, score))
    
    def add_adjustment(self, reason: str, adjustment: float):
        """Add a confidence adjustment with reason."""
        self.adjustments.append((reason, adjustment))
        self.__post_init__()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_score": self.base_score,
            "adjustments": [{"reason": r, "value": v} for r, v in self.adjustments],
            "final_score": round(self.final_score, 3)
        }


class FalsePositiveReason(str, Enum):
    """Common reasons for false positives."""
    LEGITIMATE_SCANNER = "legitimate_scanner"
    BACKUP_ACTIVITY = "backup_activity"
    SOFTWARE_UPDATE = "software_update"
    DHCP_CHANGE = "dhcp_change"
    DEVICE_REPLACEMENT = "device_replacement"
    MONITORING_TOOL = "monitoring_tool"
    HIGH_BANDWIDTH_APP = "high_bandwidth_app"
    GAMING = "gaming"
    STREAMING = "streaming"
    VPN_TRAFFIC = "vpn_traffic"
    CLOUD_SYNC = "cloud_sync"


@dataclass
class FalsePositiveAssessment:
    """
    Structured assessment of false-positive likelihood.
    
    Not just "low/medium/high" but WHY we think so.
    """
    likelihood: str  # low, medium, high
    score: float     # 0.0 (definitely real) to 1.0 (definitely false positive)
    possible_reasons: List[FalsePositiveReason] = field(default_factory=lambda: [])
    mitigation_hints: List[str] = field(default_factory=lambda: [])
    
    @classmethod
    def calculate(
        cls,
        evidence: List[EvidenceItem],
        known_benign_patterns: Optional[List[str]] = None
    ) -> 'FalsePositiveAssessment':
        """Calculate FP likelihood from evidence."""
        score = 0.3  # Start neutral
        reasons: List[FalsePositiveReason] = []
        hints: List[str] = []
        
        # Adjust based on evidence strength
        for item in evidence:
            if item.type == EvidenceType.PACKET_COUNT:
                if item.threshold and item.value:
                    ratio = item.value / item.threshold
                    if ratio > 5:
                        score -= 0.2  # Very high = less likely FP
                    elif ratio < 1.5:
                        score += 0.1  # Barely over threshold = more likely FP
            
            if item.type == EvidenceType.CORRELATION:
                score -= 0.15  # Correlated evidence = less likely FP
        
        # Classify
        if score <= 0.3:
            likelihood = "low"
        elif score <= 0.6:
            likelihood = "medium"
        else:
            likelihood = "high"
        
        return cls(
            likelihood=likelihood,
            score=max(0.0, min(1.0, score)),
            possible_reasons=reasons,
            mitigation_hints=hints
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "likelihood": self.likelihood,
            "score": round(self.score, 3),
            "possible_reasons": [r.value for r in self.possible_reasons],
            "mitigation_hints": self.mitigation_hints
        }


@dataclass
class AdminAction:
    """
    Recommended action for the administrator.
    
    Clear, actionable steps - not vague suggestions.
    """
    priority: str  # immediate, soon, when_convenient
    summary: str   # One-line summary
    steps: List[str] = field(default_factory=lambda: [])
    automated_options: List[str] = field(default_factory=lambda: [])  # What can be auto-remediated
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "priority": self.priority,
            "summary": self.summary,
            "steps": self.steps,
            "automated_options": self.automated_options
        }


@dataclass
class DetectionEvidence:
    """
    Complete evidence package for a detection.
    
    This is the "proof" that justifies an alert. Every field is required
    because every detection must be explainable and auditable.
    """
    # When did this happen?
    time_window: TimeWindow
    
    # What did we observe?
    evidence_items: List[EvidenceItem]
    
    # How confident are we?
    confidence: ConfidenceScore
    
    # Could this be a false positive?
    false_positive: FalsePositiveAssessment
    
    # What should the admin do?
    recommended_action: AdminAction
    
    # Additional context
    related_ips: List[str] = field(default_factory=lambda: [])
    related_alerts: List[int] = field(default_factory=lambda: [])  # Alert IDs
    tags: List[str] = field(default_factory=lambda: [])
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window.to_dict(),
            "evidence_items": [e.to_dict() for e in self.evidence_items],
            "confidence": self.confidence.to_dict(),
            "false_positive": self.false_positive.to_dict(),
            "recommended_action": self.recommended_action.to_dict(),
            "related_ips": self.related_ips,
            "related_alerts": self.related_alerts,
            "tags": self.tags
        }
    
    def get_evidence_summary(self) -> str:
        """Generate a human-readable evidence summary."""
        lines: List[str] = []
        for item in self.evidence_items:
            if item.threshold:
                lines.append(
                    f"• {item.description}: {item.value} {item.unit} "
                    f"(threshold: {item.threshold})"
                )
            else:
                lines.append(f"• {item.description}: {item.value} {item.unit}")
        return "\n".join(lines)
    
    def evidence_hash(self) -> str:
        """Generate a hash of the evidence for deduplication."""
        data = str(sorted([
            (e.key, e.value) for e in self.evidence_items
        ]))
        return hashlib.sha256(data.encode()).hexdigest()[:16]


# =============================================================================
# Evidence Builders (Factory functions for common patterns)
# =============================================================================

def build_threshold_evidence(
    metric_name: str,
    observed_value: int,
    threshold: int,
    window_seconds: int,
    unit: str = "events"
) -> Tuple[EvidenceItem, TimeWindow]:
    """Build evidence for a simple threshold breach."""
    evidence = EvidenceItem(
        type=EvidenceType.THRESHOLD_BREACH,
        key=metric_name,
        value=observed_value,
        threshold=threshold,
        unit=unit,
        description=f"Observed {metric_name} count exceeded threshold"
    )
    window = TimeWindow.last_n_seconds(window_seconds)
    return evidence, window


def build_scan_evidence(
    source_ip: str,
    unique_ports: List[int],
    unique_hosts: List[str],
    window_seconds: int
) -> List[EvidenceItem]:
    """Build evidence for scanning activity."""
    items: List[EvidenceItem] = []
    
    if unique_ports:
        items.append(EvidenceItem(
            type=EvidenceType.UNIQUE_TARGETS,
            key="unique_destination_ports",
            value=len(unique_ports),
            unit="ports",
            description="Unique destination ports contacted",
            raw_data={"ports": sorted(unique_ports)[:20]}  # Cap for readability
        ))
    
    if unique_hosts:
        items.append(EvidenceItem(
            type=EvidenceType.UNIQUE_TARGETS,
            key="unique_destination_hosts",
            value=len(unique_hosts),
            unit="hosts",
            description="Unique hosts contacted",
            raw_data={"hosts": sorted(unique_hosts)[:20]}
        ))
    
    return items


def build_timing_evidence(
    intervals: List[float],
    regularity_threshold: float = 0.1
) -> Optional[EvidenceItem]:
    """
    Build evidence for timing patterns (beaconing).
    
    Returns evidence if intervals are suspiciously regular.
    """
    if len(intervals) < 3:
        return None
    
    import statistics
    mean = statistics.mean(intervals)
    if mean == 0:
        return None
    
    try:
        stdev = statistics.stdev(intervals)
        coefficient_of_variation = stdev / mean
    except statistics.StatisticsError:
        return None
    
    # Low CV = regular intervals = suspicious
    if coefficient_of_variation <= regularity_threshold:
        return EvidenceItem(
            type=EvidenceType.TIME_PATTERN,
            key="interval_regularity",
            value=round(coefficient_of_variation, 4),
            threshold=regularity_threshold,
            unit="CV",
            description="Coefficient of variation of connection intervals (lower = more regular)",
            raw_data={
                "mean_interval_seconds": round(mean, 2),
                "stdev_seconds": round(stdev, 2),
                "sample_count": len(intervals)
            }
        )
    
    return None


def calculate_confidence(
    base: float,
    sample_size: int,
    min_samples: int = 5,
    has_corroboration: bool = False,
    threshold_ratio: float = 1.0
) -> ConfidenceScore:
    """
    Calculate confidence score with explicit reasoning.
    
    Args:
        base: Base confidence from rule design (0.5-0.9)
        sample_size: Number of observations
        min_samples: Minimum samples for full confidence
        has_corroboration: Whether other detections support this
        threshold_ratio: How much the value exceeds threshold (1.0 = at threshold)
    """
    score = ConfidenceScore(base_score=base)
    
    # Sample size adjustment
    if sample_size < min_samples:
        score.add_adjustment(
            f"Low sample size ({sample_size} < {min_samples})",
            -0.15
        )
    elif sample_size > min_samples * 3:
        score.add_adjustment(
            f"Large sample size ({sample_size} observations)",
            +0.1
        )
    
    # Threshold ratio adjustment
    if threshold_ratio > 3.0:
        score.add_adjustment(
            f"Significantly above threshold ({threshold_ratio:.1f}x)",
            +0.15
        )
    elif threshold_ratio < 1.5:
        score.add_adjustment(
            f"Marginally above threshold ({threshold_ratio:.1f}x)",
            -0.1
        )
    
    # Corroboration
    if has_corroboration:
        score.add_adjustment(
            "Corroborated by related detections",
            +0.1
        )
    
    return score

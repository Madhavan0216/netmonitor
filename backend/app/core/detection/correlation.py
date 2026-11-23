"""
Correlation Engine

Correlates multiple detection signals to identify complex attack patterns.
Uses simple state machines - no ML, fully explainable.

Design principles:
1. Every correlation is documented
2. State transitions are explicit
3. No hidden heuristics
4. All logic is auditable
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import threading
import structlog

from app.core.detection.engine import DetectionEvent, DetectionSeverity, FalsePositiveLikelihood
from app.core.detection.evidence import (
    EvidenceItem, EvidenceType, TimeWindow, ConfidenceScore,
    FalsePositiveAssessment, AdminAction, DetectionEvidence
)

logger = structlog.get_logger(__name__)


# =============================================================================
# Attack Pattern Definitions
# =============================================================================

class AttackPhase(str, Enum):
    """Phases of a typical attack lifecycle."""
    RECONNAISSANCE = "reconnaissance"   # Scanning, enumeration
    INITIAL_ACCESS = "initial_access"   # First foothold
    LATERAL_MOVEMENT = "lateral_movement"  # Moving through network
    PERSISTENCE = "persistence"         # Maintaining access
    EXFILTRATION = "exfiltration"       # Data theft
    COMMAND_CONTROL = "command_control"  # C2 communication


@dataclass
class CorrelatedIndicator:
    """A detection that contributes to a correlated alert."""
    rule_id: str
    timestamp: datetime
    source_ip: str
    severity: str
    summary: str
    phase: AttackPhase


@dataclass
class AttackChain:
    """
    A chain of related attack indicators.
    
    Attack chains represent the progression of an attack through
    multiple phases. Each indicator strengthens the overall assessment.
    """
    id: str
    primary_source_ip: str
    start_time: datetime
    last_update: datetime
    indicators: List[CorrelatedIndicator] = field(default_factory=lambda: [])
    phases_observed: Set[AttackPhase] = field(default_factory=lambda: set())
    confidence: float = 0.0
    
    def add_indicator(self, indicator: CorrelatedIndicator):
        """Add an indicator to the chain."""
        self.indicators.append(indicator)
        self.phases_observed.add(indicator.phase)
        self.last_update = datetime.now(timezone.utc)
        self._recalculate_confidence()
    
    def _recalculate_confidence(self):
        """Recalculate confidence based on indicators."""
        # Base confidence from number of indicators
        self.confidence = min(0.5 + (len(self.indicators) * 0.1), 0.95)
        
        # Bonus for multiple phases (more complete attack picture)
        if len(self.phases_observed) >= 3:
            self.confidence = min(self.confidence + 0.15, 0.95)
        elif len(self.phases_observed) >= 2:
            self.confidence = min(self.confidence + 0.1, 0.95)
    
    def get_severity(self) -> DetectionSeverity:
        """Determine severity based on attack progression."""
        critical_phases = {
            AttackPhase.LATERAL_MOVEMENT,
            AttackPhase.EXFILTRATION,
            AttackPhase.PERSISTENCE
        }
        
        if self.phases_observed & critical_phases:
            return DetectionSeverity.CRITICAL
        
        if len(self.indicators) >= 3:
            return DetectionSeverity.WARNING
        
        return DetectionSeverity.INFO


# =============================================================================
# State Machine for Attack Patterns
# =============================================================================

class AttackStateMachine:
    """
    State machine for tracking attack patterns.
    
    States:
    - IDLE: No suspicious activity
    - RECON_DETECTED: Reconnaissance activity observed
    - ACCESS_DETECTED: Potential initial access
    - ACTIVE_ATTACK: Attack in progress
    - POST_COMPROMISE: Post-compromise activity
    
    Transitions are based on detection events with explicit rules.
    """
    
    class State(str, Enum):
        IDLE = "idle"
        RECON_DETECTED = "recon_detected"
        ACCESS_DETECTED = "access_detected"
        ACTIVE_ATTACK = "active_attack"
        POST_COMPROMISE = "post_compromise"
    
    # Which detections trigger which phases
    DETECTION_TO_PHASE = {
        # Reconnaissance
        "PORT_SCAN_DETECTION": AttackPhase.RECONNAISSANCE,
        "ICMP_SWEEP_DETECTION": AttackPhase.RECONNAISSANCE,
        "FAILED_CONN_DETECTION": AttackPhase.RECONNAISSANCE,
        
        # Initial Access / Exploit attempts
        "SUSPICIOUS_PORT": AttackPhase.INITIAL_ACCESS,
        "PACKET_FLOOD_DETECTION": AttackPhase.INITIAL_ACCESS,
        
        # Lateral Movement
        "LATERAL_MOVEMENT": AttackPhase.LATERAL_MOVEMENT,
        "ARP_SPOOF_DETECTION": AttackPhase.LATERAL_MOVEMENT,
        
        # Persistence
        "ROGUE_DHCP": AttackPhase.PERSISTENCE,
        
        # C2 / Exfiltration
        "BEACONING_DETECTED": AttackPhase.COMMAND_CONTROL,
        "DNS_TUNNEL_DETECTION": AttackPhase.EXFILTRATION,
        "DNS_HIGH_RATE": AttackPhase.EXFILTRATION,
    }
    
    # State transitions
    TRANSITIONS: Dict["AttackStateMachine.State", Dict[AttackPhase, "AttackStateMachine.State"]] = {
        State.IDLE: {
            AttackPhase.RECONNAISSANCE: State.RECON_DETECTED,
            AttackPhase.INITIAL_ACCESS: State.ACCESS_DETECTED,
            AttackPhase.LATERAL_MOVEMENT: State.ACTIVE_ATTACK,
            AttackPhase.COMMAND_CONTROL: State.POST_COMPROMISE,
            AttackPhase.EXFILTRATION: State.POST_COMPROMISE,
        },
        State.RECON_DETECTED: {
            AttackPhase.INITIAL_ACCESS: State.ACCESS_DETECTED,
            AttackPhase.LATERAL_MOVEMENT: State.ACTIVE_ATTACK,
            AttackPhase.COMMAND_CONTROL: State.POST_COMPROMISE,
            AttackPhase.EXFILTRATION: State.POST_COMPROMISE,
        },
        State.ACCESS_DETECTED: {
            AttackPhase.LATERAL_MOVEMENT: State.ACTIVE_ATTACK,
            AttackPhase.PERSISTENCE: State.ACTIVE_ATTACK,
            AttackPhase.COMMAND_CONTROL: State.POST_COMPROMISE,
            AttackPhase.EXFILTRATION: State.POST_COMPROMISE,
        },
        State.ACTIVE_ATTACK: {
            AttackPhase.COMMAND_CONTROL: State.POST_COMPROMISE,
            AttackPhase.EXFILTRATION: State.POST_COMPROMISE,
        },
        State.POST_COMPROMISE: {
            # Stay in post-compromise for any further activity
        }
    }
    
    def __init__(self, source_ip: str):
        self.source_ip = source_ip
        self.state = self.State.IDLE
        self.state_history: List[Tuple[datetime, "AttackStateMachine.State", str]] = []
        self.last_transition = datetime.now(timezone.utc)
    
    def process_event(self, event: DetectionEvent) -> Optional[Tuple[State, State]]:
        """
        Process a detection event and potentially transition state.
        
        Returns:
            Tuple of (old_state, new_state) if transition occurred, else None
        """
        # Get the attack phase for this detection
        phase = self.DETECTION_TO_PHASE.get(event.rule_id)
        if not phase:
            return None
        
        # Check if this phase triggers a transition
        transitions = self.TRANSITIONS.get(self.state, {})
        new_state = transitions.get(phase)
        
        if new_state and new_state != self.state:
            old_state = self.state
            self.state = new_state
            self.last_transition = datetime.now(timezone.utc)
            self.state_history.append((
                datetime.now(timezone.utc),
                new_state,
                f"{event.rule_id} ({phase.value})"
            ))
            return (old_state, new_state)
        
        return None


# =============================================================================
# Correlation Engine
# =============================================================================

class CorrelationEngine:
    """
    Correlates multiple detections into attack chains.
    
    The engine:
    1. Tracks detections per source IP
    2. Maintains state machines for attack progression
    3. Generates correlated alerts when patterns emerge
    4. Provides timeline-based attack visualization
    """
    
    # Time window for correlation (detections within this window are related)
    CORRELATION_WINDOW = 900  # 15 minutes
    
    # Minimum indicators to trigger correlation alert
    MIN_INDICATORS = 2
    
    def __init__(self):
        # Attack chains by source IP
        self.attack_chains: Dict[str, AttackChain] = {}
        
        # State machines by source IP
        self.state_machines: Dict[str, AttackStateMachine] = {}
        
        # Recent detections for correlation
        self.recent_detections: Dict[str, List[DetectionEvent]] = defaultdict(list)
        
        self.lock = threading.Lock()
        self.chain_counter = 0
        
        logger.info("Correlation engine initialized")
    
    def process_detection(self, event: DetectionEvent) -> Optional[DetectionEvent]:
        """
        Process a detection event and check for correlations.
        
        Returns:
            A correlation alert if a pattern is detected, else None
        """
        if not event.source_ip:
            return None
        
        with self.lock:
            # Add to recent detections
            self._add_detection(event)
            
            # Update state machine
            self._update_state_machine(event)
            
            # Check for attack chain
            return self._check_correlation(event.source_ip)
    
    def _add_detection(self, event: DetectionEvent):
        """Add detection to tracking."""
        if event.source_ip is None:
            return
        self.recent_detections[event.source_ip].append(event)
        
        # Prune old detections
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.CORRELATION_WINDOW)
        self.recent_detections[event.source_ip] = [
            e for e in self.recent_detections[event.source_ip]
            if e.timestamp > cutoff
        ]
    
    def _update_state_machine(self, event: DetectionEvent):
        """Update state machine for source IP."""
        if event.source_ip is None:
            return
        if event.source_ip not in self.state_machines:
            self.state_machines[event.source_ip] = AttackStateMachine(event.source_ip)
        
        sm = self.state_machines[event.source_ip]
        transition = sm.process_event(event)
        
        if transition:
            old_state, new_state = transition
            logger.info(
                "Attack state transition",
                source_ip=event.source_ip,
                old_state=old_state.value,
                new_state=new_state.value,
                trigger=event.rule_id
            )
    
    def _check_correlation(self, source_ip: str) -> Optional[DetectionEvent]:
        """Check if detections for this IP form a correlated pattern."""
        detections = self.recent_detections.get(source_ip, [])
        
        if len(detections) < self.MIN_INDICATORS:
            return None
        
        # Get or create attack chain
        if source_ip not in self.attack_chains:
            self.chain_counter += 1
            self.attack_chains[source_ip] = AttackChain(
                id=f"chain_{self.chain_counter}",
                primary_source_ip=source_ip,
                start_time=detections[0].timestamp,
                last_update=datetime.now(timezone.utc)
            )
        
        chain = self.attack_chains[source_ip]
        
        # Add new indicators
        for detection in detections:
            phase = AttackStateMachine.DETECTION_TO_PHASE.get(detection.rule_id)
            if phase and not any(
                ind.rule_id == detection.rule_id and 
                ind.timestamp == detection.timestamp 
                for ind in chain.indicators
            ):
                chain.add_indicator(CorrelatedIndicator(
                    rule_id=detection.rule_id,
                    timestamp=detection.timestamp,
                    source_ip=source_ip,
                    severity=detection.severity.value,
                    summary=detection.title,
                    phase=phase
                ))
        
        # Check if we should generate a correlation alert
        if len(chain.indicators) >= self.MIN_INDICATORS:
            # Check if we've already alerted for similar state
            if self._should_alert_chain(chain):
                return self._create_correlation_alert(chain)
        
        return None
    
    def _should_alert_chain(self, chain: AttackChain) -> bool:
        """Determine if we should generate an alert for this chain."""
        # Alert if we see multiple phases
        if len(chain.phases_observed) >= 2:
            return True
        
        # Alert if we have many indicators in one phase
        if len(chain.indicators) >= 4:
            return True
        
        return False
    
    def _create_correlation_alert(self, chain: AttackChain) -> DetectionEvent:
        """Create a correlated attack alert."""
        
        # Build timeline
        timeline: List[Dict[str, str]] = []
        for ind in sorted(chain.indicators, key=lambda x: x.timestamp):
            timeline.append({
                "time": ind.timestamp.isoformat(),
                "phase": ind.phase.value,
                "detection": ind.rule_id,
                "summary": ind.summary
            })
        
        # Build evidence
        evidence_items = [
            EvidenceItem(
                type=EvidenceType.CORRELATION,
                key="related_detections",
                value=len(chain.indicators),
                threshold=self.MIN_INDICATORS,
                unit="detections",
                description="Number of related security detections",
                raw_data={"rule_ids": [i.rule_id for i in chain.indicators]}
            ),
            EvidenceItem(
                type=EvidenceType.BEHAVIORAL,
                key="attack_phases",
                value=list(p.value for p in chain.phases_observed),
                description="Attack phases observed in this chain"
            ),
            EvidenceItem(
                type=EvidenceType.TIME_PATTERN,
                key="attack_timeline",
                value=timeline,
                description="Chronological timeline of attack indicators"
            )
        ]
        
        # Get state machine state
        sm = self.state_machines.get(chain.primary_source_ip)
        if sm:
            evidence_items.append(EvidenceItem(
                type=EvidenceType.BEHAVIORAL,
                key="attack_state",
                value=sm.state.value,
                description="Current attack progression state"
            ))
        
        # Confidence is high because we have multiple correlated signals
        confidence = ConfidenceScore(
            base_score=chain.confidence,
            adjustments=[
                (f"{len(chain.indicators)} correlated indicators", +0.1),
                (f"{len(chain.phases_observed)} attack phases observed", +0.05 * len(chain.phases_observed))
            ]
        )
        
        # This is less likely to be a false positive due to correlation
        fp_assessment = FalsePositiveAssessment(
            likelihood="low",
            score=0.2,
            possible_reasons=[],
            mitigation_hints=[
                "Multiple correlated signals reduce false positive likelihood",
                "Review each individual detection for context"
            ]
        )
        
        # Determine severity from attack progression
        severity = chain.get_severity()
        
        if severity == DetectionSeverity.CRITICAL:
            priority = "immediate"
        elif severity == DetectionSeverity.WARNING:
            priority = "soon"
        else:
            priority = "when_convenient"
        
        action = AdminAction(
            priority=priority,
            summary=f"Investigate coordinated attack activity from {chain.primary_source_ip}",
            steps=[
                f"1. Isolate or closely monitor {chain.primary_source_ip}",
                "2. Review the attack timeline below",
                "3. Check each individual detection for details",
                "4. Identify affected systems and potential damage",
                "5. Begin incident response if attack confirmed"
            ],
            automated_options=["Isolate source IP (requires confirmation)"]
        )
        
        related_alert_ids: List[int] = []  # No integer alert IDs available; rule_ids stored in evidence_items raw_data
        tags_list: List[str] = ["correlated-attack", "multi-phase"] + [p.value for p in chain.phases_observed]
        evidence = DetectionEvidence(
            time_window=TimeWindow(
                start=chain.start_time,
                end=chain.last_update
            ),
            evidence_items=evidence_items,
            confidence=confidence,
            false_positive=fp_assessment,
            recommended_action=action,
            related_alerts=related_alert_ids,
            tags=tags_list
        )
        
        # Phase descriptions for explanation
        phase_descriptions = {
            AttackPhase.RECONNAISSANCE: "scanning/reconnaissance",
            AttackPhase.INITIAL_ACCESS: "initial access attempts",
            AttackPhase.LATERAL_MOVEMENT: "lateral movement",
            AttackPhase.PERSISTENCE: "persistence mechanisms",
            AttackPhase.COMMAND_CONTROL: "command & control communication",
            AttackPhase.EXFILTRATION: "data exfiltration"
        }
        
        phases_text = ", ".join(
            phase_descriptions.get(p, p.value) for p in chain.phases_observed
        )
        
        return DetectionEvent(
            rule_id="CORRELATED_ATTACK",
            severity=severity,
            title=f"Correlated Attack Pattern: {len(chain.indicators)} Indicators",
            description=(
                f"Attack chain from {chain.primary_source_ip} showing "
                f"{phases_text}"
            ),
            explanation=(
                f"We've detected multiple related security events from {chain.primary_source_ip} "
                f"that together suggest a coordinated attack rather than isolated incidents."
                "\n\n"
                f"Over the past {(chain.last_update - chain.start_time).total_seconds() / 60:.0f} minutes, "
                f"we observed {len(chain.indicators)} suspicious activities including {phases_text}."
                "\n\n"
                "Attack Timeline:\n" +
                "\n".join(
                    f"• {ind.timestamp.strftime('%H:%M:%S')} - {ind.summary}"
                    for ind in sorted(chain.indicators, key=lambda x: x.timestamp)
                ) +
                "\n\n"
                "When we see multiple attack phases from the same source, it strongly suggests "
                "an active intrusion attempt rather than random noise. Each individual detection "
                "might have been a false positive, but together they form a pattern."
            ),
            source_ip=chain.primary_source_ip,
            evidence=evidence.to_dict(),
            recommended_action=action.summary,
            confidence=confidence.final_score,
            false_positive_likelihood=FalsePositiveLikelihood.LOW
        )
    
    def get_chain_for_ip(self, source_ip: str) -> Optional[Dict[str, Any]]:
        """Get attack chain information for an IP."""
        with self.lock:
            chain = self.attack_chains.get(source_ip)
            if not chain:
                return None
            
            return {
                "id": chain.id,
                "source_ip": chain.primary_source_ip,
                "start_time": chain.start_time.isoformat(),
                "last_update": chain.last_update.isoformat(),
                "indicator_count": len(chain.indicators),
                "phases_observed": [p.value for p in chain.phases_observed],
                "confidence": chain.confidence,
                "indicators": [
                    {
                        "rule_id": i.rule_id,
                        "timestamp": i.timestamp.isoformat(),
                        "phase": i.phase.value,
                        "summary": i.summary
                    }
                    for i in chain.indicators
                ]
            }
    
    def get_active_chains(self) -> List[Dict[str, Any]]:
        """Get all active attack chains."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.CORRELATION_WINDOW)
        
        with self.lock:
            active: List[Optional[Dict[str, Any]]] = []
            for ip, chain in self.attack_chains.items():
                if chain.last_update > cutoff:
                    active.append(self.get_chain_for_ip(ip))
            return [a for a in active if a is not None]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get correlation engine statistics."""
        with self.lock:
            return {
                "active_chains": len(self.attack_chains),
                "tracked_sources": len(self.recent_detections),
                "total_chains_created": self.chain_counter,
                "state_machines": {
                    ip: sm.state.value 
                    for ip, sm in self.state_machines.items()
                }
            }


# =============================================================================
# Singleton instance
# =============================================================================

correlation_engine = CorrelationEngine()

"""
Threat Detection Engine

Rule-based detection for suspicious network activity.
Per DESIGN_SPECIFICATION.md Section 6.

Key features:
- Explainable detections (every alert includes plain-English explanation)
- Structured evidence model
- Sliding window counters for rate-based detection
- ARP cache tracking for spoofing detection
- Cooldown periods to prevent alert storms
- Correlation with other detections
- Advanced rules: lateral movement, beaconing, broadcast abuse, device risk
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import threading
import structlog

from app.core.config import settings
from app.core.capture.packet_capture import PacketInfo

logger = structlog.get_logger(__name__)


# =============================================================================
# Detection Types
# =============================================================================

class DetectionSeverity(str, Enum):
    """Severity levels for detections."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class FalsePositiveLikelihood(str, Enum):
    """Likelihood of false positive."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# =============================================================================
# Detection Event Model
# =============================================================================

@dataclass
class DetectionEvent:
    """
    A detected security event with explainable output.
    
    Every detection includes:
    - rule_id: Unique identifier for the rule
    - severity: info | warning | critical
    - title: Human-readable title
    - description: Technical description
    - explanation: Plain English explanation for non-experts
    - evidence: Data that triggered the detection
    - recommended_action: What the user should do
    """
    rule_id: str
    severity: DetectionSeverity
    title: str
    description: str
    explanation: str  # Plain English for non-experts
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommended_action: str = ""
    confidence: float = 1.0  # 0.0 to 1.0
    false_positive_likelihood: FalsePositiveLikelihood = FalsePositiveLikelihood.LOW
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value if isinstance(self.severity, DetectionSeverity) else self.severity,
            "title": self.title,
            "description": self.description,
            "explanation": self.explanation,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "port": self.port,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            "evidence": self.evidence,
            "recommended_action": self.recommended_action,
            "confidence": self.confidence,
            "false_positive_likelihood": self.false_positive_likelihood.value if isinstance(self.false_positive_likelihood, FalsePositiveLikelihood) else self.false_positive_likelihood
        }


# =============================================================================
# Detection Rule Model
# =============================================================================

@dataclass
class DetectionRule:
    """Configuration for a detection rule."""
    id: str
    name: str
    description: str
    severity: DetectionSeverity
    enabled: bool = True
    threshold: Optional[int] = None
    window_seconds: int = 60
    cooldown_seconds: int = 60


# =============================================================================
# Sliding Window Counter
# =============================================================================

class SlidingWindowCounter:
    """Thread-safe sliding window counter for rate limiting and detection."""
    
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.events: Dict[str, List[datetime]] = defaultdict(list)
        self.lock = threading.Lock()
    
    def add(self, key: str) -> int:
        """Add an event and return current count within window."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)
        
        with self.lock:
            # Remove expired events
            self.events[key] = [t for t in self.events[key] if t > cutoff]
            # Add new event
            self.events[key].append(now)
            return len(self.events[key])
    
    def get_count(self, key: str) -> int:
        """Get current count for a key."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)
        
        with self.lock:
            self.events[key] = [t for t in self.events[key] if t > cutoff]
            return len(self.events[key])
    
    def clear(self, key: Optional[str] = None):
        """Clear events for a key or all keys."""
        with self.lock:
            if key:
                self.events.pop(key, None)
            else:
                self.events.clear()
    
    def get_all_counts(self) -> Dict[str, int]:
        """Get counts for all keys."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)
        
        with self.lock:
            return {
                key: len([t for t in times if t > cutoff])
                for key, times in self.events.items()
            }


# =============================================================================
# ARP Cache for Spoofing Detection
# =============================================================================

class ARPCache:
    """Track ARP IP-MAC mappings for spoofing detection."""
    
    def __init__(self, ttl_seconds: int = 300):
        self.mappings: Dict[str, Dict[str, Any]] = {}
        self.ttl_seconds = ttl_seconds
        self.lock = threading.Lock()
    
    def update(self, ip: str, mac: str) -> Optional[str]:
        """
        Update ARP cache. Returns previous MAC if changed (potential spoof).
        """
        now = datetime.utcnow()
        
        with self.lock:
            if ip in self.mappings:
                existing = self.mappings[ip]
                # Check if MAC changed
                if existing['mac'] != mac:
                    old_mac = existing['mac']
                    self.mappings[ip] = {'mac': mac, 'last_seen': now, 'first_seen': existing['first_seen']}
                    return old_mac
                else:
                    self.mappings[ip]['last_seen'] = now
            else:
                self.mappings[ip] = {'mac': mac, 'last_seen': now, 'first_seen': now}
        
        return None
    
    def get_all(self) -> Dict[str, Dict]:
        """Get all current mappings."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.ttl_seconds)
        
        with self.lock:
            return {
                ip: data for ip, data in self.mappings.items()
                if data['last_seen'] > cutoff
            }


class DetectionEngine:
    """
    Rule-based threat detection engine.
    Analyzes packets and generates alerts for suspicious activity.
    
    Now includes advanced detections:
    - Lateral movement detection
    - C2 beaconing pattern detection
    - Broadcast abuse detection
    - New device risk scoring
    - Cross-detection correlation
    """
    
    # Suspicious ports often used by malware/hackers
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 31337, 12345, 65535, 1337, 6667}
    
    # Common service ports for reference
    COMMON_PORTS = {
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139,
        143, 161, 162, 389, 443, 445, 465, 514, 587, 636, 993, 995, 1433, 1434,
        3306, 3389, 5432, 5900, 8080, 8443
    }
    
    def __init__(self, alert_manager=None):
        self.alert_manager = alert_manager
        
        # Callbacks for real-time event notifications
        self.event_callbacks: List[Callable] = []
        
        # Detection windows/counters
        self.port_scan_window = SlidingWindowCounter(settings.DETECTION_WINDOW_SECONDS)
        self.flood_window = SlidingWindowCounter(10)  # 10 second window for flood detection
        self.failed_conn_window = SlidingWindowCounter(settings.DETECTION_WINDOW_SECONDS)
        self.icmp_window = SlidingWindowCounter(30)
        self.dns_window = SlidingWindowCounter(60)
        
        # ARP cache for spoofing detection
        self.arp_cache = ARPCache()
        
        # Track unique destination ports per source IP (for port scan detection)
        self.port_scan_tracker: Dict[str, set] = defaultdict(set)
        self.port_scan_lock = threading.Lock()
        
        # Recently detected events (to avoid duplicate alerts)
        self.recent_detections: Dict[str, datetime] = {}
        self.detection_cooldown = 60  # Seconds before re-alerting same event
        
        # Initialize advanced detectors
        self._init_advanced_detectors()
        
        # Statistics
        self.detection_stats = {
            "total_analyzed": 0,
            "port_scans_detected": 0,
            "arp_spoofs_detected": 0,
            "floods_detected": 0,
            "dns_tunnels_detected": 0,
            "suspicious_traffic_detected": 0,
            "lateral_movement_detected": 0,
            "beaconing_detected": 0,
            "broadcast_abuse_detected": 0,
            "new_device_risks_detected": 0,
            "correlated_attacks_detected": 0
        }
        
        logger.info("Detection engine initialized with advanced detectors")
    
    def _init_advanced_detectors(self):
        """Initialize advanced detection modules."""
        try:
            from app.core.detection.rules import (
                LateralMovementDetector,
                BeaconingDetector,
                BroadcastAbuseDetector,
                NewDeviceScorer
            )
            from app.core.detection.correlation import correlation_engine
            
            self.lateral_detector = LateralMovementDetector(window_seconds=300)
            self.beacon_detector = BeaconingDetector(observation_window=600)
            self.broadcast_detector = BroadcastAbuseDetector(window_seconds=60)
            self.device_scorer = NewDeviceScorer(observation_window=300)
            self.correlation_engine = correlation_engine
            
            self._advanced_detectors_available = True
            logger.info("Advanced detectors initialized successfully")
        except ImportError as e:
            logger.warning("Advanced detectors not available", error=str(e))
            self._advanced_detectors_available = False
            self.lateral_detector = None
            self.beacon_detector = None
            self.broadcast_detector = None
            self.device_scorer = None
            self.correlation_engine = None
    
    def analyze_packet(self, packet: PacketInfo):
        """Analyze a packet for suspicious activity."""
        self.detection_stats["total_analyzed"] += 1
        
        # Run core detection rules
        self._detect_port_scan(packet)
        self._detect_packet_flood(packet)
        self._detect_arp_spoofing(packet)
        self._detect_dns_tunneling(packet)
        self._detect_suspicious_ports(packet)
        self._detect_failed_connections(packet)
        self._detect_icmp_sweep(packet)
        
        # Run advanced detection rules
        if self._advanced_detectors_available:
            self._run_advanced_detections(packet)
    
    def _run_advanced_detections(self, packet: PacketInfo):
        """Run advanced detection modules."""
        # Lateral movement detection
        if self.lateral_detector:
            event = self.lateral_detector.analyze(packet)
            if event:
                self.detection_stats["lateral_movement_detected"] += 1
                self._create_alert(event)
                self._correlate_event(event)
        
        # Beaconing detection
        if self.beacon_detector:
            event = self.beacon_detector.analyze(packet)
            if event:
                self.detection_stats["beaconing_detected"] += 1
                self._create_alert(event)
                self._correlate_event(event)
        
        # Broadcast abuse detection
        if self.broadcast_detector:
            event = self.broadcast_detector.analyze(packet)
            if event:
                self.detection_stats["broadcast_abuse_detected"] += 1
                self._create_alert(event)
        
        # New device risk scoring
        if self.device_scorer:
            event = self.device_scorer.observe(packet)
            if event:
                self.detection_stats["new_device_risks_detected"] += 1
                self._create_alert(event)
    
    def _correlate_event(self, event: DetectionEvent):
        """Send event to correlation engine."""
        if self.correlation_engine:
            correlated = self.correlation_engine.process_detection(event)
            if correlated:
                self.detection_stats["correlated_attacks_detected"] += 1
                self._create_alert(correlated)
    
    def _should_alert(self, detection_key: str) -> bool:
        """Check if we should alert for this detection (cooldown check)."""
        now = datetime.utcnow()
        
        if detection_key in self.recent_detections:
            last_alert = self.recent_detections[detection_key]
            if (now - last_alert).total_seconds() < self.detection_cooldown:
                return False
        
        self.recent_detections[detection_key] = now
        return True
    
    def _create_alert(self, event: DetectionEvent):
        """Create an alert from a detection event."""
        if self.alert_manager:
            self.alert_manager.create_alert(event)
        else:
            logger.warning("Alert created (no alert manager)", event=event.to_dict())
        
        # Notify all registered callbacks
        self._notify_callbacks(event)
    
    def add_callback(self, callback: Callable):
        """Add a callback for detection events."""
        self.event_callbacks.append(callback)
    
    def remove_callback(self, callback: Callable):
        """Remove a detection event callback."""
        if callback in self.event_callbacks:
            self.event_callbacks.remove(callback)
    
    def _notify_callbacks(self, event: DetectionEvent):
        """Notify all registered callbacks of a detection event."""
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error("Detection callback error", error=str(e))
    
    def _detect_port_scan(self, packet: PacketInfo):
        """Detect port scanning activity."""
        if packet.protocol not in ["TCP", "UDP"]:
            return
        
        if not packet.destination_port or not packet.source_ip:
            return
        
        # Track unique ports scanned by source IP
        key = f"{packet.source_ip}"
        
        with self.port_scan_lock:
            self.port_scan_tracker[key].add(packet.destination_port)
            unique_ports = len(self.port_scan_tracker[key])
            scanned_ports = list(self.port_scan_tracker[key])
        
        # Count connections from this source
        count = self.port_scan_window.add(key)
        
        # Check threshold
        if unique_ports >= settings.PORT_SCAN_THRESHOLD:
            detection_key = f"port_scan:{packet.source_ip}"
            
            if self._should_alert(detection_key):
                self.detection_stats["port_scans_detected"] += 1
                
                # Calculate confidence based on how much threshold is exceeded
                threshold_ratio = unique_ports / settings.PORT_SCAN_THRESHOLD
                base_confidence = 0.7
                if threshold_ratio > 2:
                    confidence = min(base_confidence + 0.15, 0.95)
                elif threshold_ratio > 1.5:
                    confidence = base_confidence + 0.1
                else:
                    confidence = base_confidence
                
                # Structured evidence
                evidence = {
                    "time_window": {
                        "duration_seconds": settings.DETECTION_WINDOW_SECONDS,
                        "end_time": datetime.utcnow().isoformat()
                    },
                    "evidence_items": [
                        {
                            "type": "unique_targets",
                            "key": "unique_destination_ports",
                            "value": unique_ports,
                            "threshold": settings.PORT_SCAN_THRESHOLD,
                            "unit": "ports",
                            "description": "Unique destination ports contacted"
                        },
                        {
                            "type": "packet_count",
                            "key": "total_connections",
                            "value": count,
                            "unit": "connections",
                            "description": "Total connection attempts in window"
                        }
                    ],
                    "confidence": {
                        "score": confidence,
                        "factors": [
                            f"Threshold exceeded by {threshold_ratio:.1f}x",
                            f"Based on {unique_ports} unique ports"
                        ]
                    },
                    "scanned_ports_sample": sorted(scanned_ports)[:20],
                    "false_positive_hints": [
                        "Could be legitimate if source is a known vulnerability scanner",
                        "Network monitoring tools often scan ports",
                        "Some backup software scans for available services"
                    ],
                    "recommended_action": {
                        "priority": "soon",
                        "steps": [
                            f"1. Identify the device at {packet.source_ip}",
                            "2. Check if it's running authorized scanning software",
                            "3. Review if any security scans were scheduled",
                            "4. If unauthorized, investigate the device for compromise"
                        ]
                    }
                }
                
                event = DetectionEvent(
                    rule_id="PORT_SCAN_DETECTION",
                    severity=DetectionSeverity.WARNING,
                    title="Port Scan Detected",
                    description=f"Host {packet.source_ip} has probed {unique_ports} different ports",
                    explanation=(
                        f"We detected that {packet.source_ip} is connecting to many different ports "
                        f"on your network ({unique_ports} ports in {settings.DETECTION_WINDOW_SECONDS} seconds). "
                        "This pattern is typical of port scanning, which is often used by attackers "
                        "to discover running services and potential vulnerabilities."
                        "\n\n"
                        "Port scanning by itself isn't an attack, but it's often the first step "
                        "in reconnaissance before an attack. Think of it like someone walking down "
                        "a hallway trying every door handle - they're looking for unlocked doors."
                        "\n\n"
                        "If this IP is a known security scanner or IT monitoring tool, this is expected. "
                        "If not, the source device may be compromised or an unauthorized scanner."
                    ),
                    source_ip=packet.source_ip,
                    protocol=packet.protocol,
                    evidence=evidence,
                    recommended_action="Verify if this IP belongs to a known security scanner; if not, investigate the source device.",
                    confidence=confidence,
                    false_positive_likelihood=FalsePositiveLikelihood.MEDIUM
                )
                self._create_alert(event)
                
                # Correlate with other detections
                if self._advanced_detectors_available:
                    self._correlate_event(event)
                
                # Reset tracker for this IP
                with self.port_scan_lock:
                    self.port_scan_tracker[key].clear()
    
    def _detect_packet_flood(self, packet: PacketInfo):
        """Detect potential DoS/DDoS packet floods."""
        if not packet.source_ip:
            return
        
        key = f"{packet.source_ip}"
        count = self.flood_window.add(key)
        
        if count >= settings.FLOOD_THRESHOLD:
            detection_key = f"flood:{packet.source_ip}"
            
            if self._should_alert(detection_key):
                self.detection_stats["floods_detected"] += 1
                
                event = DetectionEvent(
                    rule_id="PACKET_FLOOD_DETECTION",
                    severity=DetectionSeverity.CRITICAL,
                    title="Potential Packet Flood Detected",
                    description=f"High packet rate ({count} packets/10s) from {packet.source_ip}",
                    explanation=(
                        f"We detected an unusually high number of packets ({count}) from {packet.source_ip} "
                        "in a short time period. This could indicate a Denial of Service (DoS) attack "
                        "attempting to overwhelm your network or a specific service. "
                        "It could also be legitimate traffic from a backup or file transfer. "
                        "Check if this traffic is expected; if not, consider blocking this IP."
                    ),
                    source_ip=packet.source_ip,
                    destination_ip=packet.destination_ip,
                    protocol=packet.protocol,
                    evidence={"packet_count": count, "window_seconds": 10},
                    recommended_action="Check if traffic is expected (backup, large file transfer); if not, consider blocking the source IP.",
                    confidence=0.75,
                    false_positive_likelihood=FalsePositiveLikelihood.MEDIUM
                )
                self._create_alert(event)
    
    def _detect_arp_spoofing(self, packet: PacketInfo):
        """Detect potential ARP spoofing attacks."""
        if packet.protocol != "ARP":
            return
        
        if not packet.source_ip or not packet.source_mac:
            return
        
        old_mac = self.arp_cache.update(packet.source_ip, packet.source_mac)
        
        if old_mac:
            detection_key = f"arp_spoof:{packet.source_ip}"
            
            if self._should_alert(detection_key):
                self.detection_stats["arp_spoofs_detected"] += 1
                
                event = DetectionEvent(
                    rule_id="ARP_SPOOF_DETECTION",
                    severity=DetectionSeverity.CRITICAL,
                    title="Potential ARP Spoofing Detected",
                    description=f"IP {packet.source_ip} MAC changed from {old_mac} to {packet.source_mac}",
                    explanation=(
                        f"The MAC address for IP {packet.source_ip} has changed from {old_mac} to "
                        f"{packet.source_mac}. This could indicate an ARP spoofing attack, where "
                        "an attacker is trying to intercept traffic by impersonating another device. "
                        "This is a serious security concern as it can enable man-in-the-middle attacks. "
                        "However, this can also occur legitimately if a device was replaced or "
                        "if DHCP reassigned an IP. Verify with your network administrator."
                    ),
                    source_ip=packet.source_ip,
                    protocol="ARP",
                    evidence={"old_mac": old_mac, "new_mac": packet.source_mac},
                    recommended_action="Verify with network administrator if device replacement or IP reassignment occurred; if not, investigate for man-in-the-middle attack.",
                    confidence=0.7,
                    false_positive_likelihood=FalsePositiveLikelihood.MEDIUM
                )
                self._create_alert(event)
    
    def _detect_dns_tunneling(self, packet: PacketInfo):
        """Detect potential DNS tunneling."""
        if packet.protocol != "DNS":
            return
        
        # Check for unusually long DNS query in packet info
        if packet.info and "Query:" in packet.info:
            query = packet.info.replace("Query:", "").strip()
            
            # DNS tunneling often uses very long subdomain names
            if len(query) > 50:
                detection_key = f"dns_tunnel:{packet.source_ip}"
                
                if self._should_alert(detection_key):
                    self.detection_stats["dns_tunnels_detected"] += 1
                    
                    event = DetectionEvent(
                        rule_id="DNS_TUNNEL_DETECTION",
                        severity=DetectionSeverity.WARNING,
                        title="Suspicious DNS Query Detected",
                        description=f"Unusually long DNS query ({len(query)} chars) from {packet.source_ip}",
                        explanation=(
                            f"We detected an unusually long DNS query from {packet.source_ip}. "
                            "Legitimate DNS queries are typically short domain names, but this query "
                            f"is {len(query)} characters long. This pattern is often associated with "
                            "DNS tunneling, a technique used to bypass firewalls and exfiltrate data "
                            "by encoding it in DNS queries. This could indicate malware or unauthorized "
                            "data transfer. Investigate the source device for potential compromise."
                        ),
                        source_ip=packet.source_ip,
                        destination_ip=packet.destination_ip,
                        protocol="DNS",
                        port=53,
                        evidence={"query_length": len(query), "query_preview": query[:50] + "..."},
                        recommended_action="Investigate the source device for malware or unauthorized software; check what application is generating these queries.",
                        confidence=0.8,
                        false_positive_likelihood=FalsePositiveLikelihood.LOW
                    )
                    self._create_alert(event)
        
        # Also check for high DNS request frequency
        key = f"dns_freq:{packet.source_ip}"
        count = self.dns_window.add(key)
        
        if count > 100:  # More than 100 DNS queries per minute
            detection_key = f"dns_flood:{packet.source_ip}"
            
            if self._should_alert(detection_key):
                event = DetectionEvent(
                    rule_id="DNS_HIGH_RATE",
                    severity=DetectionSeverity.WARNING,
                    title="High DNS Query Rate",
                    description=f"Unusual DNS query rate ({count}/min) from {packet.source_ip}",
                    explanation=(
                        f"We detected an unusually high rate of DNS queries ({count} per minute) "
                        f"from {packet.source_ip}. While some applications may generate many DNS "
                        "queries, this volume is suspicious and could indicate DNS tunneling or "
                        "a compromised host communicating with a command and control server."
                    ),
                    source_ip=packet.source_ip,
                    protocol="DNS",
                    evidence={"query_count": count, "window_seconds": 60},
                    recommended_action="Identify the application generating DNS queries; check for malware if source is unknown.",
                    confidence=0.7,
                    false_positive_likelihood=FalsePositiveLikelihood.MEDIUM
                )
                self._create_alert(event)
    
    def _detect_suspicious_ports(self, packet: PacketInfo):
        """Detect traffic on known suspicious ports."""
        if packet.protocol not in ["TCP", "UDP"]:
            return
        
        port = packet.destination_port or packet.source_port
        if not port:
            return
        
        if port in self.SUSPICIOUS_PORTS:
            detection_key = f"suspicious_port:{packet.source_ip}:{port}"
            
            if self._should_alert(detection_key):
                self.detection_stats["suspicious_traffic_detected"] += 1
                
                # Determine direction
                is_outbound = packet.source_port != port
                direction = "outbound to" if is_outbound else "inbound from"
                
                event = DetectionEvent(
                    rule_id="SUSPICIOUS_PORT",
                    severity=DetectionSeverity.WARNING,
                    title=f"Traffic on Suspicious Port {port}",
                    description=f"{packet.protocol} traffic {direction} port {port}",
                    explanation=(
                        f"We detected network traffic on port {port}, which is commonly associated "
                        "with hacking tools, backdoors, or malware. While there may be legitimate "
                        f"uses for this port, it warrants investigation. The traffic is {direction} "
                        f"{packet.destination_ip if is_outbound else packet.source_ip}. "
                        "Check if any authorized application uses this port; if not, "
                        "investigate the involved hosts for potential compromise."
                    ),
                    source_ip=packet.source_ip,
                    destination_ip=packet.destination_ip,
                    protocol=packet.protocol,
                    port=port,
                    evidence={"direction": "outbound" if is_outbound else "inbound"},
                    recommended_action=f"Identify what application is using port {port}; if unknown, investigate the host for compromise.",
                    confidence=0.65,
                    false_positive_likelihood=FalsePositiveLikelihood.MEDIUM
                )
                self._create_alert(event)
    
    def _detect_failed_connections(self, packet: PacketInfo):
        """Detect repeated failed connection attempts (TCP RST/ICMP unreachable)."""
        # Look for TCP RST flags
        if packet.protocol == "TCP" and packet.flags and "R" in packet.flags:
            key = f"failed_conn:{packet.destination_ip}"
            count = self.failed_conn_window.add(key)
            
            if count >= 20:
                detection_key = f"failed_conn_alert:{packet.destination_ip}"
                
                if self._should_alert(detection_key):
                    event = DetectionEvent(
                        rule_id="FAILED_CONN_DETECTION",
                        severity=DetectionSeverity.INFO,
                        title="Repeated Failed Connections",
                        description=f"Multiple connection resets ({count}) to {packet.destination_ip}",
                        explanation=(
                            f"We detected {count} failed connection attempts (TCP resets) to "
                            f"{packet.destination_ip} in the last minute. This could indicate "
                            "port scanning, a misconfigured service, or a brute-force attack. "
                            "It may also be caused by a crashed service or firewall blocking. "
                            "Check if the target service is running correctly."
                        ),
                        source_ip=packet.source_ip,
                        destination_ip=packet.destination_ip,
                        protocol="TCP",
                        evidence={"reset_count": count},
                        recommended_action="Check if target service is running; review firewall logs for blocks.",
                        confidence=0.6,
                        false_positive_likelihood=FalsePositiveLikelihood.HIGH
                    )
                    self._create_alert(event)
    
    def _detect_icmp_sweep(self, packet: PacketInfo):
        """Detect ICMP-based host discovery sweeps."""
        if packet.protocol != "ICMP":
            return
        
        # Track ICMP requests (Echo Request is type 8)
        if "Echo Request" in packet.info or "Request" in packet.info:
            key = f"icmp_sweep:{packet.source_ip}"
            count = self.icmp_window.add(key)
            
            if count >= 20:
                detection_key = f"icmp_sweep_alert:{packet.source_ip}"
                
                if self._should_alert(detection_key):
                    event = DetectionEvent(
                        rule_id="ICMP_SWEEP_DETECTION",
                        severity=DetectionSeverity.INFO,
                        title="ICMP Sweep Detected",
                        description=f"Multiple ICMP requests ({count}) from {packet.source_ip}",
                        explanation=(
                            f"We detected {count} ICMP echo requests (pings) from {packet.source_ip} "
                            "in a short time period. This pattern is typical of a ping sweep, "
                            "which is used to discover active hosts on a network. While ping is "
                            "a legitimate diagnostic tool, automated sweeps may indicate "
                            "reconnaissance activity preceding an attack."
                        ),
                        source_ip=packet.source_ip,
                        protocol="ICMP",
                        evidence={"ping_count": count},
                        recommended_action="Check if this is an authorized network monitoring tool; if not, investigate.",
                        confidence=0.7,
                        false_positive_likelihood=FalsePositiveLikelihood.MEDIUM
                    )
                    self._create_alert(event)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics."""
        stats = self.detection_stats.copy()
        
        # Add correlation stats if available
        if self._advanced_detectors_available and self.correlation_engine:
            stats["correlation"] = self.correlation_engine.get_statistics()
        
        return stats
    
    def get_arp_cache(self) -> Dict[str, Dict]:
        """Get current ARP cache."""
        return self.arp_cache.get_all()
    
    def get_attack_chains(self) -> List[Dict[str, Any]]:
        """Get active attack chains from correlation engine."""
        if self._advanced_detectors_available and self.correlation_engine:
            return self.correlation_engine.get_active_chains()
        return []
    
    def reset_stats(self):
        """Reset detection statistics."""
        for key in self.detection_stats:
            if key != "total_analyzed":
                self.detection_stats[key] = 0

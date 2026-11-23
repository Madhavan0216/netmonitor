"""
Advanced Detection Rules

New defensive detections for:
- Lateral movement indicators
- Beaconing patterns (C2 communication)
- Misconfigured services
- Broadcast/multicast abuse
- New device risk scoring

All detections include:
- Structured evidence
- Explicit time windows
- Calculated confidence
- False-positive assessment
- Actionable recommendations
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import threading
import statistics
import structlog

from app.core.capture.packet_capture import PacketInfo
from app.core.detection.evidence import (
    EvidenceItem, EvidenceType, TimeWindow, ConfidenceScore,
    FalsePositiveAssessment, FalsePositiveReason, AdminAction,
    DetectionEvidence, calculate_confidence
)
from app.core.detection.engine import (
    DetectionEvent, DetectionSeverity, FalsePositiveLikelihood,
    SlidingWindowCounter
)

logger = structlog.get_logger(__name__)


# =============================================================================
# Data Structures for Advanced Detection
# =============================================================================

@dataclass
class ConnectionRecord:
    """Record of a connection for behavioral analysis."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    size: int
    flags: Optional[str] = None


@dataclass
class HostBehavior:
    """Behavioral profile of a host."""
    ip: str
    first_seen: datetime
    last_seen: datetime
    connections: List[ConnectionRecord] = field(default_factory=lambda: [])
    unique_dst_ips: Set[str] = field(default_factory=lambda: set())
    unique_dst_ports: Set[int] = field(default_factory=lambda: set())
    protocols_used: Set[str] = field(default_factory=lambda: set())
    total_bytes: int = 0
    
    # Timing analysis
    connection_intervals: List[float] = field(default_factory=lambda: [])
    
    # Risk indicators
    contacted_external: bool = False
    used_suspicious_port: bool = False
    high_port_diversity: bool = False


@dataclass 
class DeviceProfile:
    """Profile for new device risk scoring."""
    mac: str
    ip: str
    first_seen: datetime
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    
    # Observed behavior
    services_accessed: Set[int] = field(default_factory=lambda: set())
    hosts_contacted: Set[str] = field(default_factory=lambda: set())
    protocols: Set[str] = field(default_factory=lambda: set())
    
    # Risk factors
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=lambda: [])


# =============================================================================
# Lateral Movement Detection
# =============================================================================

class LateralMovementDetector:
    """
    Detects potential lateral movement within the network.
    
    Lateral movement indicators:
    1. Host contacts many internal IPs in short time
    2. SMB/RDP/SSH connections to multiple hosts
    3. Pass-the-hash patterns (same creds to multiple hosts)
    4. Unusual admin port access patterns
    
    This is NOT about detecting an initial breach - it's about detecting
    an attacker moving through your network after gaining initial access.
    """
    
    # Ports associated with lateral movement
    LATERAL_PORTS = {
        22: "SSH",
        23: "Telnet", 
        135: "RPC",
        139: "NetBIOS",
        445: "SMB",
        3389: "RDP",
        5985: "WinRM-HTTP",
        5986: "WinRM-HTTPS"
    }
    
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self.host_behaviors: Dict[str, HostBehavior] = {}
        self.lock = threading.Lock()
        
        # Track lateral port usage: src_ip -> {dst_ip: [timestamps]}
        self.lateral_connections: Dict[str, Dict[str, List[datetime]]] = defaultdict(
            lambda: defaultdict(list)
        )
    
    def analyze(self, packet: PacketInfo) -> Optional[DetectionEvent]:
        """Analyze packet for lateral movement indicators."""
        if packet.protocol not in ("TCP", "UDP"):
            return None
        
        if not packet.source_ip or not packet.destination_ip:
            return None
        
        if not packet.destination_port:
            return None
        
        # Only analyze internal-to-internal traffic
        if not self._is_internal(packet.source_ip) or not self._is_internal(packet.destination_ip):
            return None
        
        # Track behavior
        self._record_connection(packet)
        
        # Check for lateral movement patterns
        return self._check_lateral_patterns(packet.source_ip)
    
    def _is_internal(self, ip: str) -> bool:
        """Check if IP is internal (RFC1918 or link-local)."""
        if ip.startswith("10."):
            return True
        if ip.startswith("172."):
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return True
        if ip.startswith("192.168."):
            return True
        if ip.startswith("169.254."):
            return True
        return False
    
    def _record_connection(self, packet: PacketInfo):
        """Record connection for behavioral analysis."""
        now = datetime.now(timezone.utc)
        
        with self.lock:
            # Get or create host behavior
            if packet.source_ip not in self.host_behaviors:
                self.host_behaviors[packet.source_ip] = HostBehavior(
                    ip=packet.source_ip,
                    first_seen=now,
                    last_seen=now
                )
            
            behavior = self.host_behaviors[packet.source_ip]
            behavior.last_seen = now
            behavior.unique_dst_ips.add(packet.destination_ip)
            if packet.destination_port is not None:
                behavior.unique_dst_ports.add(packet.destination_port)
            behavior.protocols_used.add(packet.protocol)
            behavior.total_bytes += packet.size
            
            # Track timing for interval analysis
            if behavior.connections:
                last_time = behavior.connections[-1].timestamp
                interval = (now - last_time).total_seconds()
                if interval > 0:
                    behavior.connection_intervals.append(interval)
            
            # Keep limited history
            if len(behavior.connections) > 1000:
                behavior.connections = behavior.connections[-500:]
            if len(behavior.connection_intervals) > 500:
                behavior.connection_intervals = behavior.connection_intervals[-250:]
            
            if packet.destination_port is not None:
                behavior.connections.append(ConnectionRecord(
                    timestamp=now,
                    src_ip=packet.source_ip,
                    dst_ip=packet.destination_ip,
                    dst_port=packet.destination_port,
                    protocol=packet.protocol,
                    size=packet.size,
                    flags=packet.flags
                ))
            
            # Track lateral port connections specifically
            if packet.destination_port is not None and packet.destination_port in self.LATERAL_PORTS:
                self.lateral_connections[packet.source_ip][packet.destination_ip].append(now)
    
    def _check_lateral_patterns(self, source_ip: str) -> Optional[DetectionEvent]:
        """Check for lateral movement patterns from a source IP."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)
        
        with self.lock:
            lateral_conns = self.lateral_connections.get(source_ip, {})
            
            # Count unique hosts contacted via lateral ports recently
            recent_targets: Set[str] = set()
            recent_connections: List[datetime] = []
            
            for dst_ip, timestamps in lateral_conns.items():
                recent = [t for t in timestamps if t > cutoff]
                if recent:
                    recent_targets.add(dst_ip)
                    recent_connections.extend(recent)
            
            # Threshold: 3+ unique internal hosts via admin ports
            if len(recent_targets) >= 3:
                return self._create_lateral_alert(
                    source_ip, recent_targets, recent_connections
                )
        
        return None
    
    def _create_lateral_alert(
        self,
        source_ip: str,
        targets: Set[str],
        connection_times: List[datetime]
    ) -> DetectionEvent:
        """Create a lateral movement detection alert."""
        
        # Build evidence
        evidence_items = [
            EvidenceItem(
                type=EvidenceType.UNIQUE_TARGETS,
                key="internal_admin_targets",
                value=len(targets),
                threshold=3,
                unit="hosts",
                description="Unique internal hosts contacted via admin ports (SMB/RDP/SSH/WinRM)",
                raw_data={"target_ips": list(targets)[:10]}
            ),
            EvidenceItem(
                type=EvidenceType.PACKET_COUNT,
                key="admin_port_connections",
                value=len(connection_times),
                unit="connections",
                description="Total admin-port connections in time window"
            )
        ]
        
        # Calculate time spread
        if len(connection_times) >= 2:
            sorted_times = sorted(connection_times)
            spread = (sorted_times[-1] - sorted_times[0]).total_seconds()
            evidence_items.append(EvidenceItem(
                type=EvidenceType.TIME_PATTERN,
                key="connection_spread",
                value=round(spread, 1),
                unit="seconds",
                description="Time spread of lateral connections"
            ))
        
        # Confidence calculation
        confidence = calculate_confidence(
            base=0.75,
            sample_size=len(targets),
            min_samples=3,
            threshold_ratio=len(targets) / 3.0
        )
        
        # False positive assessment
        fp_assessment = FalsePositiveAssessment(
            likelihood="medium",
            score=0.4,
            possible_reasons=[
                FalsePositiveReason.MONITORING_TOOL,
                FalsePositiveReason.BACKUP_ACTIVITY
            ],
            mitigation_hints=[
                "Check if source is an IT admin workstation",
                "Verify if this is scheduled IT maintenance",
                "Check for authorized remote management tools"
            ]
        )
        
        # Recommended action
        action = AdminAction(
            priority="immediate",
            summary=f"Investigate {source_ip} for potential lateral movement",
            steps=[
                f"1. Identify the device at {source_ip} (check DHCP/DNS)",
                "2. Review user activity on this host",
                "3. Check if recent IT maintenance was scheduled",
                f"4. Examine what was accessed on {', '.join(list(targets)[:3])}...",
                "5. Look for signs of compromise (unusual processes, files)"
            ],
            automated_options=["Isolate host (requires confirmation)"]
        )
        
        # Full evidence package
        evidence = DetectionEvidence(
            time_window=TimeWindow.last_n_seconds(self.window_seconds),
            evidence_items=evidence_items,
            confidence=confidence,
            false_positive=fp_assessment,
            recommended_action=action,
            related_ips=list(targets),
            tags=["lateral-movement", "internal-recon"]
        )
        
        return DetectionEvent(
            rule_id="LATERAL_MOVEMENT",
            severity=DetectionSeverity.CRITICAL,
            title="Potential Lateral Movement Detected",
            description=(
                f"Host {source_ip} connected to {len(targets)} internal hosts "
                f"via admin ports (SMB/RDP/SSH) in {self.window_seconds} seconds"
            ),
            explanation=(
                f"We detected that {source_ip} is connecting to multiple other computers "
                f"on your network ({len(targets)} hosts) using administrative protocols like "
                "file sharing (SMB), remote desktop (RDP), or secure shell (SSH). "
                "\n\n"
                "This pattern is called 'lateral movement' - it's how attackers spread through "
                "a network after compromising one machine. An attacker might be using stolen "
                "credentials to access other systems, looking for valuable data or trying to "
                "reach more critical servers."
                "\n\n"
                "However, this could also be legitimate IT administration. System administrators "
                "often need to connect to multiple servers. Check if this activity is expected."
            ),
            source_ip=source_ip,
            protocol="TCP",
            evidence=evidence.to_dict(),
            recommended_action=action.summary,
            confidence=confidence.final_score,
            false_positive_likelihood=FalsePositiveLikelihood.MEDIUM
        )


# =============================================================================
# Beaconing Detection
# =============================================================================

class BeaconingDetector:
    """
    Detects C2 beaconing patterns.
    
    Beaconing indicators:
    1. Regular interval connections to same host
    2. Consistent packet sizes
    3. Long-running periodic communication
    4. Known bad ports/protocols
    
    Beaconing is how malware "phones home" to get instructions.
    The key signature is REGULARITY - human traffic is irregular,
    but automated malware callbacks happen on predictable schedules.
    """
    
    # Minimum observations needed to detect pattern
    MIN_SAMPLES = 10
    
    # Maximum coefficient of variation for "regular" intervals
    # CV < 0.1 = very regular (suspicious)
    # CV 0.1-0.3 = somewhat regular (worth investigating)
    MAX_CV_THRESHOLD = 0.15
    
    def __init__(self, observation_window: int = 600):
        """
        Args:
            observation_window: Seconds to observe before concluding (default 10 min)
        """
        self.observation_window = observation_window
        
        # Track connections: (src_ip, dst_ip, dst_port) -> [timestamps]
        self.connection_times: Dict[Tuple[str, str, int], List[datetime]] = defaultdict(list)
        
        # Track packet sizes for consistency analysis
        self.packet_sizes: Dict[Tuple[str, str, int], List[int]] = defaultdict(list)
        
        self.lock = threading.Lock()
        self.last_cleanup = datetime.now(timezone.utc)
    
    def analyze(self, packet: PacketInfo) -> Optional[DetectionEvent]:
        """Analyze packet for beaconing patterns."""
        if packet.protocol not in ("TCP", "UDP"):
            return None
        
        if not packet.source_ip or not packet.destination_ip:
            return None
        
        if not packet.destination_port:
            return None
        
        # Skip local traffic for beaconing (C2 is usually external)
        if self._is_internal(packet.destination_ip):
            return None
        
        # Record this connection
        self._record_connection(packet)
        
        # Periodic cleanup
        self._cleanup_old_records()
        
        # Check for beaconing pattern
        return self._check_beaconing(
            packet.source_ip,
            packet.destination_ip,
            packet.destination_port
        )
    
    def _is_internal(self, ip: str) -> bool:
        """Check if IP is internal."""
        for prefix in ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                       "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                       "172.30.", "172.31.", "192.168.", "169.254.", "127."):
            if ip.startswith(prefix):
                return True
        return False
    
    def _record_connection(self, packet: PacketInfo):
        """Record connection for pattern analysis."""
        now = datetime.now(timezone.utc)
        if packet.destination_port is None:
            return
        key: Tuple[str, str, int] = (packet.source_ip, packet.destination_ip, packet.destination_port)
        
        with self.lock:
            self.connection_times[key].append(now)
            self.packet_sizes[key].append(packet.size)
            
            # Limit memory usage
            if len(self.connection_times[key]) > 200:
                self.connection_times[key] = self.connection_times[key][-100:]
                self.packet_sizes[key] = self.packet_sizes[key][-100:]
    
    def _cleanup_old_records(self):
        """Clean up old records periodically."""
        now = datetime.now(timezone.utc)
        if (now - self.last_cleanup).total_seconds() < 60:
            return
        
        cutoff = now - timedelta(seconds=self.observation_window * 2)
        
        with self.lock:
            self.last_cleanup = now
            keys_to_remove: List[Tuple[str, str, int]] = []
            
            for key, times in self.connection_times.items():
                # Keep only recent times
                recent = [t for t in times if t > cutoff]
                if not recent:
                    keys_to_remove.append(key)
                else:
                    self.connection_times[key] = recent
            
            for key in keys_to_remove:
                del self.connection_times[key]
                self.packet_sizes.pop(key, None)
    
    def _check_beaconing(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int
    ) -> Optional[DetectionEvent]:
        """Check for beaconing pattern in connection history."""
        key = (src_ip, dst_ip, dst_port)
        
        with self.lock:
            times = self.connection_times.get(key, [])
            sizes = self.packet_sizes.get(key, [])
        
        if len(times) < self.MIN_SAMPLES:
            return None
        
        # Calculate intervals between connections
        sorted_times = sorted(times)
        intervals: List[float] = []
        for i in range(1, len(sorted_times)):
            interval = (sorted_times[i] - sorted_times[i-1]).total_seconds()
            if interval > 0:  # Ignore simultaneous packets
                intervals.append(interval)
        
        if len(intervals) < self.MIN_SAMPLES - 1:
            return None
        
        # Calculate coefficient of variation
        mean_interval: float = statistics.mean(intervals)
        if mean_interval == 0:
            return None
        
        try:
            stdev: float = statistics.stdev(intervals)
            cv: float = stdev / mean_interval
        except statistics.StatisticsError:
            return None
        
        # Check for regular pattern
        if cv > self.MAX_CV_THRESHOLD:
            return None  # Too irregular to be beaconing
        
        # Additional check: packet size consistency
        size_consistent = False
        if len(sizes) >= self.MIN_SAMPLES:
            try:
                size_cv = statistics.stdev(sizes) / statistics.mean(sizes)
                size_consistent = size_cv < 0.2
            except (statistics.StatisticsError, ZeroDivisionError):
                pass
        
        # Create alert
        return self._create_beacon_alert(
            src_ip, dst_ip, dst_port,
            intervals, cv, mean_interval,
            sizes, size_consistent
        )
    
    def _create_beacon_alert(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        intervals: List[float],
        cv: float,
        mean_interval: float,
        sizes: List[int],
        size_consistent: bool
    ) -> DetectionEvent:
        """Create beaconing detection alert."""
        
        # Build evidence
        evidence_items = [
            EvidenceItem(
                type=EvidenceType.TIME_PATTERN,
                key="interval_coefficient_of_variation",
                value=round(cv, 4),
                threshold=self.MAX_CV_THRESHOLD,
                unit="CV",
                description=(
                    "Coefficient of variation of connection intervals. "
                    "Lower values indicate more regular (automated) timing."
                ),
                raw_data={
                    "mean_interval_seconds": round(mean_interval, 2),
                    "stdev_seconds": round(statistics.stdev(intervals), 2) if len(intervals) > 1 else 0,
                    "sample_count": len(intervals)
                }
            ),
            EvidenceItem(
                type=EvidenceType.PACKET_COUNT,
                key="connection_count",
                value=len(intervals) + 1,
                threshold=self.MIN_SAMPLES,
                unit="connections",
                description="Number of connections to this destination"
            )
        ]
        
        if size_consistent:
            evidence_items.append(EvidenceItem(
                type=EvidenceType.STATISTICAL,
                key="packet_size_consistency",
                value=round(statistics.mean(sizes)),
                unit="bytes (avg)",
                description="Packet sizes are consistent (another beaconing indicator)"
            ))
        
        # Confidence: higher for very regular patterns
        base_confidence = 0.7
        confidence = calculate_confidence(
            base=base_confidence,
            sample_size=len(intervals),
            min_samples=self.MIN_SAMPLES,
            has_corroboration=size_consistent,
            threshold_ratio=self.MAX_CV_THRESHOLD / cv  # Higher ratio = more regular
        )
        
        # False positive assessment
        fp_score = 0.3
        fp_reasons: List[FalsePositiveReason] = []
        fp_hints: List[str] = []
        
        # Some legitimate services have regular heartbeats
        if dst_port in (443, 80):
            fp_score += 0.1
            fp_reasons.append(FalsePositiveReason.CLOUD_SYNC)
            fp_hints.append("Could be cloud service keepalive (check destination domain)")
        
        if dst_port == 123:  # NTP
            fp_score += 0.3
            fp_hints.append("Port 123 is NTP - regular time sync is normal")
        
        if mean_interval > 300:  # > 5 minutes
            fp_hints.append("Long intervals could indicate legitimate monitoring")
        
        fp_assessment = FalsePositiveAssessment(
            likelihood="medium" if fp_score < 0.5 else "high",
            score=fp_score,
            possible_reasons=fp_reasons,
            mitigation_hints=fp_hints or ["Investigate the destination IP/domain"]
        )
        
        # Recommended action
        action = AdminAction(
            priority="soon",
            summary=f"Investigate regular communication from {src_ip} to {dst_ip}:{dst_port}",
            steps=[
                f"1. Identify the destination {dst_ip} (reverse DNS, threat intel lookup)",
                f"2. Check what process on {src_ip} is making these connections",
                "3. Review if any authorized software uses this pattern",
                f"4. If unknown, capture and analyze the traffic content",
                "5. Consider blocking the destination if malicious"
            ],
            automated_options=["Block destination IP (requires confirmation)"]
        )
        
        evidence = DetectionEvidence(
            time_window=TimeWindow.last_n_seconds(self.observation_window),
            evidence_items=evidence_items,
            confidence=confidence,
            false_positive=fp_assessment,
            recommended_action=action,
            related_ips=[dst_ip],
            tags=["beaconing", "c2", "automated-traffic"]
        )
        
        # Human-readable interval
        if mean_interval < 60:
            interval_desc = f"every ~{int(mean_interval)} seconds"
        elif mean_interval < 3600:
            interval_desc = f"every ~{int(mean_interval/60)} minutes"
        else:
            interval_desc = f"every ~{round(mean_interval/3600, 1)} hours"
        
        return DetectionEvent(
            rule_id="BEACONING_DETECTED",
            severity=DetectionSeverity.WARNING,
            title="Potential C2 Beaconing Pattern Detected",
            description=(
                f"{src_ip} connecting to {dst_ip}:{dst_port} {interval_desc} "
                f"(CV={cv:.3f}, {len(intervals)+1} connections)"
            ),
            explanation=(
                f"We detected that {src_ip} is connecting to {dst_ip} on port {dst_port} "
                f"at very regular intervals ({interval_desc}). This pattern occurred "
                f"{len(intervals)+1} times during our observation period."
                "\n\n"
                "This regularity is suspicious because normal human-driven network traffic "
                "is irregular - you don't check email at exactly the same second each time. "
                "But automated malware 'beacons' (calls home to its controller) on a schedule."
                "\n\n"
                "Common legitimate causes include: cloud sync services, monitoring agents, "
                "and time synchronization. The key question is: do you recognize this destination?"
                + (" The packet sizes are also consistent, which strengthens this detection." 
                   if size_consistent else "")
            ),
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol="TCP",
            port=dst_port,
            evidence=evidence.to_dict(),
            recommended_action=action.summary,
            confidence=confidence.final_score,
            false_positive_likelihood=(
                FalsePositiveLikelihood.HIGH if fp_score > 0.5 
                else FalsePositiveLikelihood.MEDIUM
            )
        )


# =============================================================================
# Broadcast Abuse Detection
# =============================================================================

class BroadcastAbuseDetector:
    """
    Detects abuse of broadcast/multicast traffic.
    
    Broadcast abuse indicators:
    1. Excessive broadcast storms
    2. Unusual broadcast sources
    3. Broadcast amplification attempts
    4. Rogue DHCP/ARP replies
    
    Broadcast traffic goes to ALL devices on a network segment.
    Attackers can abuse this for reconnaissance or denial of service.
    """
    
    # Broadcast MAC addresses
    BROADCAST_MACS = {"ff:ff:ff:ff:ff:ff", "FF:FF:FF:FF:FF:FF"}
    
    # Normal broadcast protocols and their expected rates
    NORMAL_BROADCAST_PORTS = {
        67: ("DHCP Server", 10),   # port: (name, max_per_minute)
        68: ("DHCP Client", 20),
        137: ("NetBIOS NS", 30),
        138: ("NetBIOS DGM", 20),
        5353: ("mDNS", 50),
        1900: ("SSDP/UPnP", 30)
    }
    
    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        
        # Track broadcast traffic: src_ip -> [timestamps]
        self.broadcast_counts = SlidingWindowCounter(window_seconds)
        
        # Track by source+type: (src_ip, port) -> [timestamps]
        self.detailed_counts: Dict[Tuple[str, int], List[datetime]] = defaultdict(list)
        
        # Track DHCP servers seen
        self.dhcp_servers: Dict[str, datetime] = {}
        
        self.lock = threading.Lock()
    
    def analyze(self, packet: PacketInfo) -> Optional[DetectionEvent]:
        """Analyze packet for broadcast abuse."""
        # Check if broadcast
        if not self._is_broadcast(packet):
            return None
        
        if not packet.source_ip:
            return None
        
        # Record broadcast
        self._record_broadcast(packet)
        
        # Check for abuse patterns
        event = self._check_broadcast_storm(packet.source_ip)
        if event:
            return event
        
        event = self._check_rogue_dhcp(packet)
        if event:
            return event
        
        return None
    
    def _is_broadcast(self, packet: PacketInfo) -> bool:
        """Check if packet is broadcast/multicast."""
        if packet.destination_mac in self.BROADCAST_MACS:
            return True
        if packet.destination_ip and (
            packet.destination_ip.endswith(".255") or
            packet.destination_ip == "255.255.255.255" or
            packet.destination_ip.startswith("224.") or  # Multicast
            packet.destination_ip.startswith("239.")
        ):
            return True
        return False
    
    def _record_broadcast(self, packet: PacketInfo):
        """Record broadcast packet."""
        now = datetime.now(timezone.utc)
        self.broadcast_counts.add(packet.source_ip)
        
        port = packet.destination_port or packet.source_port or 0
        
        with self.lock:
            key = (packet.source_ip, port)
            self.detailed_counts[key].append(now)
            
            # Limit memory
            if len(self.detailed_counts[key]) > 200:
                self.detailed_counts[key] = self.detailed_counts[key][-100:]
            
            # Track DHCP servers
            if packet.source_port == 67:  # DHCP server response
                self.dhcp_servers[packet.source_ip] = now
    
    def _check_broadcast_storm(self, source_ip: str) -> Optional[DetectionEvent]:
        """Check for broadcast storm from a source."""
        count = self.broadcast_counts.get_count(source_ip)
        threshold = 100  # More than 100 broadcasts per minute is concerning
        
        if count < threshold:
            return None
        
        # Gather details
        with self.lock:
            port_breakdown = {}
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.window_seconds)
            
            for (ip, port), times in self.detailed_counts.items():
                if ip == source_ip:
                    recent = [t for t in times if t > cutoff]
                    if recent:
                        port_name = self.NORMAL_BROADCAST_PORTS.get(port, ("Unknown", 0))[0]
                        port_breakdown[f"{port} ({port_name})"] = len(recent)
        
        # Build evidence
        evidence_items = [
            EvidenceItem(
                type=EvidenceType.THRESHOLD_BREACH,
                key="broadcast_count",
                value=count,
                threshold=threshold,
                unit="packets/minute",
                description="Broadcast packets sent in the last minute"
            )
        ]
        
        if port_breakdown:
            evidence_items.append(EvidenceItem(
                type=EvidenceType.BEHAVIORAL,
                key="port_breakdown",
                value=port_breakdown,
                description="Breakdown by destination port"
            ))
        
        confidence = calculate_confidence(
            base=0.7,
            sample_size=count,
            min_samples=threshold,
            threshold_ratio=count / threshold
        )
        
        fp_assessment = FalsePositiveAssessment(
            likelihood="medium",
            score=0.4,
            possible_reasons=[FalsePositiveReason.DEVICE_REPLACEMENT],
            mitigation_hints=[
                "Check if device just joined the network",
                "Review if network changes occurred"
            ]
        )
        
        action = AdminAction(
            priority="soon",
            summary=f"Investigate high broadcast traffic from {source_ip}",
            steps=[
                f"1. Identify the device at {source_ip}",
                "2. Check if device is malfunctioning",
                "3. Review network configuration",
                "4. Consider rate-limiting or isolating if continues"
            ]
        )
        
        evidence = DetectionEvidence(
            time_window=TimeWindow.last_n_seconds(self.window_seconds),
            evidence_items=evidence_items,
            confidence=confidence,
            false_positive=fp_assessment,
            recommended_action=action,
            tags=["broadcast-abuse", "network-health"]
        )
        
        return DetectionEvent(
            rule_id="BROADCAST_STORM",
            severity=DetectionSeverity.WARNING,
            title="Excessive Broadcast Traffic Detected",
            description=f"{source_ip} sent {count} broadcast packets in {self.window_seconds}s",
            explanation=(
                f"The device at {source_ip} is sending an unusually high volume of "
                f"broadcast traffic ({count} packets in the last minute). "
                "\n\n"
                "Broadcast packets are sent to ALL devices on your network segment, "
                "which consumes bandwidth on every device. Excessive broadcasts can slow "
                "down your entire network (this is called a 'broadcast storm')."
                "\n\n"
                "Common causes include: malfunctioning network equipment, misconfigured "
                "software, or network mapping/discovery tools. Rarely, attackers use "
                "broadcast floods for denial of service."
            ),
            source_ip=source_ip,
            evidence=evidence.to_dict(),
            recommended_action=action.summary,
            confidence=confidence.final_score,
            false_positive_likelihood=FalsePositiveLikelihood.MEDIUM
        )
    
    def _check_rogue_dhcp(self, packet: PacketInfo) -> Optional[DetectionEvent]:
        """Check for rogue DHCP server."""
        # DHCP server responses come from source port 67
        if packet.source_port != 67:
            return None
        
        with self.lock:
            known_servers = list(self.dhcp_servers.keys())
        
        # First DHCP server seen is assumed legitimate
        # Alert on additional ones
        if len(known_servers) <= 1:
            return None
        
        # Multiple DHCP servers - this is suspicious
        evidence_items = [
            EvidenceItem(
                type=EvidenceType.STATE_CHANGE,
                key="dhcp_servers_seen",
                value=len(known_servers),
                threshold=1,
                unit="servers",
                description="Number of DHCP servers detected on network",
                raw_data={"servers": known_servers}
            )
        ]
        
        confidence = ConfidenceScore(
            base_score=0.6,
            adjustments=[
                ("Multiple DHCP servers is unusual", +0.2)
            ]
        )
        
        action = AdminAction(
            priority="immediate",
            summary="Verify all DHCP servers are authorized",
            steps=[
                f"1. Identify devices at: {', '.join(known_servers)}",
                "2. Confirm which is your legitimate DHCP server",
                "3. If unauthorized server found, isolate it immediately",
                "4. Check if any devices got wrong IP/gateway from rogue server"
            ]
        )
        
        evidence = DetectionEvidence(
            time_window=TimeWindow.last_n_seconds(300),
            evidence_items=evidence_items,
            confidence=confidence,
            false_positive=FalsePositiveAssessment(
                likelihood="low",
                score=0.2,
                possible_reasons=[],
                mitigation_hints=["Legitimate if you have redundant DHCP"]
            ),
            recommended_action=action,
            related_ips=known_servers,
            tags=["rogue-dhcp", "mitm-risk"]
        )
        
        return DetectionEvent(
            rule_id="ROGUE_DHCP",
            severity=DetectionSeverity.CRITICAL,
            title="Multiple DHCP Servers Detected - Possible Rogue",
            description=f"Detected {len(known_servers)} DHCP servers: {', '.join(known_servers)}",
            explanation=(
                f"We detected multiple devices ({len(known_servers)}) responding to DHCP "
                "requests on your network. Normally, a network should have only one DHCP server "
                "(or a redundant pair that you've configured)."
                "\n\n"
                "A 'rogue DHCP server' is a serious security threat. Attackers can set up "
                "their own DHCP server to give devices a malicious gateway or DNS server, "
                "allowing them to intercept all your traffic (man-in-the-middle attack)."
                "\n\n"
                "Check if you intentionally have multiple DHCP servers. If not, immediately "
                "identify and disconnect the unauthorized one."
            ),
            source_ip=packet.source_ip,
            protocol="UDP",
            port=67,
            evidence=evidence.to_dict(),
            recommended_action=action.summary,
            confidence=confidence.final_score,
            false_positive_likelihood=FalsePositiveLikelihood.LOW
        )


# =============================================================================
# New Device Risk Scoring
# =============================================================================

class NewDeviceScorer:
    """
    Risk scoring for newly discovered devices.
    
    When a new device appears on the network, we assess its risk based on:
    1. First behavior (what does it do immediately?)
    2. Services accessed
    3. Traffic patterns
    4. MAC vendor (IoT devices, etc.)
    
    This helps identify potentially compromised or rogue devices early.
    """
    
    # Risk factors and their weights
    RISK_FACTORS = {
        "immediate_external_traffic": 0.15,  # Contacts external IPs immediately
        "contacts_many_hosts": 0.20,          # Scans/probes multiple hosts
        "uses_suspicious_port": 0.25,         # Uses known bad ports
        "admin_port_access": 0.15,            # Tries SMB/RDP/SSH
        "high_traffic_volume": 0.10,          # Unusual traffic volume
        "unknown_vendor": 0.10,               # MAC vendor not recognized
        "bypasses_dhcp": 0.20,                # Uses static IP
    }
    
    # Known suspicious ports
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 31337, 12345, 65535, 1337}
    ADMIN_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986}
    
    def __init__(self, observation_window: int = 300):
        """
        Args:
            observation_window: Seconds to observe new device before scoring
        """
        self.observation_window = observation_window
        self.new_devices: Dict[str, DeviceProfile] = {}
        self.scored_devices: Dict[str, float] = {}  # Already scored
        self.lock = threading.Lock()
    
    def observe(self, packet: PacketInfo) -> Optional[DetectionEvent]:
        """Observe packet and potentially score new devices."""
        if not packet.source_ip or not packet.source_mac:
            return None
        
        with self.lock:
            # Check if this is a new device
            if packet.source_mac not in self.new_devices:
                if packet.source_mac in self.scored_devices:
                    return None  # Already scored
                
                # New device discovered!
                self.new_devices[packet.source_mac] = DeviceProfile(
                    mac=packet.source_mac,
                    ip=packet.source_ip,
                    first_seen=datetime.now(timezone.utc)
                )
                logger.info("New device discovered", mac=packet.source_mac, ip=packet.source_ip)
            
            profile = self.new_devices[packet.source_mac]
            
            # Update profile
            if packet.destination_ip:
                profile.hosts_contacted.add(packet.destination_ip)
            if packet.destination_port:
                profile.services_accessed.add(packet.destination_port)
            if packet.protocol:
                profile.protocols.add(packet.protocol)
            
            # Check if observation period complete
            age = (datetime.now(timezone.utc) - profile.first_seen).total_seconds()
            if age >= self.observation_window:
                # Time to score this device
                return self._score_device(profile)
        
        return None
    
    def _score_device(self, profile: DeviceProfile) -> Optional[DetectionEvent]:
        """Calculate risk score for a device."""
        risk_score = 0.0
        risk_factors: List[str] = []
        
        # Check each risk factor
        
        # 1. Immediate external traffic
        external_hosts = [h for h in profile.hosts_contacted if not self._is_internal(h)]
        if external_hosts:
            risk_score += self.RISK_FACTORS["immediate_external_traffic"]
            risk_factors.append(f"Contacted {len(external_hosts)} external hosts immediately")
        
        # 2. Contacts many hosts (potential scanning)
        if len(profile.hosts_contacted) > 10:
            risk_score += self.RISK_FACTORS["contacts_many_hosts"]
            risk_factors.append(f"Contacted {len(profile.hosts_contacted)} hosts in first 5 minutes")
        
        # 3. Uses suspicious ports
        suspicious_used = profile.services_accessed & self.SUSPICIOUS_PORTS
        if suspicious_used:
            risk_score += self.RISK_FACTORS["uses_suspicious_port"]
            risk_factors.append(f"Used suspicious ports: {suspicious_used}")
        
        # 4. Admin port access
        admin_used = profile.services_accessed & self.ADMIN_PORTS
        if admin_used:
            risk_score += self.RISK_FACTORS["admin_port_access"]
            risk_factors.append(f"Accessed admin services: {admin_used}")
        
        # Store score
        with self.lock:
            self.scored_devices[profile.mac] = risk_score
            del self.new_devices[profile.mac]
        
        # Only alert if risk is significant
        if risk_score < 0.3:
            return None
        
        # Build evidence
        evidence_items = [
            EvidenceItem(
                type=EvidenceType.BEHAVIORAL,
                key="risk_score",
                value=round(risk_score, 2),
                threshold=0.3,
                unit="score",
                description="Calculated risk score based on initial behavior"
            ),
            EvidenceItem(
                type=EvidenceType.UNIQUE_TARGETS,
                key="hosts_contacted",
                value=len(profile.hosts_contacted),
                unit="hosts",
                description="Unique hosts contacted in observation period",
                raw_data={"hosts": list(profile.hosts_contacted)[:10]}
            ),
            EvidenceItem(
                type=EvidenceType.BEHAVIORAL,
                key="risk_factors",
                value=risk_factors,
                description="Specific behaviors contributing to risk score"
            )
        ]
        
        confidence = ConfidenceScore(
            base_score=0.65,
            adjustments=[
                (f"Based on {self.observation_window}s observation", +0.1 if len(risk_factors) > 2 else 0)
            ]
        )
        
        # Severity based on score
        if risk_score >= 0.6:
            severity = DetectionSeverity.CRITICAL
            priority = "immediate"
        elif risk_score >= 0.4:
            severity = DetectionSeverity.WARNING
            priority = "soon"
        else:
            severity = DetectionSeverity.INFO
            priority = "when_convenient"
        
        action = AdminAction(
            priority=priority,
            summary=f"Investigate new device {profile.ip} ({profile.mac})",
            steps=[
                f"1. Identify what device has MAC {profile.mac}",
                "2. Verify device is authorized to be on the network",
                "3. Review the suspicious behaviors flagged",
                "4. If unknown/unauthorized, isolate the device"
            ]
        )
        
        evidence = DetectionEvidence(
            time_window=TimeWindow(
                start=profile.first_seen,
                end=datetime.now(timezone.utc)
            ),
            evidence_items=evidence_items,
            confidence=confidence,
            false_positive=FalsePositiveAssessment(
                likelihood="medium",
                score=0.4,
                possible_reasons=[FalsePositiveReason.DEVICE_REPLACEMENT],
                mitigation_hints=["Could be legitimate new device performing setup"]
            ),
            recommended_action=action,
            related_ips=[profile.ip] + list(profile.hosts_contacted)[:5],
            tags=["new-device", "risk-assessment"]
        )
        
        return DetectionEvent(
            rule_id="NEW_DEVICE_RISK",
            severity=severity,
            title=f"New Device with Elevated Risk Score ({risk_score:.0%})",
            description=f"New device {profile.ip} ({profile.mac}) scored {risk_score:.0%} risk",
            explanation=(
                f"A new device appeared on your network at {profile.ip} (MAC: {profile.mac}) "
                f"and its initial behavior raised some concerns (risk score: {risk_score:.0%})."
                "\n\n"
                f"During the first {self.observation_window // 60} minutes, we observed:\n"
                + "\n".join(f"• {factor}" for factor in risk_factors)
                + "\n\n"
                "This doesn't mean the device is definitely malicious, but these behaviors "
                "are worth investigating. Legitimate new devices (like a new laptop) sometimes "
                "trigger this when they're first configured and connecting to various services."
            ),
            source_ip=profile.ip,
            evidence=evidence.to_dict(),
            recommended_action=action.summary,
            confidence=confidence.final_score,
            false_positive_likelihood=FalsePositiveLikelihood.MEDIUM
        )
    
    def _is_internal(self, ip: str) -> bool:
        """Check if IP is internal."""
        for prefix in ("10.", "192.168.", "169.254.", "127."):
            if ip.startswith(prefix):
                return True
        if ip.startswith("172."):
            try:
                second = int(ip.split(".")[1])
                if 16 <= second <= 31:
                    return True
            except (ValueError, IndexError):
                pass
        return False

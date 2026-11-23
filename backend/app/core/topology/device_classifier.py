"""
Device Classification Engine

Classifies network devices based on observed traffic patterns,
port usage, protocol behavior, and MAC OUI prefixes.

This is PASSIVE fingerprinting only - no active probing.
All classifications are probabilistic and explained.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime, timezone
import structlog

logger = structlog.get_logger(__name__)


class DeviceType(str, Enum):
    """Device type classifications."""
    ROUTER = "router"
    SWITCH = "switch"  # Inferred from traffic patterns
    SERVER = "server"
    WORKSTATION = "workstation"
    MOBILE = "mobile"
    IOT = "iot"
    PRINTER = "printer"
    CAMERA = "camera"
    VOIP = "voip"
    GATEWAY = "gateway"
    DNS_SERVER = "dns_server"
    DHCP_SERVER = "dhcp_server"
    NAS = "nas"
    UNKNOWN = "unknown"


class DeviceRole(str, Enum):
    """Functional role in network."""
    INFRASTRUCTURE = "infrastructure"
    ENDPOINT = "endpoint"
    SERVICE_PROVIDER = "service_provider"
    CLIENT = "client"


@dataclass
class ClassificationEvidence:
    """Evidence supporting a classification decision."""
    factor: str
    weight: float  # 0.0 to 1.0
    observation: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "factor": self.factor,
            "weight": self.weight,
            "observation": self.observation,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class DeviceClassification:
    """
    Classification result for a device.
    
    Includes confidence score and human-readable explanation
    of why this classification was chosen.
    """
    device_type: DeviceType
    role: DeviceRole
    confidence: float  # 0.0 to 1.0
    evidence: List[ClassificationEvidence] = field(default_factory=lambda: [])
    alternative_types: List[Tuple[DeviceType, float]] = field(default_factory=lambda: [])
    
    # Detailed attributes
    os_hint: Optional[str] = None
    vendor: Optional[str] = None
    services: List[str] = field(default_factory=lambda: [])
    
    def explanation(self) -> str:
        """Generate human-readable explanation."""
        if not self.evidence:
            return f"Classified as {self.device_type.value} with low confidence (insufficient data)."
        
        reasons: List[str] = []
        for e in sorted(self.evidence, key=lambda x: x.weight, reverse=True)[:3]:
            reasons.append(f"- {e.observation}")
        
        alt_str = ""
        if self.alternative_types:
            alts = [f"{t.value} ({c:.0%})" for t, c in self.alternative_types[:2]]
            alt_str = f" Could also be: {', '.join(alts)}."
        
        return (
            f"Classified as **{self.device_type.value}** ({self.confidence:.0%} confidence).\n"
            f"Key indicators:\n" + "\n".join(reasons) + alt_str
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_type": self.device_type.value,
            "role": self.role.value,
            "confidence": round(self.confidence, 2),
            "explanation": self.explanation(),
            "evidence": [e.to_dict() for e in self.evidence],
            "alternative_types": [
                {"type": t.value, "confidence": round(c, 2)} 
                for t, c in self.alternative_types
            ],
            "os_hint": self.os_hint,
            "vendor": self.vendor,
            "services": self.services
        }


# =============================================================================
# MAC OUI Database (Common vendors - expandable)
# =============================================================================

MAC_OUI_DATABASE: Dict[str, Tuple[str, Optional[DeviceType]]] = {
    # Networking equipment
    "00:00:0c": ("Cisco", DeviceType.ROUTER),
    "00:1a:a1": ("Cisco", DeviceType.ROUTER),
    "00:1b:54": ("Cisco", DeviceType.ROUTER),
    "00:50:56": ("VMware", DeviceType.SERVER),
    "00:0c:29": ("VMware", DeviceType.SERVER),
    "00:15:5d": ("Microsoft Hyper-V", DeviceType.SERVER),
    "08:00:27": ("VirtualBox", DeviceType.WORKSTATION),
    "52:54:00": ("QEMU/KVM", DeviceType.SERVER),
    
    # Consumer electronics
    "00:17:88": ("Philips Hue", DeviceType.IOT),
    "b8:27:eb": ("Raspberry Pi", DeviceType.IOT),
    "dc:a6:32": ("Raspberry Pi", DeviceType.IOT),
    "e4:5f:01": ("Raspberry Pi", DeviceType.IOT),
    
    # Printers
    "00:00:48": ("HP Printer", DeviceType.PRINTER),
    "00:1e:0b": ("HP Printer", DeviceType.PRINTER),
    "3c:2a:f4": ("Brother", DeviceType.PRINTER),
    
    # Mobile devices
    "00:26:bb": ("Apple", DeviceType.MOBILE),
    "f0:db:e2": ("Apple", DeviceType.MOBILE),
    "bc:52:b7": ("Samsung", DeviceType.MOBILE),
    
    # IP Cameras
    "00:80:f0": ("Axis Camera", DeviceType.CAMERA),
    "00:40:8c": ("Hikvision", DeviceType.CAMERA),
    "28:57:be": ("Hangzhou Hikvision", DeviceType.CAMERA),
    
    # VoIP
    "00:04:f2": ("Polycom", DeviceType.VOIP),
    "00:1b:4f": ("Avaya", DeviceType.VOIP),
    
    # NAS
    "00:11:32": ("Synology", DeviceType.NAS),
    "00:08:9b": ("QNAP", DeviceType.NAS),
}


# =============================================================================
# Port-based Service Hints
# =============================================================================

SERVER_PORTS: Dict[int, Tuple[str, DeviceType]] = {
    22: ("SSH Server", DeviceType.SERVER),
    80: ("HTTP Server", DeviceType.SERVER),
    443: ("HTTPS Server", DeviceType.SERVER),
    21: ("FTP Server", DeviceType.SERVER),
    25: ("SMTP Server", DeviceType.SERVER),
    53: ("DNS Server", DeviceType.DNS_SERVER),
    67: ("DHCP Server", DeviceType.DHCP_SERVER),
    110: ("POP3 Server", DeviceType.SERVER),
    143: ("IMAP Server", DeviceType.SERVER),
    389: ("LDAP Server", DeviceType.SERVER),
    445: ("SMB Server", DeviceType.SERVER),
    3306: ("MySQL Server", DeviceType.SERVER),
    5432: ("PostgreSQL Server", DeviceType.SERVER),
    6379: ("Redis Server", DeviceType.SERVER),
    27017: ("MongoDB Server", DeviceType.SERVER),
    8080: ("HTTP Proxy/Alt", DeviceType.SERVER),
    8443: ("HTTPS Alt", DeviceType.SERVER),
    
    # IoT common ports
    1883: ("MQTT Broker", DeviceType.IOT),
    8883: ("MQTT TLS", DeviceType.IOT),
    5683: ("CoAP", DeviceType.IOT),
    
    # Printer ports
    9100: ("Raw Print (JetDirect)", DeviceType.PRINTER),
    631: ("IPP/CUPS", DeviceType.PRINTER),
    
    # VoIP
    5060: ("SIP", DeviceType.VOIP),
    5061: ("SIP TLS", DeviceType.VOIP),
    
    # Camera
    554: ("RTSP", DeviceType.CAMERA),
    
    # NAS
    5000: ("Synology DSM", DeviceType.NAS),
    5001: ("Synology DSM SSL", DeviceType.NAS),
}


class DeviceClassifier:
    """
    Passive device classification engine.
    
    Uses multiple heuristics to classify devices:
    1. MAC OUI vendor lookup
    2. Port/service analysis
    3. Traffic pattern analysis
    4. Protocol behavior
    
    All classification is probabilistic with explainable evidence.
    """
    
    def __init__(self):
        self._device_profiles: Dict[str, Dict[str, Any]] = {}  # ip -> profile
        self._classifications: Dict[str, DeviceClassification] = {}
        logger.info("Device classifier initialized")
    
    def update_profile(
        self,
        ip: str,
        mac: Optional[str] = None,
        src_ports: Optional[Set[int]] = None,
        dst_ports: Optional[Set[int]] = None,
        protocols: Optional[Set[str]] = None,
        packet_count: int = 0,
        bytes_sent: int = 0,
        bytes_received: int = 0,
        unique_peers: int = 0,
        is_gateway_candidate: bool = False
    ):
        """Update device profile with new observations."""
        now = datetime.now(timezone.utc)
        if ip not in self._device_profiles:
            self._device_profiles[ip] = {
                "ip": ip,
                "mac": None,
                "src_ports": set(),
                "dst_ports": set(),
                "protocols": set(),
                "packet_count": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "unique_peers": 0,
                "is_gateway_candidate": False,
                "first_seen": now,
                "last_seen": now
            }
        
        profile = self._device_profiles[ip]
        
        if mac:
            profile["mac"] = mac
        if src_ports:
            profile["src_ports"].update(src_ports)
        if dst_ports:
            profile["dst_ports"].update(dst_ports)
        if protocols:
            profile["protocols"].update(protocols)
        
        profile["packet_count"] += packet_count
        profile["bytes_sent"] += bytes_sent
        profile["bytes_received"] += bytes_received
        profile["unique_peers"] = max(profile["unique_peers"], unique_peers)
        profile["is_gateway_candidate"] = profile["is_gateway_candidate"] or is_gateway_candidate
        profile["last_seen"] = now
    
    def classify(self, ip: str) -> DeviceClassification:
        """
        Classify a device based on accumulated profile data.
        
        Returns classification with confidence and evidence.
        """
        if ip not in self._device_profiles:
            return DeviceClassification(
                device_type=DeviceType.UNKNOWN,
                role=DeviceRole.ENDPOINT,
                confidence=0.0
            )
        
        profile = self._device_profiles[ip]
        evidence: List[ClassificationEvidence] = []
        type_scores: Dict[DeviceType, float] = {t: 0.0 for t in DeviceType}
        services_detected: List[str] = []
        vendor: Optional[str] = None
        os_hint: Optional[str] = None
        
        # === Factor 1: MAC OUI Lookup ===
        mac = profile.get("mac")
        if mac:
            oui = mac[:8].lower()
            if oui in MAC_OUI_DATABASE:
                vendor_name, hint_type = MAC_OUI_DATABASE[oui]
                vendor = vendor_name
                if hint_type:
                    type_scores[hint_type] += 0.4
                    evidence.append(ClassificationEvidence(
                        factor="mac_oui",
                        weight=0.4,
                        observation=f"MAC vendor {vendor_name} suggests {hint_type.value}"
                    ))
                    
                    # OS hints from vendor
                    if "VMware" in vendor_name or "VirtualBox" in vendor_name or "QEMU" in vendor_name:
                        os_hint = "Virtual Machine"
                    elif "Raspberry" in vendor_name:
                        os_hint = "Linux (ARM)"
        
        # === Factor 2: Server Port Analysis ===
        src_ports = profile.get("src_ports", set())
        for port in src_ports:
            if port in SERVER_PORTS:
                service_name, service_type = SERVER_PORTS[port]
                services_detected.append(service_name)
                type_scores[service_type] += 0.3
                evidence.append(ClassificationEvidence(
                    factor="server_port",
                    weight=0.3,
                    observation=f"Listening on port {port} ({service_name})"
                ))
        
        # === Factor 3: Gateway Detection ===
        if profile.get("is_gateway_candidate"):
            type_scores[DeviceType.GATEWAY] += 0.5
            type_scores[DeviceType.ROUTER] += 0.3
            evidence.append(ClassificationEvidence(
                factor="gateway_behavior",
                weight=0.5,
                observation="Traffic patterns indicate gateway role (high fan-out)"
            ))
        
        # === Factor 4: Traffic Volume Analysis ===
        unique_peers = profile.get("unique_peers", 0)
        if unique_peers > 20:
            # High connectivity suggests infrastructure
            type_scores[DeviceType.SERVER] += 0.2
            type_scores[DeviceType.ROUTER] += 0.2
            evidence.append(ClassificationEvidence(
                factor="connectivity",
                weight=0.2,
                observation=f"Communicates with {unique_peers} unique hosts"
            ))
        elif unique_peers <= 3:
            # Low connectivity suggests endpoint
            type_scores[DeviceType.WORKSTATION] += 0.15
            type_scores[DeviceType.MOBILE] += 0.1
            evidence.append(ClassificationEvidence(
                factor="connectivity",
                weight=0.15,
                observation=f"Limited connectivity ({unique_peers} peers) - likely endpoint"
            ))
        
        # === Factor 5: Protocol Analysis ===
        protocols = profile.get("protocols", set())
        if "DHCP" in protocols:
            type_scores[DeviceType.DHCP_SERVER] += 0.4
            evidence.append(ClassificationEvidence(
                factor="protocol",
                weight=0.4,
                observation="DHCP traffic indicates DHCP server"
            ))
        
        if "DNS" in protocols and 53 in src_ports:
            type_scores[DeviceType.DNS_SERVER] += 0.5
            evidence.append(ClassificationEvidence(
                factor="protocol",
                weight=0.5,
                observation="DNS responses from port 53 - DNS server"
            ))
        
        if "SIP" in protocols or 5060 in src_ports:
            type_scores[DeviceType.VOIP] += 0.6
            evidence.append(ClassificationEvidence(
                factor="protocol",
                weight=0.6,
                observation="SIP traffic indicates VoIP device"
            ))
        
        # === Factor 6: Ephemeral Port Ratio ===
        dst_ports = profile.get("dst_ports", set())
        ephemeral_dst = sum(1 for p in dst_ports if p > 1024)
        if dst_ports and (ephemeral_dst / len(dst_ports)) > 0.8:
            # Mostly connecting to high ports - client behavior
            type_scores[DeviceType.WORKSTATION] += 0.2
            type_scores[DeviceType.MOBILE] += 0.15
        
        # === Determine Best Classification ===
        best_type = max(type_scores, key=lambda k: type_scores[k])
        best_score = type_scores[best_type]
        
        # If no strong signal, default to workstation for local IPs
        if best_score < 0.2:
            best_type = DeviceType.UNKNOWN
            best_score = 0.1
        
        # Normalize confidence (cap at 0.95)
        confidence = min(best_score, 0.95)
        
        # Determine role
        role = DeviceRole.ENDPOINT
        if best_type in (DeviceType.ROUTER, DeviceType.SWITCH, DeviceType.GATEWAY):
            role = DeviceRole.INFRASTRUCTURE
        elif best_type in (DeviceType.SERVER, DeviceType.DNS_SERVER, DeviceType.DHCP_SERVER, DeviceType.NAS):
            role = DeviceRole.SERVICE_PROVIDER
        elif best_type in (DeviceType.WORKSTATION, DeviceType.MOBILE):
            role = DeviceRole.CLIENT
        
        # Get alternative types
        sorted_types = sorted(
            [(t, s) for t, s in type_scores.items() if s > 0.1 and t != best_type],
            key=lambda x: x[1],
            reverse=True
        )
        
        classification = DeviceClassification(
            device_type=best_type,
            role=role,
            confidence=confidence,
            evidence=evidence,
            alternative_types=sorted_types[:3],
            os_hint=os_hint,
            vendor=vendor,
            services=services_detected
        )
        
        self._classifications[ip] = classification
        return classification
    
    def get_classification(self, ip: str) -> Optional[DeviceClassification]:
        """Get cached classification for an IP."""
        return self._classifications.get(ip)
    
    def get_all_classifications(self) -> Dict[str, DeviceClassification]:
        """Get all current classifications."""
        return self._classifications.copy()
    
    def get_profile(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get raw profile data for debugging."""
        return self._device_profiles.get(ip)
    
    def clear(self):
        """Clear all profiles and classifications."""
        self._device_profiles.clear()
        self._classifications.clear()

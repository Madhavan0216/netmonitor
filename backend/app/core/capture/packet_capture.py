"""
Packet Capture Service
Captures and analyzes network packets using Scapy.
"""

import asyncio
from collections import deque
from datetime import datetime
from typing import Optional, Callable, Dict, List, Any
from dataclasses import dataclass, field, asdict
import threading
import structlog

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Ether, Raw, conf
    from scapy.arch import get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from app.core.config import settings
from app.core.capture.interface_utils import get_all_interfaces, get_default_capture_interface
from app.core.telemetry.metrics import metrics, MetricNames

logger = structlog.get_logger(__name__)


@dataclass
class PacketInfo:
    """Parsed packet information."""
    timestamp: str
    source_ip: str
    destination_ip: str
    source_mac: Optional[str] = None
    destination_mac: Optional[str] = None
    protocol: str = "UNKNOWN"
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    size: int = 0
    flags: Optional[str] = None
    info: str = ""
    layer: str = "unknown"
    raw_summary: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CaptureStats:
    """Capture statistics."""
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    arp_packets: int = 0
    dns_packets: int = 0
    http_packets: int = 0
    https_packets: int = 0
    other_packets: int = 0
    total_bytes: int = 0
    unique_sources: set = field(default_factory=set)
    unique_destinations: set = field(default_factory=set)
    start_time: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_packets": self.total_packets,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "icmp_packets": self.icmp_packets,
            "arp_packets": self.arp_packets,
            "dns_packets": self.dns_packets,
            "http_packets": self.http_packets,
            "https_packets": self.https_packets,
            "other_packets": self.other_packets,
            "total_bytes": self.total_bytes,
            "unique_sources": len(self.unique_sources),
            "unique_destinations": len(self.unique_destinations),
            "start_time": self.start_time.isoformat() if self.start_time else None
        }


class PacketCaptureService:
    """Service for capturing and processing network packets."""
    
    def __init__(self, detection_engine=None, topology_service=None):
        self.detection_engine = detection_engine
        self.topology_service = topology_service
        self.is_running = False
        self.capture_thread: Optional[threading.Thread] = None
        self.interface: Optional[str] = None
        self.bpf_filter: str = settings.CAPTURE_FILTER
        
        # Packet buffer (circular queue)
        self.packet_buffer: deque = deque(maxlen=settings.CAPTURE_BUFFER_SIZE)
        
        # Statistics
        self.stats = CaptureStats()
        
        # Callbacks for real-time updates
        self.packet_callbacks: List[Callable] = []
        
        # Event loop reference for async callbacks
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available - packet capture disabled")
    
    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Get available network interfaces with full details."""
        if not SCAPY_AVAILABLE:
            return []
        
        try:
            return get_all_interfaces()
        except Exception as e:
            logger.error("Failed to get interfaces", error=str(e))
            return []
    
    def add_callback(self, callback: Callable):
        """Add a callback for packet events."""
        self.packet_callbacks.append(callback)
    
    def remove_callback(self, callback: Callable):
        """Remove a packet callback."""
        if callback in self.packet_callbacks:
            self.packet_callbacks.remove(callback)
    
    async def start(self, interface: str = None, bpf_filter: str = None) -> bool:
        """Start packet capture."""
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start capture - Scapy not available")
            return False
        
        if self.is_running:
            logger.warning("Capture already running")
            return True
        
        self.interface = interface or settings.CAPTURE_INTERFACE or self._get_default_interface()
        self.bpf_filter = bpf_filter or settings.CAPTURE_FILTER
        
        if not self.interface:
            logger.error("No interface specified for capture")
            return False
        
        self._loop = asyncio.get_event_loop()
        self.stats = CaptureStats(start_time=datetime.utcnow())
        self.is_running = True
        
        # Start capture in separate thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            daemon=True
        )
        self.capture_thread.start()
        
        logger.info("Packet capture started", interface=self.interface, filter=self.bpf_filter)
        return True
    
    async def stop(self) -> bool:
        """Stop packet capture."""
        if not self.is_running:
            return True
        
        self.is_running = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
            self.capture_thread = None
        
        logger.info("Packet capture stopped")
        return True
    
    def _get_default_interface(self) -> Optional[str]:
        """Get default capture interface."""
        try:
            return get_default_capture_interface()
        except Exception:
            return None
    
    def _capture_packets(self):
        """Capture packets in a separate thread."""
        logger.info("Capture thread started", interface=self.interface, filter=self.bpf_filter)
        packet_count = 0
        
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter if self.bpf_filter else None,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self.is_running
            )
        except PermissionError as e:
            logger.error("Permission denied for packet capture - run as Administrator/root", error=str(e))
            self.is_running = False
        except Exception as e:
            logger.error("Capture error", error=str(e), exc_info=True)
            self.is_running = False
        finally:
            logger.info("Capture thread stopped", packets_captured=self.stats.total_packets)
    
    def _process_packet(self, packet):
        """Process a captured packet."""
        try:
            packet_info = self._parse_packet(packet)
            if packet_info:
                # Record metrics
                metrics.increment(MetricNames.PACKETS_CAPTURED)
                metrics.increment(MetricNames.BYTES_CAPTURED, packet_info.size)
                metrics.rate(MetricNames.PACKETS_PER_SEC, 1)
                
                # Update statistics
                self._update_stats(packet_info, packet)
                
                # Log every 100th packet for debugging
                if self.stats.total_packets % 100 == 1:
                    logger.debug(
                        "Packet captured",
                        count=self.stats.total_packets,
                        protocol=packet_info.protocol,
                        src=packet_info.source_ip,
                        dst=packet_info.destination_ip,
                        callbacks=len(self.packet_callbacks)
                    )
                
                # Add to buffer (deque handles overflow automatically)
                buffer_was_full = len(self.packet_buffer) >= self.packet_buffer.maxlen
                self.packet_buffer.append(packet_info)
                if buffer_was_full:
                    metrics.increment(MetricNames.PACKETS_DROPPED)
                
                # Update buffer gauge
                metrics.gauge(
                    "capture.buffer_utilization_pct",
                    (len(self.packet_buffer) / self.packet_buffer.maxlen) * 100
                )
                
                # Send to detection engine
                if self.detection_engine:
                    self.detection_engine.analyze_packet(packet_info)
                
                # Update topology service
                if self.topology_service and packet_info.source_ip != "N/A":
                    self.topology_service.process_packet(
                        src_ip=packet_info.source_ip,
                        dst_ip=packet_info.destination_ip,
                        protocol=packet_info.protocol,
                        size=packet_info.size,
                        src_mac=packet_info.source_mac,
                        dst_mac=packet_info.destination_mac,
                        src_port=packet_info.source_port,
                        dst_port=packet_info.destination_port,
                        tcp_flags=packet_info.flags
                    )
                
                # Notify callbacks
                self._notify_callbacks(packet_info)
        
        except Exception as e:
            logger.error("Error processing packet", error=str(e))
            metrics.increment("capture.errors")
    
    def _parse_packet(self, packet) -> Optional[PacketInfo]:
        """Parse a Scapy packet into PacketInfo."""
        try:
            timestamp = datetime.utcnow().isoformat()
            
            # Get Ethernet layer
            src_mac = dst_mac = None
            if Ether in packet:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
            
            # Get IP layer
            src_ip = dst_ip = "N/A"
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif ARP in packet:
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst
            else:
                return None  # Skip non-IP packets for now
            
            # Determine protocol and ports
            protocol = "UNKNOWN"
            src_port = dst_port = None
            flags = None
            info = ""
            layer = "network"
            
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = str(packet[TCP].flags)
                layer = "transport"
                
                # Check for HTTP/HTTPS
                if dst_port == 80 or src_port == 80:
                    protocol = "HTTP"
                    layer = "application"
                elif dst_port == 443 or src_port == 443:
                    protocol = "HTTPS"
                    layer = "application"
                
                info = f"Flags: {flags}"
            
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                layer = "transport"
                
                # Check for DNS
                if DNS in packet:
                    protocol = "DNS"
                    layer = "application"
                    if packet[DNS].qd:
                        info = f"Query: {packet[DNS].qd.qname.decode('utf-8', errors='ignore')}"
            
            elif ICMP in packet:
                protocol = "ICMP"
                layer = "network"
                icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
                icmp_type = packet[ICMP].type
                info = icmp_types.get(icmp_type, f"Type: {icmp_type}")
            
            elif ARP in packet:
                protocol = "ARP"
                layer = "link"
                arp_ops = {1: "Request", 2: "Reply"}
                info = arp_ops.get(packet[ARP].op, f"Op: {packet[ARP].op}")
            
            return PacketInfo(
                timestamp=timestamp,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_mac=src_mac,
                destination_mac=dst_mac,
                protocol=protocol,
                source_port=src_port,
                destination_port=dst_port,
                size=len(packet),
                flags=flags,
                info=info,
                layer=layer,
                raw_summary=packet.summary()
            )
        
        except Exception as e:
            logger.error("Error parsing packet", error=str(e))
            return None
    
    def _update_stats(self, packet_info: PacketInfo, raw_packet):
        """Update capture statistics."""
        self.stats.total_packets += 1
        self.stats.total_bytes += packet_info.size
        
        if packet_info.source_ip != "N/A":
            self.stats.unique_sources.add(packet_info.source_ip)
        if packet_info.destination_ip != "N/A":
            self.stats.unique_destinations.add(packet_info.destination_ip)
        
        protocol = packet_info.protocol.upper()
        if protocol == "TCP":
            self.stats.tcp_packets += 1
        elif protocol == "UDP":
            self.stats.udp_packets += 1
        elif protocol == "ICMP":
            self.stats.icmp_packets += 1
        elif protocol == "ARP":
            self.stats.arp_packets += 1
        elif protocol == "DNS":
            self.stats.dns_packets += 1
        elif protocol == "HTTP":
            self.stats.http_packets += 1
        elif protocol == "HTTPS":
            self.stats.https_packets += 1
        else:
            self.stats.other_packets += 1
    
    def _notify_callbacks(self, packet_info: PacketInfo):
        """Notify all registered callbacks - CRITICAL for real-time streaming."""
        if not self.packet_callbacks:
            return
            
        for callback in self.packet_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    if self._loop and self._loop.is_running():
                        future = asyncio.run_coroutine_threadsafe(
                            callback(packet_info),
                            self._loop
                        )
                        # Don't block, but log errors
                        def handle_callback_error(f):
                            try:
                                f.result()
                            except Exception as e:
                                logger.error("Async callback error", error=str(e))
                        future.add_done_callback(handle_callback_error)
                    else:
                        logger.warning("Event loop not available for async callback")
                else:
                    callback(packet_info)
            except Exception as e:
                logger.error("Callback error", error=str(e))
    
    def get_recent_packets(self, limit: int = 100) -> List[Dict]:
        """Get recent captured packets."""
        packets = list(self.packet_buffer)[-limit:]
        return [p.to_dict() for p in packets]
    
    def get_stats(self) -> Dict:
        """Get capture statistics."""
        return self.stats.to_dict()
    
    def clear_buffer(self):
        """Clear packet buffer."""
        self.packet_buffer.clear()
    
    def is_capture_running(self) -> bool:
        """Check if capture is running."""
        return self.is_running

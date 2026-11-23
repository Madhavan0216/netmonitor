"""
ARP Table Monitor

Arpwatch-like functionality for detecting:
- New devices on network
- MAC address changes (possible spoofing)
- IP conflicts
- ARP anomalies
"""

import asyncio
import platform
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Callable, Any, Tuple
import structlog

logger = structlog.get_logger(__name__)


class ARPEventType(str, Enum):
    """Types of ARP events."""
    NEW_HOST = "new_host"           # New IP/MAC pair seen
    MAC_CHANGE = "mac_change"       # MAC changed for known IP
    IP_CONFLICT = "ip_conflict"     # Multiple MACs claiming same IP
    FLIP_FLOP = "flip_flop"         # MAC oscillating between IPs
    HOST_GONE = "host_gone"         # Host not seen for threshold time
    GRATUITOUS_ARP = "gratuitous"   # Gratuitous ARP detected


@dataclass
class ARPEntry:
    """An entry in the ARP table."""
    ip_address: str
    mac_address: str
    interface: Optional[str] = None
    is_permanent: bool = False
    state: str = "REACHABLE"  # REACHABLE, STALE, DELAY, PROBE, FAILED
    
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Historical MACs seen for this IP
    mac_history: List[str] = field(default_factory=lambda: [])
    
    # Metadata
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "interface": self.interface,
            "is_permanent": self.is_permanent,
            "state": self.state,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "mac_history": self.mac_history[-5:],  # Last 5 MACs
            "vendor": self.vendor,
            "hostname": self.hostname,
            "age_seconds": (datetime.now(timezone.utc) - self.last_seen).total_seconds()
        }


@dataclass
class ARPEvent:
    """An ARP-related event."""
    event_type: ARPEventType
    ip_address: str
    mac_address: str
    
    old_mac: Optional[str] = None  # For MAC_CHANGE events
    interface: Optional[str] = None
    details: str = ""
    severity: str = "info"  # info, warning, critical
    
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "old_mac": self.old_mac,
            "interface": self.interface,
            "details": self.details,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat()
        }


class ARPMonitor:
    """
    Monitors ARP table for changes and anomalies.
    
    Features:
    - Detects new hosts on network
    - Alerts on MAC address changes (possible spoofing)
    - Tracks MAC history per IP
    - Detects flip-flop behavior
    - Configurable staleness threshold
    
    Platform support:
    - Linux: ip neigh, /proc/net/arp
    - Windows: arp -a (via subprocess)
    """
    
    def __init__(
        self,
        poll_interval: float = 10.0,
        stale_threshold: int = 300,
        on_event: Optional[Callable[[ARPEvent], None]] = None
    ):
        self._poll_interval = poll_interval
        self._stale_threshold = stale_threshold
        self._on_event = on_event
        
        self._is_linux = platform.system() == "Linux"
        self._entries: Dict[str, ARPEntry] = {}
        self._lock = threading.Lock()
        
        self._running = False
        self._task: Optional[asyncio.Task[None]] = None
        self._arp_error_logged = False  # Only log ARP errors once
        
        # Track recent MAC changes to detect flip-flops
        self._mac_changes: Dict[str, List[Tuple[datetime, str]]] = {}  # ip -> [(timestamp, mac), ...]
        
        logger.info(
            "ARP monitor initialized",
            platform=platform.system(),
            poll_interval=poll_interval,
            stale_threshold=stale_threshold
        )
    
    async def start(self):
        """Start ARP monitoring."""
        if self._running:
            return
        
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info("ARP monitor started")
    
    async def stop(self):
        """Stop ARP monitoring."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("ARP monitor stopped")
    
    async def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                await self._update_arp_table()
                await self._check_stale_entries()
                await asyncio.sleep(self._poll_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("ARP monitor loop error", error=str(e))
                await asyncio.sleep(self._poll_interval)
    
    async def _update_arp_table(self):
        """Update ARP table from system."""
        if self._is_linux:
            entries = await self._read_linux_arp()
        else:
            entries = await self._read_windows_arp()
        
        now = datetime.now(timezone.utc)
        
        with self._lock:
            # Check each new entry
            for ip, new_entry in entries.items():
                if ip not in self._entries:
                    # New host
                    self._entries[ip] = new_entry
                    self._emit_event(ARPEvent(
                        event_type=ARPEventType.NEW_HOST,
                        ip_address=ip,
                        mac_address=new_entry.mac_address,
                        interface=new_entry.interface,
                        details=f"New host discovered: {ip} -> {new_entry.mac_address}",
                        severity="info"
                    ))
                else:
                    # Existing host - check for changes
                    existing = self._entries[ip]
                    existing.last_seen = now
                    existing.state = new_entry.state
                    
                    if existing.mac_address != new_entry.mac_address:
                        # MAC change detected!
                        old_mac = existing.mac_address
                        
                        # Record in history
                        if old_mac not in existing.mac_history:
                            existing.mac_history.append(old_mac)
                        
                        existing.mac_address = new_entry.mac_address
                        
                        # Track for flip-flop detection
                        if ip not in self._mac_changes:
                            self._mac_changes[ip] = []
                        self._mac_changes[ip].append((now, new_entry.mac_address))
                        
                        # Check for flip-flop (3+ changes in 5 minutes)
                        recent_changes = [
                            c for c in self._mac_changes[ip]
                            if (now - c[0]).total_seconds() < 300
                        ]
                        
                        if len(recent_changes) >= 3:
                            self._emit_event(ARPEvent(
                                event_type=ARPEventType.FLIP_FLOP,
                                ip_address=ip,
                                mac_address=new_entry.mac_address,
                                old_mac=old_mac,
                                interface=new_entry.interface,
                                details=f"MAC flip-flop detected for {ip}: {len(recent_changes)} changes in 5 min",
                                severity="critical"
                            ))
                        else:
                            self._emit_event(ARPEvent(
                                event_type=ARPEventType.MAC_CHANGE,
                                ip_address=ip,
                                mac_address=new_entry.mac_address,
                                old_mac=old_mac,
                                interface=new_entry.interface,
                                details=f"MAC changed for {ip}: {old_mac} -> {new_entry.mac_address}",
                                severity="warning"
                            ))
    
    async def _check_stale_entries(self):
        """Check for hosts that have gone away."""
        now = datetime.now(timezone.utc)
        threshold = timedelta(seconds=self._stale_threshold)
        
        with self._lock:
            stale_ips: List[str] = []
            for ip, entry in self._entries.items():
                if (now - entry.last_seen) > threshold:
                    stale_ips.append(ip)
            
            for ip in stale_ips:
                entry = self._entries.pop(ip)
                self._emit_event(ARPEvent(
                    event_type=ARPEventType.HOST_GONE,
                    ip_address=ip,
                    mac_address=entry.mac_address,
                    interface=entry.interface,
                    details=f"Host {ip} not seen for {self._stale_threshold}s",
                    severity="info"
                ))
    
    async def _read_linux_arp(self) -> Dict[str, ARPEntry]:
        """Read ARP table on Linux."""
        entries = {}
        
        try:
            # Try ip neigh first (more detailed)
            result = await asyncio.create_subprocess_exec(
                "ip", "neigh", "show",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            # Parse: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
            for line in stdout.decode().strip().split("\n"):
                if not line:
                    continue
                
                parts = line.split()
                if len(parts) < 4:
                    continue
                
                ip = parts[0]
                
                # Find MAC and state
                mac = None
                state = "UNKNOWN"
                interface = None
                
                for i, part in enumerate(parts):
                    if part == "dev" and i + 1 < len(parts):
                        interface = parts[i + 1]
                    elif part == "lladdr" and i + 1 < len(parts):
                        mac = parts[i + 1]
                    elif part in ("REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "PERMANENT"):
                        state = part
                
                if mac and self._is_valid_mac(mac):
                    entries[ip] = ARPEntry(
                        ip_address=ip,
                        mac_address=mac.lower(),
                        interface=interface,
                        state=state,
                        is_permanent=(state == "PERMANENT")
                    )
        
        except Exception as e:
            logger.error("Error reading Linux ARP table", error=str(e))
            # Fallback to /proc/net/arp
            entries = await self._read_proc_net_arp()
        
        return entries
    
    async def _read_proc_net_arp(self) -> Dict[str, ARPEntry]:
        """Fallback: read from /proc/net/arp."""
        entries: Dict[str, ARPEntry] = {}
        
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]  # Skip header
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 6:
                    ip = parts[0]
                    mac = parts[3]
                    interface = parts[5]
                    
                    if mac != "00:00:00:00:00:00" and self._is_valid_mac(mac):
                        entries[ip] = ARPEntry(
                            ip_address=ip,
                            mac_address=mac.lower(),
                            interface=interface
                        )
        
        except Exception as e:
            logger.error("Error reading /proc/net/arp", error=str(e))
        
        return entries
    
    async def _read_windows_arp(self) -> Dict[str, ARPEntry]:
        """Read ARP table on Windows."""
        entries: Dict[str, ARPEntry] = {}
        
        try:
            result = await asyncio.create_subprocess_exec(
                "arp", "-a",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            # Check for errors
            if result.returncode != 0:
                logger.debug("Windows ARP command returned non-zero", returncode=result.returncode)
                return entries
            
            # Parse Windows arp output
            # Interface: 192.168.1.100 --- 0x3
            #   Internet Address      Physical Address      Type
            #   192.168.1.1           00-11-22-33-44-55     dynamic
            
            current_interface = None
            mac_pattern = re.compile(r"([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})")
            
            output_text = stdout.decode(errors='ignore').strip()
            for line in output_text.split("\n"):
                line = line.strip()
                
                if line.startswith("Interface:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        current_interface = parts[1]
                    continue
                
                # Match IP and MAC
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac_match = mac_pattern.search(line)
                    
                    if mac_match and self._is_valid_ip(ip):
                        mac = mac_match.group(1).replace("-", ":").lower()
                        entry_type = parts[-1] if parts[-1] in ("dynamic", "static") else "dynamic"
                        
                        entries[ip] = ARPEntry(
                            ip_address=ip,
                            mac_address=mac,
                            interface=current_interface,
                            is_permanent=(entry_type == "static")
                        )
        
        except FileNotFoundError:
            if not self._arp_error_logged:
                logger.info("Windows ARP command not available")
                self._arp_error_logged = True
        except Exception as e:
            if not self._arp_error_logged:
                logger.debug("Error reading Windows ARP table", error=str(e))
                self._arp_error_logged = True
        
        return entries
    
    def _is_valid_mac(self, mac: str) -> bool:
        """Validate MAC address format."""
        if not mac:
            return False
        mac = mac.lower().replace("-", ":")
        if mac == "00:00:00:00:00:00" or mac == "ff:ff:ff:ff:ff:ff":
            return False
        return bool(re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac))
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IPv4 address format."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    
    def _emit_event(self, event: ARPEvent):
        """Emit an ARP event."""
        logger.info(
            "ARP event",
            event_type=event.event_type.value,
            ip=event.ip_address,
            mac=event.mac_address,
            severity=event.severity
        )
        
        if self._on_event:
            try:
                self._on_event(event)
            except Exception as e:
                logger.error("ARP event callback error", error=str(e))
    
    def get_entries(self) -> Dict[str, ARPEntry]:
        """Get all ARP entries."""
        with self._lock:
            return dict(self._entries)
    
    def get_entries_dict(self) -> Dict[str, Dict[str, Any]]:
        """Get entries as dictionary."""
        entries = self.get_entries()
        return {ip: e.to_dict() for ip, e in entries.items()}
    
    def get_entry(self, ip: str) -> Optional[ARPEntry]:
        """Get entry for specific IP."""
        with self._lock:
            return self._entries.get(ip)
    
    def get_hosts_by_mac(self, mac: str) -> List[ARPEntry]:
        """Find all IPs associated with a MAC."""
        mac = mac.lower()
        with self._lock:
            return [e for e in self._entries.values() if e.mac_address == mac]
    
    def process_arp_packet(self, src_ip: str, src_mac: str, dst_ip: str, op: int):
        """
        Process an ARP packet from packet capture.
        
        Args:
            src_ip: Source IP
            src_mac: Source MAC
            dst_ip: Target IP
            op: ARP operation (1=request, 2=reply)
        """
        if not src_mac or not self._is_valid_mac(src_mac):
            return
        
        src_mac = src_mac.lower()
        
        # Detect gratuitous ARP (src_ip == dst_ip)
        if src_ip == dst_ip and op == 2:
            self._emit_event(ARPEvent(
                event_type=ARPEventType.GRATUITOUS_ARP,
                ip_address=src_ip,
                mac_address=src_mac,
                details=f"Gratuitous ARP from {src_ip} ({src_mac})",
                severity="info"
            ))
        
        # Update entry
        with self._lock:
            if src_ip in self._entries:
                entry = self._entries[src_ip]
                entry.last_seen = datetime.now(timezone.utc)
                
                if entry.mac_address != src_mac:
                    # MAC changed - will be caught in next poll
                    pass
            else:
                # New entry from packet
                self._entries[src_ip] = ARPEntry(
                    ip_address=src_ip,
                    mac_address=src_mac
                )

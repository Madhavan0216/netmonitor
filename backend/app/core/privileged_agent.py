"""
Privileged Agent Abstraction for Packet Capture

This module provides a clean abstraction layer for privileged operations
(packet capture) following DESIGN_SPECIFICATION.md Section 3.3.

The design isolates privileged code and enforces an allowlist-only approach
for security. In production, this would communicate with a separate
privileged process via Unix socket IPC.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol
import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# Operation Types (Allowlist)
# =============================================================================

class PrivilegedOperation(str, Enum):
    """
    Allowlisted privileged operations.
    
    Only these operations are permitted through the privileged agent.
    Any other operation is denied by design.
    """
    CAPTURE_START = "capture.start"
    CAPTURE_STOP = "capture.stop"
    INTERFACES_LIST = "interfaces.list"
    INTERFACES_STATS = "interfaces.get_stats"
    ARP_READ_CACHE = "arp.read_cache"


# =============================================================================
# Data Types
# =============================================================================

@dataclass
class InterfaceInfo:
    """Network interface information."""
    name: str
    display_name: str
    description: str = ""
    mac_address: Optional[str] = None
    ip_addresses: List[str] = field(default_factory=lambda: [])
    is_up: bool = False
    is_loopback: bool = False
    is_wireless: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "mac_address": self.mac_address,
            "ip_addresses": self.ip_addresses,
            "is_up": self.is_up,
            "is_loopback": self.is_loopback,
            "is_wireless": self.is_wireless
        }


@dataclass
class InterfaceStats:
    """Interface statistics."""
    name: str
    bytes_recv: int = 0
    bytes_sent: int = 0
    packets_recv: int = 0
    packets_sent: int = 0
    errors_in: int = 0
    errors_out: int = 0
    drops_in: int = 0
    drops_out: int = 0


@dataclass
class ARPEntry:
    """ARP cache entry."""
    ip_address: str
    mac_address: str
    interface: str
    state: str = "reachable"  # reachable, stale, delay, probe, failed


@dataclass
class PrivilegedRequest:
    """Request to the privileged agent."""
    operation: PrivilegedOperation
    params: Dict[str, Any] = field(default_factory=lambda: {})
    request_id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PrivilegedResponse:
    """Response from the privileged agent."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    request_id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Privileged Agent Interface
# =============================================================================

class IPrivilegedAgent(Protocol):
    """
    Interface for privileged agent implementations.
    
    This protocol defines the minimal surface area for privileged operations.
    Implementations can be:
    - Direct (in-process, for development)
    - IPC-based (Unix socket to separate process, for production)
    """
    
    async def start_capture(
        self,
        interface: str,
        bpf_filter: str = "",
        callback: Optional[Callable[[Any], None]] = None
    ) -> PrivilegedResponse:
        """Start packet capture on an interface."""
        ...
    
    async def stop_capture(self) -> PrivilegedResponse:
        """Stop active packet capture."""
        ...
    
    async def list_interfaces(self) -> PrivilegedResponse:
        """List available network interfaces."""
        ...
    
    async def get_interface_stats(self, interface: str) -> PrivilegedResponse:
        """Get statistics for a specific interface."""
        ...
    
    async def read_arp_cache(self) -> PrivilegedResponse:
        """Read the system ARP cache."""
        ...


# =============================================================================
# Direct Implementation (Development Mode)
# =============================================================================

class DirectPrivilegedAgent:
    """
    Direct in-process privileged agent for development.
    
    WARNING: This implementation runs privileged code in the same process.
    For production, use IPCPrivilegedAgent with a separate privileged process.
    """
    
    def __init__(self):
        self._capture_active = False
        self._capture_thread: Optional[threading.Thread] = None
        self._packet_callback: Optional[Callable[[Any], None]] = None
        self._stop_event = threading.Event()
        
        # Import scapy lazily to avoid issues when not installed
        self._scapy_available = False
        try:
            from scapy.all import sniff, get_if_list, get_if_addr, conf
            self._scapy_available = True
            self._sniff = sniff
            self._get_if_list = get_if_list
            self._get_if_addr = get_if_addr
            self._conf = conf
        except ImportError:
            logger.warning("Scapy not available - capture disabled")
    
    async def execute(self, request: PrivilegedRequest) -> PrivilegedResponse:
        """
        Execute a privileged operation.
        
        This is the single entry point for all privileged operations,
        enforcing the allowlist.
        """
        # Validate operation is in allowlist
        if request.operation not in PrivilegedOperation:
            return PrivilegedResponse(
                success=False,
                error=f"Operation '{request.operation}' not in allowlist",
                request_id=request.request_id
            )
        
        try:
            if request.operation == PrivilegedOperation.CAPTURE_START:
                return await self.start_capture(
                    interface=request.params.get("interface", ""),
                    bpf_filter=request.params.get("bpf_filter", ""),
                    callback=request.params.get("callback")
                )
            elif request.operation == PrivilegedOperation.CAPTURE_STOP:
                return await self.stop_capture()
            elif request.operation == PrivilegedOperation.INTERFACES_LIST:
                return await self.list_interfaces()
            elif request.operation == PrivilegedOperation.INTERFACES_STATS:
                return await self.get_interface_stats(
                    interface=request.params.get("interface", "")
                )
            elif request.operation == PrivilegedOperation.ARP_READ_CACHE:
                return await self.read_arp_cache()
            else:
                return PrivilegedResponse(
                    success=False,
                    error=f"Unhandled operation: {request.operation}",
                    request_id=request.request_id
                )
        except Exception as e:
            logger.error(
                "Privileged operation failed",
                operation=request.operation,
                error=str(e),
                exc_info=True
            )
            return PrivilegedResponse(
                success=False,
                error=str(e),
                request_id=request.request_id
            )
    
    async def start_capture(
        self,
        interface: str,
        bpf_filter: str = "",
        callback: Optional[Callable[[Any], None]] = None
    ) -> PrivilegedResponse:
        """Start packet capture."""
        if not self._scapy_available:
            return PrivilegedResponse(
                success=False,
                error="Scapy not available. Install with: pip install scapy"
            )
        
        if self._capture_active:
            return PrivilegedResponse(
                success=False,
                error="Capture already active. Stop current capture first."
            )
        
        # Validate interface exists
        try:
            interfaces = self._get_if_list()
            if interface and interface not in interfaces:
                return PrivilegedResponse(
                    success=False,
                    error=f"Interface '{interface}' not found. Available: {interfaces}"
                )
        except Exception as e:
            return PrivilegedResponse(
                success=False,
                error=f"Failed to list interfaces: {e}"
            )
        
        self._packet_callback = callback
        self._stop_event.clear()
        self._capture_active = True
        
        # Start capture in background thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(interface, bpf_filter),
            daemon=True
        )
        self._capture_thread.start()
        
        logger.info(
            "Packet capture started",
            interface=interface or "all",
            filter=bpf_filter or "none"
        )
        
        return PrivilegedResponse(
            success=True,
            data={
                "interface": interface or "all",
                "filter": bpf_filter,
                "status": "capturing"
            }
        )
    
    def _capture_loop(self, interface: str, bpf_filter: str):
        """Background capture loop."""
        try:
            def packet_handler(pkt: Any) -> bool:
                if self._stop_event.is_set():
                    return True  # Stop sniffing
                if self._packet_callback:
                    try:
                        self._packet_callback(pkt)
                    except Exception as e:
                        logger.error("Packet callback error", error=str(e))
                return False
            
            self._sniff(
                iface=interface if interface else None,
                filter=bpf_filter if bpf_filter else None,
                prn=packet_handler,
                store=False,
                stop_filter=lambda _pkt: self._stop_event.is_set()  # type: ignore[arg-type]
            )
        except Exception as e:
            logger.error("Capture loop error", error=str(e))
        finally:
            self._capture_active = False
    
    async def stop_capture(self) -> PrivilegedResponse:
        """Stop packet capture."""
        if not self._capture_active:
            return PrivilegedResponse(
                success=True,
                data={"status": "already_stopped"}
            )
        
        self._stop_event.set()
        
        # Wait for thread to finish (with timeout)
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5.0)
        
        self._capture_active = False
        self._packet_callback = None
        
        logger.info("Packet capture stopped")
        
        return PrivilegedResponse(
            success=True,
            data={"status": "stopped"}
        )
    
    async def list_interfaces(self) -> PrivilegedResponse:
        """List network interfaces."""
        if not self._scapy_available:
            # Fallback to psutil if available
            try:
                import psutil  # type: ignore[import-not-found]
                interfaces: List[Dict[str, Any]] = []
                for name, addrs in psutil.net_if_addrs().items():
                    info = InterfaceInfo(
                        name=name,
                        display_name=name,
                        ip_addresses=[
                            a.address for a in addrs 
                            if a.family.name == 'AF_INET'
                        ],
                        mac_address=next(
                            (a.address for a in addrs if a.family.name in ('AF_PACKET', 'AF_LINK')),
                            None
                        )
                    )
                    
                    # Check if up
                    stats = psutil.net_if_stats().get(name)
                    if stats:
                        info.is_up = stats.isup
                    
                    interfaces.append(info.to_dict())
                
                return PrivilegedResponse(success=True, data=interfaces)
            except ImportError:
                return PrivilegedResponse(
                    success=False,
                    error="Neither scapy nor psutil available for interface listing"
                )
        
        try:
            from scapy.arch import get_if_list, get_if_addr, get_if_hwaddr
            
            interfaces: List[Dict[str, Any]] = []
            for name in get_if_list():
                try:
                    ip = get_if_addr(name)
                    mac = get_if_hwaddr(name)
                except:
                    ip = None
                    mac = None
                
                info = InterfaceInfo(
                    name=name,
                    display_name=name,
                    ip_addresses=[ip] if ip and ip != '0.0.0.0' else [],
                    mac_address=mac,
                    is_loopback=name.startswith('lo'),
                    is_wireless=name.startswith(('wlan', 'wl', 'wifi'))
                )
                interfaces.append(info.to_dict())
            
            return PrivilegedResponse(success=True, data=interfaces)
        except Exception as e:
            return PrivilegedResponse(
                success=False,
                error=f"Failed to list interfaces: {e}"
            )
    
    async def get_interface_stats(self, interface: str) -> PrivilegedResponse:
        """Get interface statistics."""
        try:
            import psutil  # type: ignore[import-not-found]
            
            stats = psutil.net_io_counters(pernic=True).get(interface)
            if not stats:
                return PrivilegedResponse(
                    success=False,
                    error=f"Interface '{interface}' not found"
                )
            
            return PrivilegedResponse(
                success=True,
                data=InterfaceStats(
                    name=interface,
                    bytes_recv=stats.bytes_recv,
                    bytes_sent=stats.bytes_sent,
                    packets_recv=stats.packets_recv,
                    packets_sent=stats.packets_sent,
                    errors_in=stats.errin,
                    errors_out=stats.errout,
                    drops_in=stats.dropin,
                    drops_out=stats.dropout
                ).__dict__
            )
        except ImportError:
            return PrivilegedResponse(
                success=False,
                error="psutil not available for interface stats"
            )
        except Exception as e:
            return PrivilegedResponse(
                success=False,
                error=f"Failed to get stats: {e}"
            )
    
    async def read_arp_cache(self) -> PrivilegedResponse:
        """Read system ARP cache."""
        entries: List[Dict[str, Any]] = []
        
        # Try reading from /proc/net/arp (Linux)
        try:
            with open('/proc/net/arp', 'r') as f:
                lines = f.readlines()[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        mac = parts[3]
                        iface = parts[5]
                        if mac != '00:00:00:00:00:00':
                            entries.append(ARPEntry(
                                ip_address=ip,
                                mac_address=mac,
                                interface=iface
                            ).__dict__)
            
            return PrivilegedResponse(success=True, data=entries)
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning("Failed to read /proc/net/arp", error=str(e))
        
        # Fallback: try arp command (Windows/macOS)
        try:
            import subprocess
            result = subprocess.run(
                ['arp', '-a'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                import re
                # Parse arp -a output (varies by OS)
                for line in result.stdout.split('\n'):
                    # Try to match IP and MAC patterns
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    mac_match = re.search(
                        r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}',
                        line
                    )
                    if ip_match and mac_match:
                        entries.append(ARPEntry(
                            ip_address=ip_match.group(1),
                            mac_address=mac_match.group(0).replace('-', ':').lower(),
                            interface=""
                        ).__dict__)
                
                return PrivilegedResponse(success=True, data=entries)
        except Exception as e:
            logger.warning("Failed to run arp command", error=str(e))
        
        return PrivilegedResponse(
            success=False,
            error="Unable to read ARP cache (not supported on this platform)"
        )


# =============================================================================
# Factory Function
# =============================================================================

def create_privileged_agent(mode: str = "direct") -> DirectPrivilegedAgent:
    """
    Create a privileged agent instance.
    
    Args:
        mode: "direct" for in-process, "ipc" for separate process (future)
        
    Returns:
        Privileged agent instance
    """
    if mode == "direct":
        return DirectPrivilegedAgent()
    else:
        raise ValueError(f"Unknown privileged agent mode: {mode}")


# Singleton instance
_agent_instance: Optional[DirectPrivilegedAgent] = None


def get_privileged_agent() -> DirectPrivilegedAgent:
    """Get the singleton privileged agent instance."""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = create_privileged_agent("direct")
    return _agent_instance

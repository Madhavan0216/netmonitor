"""
Network Interface Monitor

Tracks interface statistics (RX/TX, errors) and state changes.
Linux-first with Windows fallback.
"""

import asyncio
import platform
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class InterfaceStats:
    """Statistics for a network interface."""
    name: str
    is_up: bool = False
    
    # Byte counters
    rx_bytes: int = 0
    tx_bytes: int = 0
    
    # Packet counters
    rx_packets: int = 0
    tx_packets: int = 0
    
    # Error counters
    rx_errors: int = 0
    tx_errors: int = 0
    rx_dropped: int = 0
    tx_dropped: int = 0
    
    # Multicast/collisions
    multicast: int = 0
    collisions: int = 0
    
    # Derived metrics (calculated)
    rx_bytes_per_sec: float = 0.0
    tx_bytes_per_sec: float = 0.0
    rx_packets_per_sec: float = 0.0
    tx_packets_per_sec: float = 0.0
    
    # Metadata
    mtu: int = 1500
    mac_address: Optional[str] = None
    ip_addresses: List[str] = field(default_factory=lambda: [])
    
    # Timing
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "is_up": self.is_up,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "rx_packets": self.rx_packets,
            "tx_packets": self.tx_packets,
            "rx_errors": self.rx_errors,
            "tx_errors": self.tx_errors,
            "rx_dropped": self.rx_dropped,
            "tx_dropped": self.tx_dropped,
            "rx_bytes_per_sec": round(self.rx_bytes_per_sec, 1),
            "tx_bytes_per_sec": round(self.tx_bytes_per_sec, 1),
            "rx_packets_per_sec": round(self.rx_packets_per_sec, 1),
            "tx_packets_per_sec": round(self.tx_packets_per_sec, 1),
            "mtu": self.mtu,
            "mac_address": self.mac_address,
            "ip_addresses": self.ip_addresses,
            "last_updated": self.last_updated.isoformat()
        }


@dataclass
class InterfaceStateChange:
    """Event for interface state change."""
    interface: str
    old_state: bool
    new_state: bool
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "interface": self.interface,
            "event": "up" if self.new_state else "down",
            "old_state": "up" if self.old_state else "down",
            "timestamp": self.timestamp.isoformat()
        }


class InterfaceMonitor:
    """
    Monitors network interface statistics and state changes.
    
    Features:
    - RX/TX byte and packet counters
    - Error and drop counters
    - Rate calculations (bytes/packets per second)
    - Interface up/down detection
    - Callback on state changes
    
    Platform support:
    - Linux: /sys/class/net and /proc/net/dev
    - Windows: psutil fallback
    """
    
    def __init__(
        self,
        poll_interval: float = 1.0,
        on_state_change: Optional[Callable[[InterfaceStateChange], None]] = None
    ):
        self._poll_interval = poll_interval
        self._on_state_change = on_state_change
        
        self._is_linux = platform.system() == "Linux"
        self._stats: Dict[str, InterfaceStats] = {}
        self._prev_stats: Dict[str, InterfaceStats] = {}
        self._lock = threading.Lock()
        
        self._running = False
        self._task: Optional[asyncio.Task[None]] = None
        self._psutil_warned = False  # Only warn once about psutil

        logger.info(
            "Interface monitor initialized",
            platform=platform.system(),
            poll_interval=poll_interval
        )
    
    async def start(self):
        """Start monitoring interfaces."""
        if self._running:
            return
        
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info("Interface monitor started")
    
    async def stop(self):
        """Stop monitoring."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Interface monitor stopped")
    
    async def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                await self._update_stats()
                await asyncio.sleep(self._poll_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Monitor loop error", error=str(e))
                await asyncio.sleep(self._poll_interval)
    
    async def _update_stats(self):
        """Update all interface statistics."""
        if self._is_linux:
            stats = self._read_linux_stats()
        else:
            stats = self._read_windows_stats()
        
        with self._lock:
            for name, new_stats in stats.items():
                # Calculate rates if we have previous stats
                if name in self._prev_stats:
                    prev = self._prev_stats[name]
                    elapsed = (new_stats.last_updated - prev.last_updated).total_seconds()
                    
                    if elapsed > 0:
                        new_stats.rx_bytes_per_sec = (new_stats.rx_bytes - prev.rx_bytes) / elapsed
                        new_stats.tx_bytes_per_sec = (new_stats.tx_bytes - prev.tx_bytes) / elapsed
                        new_stats.rx_packets_per_sec = (new_stats.rx_packets - prev.rx_packets) / elapsed
                        new_stats.tx_packets_per_sec = (new_stats.tx_packets - prev.tx_packets) / elapsed
                
                # Check for state changes
                if name in self._stats:
                    old_up = self._stats[name].is_up
                    new_up = new_stats.is_up
                    
                    if old_up != new_up and self._on_state_change:
                        change = InterfaceStateChange(
                            interface=name,
                            old_state=old_up,
                            new_state=new_up
                        )
                        try:
                            self._on_state_change(change)
                        except Exception as e:
                            logger.error("State change callback error", error=str(e))
                
                self._prev_stats[name] = self._stats.get(name, new_stats)
                self._stats[name] = new_stats
    
    def _read_linux_stats(self) -> Dict[str, InterfaceStats]:
        """Read stats from Linux /sys filesystem."""
        stats: Dict[str, InterfaceStats] = {}

        try:
            net_dir = Path("/sys/class/net")
            if not net_dir.exists():
                return self._read_proc_net_dev()
            
            for iface_dir in net_dir.iterdir():
                if not iface_dir.is_dir():
                    continue
                
                name = iface_dir.name
                stats_dir = iface_dir / "statistics"
                
                iface_stats = InterfaceStats(name=name)
                
                # Read state
                operstate = iface_dir / "operstate"
                if operstate.exists():
                    state = operstate.read_text().strip()
                    iface_stats.is_up = state == "up"
                
                # Read MAC
                address = iface_dir / "address"
                if address.exists():
                    iface_stats.mac_address = address.read_text().strip()
                
                # Read MTU
                mtu_file = iface_dir / "mtu"
                if mtu_file.exists():
                    try:
                        iface_stats.mtu = int(mtu_file.read_text().strip())
                    except ValueError:
                        pass
                
                # Read statistics
                if stats_dir.exists():
                    stat_files = {
                        "rx_bytes": "rx_bytes",
                        "tx_bytes": "tx_bytes",
                        "rx_packets": "rx_packets",
                        "tx_packets": "tx_packets",
                        "rx_errors": "rx_errors",
                        "tx_errors": "tx_errors",
                        "rx_dropped": "rx_dropped",
                        "tx_dropped": "tx_dropped",
                        "multicast": "multicast",
                        "collisions": "collisions"
                    }
                    
                    for attr, filename in stat_files.items():
                        stat_file = stats_dir / filename
                        if stat_file.exists():
                            try:
                                setattr(iface_stats, attr, int(stat_file.read_text().strip()))
                            except ValueError:
                                pass
                
                stats[name] = iface_stats
        
        except Exception as e:
            logger.error("Error reading Linux interface stats", error=str(e))
            return self._read_proc_net_dev()
        
        return stats
    
    def _read_proc_net_dev(self) -> Dict[str, InterfaceStats]:
        """Fallback: read from /proc/net/dev."""
        stats: Dict[str, InterfaceStats] = {}

        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()[2:]  # Skip headers
            
            for line in lines:
                parts = line.strip().split()
                if len(parts) < 17:
                    continue
                
                name = parts[0].rstrip(":")
                iface_stats = InterfaceStats(
                    name=name,
                    rx_bytes=int(parts[1]),
                    rx_packets=int(parts[2]),
                    rx_errors=int(parts[3]),
                    rx_dropped=int(parts[4]),
                    tx_bytes=int(parts[9]),
                    tx_packets=int(parts[10]),
                    tx_errors=int(parts[11]),
                    tx_dropped=int(parts[12])
                )
                stats[name] = iface_stats
        
        except Exception as e:
            logger.error("Error reading /proc/net/dev", error=str(e))
        
        return stats
    
    def _read_windows_stats(self) -> Dict[str, InterfaceStats]:
        """Read stats on Windows using psutil."""
        stats: Dict[str, InterfaceStats] = {}

        try:
            import psutil  # type: ignore[import-not-found]

            net_io = psutil.net_io_counters(pernic=True)
            net_if_stats = psutil.net_if_stats()
            net_if_addrs = psutil.net_if_addrs()
            
            for name, counters in net_io.items():
                iface_stats = InterfaceStats(
                    name=name,
                    rx_bytes=counters.bytes_recv,
                    tx_bytes=counters.bytes_sent,
                    rx_packets=counters.packets_recv,
                    tx_packets=counters.packets_sent,
                    rx_errors=counters.errin,
                    tx_errors=counters.errout,
                    rx_dropped=counters.dropin,
                    tx_dropped=counters.dropout
                )
                
                # Get additional info
                if name in net_if_stats:
                    if_stat = net_if_stats[name]
                    iface_stats.is_up = if_stat.isup
                    iface_stats.mtu = if_stat.mtu
                
                # Get addresses
                if name in net_if_addrs:
                    for addr in net_if_addrs[name]:
                        if addr.family.name == 'AF_INET':
                            iface_stats.ip_addresses.append(addr.address)
                        elif addr.family.name == 'AF_LINK':
                            iface_stats.mac_address = addr.address
                
                stats[name] = iface_stats
        
        except ImportError:
            # psutil not available - create minimal mock stats
            if not self._psutil_warned:
                logger.info("psutil not available, using basic interface stats on Windows")
                self._psutil_warned = True
            stats["Ethernet"] = InterfaceStats(
                name="Ethernet",
                is_up=True,
                rx_bytes=0,
                tx_bytes=0,
            )
        except Exception as e:
            logger.debug("Error reading Windows interface stats", error=str(e))
            # Return empty stats on error
        
        return stats
    
    def get_stats(self, interface: Optional[str] = None) -> Dict[str, InterfaceStats]:
        """Get interface statistics."""
        with self._lock:
            if interface:
                stats = self._stats.get(interface)
                if stats is not None:
                    return {interface: stats}
                return {}
            return dict(self._stats)
    
    def get_stats_dict(self, interface: Optional[str] = None) -> Dict[str, Any]:
        """Get stats as dictionary."""
        stats = self.get_stats(interface)
        return {name: s.to_dict() for name, s in stats.items()}
    
    def list_interfaces(self) -> List[str]:
        """List available interfaces."""
        with self._lock:
            return list(self._stats.keys())
    
    def get_primary_interface(self) -> Optional[str]:
        """Get primary (most active) interface."""
        with self._lock:
            best = None
            best_traffic = 0
            
            for name, stats in self._stats.items():
                if not stats.is_up or name == "lo":
                    continue
                
                traffic = stats.rx_bytes + stats.tx_bytes
                if traffic > best_traffic:
                    best_traffic = traffic
                    best = name
            
            return best

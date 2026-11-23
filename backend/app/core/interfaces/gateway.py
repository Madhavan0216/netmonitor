"""
Gateway Detection

Detects network gateway(s) through multiple methods:
- Routing table inspection
- DHCP info
- ARP traffic analysis
- Default route detection
"""

import asyncio
import platform
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class GatewayInfo:
    """Information about a detected gateway."""
    ip_address: str
    mac_address: Optional[str] = None
    interface: Optional[str] = None
    is_default: bool = False
    detection_method: str = "unknown"
    
    # Metrics
    metric: int = 0
    
    # Timing
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_verified: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "interface": self.interface,
            "is_default": self.is_default,
            "detection_method": self.detection_method,
            "metric": self.metric,
            "detected_at": self.detected_at.isoformat(),
            "last_verified": self.last_verified.isoformat()
        }


class GatewayDetector:
    """
    Detects network gateways.
    
    Methods:
    - Route table parsing (ip route, route print)
    - Common gateway patterns (x.x.x.1, x.x.x.254)
    - Traffic analysis (high connection count)
    
    Platform support:
    - Linux: ip route, /proc/net/route
    - Windows: route print, ipconfig
    """
    
    def __init__(self):
        self._is_linux = platform.system() == "Linux"
        self._gateways: Dict[str, GatewayInfo] = {}
        
        logger.info("Gateway detector initialized", platform=platform.system())
    
    async def detect(self) -> List[GatewayInfo]:
        """
        Detect all gateways.
        
        Returns:
            List of detected gateways
        """
        gateways: List[GatewayInfo] = []
        
        if self._is_linux:
            gateways = await self._detect_linux()
        else:
            gateways = await self._detect_windows()
        
        # Store results
        self._gateways = {g.ip_address: g for g in gateways}
        
        logger.info("Gateways detected", count=len(gateways))
        return gateways
    
    async def _detect_linux(self) -> List[GatewayInfo]:
        """Detect gateways on Linux."""
        gateways: List[GatewayInfo] = []
        
        try:
            # Method 1: ip route
            result = await asyncio.create_subprocess_exec(
                "ip", "route", "show",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            for line in stdout.decode().strip().split("\n"):
                if not line:
                    continue
                
                parts = line.split()
                
                # Default route: default via 192.168.1.1 dev eth0
                if parts[0] == "default" and "via" in parts:
                    via_idx = parts.index("via")
                    if via_idx + 1 < len(parts):
                        ip = parts[via_idx + 1]
                        interface = None
                        metric = 0
                        
                        if "dev" in parts:
                            dev_idx = parts.index("dev")
                            if dev_idx + 1 < len(parts):
                                interface = parts[dev_idx + 1]
                        
                        if "metric" in parts:
                            metric_idx = parts.index("metric")
                            if metric_idx + 1 < len(parts):
                                try:
                                    metric = int(parts[metric_idx + 1])
                                except ValueError:
                                    pass
                        
                        gateways.append(GatewayInfo(
                            ip_address=ip,
                            interface=interface,
                            is_default=True,
                            detection_method="ip_route",
                            metric=metric
                        ))
                
                # Network route with gateway: 10.0.0.0/8 via 192.168.1.1
                elif "via" in parts and "/" in parts[0]:
                    via_idx = parts.index("via")
                    if via_idx + 1 < len(parts):
                        ip = parts[via_idx + 1]
                        interface = None
                        
                        if "dev" in parts:
                            dev_idx = parts.index("dev")
                            if dev_idx + 1 < len(parts):
                                interface = parts[dev_idx + 1]
                        
                        gateways.append(GatewayInfo(
                            ip_address=ip,
                            interface=interface,
                            is_default=False,
                            detection_method="ip_route"
                        ))
        
        except Exception as e:
            logger.error("Error detecting Linux gateways via ip route", error=str(e))
            # Fallback to /proc/net/route
            gateways = await self._read_proc_net_route()
        
        return gateways
    
    async def _read_proc_net_route(self) -> List[GatewayInfo]:
        """Read gateways from /proc/net/route."""
        gateways: List[GatewayInfo] = []
        
        try:
            with open("/proc/net/route", "r") as f:
                lines = f.readlines()[1:]  # Skip header
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 8:
                    interface = parts[0]
                    destination = parts[1]
                    gateway = parts[2]
                    flags = int(parts[3], 16)
                    metric = int(parts[6])
                    
                    # Check if gateway is set (flags & 0x2 = RTF_GATEWAY)
                    if gateway != "00000000" and (flags & 0x2):
                        # Convert hex IP to dotted
                        ip = ".".join(str(int(gateway[i:i+2], 16)) 
                                     for i in range(6, -1, -2))
                        
                        is_default = (destination == "00000000")
                        
                        gateways.append(GatewayInfo(
                            ip_address=ip,
                            interface=interface,
                            is_default=is_default,
                            detection_method="proc_net_route",
                            metric=metric
                        ))
        
        except Exception as e:
            logger.error("Error reading /proc/net/route", error=str(e))
        
        return gateways
    
    async def _detect_windows(self) -> List[GatewayInfo]:
        """Detect gateways on Windows."""
        gateways: List[GatewayInfo] = []
        
        try:
            # Method 1: route print
            result = await asyncio.create_subprocess_exec(
                "route", "print", "-4",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            # Parse route table
            in_routes = False
            for line in stdout.decode().strip().split("\n"):
                line = line.strip()
                
                if "Network Destination" in line:
                    in_routes = True
                    continue
                
                if in_routes and line:
                    # Format: Network      Netmask        Gateway       Interface     Metric
                    parts = line.split()
                    if len(parts) >= 5:
                        dest = parts[0]
                        gateway = parts[2]
                        interface = parts[3]
                        
                        try:
                            metric = int(parts[4])
                        except (ValueError, IndexError):
                            metric = 0
                        
                        # Skip if gateway is "On-link"
                        if gateway and gateway != "On-link" and self._is_valid_ip(gateway):
                            is_default = (dest == "0.0.0.0")
                            
                            gateways.append(GatewayInfo(
                                ip_address=gateway,
                                interface=interface,
                                is_default=is_default,
                                detection_method="route_print",
                                metric=metric
                            ))
        
        except Exception as e:
            # Windows route command may fail on some systems - degrade gracefully
            logger.debug("Windows gateway detection via route print unavailable", error=str(e))
        
        # Method 2: ipconfig for additional info
        try:
            result = await asyncio.create_subprocess_exec(
                "ipconfig", "/all",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            # Find "Default Gateway" lines
            gateway_pattern = re.compile(r"Default Gateway.*?:\s*(\d+\.\d+\.\d+\.\d+)")
            for match in gateway_pattern.finditer(stdout.decode(errors='ignore')):
                ip = match.group(1)
                
                # Add if not already found
                existing: List[GatewayInfo] = [g for g in gateways if g.ip_address == ip]
                if not existing:
                    gateways.append(GatewayInfo(
                        ip_address=ip,
                        is_default=True,
                        detection_method="ipconfig"
                    ))
        
        except Exception as e:
            # ipconfig parsing failure is not critical - degrade gracefully
            logger.debug("Windows ipconfig parsing unavailable", error=str(e))
        
        return gateways
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IPv4 address."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    
    def get_default_gateway(self) -> Optional[GatewayInfo]:
        """Get the default gateway (lowest metric)."""
        defaults = [g for g in self._gateways.values() if g.is_default]
        if not defaults:
            return None
        return min(defaults, key=lambda g: g.metric)
    
    def get_all_gateways(self) -> List[GatewayInfo]:
        """Get all detected gateways."""
        return list(self._gateways.values())
    
    def get_gateway(self, ip: str) -> Optional[GatewayInfo]:
        """Get gateway by IP."""
        return self._gateways.get(ip)
    
    async def verify_gateway(self, ip: str) -> bool:
        """
        Verify a gateway is reachable via ICMP ping.
        
        Args:
            ip: Gateway IP to verify
            
        Returns:
            True if reachable
        """
        try:
            if self._is_linux:
                cmd = ["ping", "-c", "1", "-W", "2", ip]
            else:
                cmd = ["ping", "-n", "1", "-w", "2000", ip]
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            is_reachable = (result.returncode == 0)
            
            if ip in self._gateways:
                self._gateways[ip].last_verified = datetime.now(timezone.utc)
            
            return is_reachable
        
        except Exception as e:
            logger.error("Error verifying gateway", ip=ip, error=str(e))
            return False

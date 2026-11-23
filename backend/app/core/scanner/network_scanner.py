"""
Network Scanner Service
Safe network scanning using python-nmap.

Safety Features (per DESIGN_SPECIFICATION.md Section 7):
- CIDR limit: /24 maximum (256 hosts)
- Rate limit: 100 packets/second default
- Local network enforcement (RFC1918 by default)
- Scan timeout: 5 minutes max
- Concurrent scan limit: 3
"""

import asyncio
from datetime import datetime
from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass, field
import threading
import structlog
import ipaddress
import re
from enum import Enum

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

from app.core.config import settings

logger = structlog.get_logger(__name__)


# =============================================================================
# Safety Constants
# =============================================================================

# RFC1918 Private Address Ranges
RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Link-local addresses (also safe for local scanning)
LINK_LOCAL_NETWORK = ipaddress.ip_network("169.254.0.0/16")

# Maximum hosts per scan (safety limit)
MAX_SCAN_HOSTS = 256  # /24 equivalent

# Maximum ports per scan
MAX_SCAN_PORTS = 10000

# Scan timeout in seconds
MAX_SCAN_TIMEOUT = 300  # 5 minutes


class ScanRiskLevel(str, Enum):
    """Risk level for scan types."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class ScanProfile:
    """Scan profile with safety metadata."""
    nmap_args: str
    description: str
    risk_level: ScanRiskLevel
    requires_root: bool = False
    estimated_time_per_host: float = 1.0  # seconds


@dataclass
class ScanResult:
    """Network scan result with enhanced metadata."""
    scan_id: str
    scan_type: str
    target: str
    status: str = "pending"
    progress: int = 0
    hosts: List[Dict] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error: Optional[str] = None
    statistics: Dict = field(default_factory=dict)
    
    # Safety metadata
    is_local_only: bool = True
    target_host_count: int = 0
    rate_limit: int = 100
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "target": self.target,
            "status": self.status,
            "progress": self.progress,
            "hosts": self.hosts,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "error": self.error,
            "statistics": self.statistics,
            "is_local_only": self.is_local_only,
            "target_host_count": self.target_host_count,
            "rate_limit": self.rate_limit
        }


@dataclass
class DiscoveredHost:
    """Discovered host information with enhanced details."""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    state: str = "unknown"
    os_guess: Optional[str] = None
    open_ports: List[Dict] = field(default_factory=list)
    services: List[Dict] = field(default_factory=list)
    is_gateway: bool = False
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "state": self.state,
            "os_guess": self.os_guess,
            "open_ports": self.open_ports,
            "services": self.services,
            "is_gateway": self.is_gateway,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None
        }


@dataclass
class ValidationResult:
    """Result of target/port validation."""
    valid: bool
    error: Optional[str] = None
    normalized_target: Optional[str] = None
    host_count: int = 0
    is_private: bool = False
    network: Optional[ipaddress.IPv4Network] = None


class NetworkScannerService:
    """
    Service for network scanning operations.
    
    Safety Features (per DESIGN_SPECIFICATION.md):
    - CIDR limit: /24 maximum (256 hosts)
    - Rate limit: configurable, default 100 pps
    - Local network enforcement: RFC1918 by default
    - Scan timeout: 5 minutes maximum
    - Concurrent scan limit: 3
    """
    
    # Safe scan profiles per DESIGN_SPECIFICATION.md Section 3.2.2
    SCAN_PROFILES: Dict[str, ScanProfile] = {
        "ping": ScanProfile(
            nmap_args="-sn",
            description="Host discovery only, no port scan",
            risk_level=ScanRiskLevel.LOW,
            requires_root=False,
            estimated_time_per_host=0.5
        ),
        "quick": ScanProfile(
            nmap_args="-T4 -F --max-rate 100",
            description="Top 100 ports, fast timing",
            risk_level=ScanRiskLevel.LOW,
            requires_root=False,
            estimated_time_per_host=2.0
        ),
        "connect": ScanProfile(
            nmap_args="-sT -T3 --top-ports 1000",
            description="Top 1000 ports, TCP connect scan",
            risk_level=ScanRiskLevel.MEDIUM,
            requires_root=False,
            estimated_time_per_host=5.0
        ),
        "service": ScanProfile(
            nmap_args="-sV -sC --version-light",
            description="Service version detection with safe scripts",
            risk_level=ScanRiskLevel.MEDIUM,
            requires_root=False,
            estimated_time_per_host=10.0
        ),
        "syn": ScanProfile(
            nmap_args="-sS -T3",
            description="TCP SYN scan (requires elevated privileges)",
            risk_level=ScanRiskLevel.MEDIUM,
            requires_root=True,
            estimated_time_per_host=3.0
        ),
    }
    
    # Legacy mapping for backwards compatibility
    ALLOWED_SCAN_TYPES = {
        "ping": "-sn",
        "syn": "-sS",
        "connect": "-sT",
        "service": "-sV",
        "quick": "-T4 -F",
    }
    
    def __init__(self, local_only: bool = True):
        """
        Initialize scanner service.
        
        Args:
            local_only: If True, only allow scanning of RFC1918 addresses
        """
        self.active_scans: Dict[str, ScanResult] = {}
        self.scan_lock = threading.Lock()
        self._scan_counter = 0
        self.local_only = local_only
        self._callbacks: List[Callable[[ScanResult], None]] = []
        
        # Rate limiting configuration
        self.rate_limit = getattr(settings, 'SCAN_RATE_LIMIT', 100)
        self.max_concurrent_scans = getattr(settings, 'MAX_CONCURRENT_SCANS', 3)
        
        if not NMAP_AVAILABLE:
            logger.warning("python-nmap not available - scanning disabled")
        else:
            logger.info(
                "Network scanner initialized",
                local_only=local_only,
                rate_limit=self.rate_limit,
                max_concurrent=self.max_concurrent_scans
            )
    
    def register_callback(self, callback: Callable[[ScanResult], None]) -> None:
        """Register a callback for scan completion."""
        self._callbacks.append(callback)
    
    def unregister_callback(self, callback: Callable[[ScanResult], None]) -> None:
        """Unregister a callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
    
    def _notify_callbacks(self, result: ScanResult) -> None:
        """Notify all registered callbacks."""
        for callback in self._callbacks:
            try:
                callback(result)
            except Exception as e:
                logger.error("Callback error", error=str(e))
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID."""
        self._scan_counter += 1
        return f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{self._scan_counter}"
    
    def _is_private_address(self, ip: ipaddress.IPv4Address) -> bool:
        """Check if IP address is in RFC1918 private range."""
        for network in RFC1918_NETWORKS:
            if ip in network:
                return True
        # Also allow link-local
        if ip in LINK_LOCAL_NETWORK:
            return True
        return False
    
    def _is_private_network(self, network: ipaddress.IPv4Network) -> bool:
        """Check if entire network is within RFC1918 private ranges."""
        # Check if network address and broadcast are both private
        return self._is_private_address(network.network_address) and \
               self._is_private_address(network.broadcast_address)

    def _validate_target(self, target: str, enforce_local: bool = True) -> ValidationResult:
        """
        Validate scan target for safety.
        
        Args:
            target: IP, CIDR, range, or hostname
            enforce_local: If True, require RFC1918 addresses
            
        Returns:
            ValidationResult with validation status and parsed data
        """
        target = target.strip()
        
        if not target:
            return ValidationResult(valid=False, error="Target cannot be empty")
        
        # Try parsing as single IP
        try:
            ip = ipaddress.IPv4Address(target)
            is_private = self._is_private_address(ip)
            
            if enforce_local and not is_private:
                return ValidationResult(
                    valid=False,
                    error=f"Target {target} is not a private network address. "
                          "Only RFC1918 ranges allowed for safety "
                          "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)"
                )
            
            return ValidationResult(
                valid=True,
                normalized_target=str(ip),
                host_count=1,
                is_private=is_private,
                network=ipaddress.IPv4Network(f"{ip}/32", strict=False)
            )
        except ipaddress.AddressValueError:
            pass
        
        # Try parsing as CIDR network
        try:
            network = ipaddress.IPv4Network(target, strict=False)
            host_count = network.num_addresses
            
            # Enforce CIDR limit
            if host_count > MAX_SCAN_HOSTS:
                return ValidationResult(
                    valid=False,
                    error=f"Network too large: {host_count} hosts. "
                          f"Maximum {MAX_SCAN_HOSTS} hosts (/24) allowed for safety."
                )
            
            is_private = self._is_private_network(network)
            
            if enforce_local and not is_private:
                return ValidationResult(
                    valid=False,
                    error=f"Target {target} is not within private network ranges. "
                          "Only RFC1918 ranges allowed for safety."
                )
            
            return ValidationResult(
                valid=True,
                normalized_target=str(network),
                host_count=host_count,
                is_private=is_private,
                network=network
            )
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            pass
        
        # Try parsing as IP range (e.g., 192.168.1.1-50)
        range_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$'
        match = re.match(range_pattern, target)
        if match:
            try:
                base = match.group(1)
                start = int(match.group(2))
                end = int(match.group(3))
                
                if start > end:
                    return ValidationResult(valid=False, error="Invalid IP range: start > end")
                
                host_count = end - start + 1
                
                if host_count > MAX_SCAN_HOSTS:
                    return ValidationResult(
                        valid=False,
                        error=f"Range too large: {host_count} hosts. Maximum {MAX_SCAN_HOSTS}."
                    )
                
                # Check if range is private
                start_ip = ipaddress.IPv4Address(f"{base}.{start}")
                end_ip = ipaddress.IPv4Address(f"{base}.{end}")
                is_private = self._is_private_address(start_ip) and self._is_private_address(end_ip)
                
                if enforce_local and not is_private:
                    return ValidationResult(
                        valid=False,
                        error="IP range is not within private network ranges."
                    )
                
                return ValidationResult(
                    valid=True,
                    normalized_target=target,
                    host_count=host_count,
                    is_private=is_private
                )
            except ValueError:
                pass
        
        # For hostnames, we cannot validate until resolution
        # But we block external hostnames when local_only
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})*$'
        if re.match(hostname_pattern, target):
            if enforce_local:
                # Only allow .local, .lan, .home, .internal TLDs
                allowed_tlds = ('.local', '.lan', '.home', '.internal', '.localdomain')
                if not any(target.lower().endswith(tld) for tld in allowed_tlds):
                    return ValidationResult(
                        valid=False,
                        error=f"External hostnames not allowed in local-only mode. "
                              f"Use IP address or local hostname ({', '.join(allowed_tlds)})"
                    )
            
            return ValidationResult(
                valid=True,
                normalized_target=target,
                host_count=1,
                is_private=True  # Assume local hostname is private
            )
        
        return ValidationResult(
            valid=False,
            error="Invalid target format. Use IP address, CIDR notation (e.g., 192.168.1.0/24), "
                  "IP range (e.g., 192.168.1.1-50), or hostname."
        )
    
    def _validate_ports(self, ports: Optional[str]) -> ValidationResult:
        """
        Validate port specification.
        
        Args:
            ports: Port specification (e.g., "22", "22-80", "22,80,443")
            
        Returns:
            ValidationResult with validation status
        """
        if not ports:
            return ValidationResult(valid=True)
        
        ports = ports.strip()
        
        # Block "all ports" scanning
        if ports == "-" or ports.lower() == "all":
            return ValidationResult(
                valid=False,
                error=f"Cannot scan all ports. Maximum {MAX_SCAN_PORTS} ports allowed."
            )
        
        # Valid formats: 22, 22-80, 22,80,443, 22-80,443
        port_pattern = r'^(\d{1,5}(-\d{1,5})?,?)+$'
        cleaned = ports.replace(" ", "")
        if not re.match(port_pattern, cleaned):
            return ValidationResult(
                valid=False,
                error="Invalid port format. Use: 22, 22-80, or 22,80,443"
            )
        
        # Count and validate individual ports
        port_count = 0
        for part in cleaned.rstrip(",").split(","):
            if "-" in part:
                try:
                    start, end = map(int, part.split("-"))
                    if not (1 <= start <= 65535) or not (1 <= end <= 65535):
                        return ValidationResult(
                            valid=False,
                            error=f"Port out of range: {part}. Must be 1-65535."
                        )
                    if start > end:
                        return ValidationResult(
                            valid=False,
                            error=f"Invalid port range: {part}. Start must be <= end."
                        )
                    port_count += (end - start + 1)
                except ValueError:
                    return ValidationResult(valid=False, error=f"Invalid port range: {part}")
            else:
                try:
                    port = int(part)
                    if not (1 <= port <= 65535):
                        return ValidationResult(
                            valid=False,
                            error=f"Port out of range: {port}. Must be 1-65535."
                        )
                    port_count += 1
                except ValueError:
                    return ValidationResult(valid=False, error=f"Invalid port: {part}")
        
        if port_count > MAX_SCAN_PORTS:
            return ValidationResult(
                valid=False,
                error=f"Too many ports: {port_count}. Maximum {MAX_SCAN_PORTS} allowed."
            )
        
        return ValidationResult(valid=True, host_count=port_count)
    
    async def start_scan(
        self,
        target: str,
        scan_type: str = "ping",
        ports: Optional[str] = None,
        local_only: Optional[bool] = None,
        callback: Optional[Callable] = None
    ) -> ScanResult:
        """
        Start a network scan with safety guardrails.
        
        Args:
            target: IP address, CIDR, IP range, or hostname
            scan_type: One of SCAN_PROFILES keys
            ports: Port specification (optional)
            local_only: Override instance-level local_only setting
            callback: Optional callback for scan completion
            
        Returns:
            ScanResult with scan status and ID
        """
        enforce_local = local_only if local_only is not None else self.local_only
        
        if not NMAP_AVAILABLE:
            return ScanResult(
                scan_id="error",
                scan_type=scan_type,
                target=target,
                status="failed",
                error="Nmap not available. Please install nmap and python-nmap."
            )
        
        # Validate scan type
        if scan_type not in self.SCAN_PROFILES:
            return ScanResult(
                scan_id="error",
                scan_type=scan_type,
                target=target,
                status="failed",
                error=f"Invalid scan type '{scan_type}'. "
                      f"Allowed: {list(self.SCAN_PROFILES.keys())}"
            )
        
        profile = self.SCAN_PROFILES[scan_type]
        
        # Validate target with RFC1918 enforcement
        target_result = self._validate_target(target, enforce_local=enforce_local)
        if not target_result.valid:
            logger.warning(
                "Scan target validation failed",
                target=target,
                error=target_result.error,
                enforce_local=enforce_local
            )
            return ScanResult(
                scan_id="error",
                scan_type=scan_type,
                target=target,
                status="failed",
                error=target_result.error
            )
        
        # Validate ports
        ports_result = self._validate_ports(ports)
        if not ports_result.valid:
            return ScanResult(
                scan_id="error",
                scan_type=scan_type,
                target=target,
                status="failed",
                error=ports_result.error
            )
        
        # Check concurrent scan limit
        with self.scan_lock:
            active_count = sum(1 for s in self.active_scans.values() if s.status == "running")
            if active_count >= self.max_concurrent_scans:
                return ScanResult(
                    scan_id="error",
                    scan_type=scan_type,
                    target=target,
                    status="failed",
                    error=f"Maximum concurrent scans ({self.max_concurrent_scans}) reached. "
                          "Please wait for a scan to complete."
                )
        
        # Create scan result with safety metadata
        scan_id = self._generate_scan_id()
        result = ScanResult(
            scan_id=scan_id,
            scan_type=scan_type,
            target=target_result.normalized_target or target,
            status="running",
            start_time=datetime.utcnow(),
            is_local_only=enforce_local,
            target_host_count=target_result.host_count,
            rate_limit=self.rate_limit
        )
        
        with self.scan_lock:
            self.active_scans[scan_id] = result
        
        logger.info(
            "Starting network scan",
            scan_id=scan_id,
            target=target_result.normalized_target,
            scan_type=scan_type,
            host_count=target_result.host_count,
            is_private=target_result.is_private,
            risk_level=profile.risk_level.value
        )
        
        # Run scan in background
        loop = asyncio.get_event_loop()
        loop.run_in_executor(
            None,
            self._run_scan,
            scan_id,
            target_result.normalized_target or target,
            scan_type,
            ports,
            callback
        )
        
        return result
    
    def _run_scan(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        ports: Optional[str],
        callback: Optional[Callable]
    ):
        """
        Run the actual nmap scan with safety limits.
        
        This method runs in a background thread.
        """
        try:
            nm = nmap.PortScanner()
            profile = self.SCAN_PROFILES[scan_type]
            
            # Build scan arguments with safety limits
            args = profile.nmap_args
            args += f" --max-rate {self.rate_limit}"  # Rate limit
            args += " --host-timeout 60s"             # Per-host timeout
            args += f" --max-retries 2"               # Limit retries
            
            # Add ports if specified and not a ping scan
            if ports and scan_type != "ping":
                args += f" -p {ports}"
            
            logger.info(
                "Executing nmap scan",
                scan_id=scan_id,
                target=target,
                args=args,
                risk_level=profile.risk_level.value
            )
            
            # Run scan with timeout
            nm.scan(hosts=target, arguments=args, timeout=MAX_SCAN_TIMEOUT)
            
            # Parse results
            hosts = []
            for host in nm.all_hosts():
                host_info = self._parse_host_result(nm, host)
                hosts.append(host_info.to_dict())
            
            # Update result
            with self.scan_lock:
                if scan_id in self.active_scans:
                    scan_result = self.active_scans[scan_id]
                    scan_result.status = "completed"
                    scan_result.progress = 100
                    scan_result.hosts = hosts
                    scan_result.end_time = datetime.utcnow()
                    scan_result.statistics = {
                        "hosts_up": len([h for h in hosts if h.get("state") == "up"]),
                        "hosts_down": len([h for h in hosts if h.get("state") == "down"]),
                        "total_hosts": len(hosts),
                        "scan_time": nm.scanstats().get("elapsed", "0"),
                        "rate_limit": self.rate_limit,
                        "scan_type": scan_type,
                        "risk_level": profile.risk_level.value
                    }
                    
                    # Notify callbacks
                    self._notify_callbacks(scan_result)
            
            logger.info(
                "Scan completed successfully",
                scan_id=scan_id,
                hosts_found=len(hosts),
                scan_time=nm.scanstats().get("elapsed", "0")
            )
            
            if callback:
                callback(self.active_scans[scan_id])
        
        except nmap.PortScannerError as e:
            error_msg = str(e)
            logger.error("Nmap scan error", scan_id=scan_id, error=error_msg)
            self._fail_scan(scan_id, f"Nmap error: {error_msg}")
            
        except Exception as e:
            logger.error("Scan failed", scan_id=scan_id, error=str(e), exc_info=True)
            self._fail_scan(scan_id, str(e))
    
    def _fail_scan(self, scan_id: str, error: str) -> None:
        """Mark a scan as failed."""
        with self.scan_lock:
            if scan_id in self.active_scans:
                scan_result = self.active_scans[scan_id]
                scan_result.status = "failed"
                scan_result.error = error
                scan_result.end_time = datetime.utcnow()
                self._notify_callbacks(scan_result)
    def _parse_host_result(self, nm: 'nmap.PortScanner', host: str) -> DiscoveredHost:
        """Parse nmap result for a single host."""
        host_data = nm[host]
        
        # Get hostname
        hostname = None
        if 'hostnames' in host_data and host_data['hostnames']:
            for hn in host_data['hostnames']:
                if hn.get('name'):
                    hostname = hn['name']
                    break
        
        # Get MAC address and vendor
        mac_address = None
        vendor = None
        if 'addresses' in host_data:
            mac_address = host_data['addresses'].get('mac')
        if 'vendor' in host_data and mac_address:
            vendor = host_data['vendor'].get(mac_address)
        
        # Get state
        state = host_data.get('status', {}).get('state', 'unknown')
        
        # Get OS guess
        os_guess = None
        if 'osmatch' in host_data and host_data['osmatch']:
            os_guess = host_data['osmatch'][0].get('name')
        
        # Get open ports and services
        open_ports = []
        services = []
        
        for proto in ['tcp', 'udp']:
            if proto in host_data:
                for port, port_data in host_data[proto].items():
                    if port_data.get('state') == 'open':
                        open_ports.append({
                            "port": port,
                            "protocol": proto,
                            "state": port_data.get('state', 'unknown')
                        })
                        
                        service = port_data.get('name', 'unknown')
                        version = port_data.get('version', '')
                        product = port_data.get('product', '')
                        
                        services.append({
                            "port": port,
                            "protocol": proto,
                            "service": service,
                            "product": product,
                            "version": version,
                            "info": port_data.get('extrainfo', '')
                        })
        
        # Detect if this might be a gateway (common gateway ports)
        gateway_ports = {80, 443, 53, 67, 68}
        is_gateway = any(p.get('port') in gateway_ports for p in open_ports)
        
        return DiscoveredHost(
            ip_address=host,
            hostname=hostname,
            mac_address=mac_address,
            vendor=vendor,
            state=state,
            os_guess=os_guess,
            open_ports=open_ports,
            services=services,
            is_gateway=is_gateway
        )
    
    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Get scan result by ID."""
        with self.scan_lock:
            return self.active_scans.get(scan_id)
    
    def get_all_scans(self, status: Optional[str] = None) -> List[Dict]:
        """
        Get all scan results, optionally filtered by status.
        
        Args:
            status: Optional filter by status (running, completed, failed, cancelled)
        """
        with self.scan_lock:
            scans = list(self.active_scans.values())
            if status:
                scans = [s for s in scans if s.status == status]
            return [scan.to_dict() for scan in scans]
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan."""
        with self.scan_lock:
            if scan_id in self.active_scans:
                scan = self.active_scans[scan_id]
                if scan.status == "running":
                    scan.status = "cancelled"
                    scan.end_time = datetime.utcnow()
                    logger.info("Scan cancelled", scan_id=scan_id)
                    self._notify_callbacks(scan)
                    return True
        return False
    
    def get_scan_types(self) -> Dict[str, Dict]:
        """Get available scan types with metadata."""
        return {
            name: {
                "name": name,
                "description": profile.description,
                "risk_level": profile.risk_level.value,
                "requires_root": profile.requires_root,
                "estimated_time_per_host": profile.estimated_time_per_host
            }
            for name, profile in self.SCAN_PROFILES.items()
        }
    
    def validate_target(self, target: str) -> Dict[str, Any]:
        """
        Public method to validate a target without starting a scan.
        Useful for UI validation.
        """
        result = self._validate_target(target, enforce_local=self.local_only)
        return {
            "valid": result.valid,
            "error": result.error,
            "normalized_target": result.normalized_target,
            "host_count": result.host_count,
            "is_private": result.is_private,
            "local_only_mode": self.local_only
        }
    
    def get_common_ports(self) -> Dict[str, List[int]]:
        """Get list of common ports by category."""
        return {
            "web": [80, 443, 8080, 8443],
            "mail": [25, 110, 143, 465, 587, 993, 995],
            "file_transfer": [20, 21, 22, 69, 115, 139, 445],
            "database": [1433, 1521, 3306, 5432, 27017, 6379],
            "remote_access": [22, 23, 3389, 5900],
            "dns_dhcp": [53, 67, 68],
            "top_20": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 
                       143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        }
    
    def get_safety_limits(self) -> Dict[str, Any]:
        """Get current safety limits for display in UI."""
        return {
            "max_hosts_per_scan": MAX_SCAN_HOSTS,
            "max_ports_per_scan": MAX_SCAN_PORTS,
            "max_scan_timeout_seconds": MAX_SCAN_TIMEOUT,
            "max_concurrent_scans": self.max_concurrent_scans,
            "rate_limit_pps": self.rate_limit,
            "local_only_mode": self.local_only,
            "allowed_private_ranges": [
                "10.0.0.0/8",
                "172.16.0.0/12", 
                "192.168.0.0/16",
                "169.254.0.0/16 (link-local)"
            ]
        }

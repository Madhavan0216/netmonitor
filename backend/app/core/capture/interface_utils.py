"""
Interface Enumeration Utilities

Platform-aware interface enumeration with:
- Friendly names
- IP addresses
- MAC addresses
- Status (up/down)
- Loopback detection

Works on Windows (Npcap), Linux, and macOS (libpcap).
"""

import socket
import sys
from typing import List, Dict, Any, Optional
import structlog

logger = structlog.get_logger(__name__)

# Type alias for interface info
InterfaceDict = Dict[str, Any]

# Track availability of optional modules
_psutil_available = False
_scapy_available = False
_winreg_module = None

# Try to import platform-specific libraries
try:
    import psutil
    _psutil_available = True
except ImportError:
    psutil = None  # type: ignore
    logger.warning("psutil not available - interface details will be limited")

try:
    from scapy.all import get_if_list, get_if_hwaddr
    from scapy.arch import get_if_addr
    _scapy_available = True
except ImportError:
    get_if_list = None  # type: ignore
    get_if_hwaddr = None  # type: ignore
    get_if_addr = None  # type: ignore
    logger.warning("scapy not available - packet capture disabled")

# Windows-specific imports
if sys.platform == 'win32':
    try:
        import winreg
        _winreg_module = winreg
    except ImportError:
        pass


def get_windows_interface_names() -> Dict[str, str]:
    """
    Get Windows interface friendly names from registry.
    Maps NPF GUID to friendly name.
    """
    if _winreg_module is None or sys.platform != 'win32':
        return {}
    
    friendly_names: Dict[str, str] = {}
    winreg = _winreg_module
    
    try:
        # Open network adapters registry key
        reg_path = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
            i = 0
            while True:
                try:
                    guid = winreg.EnumKey(key, i)
                    if guid.startswith('{') and guid.endswith('}'):
                        try:
                            conn_path = f"{reg_path}\\{guid}\\Connection"
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, conn_path) as conn_key:
                                name, _ = winreg.QueryValueEx(conn_key, "Name")
                                friendly_names[guid] = str(name)
                        except (FileNotFoundError, OSError):
                            pass
                    i += 1
                except OSError:
                    break
    except Exception as e:
        logger.debug("Could not read Windows registry for interface names", error=str(e))
    
    return friendly_names


def get_interface_details_psutil() -> List[InterfaceDict]:
    """Get interface details using psutil (cross-platform)."""
    if not _psutil_available or psutil is None:
        return []
    
    interfaces: List[InterfaceDict] = []
    
    try:
        # Get all interface addresses
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        for iface_name, addr_list in addrs.items():
            iface: InterfaceDict = {
                "name": iface_name,
                "display_name": iface_name,
                "description": iface_name,
                "ip_addresses": [],
                "mac_address": None,
                "is_up": False,
                "is_loopback": False,
                "mtu": 0
            }
            
            # Get stats
            if iface_name in stats:
                iface["is_up"] = stats[iface_name].isup
                iface["mtu"] = stats[iface_name].mtu
                iface["is_loopback"] = (
                    'loopback' in iface_name.lower() or 
                    iface_name.lower() == 'lo' or
                    stats[iface_name].mtu == 65536  # Common loopback MTU
                )
            
            # Get addresses
            for addr in addr_list:
                if addr.family == socket.AF_INET:  # IPv4
                    iface["ip_addresses"].append(addr.address)
                elif addr.family == socket.AF_INET6:  # IPv6
                    # Skip link-local IPv6 for cleaner display
                    if not addr.address.startswith('fe80'):
                        iface["ip_addresses"].append(addr.address)
                elif addr.family == psutil.AF_LINK:  # MAC address
                    if addr.address and addr.address != '00:00:00:00:00:00':
                        iface["mac_address"] = addr.address
            
            interfaces.append(iface)
        
        return interfaces
    
    except Exception as e:
        logger.error("Failed to get interface details via psutil", error=str(e))
        return []


def get_scapy_interfaces() -> List[InterfaceDict]:
    """Get interfaces using Scapy (for capture compatibility)."""
    if not _scapy_available or get_if_list is None:
        return []
    
    interfaces: List[InterfaceDict] = []
    win_names = get_windows_interface_names() if sys.platform == 'win32' else {}
    
    try:
        raw_interfaces = get_if_list()
        
        for iface in raw_interfaces:
            iface_info: InterfaceDict = {
                "name": iface,
                "display_name": iface,
                "description": iface,
                "ip_addresses": [],
                "mac_address": None,
                "is_up": True,  # Assume up since Scapy lists it
                "is_loopback": False
            }
            
            # On Windows, try to get friendly name from GUID
            if sys.platform == 'win32':
                # Extract GUID from NPF device name
                if '\\Device\\NPF_' in iface:
                    guid = iface.replace('\\Device\\NPF_', '')
                    if guid in win_names:
                        iface_info["display_name"] = win_names[guid]
                        iface_info["description"] = f"{win_names[guid]}"
            
            # Try to get IP address
            if get_if_addr is not None:
                try:
                    ip = get_if_addr(iface)
                    if ip and ip != '0.0.0.0':
                        iface_info["ip_addresses"].append(ip)
                except Exception:
                    pass
            
            # Try to get MAC address
            if get_if_hwaddr is not None:
                try:
                    mac = get_if_hwaddr(iface)
                    if mac and mac != '00:00:00:00:00:00':
                        iface_info["mac_address"] = mac
                except Exception:
                    pass
            
            # Detect loopback
            if 'loopback' in iface.lower() or iface.lower() == 'lo':
                iface_info["is_loopback"] = True
            elif iface_info["ip_addresses"]:
                # Check if IP is localhost
                ip_list: List[str] = iface_info["ip_addresses"]
                iface_info["is_loopback"] = any(
                    ip.startswith('127.') for ip in ip_list
                )
            
            interfaces.append(iface_info)
        
        return interfaces
    
    except Exception as e:
        logger.error("Failed to get Scapy interfaces", error=str(e))
        return []


def get_all_interfaces() -> List[InterfaceDict]:
    """
    Get comprehensive interface list by merging Scapy and psutil data.
    
    Returns interfaces suitable for packet capture with:
    - Friendly display names
    - IP addresses
    - MAC addresses
    - Up/down status
    - Loopback detection
    """
    # Get psutil data for friendly names and status
    psutil_ifaces = {iface["name"]: iface for iface in get_interface_details_psutil()}
    
    # Get Scapy interfaces (these are what we can actually capture on)
    scapy_ifaces = get_scapy_interfaces()
    
    if not scapy_ifaces:
        # Fall back to psutil only
        return list(psutil_ifaces.values())
    
    # Merge: Use Scapy names but enrich with psutil data
    result: List[InterfaceDict] = []
    win_names = get_windows_interface_names() if sys.platform == 'win32' else {}
    
    for scapy_iface in scapy_ifaces:
        iface = scapy_iface.copy()
        scapy_name: str = scapy_iface["name"]
        
        # On Windows, match by GUID
        if sys.platform == 'win32' and '\\Device\\NPF_' in scapy_name:
            guid = scapy_name.replace('\\Device\\NPF_', '')
            friendly = win_names.get(guid)
            
            if friendly and friendly in psutil_ifaces:
                psutil_data = psutil_ifaces[friendly]
                iface["display_name"] = friendly
                iface["description"] = f"{friendly}"
                iface["ip_addresses"] = psutil_data.get("ip_addresses", iface["ip_addresses"])
                iface["mac_address"] = psutil_data.get("mac_address") or iface["mac_address"]
                iface["is_up"] = psutil_data.get("is_up", True)
                iface["is_loopback"] = psutil_data.get("is_loopback", False)
        else:
            # Direct name match (Linux/macOS)
            if scapy_name in psutil_ifaces:
                psutil_data = psutil_ifaces[scapy_name]
                iface["ip_addresses"] = psutil_data.get("ip_addresses", iface["ip_addresses"])
                iface["mac_address"] = psutil_data.get("mac_address") or iface["mac_address"]
                iface["is_up"] = psutil_data.get("is_up", True)
                iface["is_loopback"] = psutil_data.get("is_loopback", False)
        
        result.append(iface)
    
    # Sort: put interfaces with IPs and that are up first
    def sort_key(iface: InterfaceDict) -> tuple[bool, bool, bool, str]:
        ip_list: List[str] = iface.get("ip_addresses", []) or []
        has_ip = len(ip_list) > 0
        is_up = bool(iface.get("is_up", False))
        is_loopback = bool(iface.get("is_loopback", False))
        display_name = str(iface.get("display_name", ""))
        # Priority: up with IP > up without IP > down > loopback
        return (not is_loopback, is_up, has_ip, display_name)
    
    result.sort(key=sort_key, reverse=True)
    
    return result


def get_default_capture_interface() -> Optional[str]:
    """
    Get the best default interface for packet capture.
    
    Prefers: Active interface with IP that is not loopback.
    """
    interfaces = get_all_interfaces()
    
    for iface in interfaces:
        if (iface.get("is_up", False) and 
            not iface.get("is_loopback", False) and 
            iface.get("ip_addresses")):
            return str(iface["name"])
    
    # Fallback to first non-loopback
    for iface in interfaces:
        if not iface.get("is_loopback", False):
            return str(iface["name"])
    
    # Last resort: first interface
    return str(interfaces[0]["name"]) if interfaces else None

"""
NetMonitor Configuration Settings
"""

from typing import List
from pydantic_settings import BaseSettings
from pydantic import Field
import secrets


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    APP_NAME: str = "NetMonitor"
    DEBUG: bool = True  # Enable debug mode for development
    
    # Security - Fixed key for development (MUST change in production!)
    SECRET_KEY: str = Field(default="netmonitor-dev-secret-key-change-in-production-2024")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours for development
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./netmonitor.db"
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:5173"]
    
    # Packet Capture
    CAPTURE_INTERFACE: str = ""  # Empty = auto-detect
    CAPTURE_BUFFER_SIZE: int = 1000  # Max packets in buffer
    CAPTURE_FILTER: str = ""  # BPF filter
    
    # Scanner Settings
    SCAN_RATE_LIMIT: int = 100  # Max packets per second
    SCAN_TIMEOUT: int = 300  # Max scan duration in seconds
    MAX_CONCURRENT_SCANS: int = 3
    ALLOWED_SCAN_TYPES: List[str] = ["ping", "syn", "connect", "service"]
    
    # Detection Engine
    DETECTION_WINDOW_SECONDS: int = 60
    PORT_SCAN_THRESHOLD: int = 10  # Ports in window
    FLOOD_THRESHOLD: int = 1000  # Packets in window
    
    # Alerting
    ALERT_RETENTION_DAYS: int = 30
    MAX_ALERTS_PER_MINUTE: int = 100
    
    # Rate Limiting (API)
    RATE_LIMIT_PER_MINUTE: int = 60
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()


# Network interface detection helper
def get_default_interface() -> str:
    """Get the default network interface for packet capture."""
    try:
        from scapy.arch import get_if_list, conf
        interfaces = get_if_list()
        if interfaces:
            # Prefer non-loopback interface
            for iface in interfaces:
                if 'loopback' not in iface.lower() and 'lo' != iface:
                    return iface
            return interfaces[0]
    except Exception:
        pass
    return ""

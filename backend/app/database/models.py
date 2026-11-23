"""
Database models for NetMonitor.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text, Enum as SQLEnum, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from app.database.session import Base


class AlertSeverity(enum.Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class ScanStatus(enum.Enum):
    """Network scan status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(enum.Enum):
    """Allowed scan types."""
    PING = "ping"
    SYN = "syn"
    CONNECT = "connect"
    SERVICE = "service"


class User(Base):
    """User model for authentication."""
    __tablename__ = "users"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[Optional[str]] = mapped_column(String(100), unique=True, nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Relationships
    scans: Mapped[list["NetworkScan"]] = relationship(back_populates="user")


class Alert(Base):
    """Security alert model."""
    __tablename__ = "alerts"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    severity: Mapped[AlertSeverity] = mapped_column(SQLEnum(AlertSeverity))
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    explanation: Mapped[str] = mapped_column(Text)  # Plain English explanation
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    extra_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class NetworkScan(Base):
    """Network scan record."""
    __tablename__ = "network_scans"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    scan_type: Mapped[ScanType] = mapped_column(SQLEnum(ScanType))
    target: Mapped[str] = mapped_column(String(255))  # IP, range, or CIDR
    ports: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)  # Port specification
    status: Mapped[ScanStatus] = mapped_column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    progress: Mapped[int] = mapped_column(Integer, default=0)  # 0-100
    results: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user: Mapped["User"] = relationship(back_populates="scans")


class DiscoveredHost(Base):
    """Discovered network host."""
    __tablename__ = "discovered_hosts"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    vendor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    os_guess: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    open_ports: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    services: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_local: Mapped[bool] = mapped_column(Boolean, default=True)


class PacketStats(Base):
    """Aggregated packet statistics for dashboard."""
    __tablename__ = "packet_stats"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    total_packets: Mapped[int] = mapped_column(Integer, default=0)
    total_bytes: Mapped[int] = mapped_column(Integer, default=0)
    tcp_packets: Mapped[int] = mapped_column(Integer, default=0)
    udp_packets: Mapped[int] = mapped_column(Integer, default=0)
    icmp_packets: Mapped[int] = mapped_column(Integer, default=0)
    dns_packets: Mapped[int] = mapped_column(Integer, default=0)
    http_packets: Mapped[int] = mapped_column(Integer, default=0)
    https_packets: Mapped[int] = mapped_column(Integer, default=0)
    other_packets: Mapped[int] = mapped_column(Integer, default=0)
    unique_sources: Mapped[int] = mapped_column(Integer, default=0)
    unique_destinations: Mapped[int] = mapped_column(Integer, default=0)


class DetectionRule(Base):
    """Custom detection rule."""
    __tablename__ = "detection_rules"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(50))
    severity: Mapped[AlertSeverity] = mapped_column(SQLEnum(AlertSeverity))
    conditions: Mapped[dict] = mapped_column(JSON)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

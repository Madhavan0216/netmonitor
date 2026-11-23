"""
Audit Logging Infrastructure

Provides structured audit logging for security-relevant operations
per DESIGN_SPECIFICATION.md Section 7.

All security operations are logged with:
- Timestamp
- User (if authenticated)
- Operation type
- Target resource
- Result (success/failure)
- Additional context
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional
import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# Audit Event Types
# =============================================================================

class AuditEventType(str, Enum):
    """Types of auditable events."""
    
    # Authentication events
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_LOGIN_FAILED = "auth.login_failed"
    AUTH_PASSWORD_CHANGE = "auth.password_change"
    
    # Scan operations
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_CANCELLED = "scan.cancelled"
    
    # Capture operations
    CAPTURE_STARTED = "capture.started"
    CAPTURE_STOPPED = "capture.stopped"
    CAPTURE_FAILED = "capture.failed"
    
    # Alert operations
    ALERT_CREATED = "alert.created"
    ALERT_ACKNOWLEDGED = "alert.acknowledged"
    ALERT_DELETED = "alert.deleted"
    
    # Detection operations
    DETECTION_TRIGGERED = "detection.triggered"
    DETECTION_RULE_CHANGED = "detection.rule_changed"
    
    # Configuration changes
    CONFIG_CHANGED = "config.changed"
    
    # System events
    SYSTEM_STARTED = "system.started"
    SYSTEM_STOPPED = "system.stopped"
    SYSTEM_ERROR = "system.error"


class AuditSeverity(str, Enum):
    """Severity level for audit events."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# =============================================================================
# Audit Event Model
# =============================================================================

@dataclass
class AuditEvent:
    """
    Structured audit event.
    
    All security-relevant operations generate an audit event
    that can be stored and analyzed.
    """
    event_type: AuditEventType
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    severity: AuditSeverity = AuditSeverity.INFO
    
    # Actor information
    user_id: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    
    # Target information
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    
    # Result
    success: bool = True
    error_message: Optional[str] = None
    
    # Additional context
    details: Dict[str, Any] = field(default_factory=lambda: {})
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "user_id": self.user_id,
            "username": self.username,
            "source_ip": self.source_ip,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "success": self.success,
            "error_message": self.error_message,
            "details": self.details
        }
    
    def to_log_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for structlog."""
        d: Dict[str, Any] = {
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "success": self.success
        }
        
        if self.user_id:
            d["user_id"] = self.user_id
        if self.username:
            d["username"] = self.username
        if self.source_ip:
            d["source_ip"] = self.source_ip
        if self.resource_type:
            d["resource_type"] = self.resource_type
        if self.resource_id:
            d["resource_id"] = self.resource_id
        if self.error_message:
            d["error"] = self.error_message
        
        d.update(self.details)
        return d


# =============================================================================
# Audit Logger Service
# =============================================================================

class AuditLogger:
    """
    Centralized audit logging service.
    
    Features:
    - In-memory ring buffer for recent events
    - Async callbacks for persistence/alerting
    - Structured logging via structlog
    - Query interface for recent events
    """
    
    def __init__(
        self,
        buffer_size: int = 10000,
        enable_file_logging: bool = True
    ):
        self._buffer: deque[AuditEvent] = deque(maxlen=buffer_size)
        self._callbacks: List[Callable[[AuditEvent], None]] = []
        self._async_callbacks: List[Callable[[AuditEvent], Coroutine[Any, Any, None]]] = []
        self._enable_file_logging = enable_file_logging
        
        # Statistics
        self._total_events: int = 0
        self._events_by_type: Dict[str, int] = {}
        self._events_by_severity: Dict[str, int] = {s.value: 0 for s in AuditSeverity}
    
    def log(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity = AuditSeverity.INFO,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        source_ip: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        **details: Any
    ) -> AuditEvent:
        """
        Log an audit event.
        
        This is the primary entry point for audit logging.
        
        Args:
            event_type: Type of event
            severity: Event severity
            user_id: ID of user performing action
            username: Username for display
            source_ip: IP address of client
            resource_type: Type of resource affected
            resource_id: ID of resource affected
            success: Whether operation succeeded
            error_message: Error message if failed
            **details: Additional context
            
        Returns:
            The created AuditEvent
        """
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            username=username,
            source_ip=source_ip,
            resource_type=resource_type,
            resource_id=resource_id,
            success=success,
            error_message=error_message,
            details=details
        )
        
        # Store in buffer
        self._buffer.append(event)
        
        # Update statistics
        self._total_events += 1
        self._events_by_type[event_type.value] = \
            self._events_by_type.get(event_type.value, 0) + 1
        self._events_by_severity[severity.value] += 1
        
        # Log to structlog
        log_dict = event.to_log_dict()
        if severity == AuditSeverity.CRITICAL:
            logger.critical("Audit event", **log_dict)
        elif severity == AuditSeverity.ERROR:
            logger.error("Audit event", **log_dict)
        elif severity == AuditSeverity.WARNING:
            logger.warning("Audit event", **log_dict)
        else:
            logger.info("Audit event", **log_dict)
        
        # Notify callbacks
        self._notify_callbacks(event)
        
        return event
    
    def _notify_callbacks(self, event: AuditEvent) -> None:
        """Notify registered callbacks."""
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error("Audit callback error", error=str(e))
        
        # Handle async callbacks
        for async_callback in self._async_callbacks:
            try:
                coro = async_callback(event)
                asyncio.create_task(coro)  # type: ignore[arg-type]
            except Exception as e:
                logger.error("Async audit callback error", error=str(e))
    
    def register_callback(
        self,
        callback: Callable[[AuditEvent], None],
        is_async: bool = False
    ) -> None:
        """Register a callback for audit events."""
        if is_async:
            # Cast to async callback type - at runtime this works correctly
            self._async_callbacks.append(callback)  # type: ignore[arg-type]
        else:
            self._callbacks.append(callback)
    
    def unregister_callback(self, callback: Callable[[AuditEvent], None]) -> None:
        """Unregister a callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
        # Also check async callbacks with type cast
        async_cb: Callable[[AuditEvent], Coroutine[Any, Any, None]] = callback  # type: ignore[assignment]
        if async_cb in self._async_callbacks:
            self._async_callbacks.remove(async_cb)
    
    def get_recent_events(
        self,
        limit: int = 100,
        event_type: Optional[AuditEventType] = None,
        severity: Optional[AuditSeverity] = None,
        user_id: Optional[str] = None,
        success: Optional[bool] = None
    ) -> List[AuditEvent]:
        """
        Query recent audit events.
        
        Args:
            limit: Maximum number of events to return
            event_type: Filter by event type
            severity: Filter by severity
            user_id: Filter by user
            success: Filter by success/failure
            
        Returns:
            List of matching events (newest first)
        """
        events = list(self._buffer)
        events.reverse()  # Newest first
        
        # Apply filters
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if severity:
            events = [e for e in events if e.severity == severity]
        if user_id:
            events = [e for e in events if e.user_id == user_id]
        if success is not None:
            events = [e for e in events if e.success == success]
        
        return events[:limit]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get audit statistics."""
        return {
            "total_events": self._total_events,
            "events_by_type": self._events_by_type,
            "events_by_severity": self._events_by_severity,
            "buffer_size": len(self._buffer),
            "buffer_max": self._buffer.maxlen
        }
    
    # ==========================================================================
    # Convenience methods for common operations
    # ==========================================================================
    
    def log_auth_success(
        self,
        username: str,
        source_ip: Optional[str] = None,
        **details: Any
    ) -> AuditEvent:
        """Log successful authentication."""
        return self.log(
            event_type=AuditEventType.AUTH_LOGIN,
            severity=AuditSeverity.INFO,
            username=username,
            source_ip=source_ip,
            resource_type="auth",
            success=True,
            **details
        )
    
    def log_auth_failure(
        self,
        username: str,
        source_ip: Optional[str] = None,
        reason: str = "Invalid credentials",
        **details: Any
    ) -> AuditEvent:
        """Log failed authentication attempt."""
        return self.log(
            event_type=AuditEventType.AUTH_LOGIN_FAILED,
            severity=AuditSeverity.WARNING,
            username=username,
            source_ip=source_ip,
            resource_type="auth",
            success=False,
            error_message=reason,
            **details
        )
    
    def log_scan_started(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        **details: Any
    ) -> AuditEvent:
        """Log scan start."""
        return self.log(
            event_type=AuditEventType.SCAN_STARTED,
            severity=AuditSeverity.INFO,
            user_id=user_id,
            username=username,
            resource_type="scan",
            resource_id=scan_id,
            target=target,
            scan_type=scan_type,
            **details
        )
    
    def log_scan_completed(
        self,
        scan_id: str,
        hosts_found: int,
        duration_seconds: float,
        **details: Any
    ) -> AuditEvent:
        """Log scan completion."""
        return self.log(
            event_type=AuditEventType.SCAN_COMPLETED,
            severity=AuditSeverity.INFO,
            resource_type="scan",
            resource_id=scan_id,
            hosts_found=hosts_found,
            duration_seconds=duration_seconds,
            **details
        )
    
    def log_capture_started(
        self,
        interface: str,
        bpf_filter: Optional[str] = None,
        user_id: Optional[str] = None,
        **details: Any
    ) -> AuditEvent:
        """Log capture start."""
        return self.log(
            event_type=AuditEventType.CAPTURE_STARTED,
            severity=AuditSeverity.INFO,
            user_id=user_id,
            resource_type="capture",
            resource_id=interface,
            bpf_filter=bpf_filter,
            **details
        )
    
    def log_capture_stopped(
        self,
        interface: str,
        packets_captured: int,
        duration_seconds: float,
        **details: Any
    ) -> AuditEvent:
        """Log capture stop."""
        return self.log(
            event_type=AuditEventType.CAPTURE_STOPPED,
            severity=AuditSeverity.INFO,
            resource_type="capture",
            resource_id=interface,
            packets_captured=packets_captured,
            duration_seconds=duration_seconds,
            **details
        )
    
    def log_detection(
        self,
        rule_id: str,
        alert_title: str,
        source_ip: Optional[str] = None,
        severity: AuditSeverity = AuditSeverity.WARNING,
        **details: Any
    ) -> AuditEvent:
        """Log detection event."""
        return self.log(
            event_type=AuditEventType.DETECTION_TRIGGERED,
            severity=severity,
            source_ip=source_ip,
            resource_type="detection",
            resource_id=rule_id,
            alert_title=alert_title,
            **details
        )
    
    def log_alert_acknowledged(
        self,
        alert_id: int,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        **details: Any
    ) -> AuditEvent:
        """Log alert acknowledgment."""
        return self.log(
            event_type=AuditEventType.ALERT_ACKNOWLEDGED,
            severity=AuditSeverity.INFO,
            user_id=user_id,
            username=username,
            resource_type="alert",
            resource_id=str(alert_id),
            **details
        )
    
    def log_error(
        self,
        error_message: str,
        event_type: AuditEventType = AuditEventType.SYSTEM_ERROR,
        **details: Any
    ) -> AuditEvent:
        """Log a system error."""
        return self.log(
            event_type=event_type,
            severity=AuditSeverity.ERROR,
            success=False,
            error_message=error_message,
            **details
        )


# =============================================================================
# Singleton Instance
# =============================================================================

_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get the singleton audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


# =============================================================================
# Context Manager for Operation Tracking
# =============================================================================

class AuditContext:
    """
    Context manager for tracking operation audit.
    
    Automatically logs start and completion/failure of an operation.
    
    Example:
        async with AuditContext(
            audit_logger,
            AuditEventType.SCAN_STARTED,
            resource_type="scan",
            resource_id=scan_id
        ) as ctx:
            # Do operation
            ctx.details["hosts_found"] = 10
    """
    
    def __init__(
        self,
        logger: AuditLogger,
        event_type: AuditEventType,
        completion_event_type: Optional[AuditEventType] = None,
        failure_event_type: Optional[AuditEventType] = None,
        **initial_details: Any
    ):
        self.logger = logger
        self.event_type = event_type
        self.completion_event_type = completion_event_type
        self.failure_event_type = failure_event_type
        self.initial_details = initial_details
        self.details: Dict[str, Any] = {}
        self._start_time: Optional[datetime] = None
    
    def __enter__(self) -> "AuditContext":
        self._start_time = datetime.now(timezone.utc)
        self.logger.log(
            event_type=self.event_type,
            **self.initial_details
        )
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        if self._start_time is None:
            return False
        duration = (datetime.now(timezone.utc) - self._start_time).total_seconds()
        
        if exc_type is not None:
            # Operation failed
            event_type = self.failure_event_type or AuditEventType.SYSTEM_ERROR
            self.logger.log(
                event_type=event_type,
                severity=AuditSeverity.ERROR,
                success=False,
                error_message=str(exc_val),
                duration_seconds=duration,
                **self.initial_details,
                **self.details
            )
        elif self.completion_event_type:
            # Operation succeeded
            self.logger.log(
                event_type=self.completion_event_type,
                success=True,
                duration_seconds=duration,
                **self.initial_details,
                **self.details
            )
        
        return False  # Don't suppress exceptions
    
    async def __aenter__(self) -> "AuditContext":
        return self.__enter__()
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        return self.__exit__(exc_type, exc_val, exc_tb)

"""
Alert Manager
Manages security alerts and notifications.
"""

from collections import deque
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
import threading
import structlog
import asyncio

from app.core.config import settings
from app.core.detection.engine import DetectionEvent

logger = structlog.get_logger(__name__)


@dataclass
class Alert:
    """Security alert."""
    id: int
    severity: str  # info, warning, critical
    title: str
    description: str
    explanation: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    rule_id: Optional[str] = None
    metadata: Dict = field(default_factory=dict)
    is_acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AlertManager:
    """
    Manages security alerts, storage, and notification.
    """
    
    def __init__(self, max_alerts: int = 1000):
        self.alerts: deque = deque(maxlen=max_alerts)
        self.alert_counter = 0
        self.lock = threading.Lock()
        
        # Rate limiting
        self.rate_limiter = {}
        self.rate_limit_window = 60  # seconds
        
        # Alert callbacks (for WebSocket notifications)
        self.callbacks: List[Callable] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        
        # Statistics
        self.stats = {
            "total_alerts": 0,
            "info_count": 0,
            "warning_count": 0,
            "critical_count": 0,
            "acknowledged_count": 0
        }
        
        logger.info("Alert manager initialized")
    
    def set_event_loop(self, loop: asyncio.AbstractEventLoop):
        """Set the event loop for async callbacks."""
        self._loop = loop
    
    def add_callback(self, callback: Callable):
        """Add a callback for new alerts."""
        self.callbacks.append(callback)
    
    def remove_callback(self, callback: Callable):
        """Remove an alert callback."""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def _check_rate_limit(self, rule_id: str) -> bool:
        """Check if we should rate limit this alert."""
        now = datetime.utcnow()
        
        if rule_id in self.rate_limiter:
            last_alert, count = self.rate_limiter[rule_id]
            time_diff = (now - last_alert).total_seconds()
            
            if time_diff < self.rate_limit_window:
                if count >= settings.MAX_ALERTS_PER_MINUTE:
                    return True  # Rate limited
                self.rate_limiter[rule_id] = (last_alert, count + 1)
            else:
                self.rate_limiter[rule_id] = (now, 1)
        else:
            self.rate_limiter[rule_id] = (now, 1)
        
        return False
    
    def create_alert(self, event: DetectionEvent) -> Optional[Alert]:
        """Create a new alert from a detection event."""
        # Check rate limiting
        if event.rule_id and self._check_rate_limit(event.rule_id):
            logger.debug("Alert rate limited", rule_id=event.rule_id)
            return None
        
        with self.lock:
            self.alert_counter += 1
            
            alert = Alert(
                id=self.alert_counter,
                severity=event.severity,
                title=event.title,
                description=event.description,
                explanation=event.explanation,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                protocol=event.protocol,
                port=event.port,
                rule_id=event.rule_id,
                metadata=event.metadata,
                created_at=event.timestamp
            )
            
            self.alerts.append(alert)
            
            # Update statistics
            self.stats["total_alerts"] += 1
            if event.severity == "info":
                self.stats["info_count"] += 1
            elif event.severity == "warning":
                self.stats["warning_count"] += 1
            elif event.severity == "critical":
                self.stats["critical_count"] += 1
        
        logger.info(
            "Alert created",
            alert_id=alert.id,
            severity=alert.severity,
            title=alert.title
        )
        
        # Notify callbacks
        self._notify_callbacks(alert)
        
        return alert
    
    def _notify_callbacks(self, alert: Alert):
        """Notify all registered callbacks about new alert."""
        for callback in self.callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    if self._loop:
                        asyncio.run_coroutine_threadsafe(
                            callback(alert),
                            self._loop
                        )
                else:
                    callback(alert)
            except Exception as e:
                logger.error("Alert callback error", error=str(e))
    
    def get_alerts(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        source_ip: Optional[str] = None,
        rule_id: Optional[str] = None
    ) -> List[Dict]:
        """Get alerts with optional filtering."""
        with self.lock:
            alerts = list(self.alerts)
        
        # Apply filters
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        if acknowledged is not None:
            alerts = [a for a in alerts if a.is_acknowledged == acknowledged]
        
        if source_ip:
            alerts = [a for a in alerts if a.source_ip == source_ip]
        
        if rule_id:
            alerts = [a for a in alerts if a.rule_id == rule_id]
        
        # Return most recent first
        alerts = sorted(alerts, key=lambda a: a.created_at, reverse=True)
        
        return [a.to_dict() for a in alerts[:limit]]
    
    def get_alert_by_id(self, alert_id: int) -> Optional[Dict]:
        """Get a specific alert by ID."""
        with self.lock:
            for alert in self.alerts:
                if alert.id == alert_id:
                    return alert.to_dict()
        return None
    
    def acknowledge_alert(self, alert_id: int, username: str) -> bool:
        """Acknowledge an alert."""
        with self.lock:
            for alert in self.alerts:
                if alert.id == alert_id:
                    if not alert.is_acknowledged:
                        alert.is_acknowledged = True
                        alert.acknowledged_by = username
                        alert.acknowledged_at = datetime.utcnow().isoformat()
                        self.stats["acknowledged_count"] += 1
                        logger.info("Alert acknowledged", alert_id=alert_id, by=username)
                    return True
        return False
    
    def acknowledge_all(self, username: str, severity: Optional[str] = None) -> int:
        """Acknowledge all alerts, optionally filtered by severity."""
        count = 0
        with self.lock:
            for alert in self.alerts:
                if not alert.is_acknowledged:
                    if severity is None or alert.severity == severity:
                        alert.is_acknowledged = True
                        alert.acknowledged_by = username
                        alert.acknowledged_at = datetime.utcnow().isoformat()
                        count += 1
            
            self.stats["acknowledged_count"] += count
        
        logger.info("Alerts acknowledged", count=count, by=username)
        return count
    
    def delete_alert(self, alert_id: int) -> bool:
        """Delete an alert by ID."""
        with self.lock:
            for i, alert in enumerate(self.alerts):
                if alert.id == alert_id:
                    del self.alerts[i]
                    logger.info("Alert deleted", alert_id=alert_id)
                    return True
        return False
    
    def clear_alerts(self, acknowledged_only: bool = True) -> int:
        """Clear alerts."""
        with self.lock:
            if acknowledged_only:
                original_count = len(self.alerts)
                self.alerts = deque(
                    [a for a in self.alerts if not a.is_acknowledged],
                    maxlen=self.alerts.maxlen
                )
                count = original_count - len(self.alerts)
            else:
                count = len(self.alerts)
                self.alerts.clear()
        
        logger.info("Alerts cleared", count=count, acknowledged_only=acknowledged_only)
        return count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        with self.lock:
            unacknowledged = sum(1 for a in self.alerts if not a.is_acknowledged)
            critical_unack = sum(1 for a in self.alerts if not a.is_acknowledged and a.severity == "critical")
        
        return {
            **self.stats,
            "unacknowledged_count": unacknowledged,
            "critical_unacknowledged": critical_unack,
            "current_count": len(self.alerts)
        }
    
    def get_recent_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get summary of alerts from the last N hours."""
        cutoff = datetime.utcnow().replace(
            hour=datetime.utcnow().hour - hours if datetime.utcnow().hour >= hours else 0
        )
        cutoff_str = cutoff.isoformat()
        
        with self.lock:
            recent = [a for a in self.alerts if a.created_at >= cutoff_str]
        
        by_severity = {"info": 0, "warning": 0, "critical": 0}
        by_rule = {}
        by_source = {}
        
        for alert in recent:
            by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
            
            if alert.rule_id:
                by_rule[alert.rule_id] = by_rule.get(alert.rule_id, 0) + 1
            
            if alert.source_ip:
                by_source[alert.source_ip] = by_source.get(alert.source_ip, 0) + 1
        
        # Top sources
        top_sources = sorted(by_source.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "total": len(recent),
            "by_severity": by_severity,
            "by_rule": by_rule,
            "top_sources": top_sources,
            "period_hours": hours
        }

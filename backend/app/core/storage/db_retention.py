"""
Database Retention Policies

Manages warm data retention in SQLite/Postgres:
- Alert retention (30 days default)
- Scan retention (90 days default)
- Audit log retention (365 days default)
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
import structlog

from app.database.session import AsyncSession
from sqlalchemy import delete, select, func

logger = structlog.get_logger(__name__)


class DatabaseRetention:
    """
    Manages database record retention.
    
    Runs periodic cleanup of old records based on retention policies.
    """
    
    def __init__(
        self,
        alert_retention_days: int = 30,
        scan_retention_days: int = 90,
        audit_retention_days: int = 365
    ):
        self._alert_retention = timedelta(days=alert_retention_days)
        self._scan_retention = timedelta(days=scan_retention_days)
        self._audit_retention = timedelta(days=audit_retention_days)
        
        self._running = False
        self._task: Optional[asyncio.Task[None]] = None
        self._cleanup_interval = 3600  # 1 hour
        
        logger.info(
            "Database retention initialized",
            alert_days=alert_retention_days,
            scan_days=scan_retention_days,
            audit_days=audit_retention_days
        )
    
    async def start(self):
        """Start background retention task."""
        if self._running:
            return
        
        self._running = True
        self._task = asyncio.create_task(self._retention_loop())
        logger.info("Database retention started")
    
    async def stop(self):
        """Stop background retention task."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Database retention stopped")
    
    async def _retention_loop(self):
        """Background retention loop."""
        while self._running:
            try:
                await asyncio.sleep(self._cleanup_interval)
                await self.cleanup()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Retention loop error", error=str(e))
    
    async def cleanup(self) -> Dict[str, Any]:
        """Run retention cleanup on all tables."""
        results: Dict[str, Any] = {}
        
        try:
            from app.database.session import engine
            from app.database.models import Alert, NetworkScan
            
            async with AsyncSession(engine) as session:
                now = datetime.now(timezone.utc)
                
                # Clean old alerts
                alert_cutoff = now - self._alert_retention
                result = await session.execute(
                    delete(Alert).where(Alert.created_at < alert_cutoff)
                )
                results["alerts_deleted"] = result.rowcount  # type: ignore[union-attr]
                
                # Clean old scans
                scan_cutoff = now - self._scan_retention
                result = await session.execute(
                    delete(NetworkScan).where(NetworkScan.created_at < scan_cutoff)
                )
                results["scans_deleted"] = result.rowcount  # type: ignore[union-attr]
                
                await session.commit()
                
                logger.info("Database retention cleanup completed", **results)
        
        except Exception as e:
            logger.error("Database retention cleanup error", error=str(e))
            results["error"] = str(e)
        
        return results
    
    async def get_table_stats(self) -> Dict[str, Any]:
        """Get row counts and oldest records for each table."""
        try:
            from app.database.session import engine
            from app.database.models import Alert, NetworkScan
            
            stats: Dict[str, Any] = {}
            
            async with AsyncSession(engine) as session:
                # Alert stats
                alert_count = await session.execute(select(func.count(Alert.id)))
                oldest_alert = await session.execute(
                    select(func.min(Alert.created_at))
                )
                
                stats["alerts"] = {
                    "count": alert_count.scalar() or 0,
                    "oldest": oldest_alert.scalar(),
                    "retention_days": self._alert_retention.days
                }
                
                # Scan stats
                scan_count = await session.execute(select(func.count(NetworkScan.id)))
                oldest_scan = await session.execute(
                    select(func.min(NetworkScan.created_at))
                )
                
                stats["scans"] = {
                    "count": scan_count.scalar() or 0,
                    "oldest": oldest_scan.scalar(),
                    "retention_days": self._scan_retention.days
                }
            
            return stats
        
        except Exception as e:
            logger.error("Error getting table stats", error=str(e))
            return {"error": str(e)}


# Global instance
db_retention = DatabaseRetention()

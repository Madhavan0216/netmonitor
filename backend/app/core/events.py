"""
Event Bus Implementation

Provides async event-driven communication between services
per DESIGN_SPECIFICATION.md Section 2.1.

Features:
- Topic-based pub/sub
- Async event handlers
- Event filtering
- Backpressure handling
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# Event Types
# =============================================================================

class EventType(str, Enum):
    """System event types."""
    
    # Packet events
    PACKET_CAPTURED = "packet.captured"
    PACKET_BATCH = "packet.batch"
    
    # Detection events
    DETECTION_TRIGGERED = "detection.triggered"
    DETECTION_RULE_ADDED = "detection.rule_added"
    DETECTION_RULE_REMOVED = "detection.rule_removed"
    
    # Alert events
    ALERT_CREATED = "alert.created"
    ALERT_ACKNOWLEDGED = "alert.acknowledged"
    ALERT_DELETED = "alert.deleted"
    
    # Scan events
    SCAN_STARTED = "scan.started"
    SCAN_PROGRESS = "scan.progress"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_CANCELLED = "scan.cancelled"
    
    # Network events
    HOST_DISCOVERED = "network.host_discovered"
    HOST_UPDATED = "network.host_updated"
    TOPOLOGY_CHANGED = "network.topology_changed"
    ARP_CACHE_UPDATED = "network.arp_cache_updated"
    
    # System events
    SYSTEM_STARTED = "system.started"
    SYSTEM_STOPPING = "system.stopping"
    CONFIG_CHANGED = "config.changed"
    
    # Stats events
    STATS_UPDATED = "stats.updated"


# =============================================================================
# Event Model
# =============================================================================

@dataclass
class Event:
    """
    Base event class for all system events.
    
    Events are immutable messages that flow through the event bus.
    """
    event_type: EventType
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    data: Any = None
    source: Optional[str] = None
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "source": self.source,
            "correlation_id": self.correlation_id
        }


# Type alias for event handlers
EventHandler = Callable[[Event], Any]


# =============================================================================
# Event Bus
# =============================================================================

class EventBus:
    """
    Async event bus for decoupled service communication.
    
    Features:
    - Topic-based subscriptions
    - Wildcard subscriptions (e.g., "scan.*")
    - Async handler execution
    - Backpressure via bounded queue
    - Event history for debugging
    """
    
    def __init__(
        self,
        queue_size: int = 10000,
        history_size: int = 1000
    ):
        # Subscriptions: topic -> list of handlers
        self._handlers: Dict[str, List[EventHandler]] = defaultdict(list)
        
        # Wildcard subscriptions: prefix -> list of handlers
        self._wildcard_handlers: Dict[str, List[EventHandler]] = defaultdict(list)
        
        # Event queue for async processing
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)
        
        # Event history for debugging
        self._history: List[Event] = []
        self._history_size = history_size
        
        # Processing task
        self._processor_task: Optional[asyncio.Task[None]] = None
        self._running = False
        
        # Statistics
        self._stats = {
            "events_published": 0,
            "events_processed": 0,
            "events_dropped": 0,
            "handler_errors": 0
        }
    
    async def start(self):
        """Start the event bus processor."""
        if self._running:
            return
        
        self._running = True
        self._processor_task = asyncio.create_task(self._process_events())
        logger.info("Event bus started")
    
    async def stop(self):
        """Stop the event bus processor."""
        self._running = False
        
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Event bus stopped")
    
    def subscribe(
        self,
        event_type: EventType | str,
        handler: EventHandler
    ) -> None:
        """
        Subscribe to events of a specific type.
        
        Args:
            event_type: Event type or pattern (e.g., "scan.*")
            handler: Async or sync function to handle events
        """
        topic = event_type.value if isinstance(event_type, EventType) else event_type
        
        if topic.endswith(".*"):
            # Wildcard subscription
            prefix = topic[:-2]
            self._wildcard_handlers[prefix].append(handler)
            logger.debug("Wildcard subscription added", prefix=prefix)
        else:
            self._handlers[topic].append(handler)
            logger.debug("Subscription added", topic=topic)
    
    def unsubscribe(
        self,
        event_type: EventType | str,
        handler: EventHandler
    ) -> bool:
        """Unsubscribe a handler from an event type."""
        topic = event_type.value if isinstance(event_type, EventType) else event_type
        
        if topic.endswith(".*"):
            prefix = topic[:-2]
            if handler in self._wildcard_handlers[prefix]:
                self._wildcard_handlers[prefix].remove(handler)
                return True
        else:
            if handler in self._handlers[topic]:
                self._handlers[topic].remove(handler)
                return True
        
        return False
    
    async def publish(self, event: Event) -> bool:
        """
        Publish an event to the bus.
        
        Args:
            event: Event to publish
            
        Returns:
            True if queued, False if dropped due to backpressure
        """
        try:
            self._queue.put_nowait(event)
            self._stats["events_published"] += 1
            
            # Add to history
            self._history.append(event)
            if len(self._history) > self._history_size:
                self._history.pop(0)
            
            return True
        except asyncio.QueueFull:
            self._stats["events_dropped"] += 1
            logger.warning(
                "Event dropped due to backpressure",
                event_type=event.event_type.value
            )
            return False
    
    async def publish_now(self, event: Event) -> None:
        """
        Publish and process an event immediately (bypass queue).
        
        Use sparingly - mainly for critical events.
        """
        await self._dispatch_event(event)
        self._stats["events_published"] += 1
        self._stats["events_processed"] += 1
    
    def emit(
        self,
        event_type: EventType,
        data: Any = None,
        source: Optional[str] = None
    ) -> asyncio.Task[bool]:
        """
        Convenience method to emit an event.
        
        Returns a task that completes when event is queued.
        """
        event = Event(
            event_type=event_type,
            data=data,
            source=source
        )
        return asyncio.create_task(self.publish(event))
    
    async def _process_events(self):
        """Background task to process queued events."""
        while self._running:
            try:
                # Wait for event with timeout (allows periodic checks)
                try:
                    event = await asyncio.wait_for(
                        self._queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                await self._dispatch_event(event)
                self._stats["events_processed"] += 1
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Event processing error", error=str(e))
    
    async def _dispatch_event(self, event: Event):
        """Dispatch an event to all matching handlers."""
        topic = event.event_type.value
        handlers: List[EventHandler] = []
        
        # Get exact match handlers
        handlers.extend(self._handlers.get(topic, []))
        
        # Get wildcard match handlers
        for prefix, prefix_handlers in self._wildcard_handlers.items():
            if topic.startswith(prefix):
                handlers.extend(prefix_handlers)
        
        # Execute handlers
        for handler in handlers:
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                self._stats["handler_errors"] += 1
                logger.error(
                    "Event handler error",
                    event_type=topic,
                    handler=handler.__name__,
                    error=str(e)
                )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get event bus statistics."""
        return {
            **self._stats,
            "queue_size": self._queue.qsize(),
            "queue_max": self._queue.maxsize,
            "subscription_count": sum(
                len(h) for h in self._handlers.values()
            ) + sum(
                len(h) for h in self._wildcard_handlers.values()
            ),
            "history_size": len(self._history)
        }
    
    def get_recent_events(
        self,
        limit: int = 100,
        event_type: Optional[EventType] = None
    ) -> List[Event]:
        """Get recent events from history."""
        events = self._history.copy()
        events.reverse()  # Newest first
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        return events[:limit]


# =============================================================================
# Singleton Instance
# =============================================================================

_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """Get the singleton event bus instance."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


# =============================================================================
# Decorator for Event Handlers
# =============================================================================

def on_event(event_type: EventType | str):
    """
    Decorator to register an event handler.
    
    Example:
        @on_event(EventType.PACKET_CAPTURED)
        async def handle_packet(event: Event):
            print(f"Packet: {event.data}")
    """
    def decorator(func: EventHandler) -> EventHandler:
        event_bus = get_event_bus()
        event_bus.subscribe(event_type, func)
        return func
    return decorator

"""
WebSocket Manager for real-time updates.

Enhanced with proper channel management per DESIGN_SPECIFICATION.md Section 4.
"""

import asyncio
import json
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set
from dataclasses import dataclass, field
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from jose import JWTError, jwt
import structlog

from app.core.config import settings
from app.core.capture.packet_capture import PacketInfo
from app.core.alerting.alert_manager import Alert
from app.core.telemetry.metrics import metrics

logger = structlog.get_logger(__name__)

router = APIRouter()


# =============================================================================
# Channel Definitions
# =============================================================================

class Channel:
    """Channel constants."""
    PACKETS = "packets"
    ALERTS = "alerts"
    STATS = "stats"
    TOPOLOGY = "topology"
    SCANS = "scans"
    ALL = "all"
    
    @classmethod
    def all_channels(cls) -> Set[str]:
        return {cls.PACKETS, cls.ALERTS, cls.STATS, cls.TOPOLOGY, cls.SCANS}


@dataclass
class WSMessage:
    """Structured WebSocket message."""
    channel: str
    event: str
    data: Any
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> dict:
        return {
            "channel": self.channel,
            "event": self.event,
            "data": self.data,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ConnectionInfo:
    """Information about a WebSocket connection."""
    websocket: WebSocket
    user_id: Optional[str] = None
    channels: Set[str] = field(default_factory=set)
    connected_at: datetime = field(default_factory=datetime.utcnow)
    message_count: int = 0


class ConnectionManager:
    """
    Manages WebSocket connections and broadcasts.
    
    Features:
    - Channel-based subscriptions
    - Connection tracking with metadata
    - Rate-limited broadcasting
    - Graceful error handling
    """
    
    def __init__(self, max_connections: int = 100, broadcast_interval: float = 0.1):
        # Connection tracking
        self._connections: Dict[WebSocket, ConnectionInfo] = {}
        
        # Channel subscriptions (channel -> set of websockets)
        self._channels: Dict[str, Set[WebSocket]] = {
            Channel.PACKETS: set(),
            Channel.ALERTS: set(),
            Channel.STATS: set(),
            Channel.TOPOLOGY: set(),
            Channel.SCANS: set(),
            Channel.ALL: set()
        }
        
        # Legacy compatibility
        self.active_connections = self._channels
        
        # Configuration
        self._max_connections = max_connections
        self._broadcast_interval = broadcast_interval
        
        # Broadcast queue for rate limiting
        self._broadcast_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._broadcast_task: Optional[asyncio.Task] = None
        
        # Metrics
        self._metrics = {
            "total_connections": 0,
            "total_messages_sent": 0,
            "total_messages_dropped": 0
        }
    
    @property
    def connection_count(self) -> int:
        """Get current connection count."""
        return len(self._connections)
    
    @property
    def metrics(self) -> Dict[str, Any]:
        """Get connection metrics."""
        return {
            **self._metrics,
            "active_connections": self.connection_count,
            "channels": {
                name: len(sockets) 
                for name, sockets in self._channels.items()
            }
        }
    
    async def connect(
        self,
        websocket: WebSocket,
        channel: str = "all",
        user_id: Optional[str] = None
    ) -> bool:
        """
        Accept a new WebSocket connection.
        
        Args:
            websocket: The WebSocket connection
            channel: Initial channel to subscribe to
            user_id: Optional user ID for tracking
            
        Returns:
            True if connected, False if rejected
        """
        # Check connection limit
        if self.connection_count >= self._max_connections:
            logger.warning(
                "Connection rejected - limit reached",
                current=self.connection_count,
                max=self._max_connections
            )
            await websocket.close(code=1013, reason="Server at capacity")
            return False
        
        await websocket.accept()
        
        # Normalize channel
        if channel not in self._channels:
            channel = Channel.ALL
        
        # Track connection
        conn_info = ConnectionInfo(
            websocket=websocket,
            user_id=user_id,
            channels={channel}
        )
        self._connections[websocket] = conn_info
        
        # Subscribe to channel
        self._channels[channel].add(websocket)
        if channel != Channel.ALL:
            self._channels[Channel.ALL].add(websocket)
        
        self._metrics["total_connections"] += 1
        
        logger.info(
            "WebSocket connected",
            channel=channel,
            user_id=user_id,
            total_connections=self.connection_count
        )
        
        return True
    
    def disconnect(self, websocket: WebSocket, channel: str = "all"):
        """Remove a WebSocket connection."""
        conn_info = self._connections.pop(websocket, None)
        
        # Remove from all channels
        for ch in self._channels.values():
            ch.discard(websocket)
        
        if conn_info:
            logger.info(
                "WebSocket disconnected",
                channels=list(conn_info.channels),
                user_id=conn_info.user_id,
                messages_sent=conn_info.message_count,
                total_connections=self.connection_count
            )
    
    async def subscribe(self, websocket: WebSocket, channels: List[str]) -> bool:
        """
        Subscribe a connection to additional channels.
        
        Args:
            websocket: The WebSocket connection
            channels: List of channel names to subscribe to
            
        Returns:
            True if subscribed, False if not connected
        """
        if websocket not in self._connections:
            return False
        
        conn_info = self._connections[websocket]
        
        for channel in channels:
            if channel in self._channels:
                self._channels[channel].add(websocket)
                conn_info.channels.add(channel)
        
        logger.debug(
            "Channels updated",
            websocket_id=id(websocket),
            channels=list(conn_info.channels)
        )
        return True
    
    async def unsubscribe(self, websocket: WebSocket, channels: List[str]) -> bool:
        """Unsubscribe a connection from channels."""
        if websocket not in self._connections:
            return False
        
        conn_info = self._connections[websocket]
        
        for channel in channels:
            if channel in self._channels and channel != Channel.ALL:
                self._channels[channel].discard(websocket)
                conn_info.channels.discard(channel)
        
        return True
    
    async def broadcast_to_channel(self, channel: str, message: dict):
        """Broadcast a message to all connections in a channel."""
        if channel not in self._channels:
            return
        
        dead_connections = set()
        sent_count = 0
        
        for websocket in self._channels[channel].copy():
            try:
                await websocket.send_json(message)
                sent_count += 1
                
                # Update connection metrics
                if websocket in self._connections:
                    self._connections[websocket].message_count += 1
                    
            except Exception as e:
                logger.debug("Send failed, marking for cleanup", error=str(e))
                dead_connections.add(websocket)
        
        # Clean up dead connections
        for dead in dead_connections:
            self.disconnect(dead)
        
        self._metrics["total_messages_sent"] += sent_count
        
        # Record metrics
        metrics.increment("ws.messages_sent", sent_count)
        if dead_connections:
            metrics.increment("ws.connections_dropped", len(dead_connections))
        metrics.gauge("ws.active_connections", self.connection_count)
    
    async def send_to_connection(
        self,
        websocket: WebSocket,
        message: WSMessage
    ) -> bool:
        """Send a message to a specific connection."""
        try:
            await websocket.send_json(message.to_dict())
            if websocket in self._connections:
                self._connections[websocket].message_count += 1
            self._metrics["total_messages_sent"] += 1
            return True
        except Exception:
            self.disconnect(websocket)
            return False
    
    async def broadcast_packet(self, packet: PacketInfo):
        """Broadcast a new packet to subscribers."""
        message = {
            "type": "packet",
            "channel": Channel.PACKETS,
            "data": packet.to_dict(),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Log broadcast activity periodically
        subscribers = len(self._channels.get(Channel.PACKETS, set()))
        all_subscribers = len(self._channels.get(Channel.ALL, set()))
        
        if (self._metrics.get("total_messages_sent", 0) % 50) == 0:
            logger.debug(
                "Broadcasting packet",
                packet_subscribers=subscribers,
                all_subscribers=all_subscribers,
                protocol=packet.protocol
            )
        
        await self.broadcast_to_channel(Channel.PACKETS, message)
        # Also broadcast to 'all' channel subscribers
        await self.broadcast_to_channel(Channel.ALL, message)
    
    async def broadcast_alert(self, alert):
        """Broadcast a new alert to subscribers.
        
        Args:
            alert: Either an Alert object with to_dict() or a plain dict
        """
        # Support both Alert objects and plain dicts
        if hasattr(alert, 'to_dict'):
            alert_data = alert.to_dict()
        else:
            alert_data = alert
        
        message = {
            "type": "alert",
            "channel": Channel.ALERTS,
            "data": alert_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_channel(Channel.ALERTS, message)
    
    async def broadcast_stats(self, stats: dict):
        """Broadcast statistics update."""
        message = {
            "type": "stats",
            "channel": Channel.STATS,
            "data": stats,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_channel(Channel.STATS, message)
    
    async def broadcast_topology(self, topology: dict):
        """Broadcast topology update."""
        message = {
            "type": "topology",
            "channel": Channel.TOPOLOGY,
            "data": topology,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_channel(Channel.TOPOLOGY, message)
    
    async def broadcast_scan_update(self, scan_data: dict):
        """Broadcast scan progress/result update."""
        message = {
            "type": "scan",
            "channel": Channel.SCANS,
            "data": scan_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_channel(Channel.SCANS, message)


# Global connection manager (fallback - prefer app.state.ws_manager)
manager = ConnectionManager()


def get_manager_from_app(websocket: WebSocket) -> ConnectionManager:
    """Get the ConnectionManager from app state, falling back to global."""
    try:
        # Access app from websocket's scope
        app = websocket.scope.get("app")
        if app and hasattr(app, "state") and hasattr(app.state, "ws_manager"):
            return app.state.ws_manager
    except Exception:
        pass
    return manager


async def verify_token(token: str) -> Optional[str]:
    """
    Verify JWT token for WebSocket authentication.
    
    Returns:
        Username if valid, None otherwise
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
        return username
    except JWTError:
        return None


@router.websocket("/live")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(None),
    channel: str = Query("all")
):
    """
    WebSocket endpoint for real-time updates.
    
    **Channels:**
    - `all`: All updates (packets, alerts, stats, topology, scans)
    - `packets`: Only packet capture updates
    - `alerts`: Only security alert updates
    - `stats`: Only statistics updates
    - `topology`: Only network topology updates
    - `scans`: Only scan progress updates
    
    **Authentication:**
    Pass the JWT token as a query parameter: `?token=<jwt_token>`
    
    **Message Format (Outgoing):**
    ```json
    {
        "type": "packet|alert|stats|topology|scan",
        "channel": "packets|alerts|stats|topology|scans",
        "data": { ... },
        "timestamp": "2024-01-01T00:00:00.000Z"
    }
    ```
    
    **Message Format (Incoming):**
    ```json
    {
        "type": "ping|subscribe|unsubscribe",
        "channel": "channel_name"  // for subscribe/unsubscribe
    }
    ```
    """
    # Verify authentication
    user_id = None
    if token:
        user_id = await verify_token(token)
        if not user_id:
            await websocket.close(code=4001, reason="Invalid token")
            return
    
    # Get the correct manager instance (from app.state, not global)
    ws_manager = get_manager_from_app(websocket)
    
    # Connect with tracking
    connected = await ws_manager.connect(websocket, channel, user_id)
    if not connected:
        return
    
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connected",
            "channel": channel,
            "message": "Successfully connected to NetMonitor WebSocket",
            "available_channels": list(Channel.all_channels()),
            "timestamp": datetime.utcnow().isoformat()
        })
        
        logger.info("WebSocket client connected", channel=channel, user_id=user_id)
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for messages (with timeout for keepalive)
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                
                # Handle incoming messages
                try:
                    message = json.loads(data)
                    msg_type = message.get("type", "")
                    
                    if msg_type == "ping":
                        await websocket.send_json({
                            "type": "pong",
                            "timestamp": datetime.utcnow().isoformat()
                        })
                    
                    elif msg_type == "subscribe":
                        channels_to_sub = message.get("channels", [])
                        if isinstance(channels_to_sub, str):
                            channels_to_sub = [channels_to_sub]
                        
                        # Also support legacy "channel" field
                        if message.get("channel"):
                            channels_to_sub.append(message["channel"])
                        
                        await ws_manager.subscribe(websocket, channels_to_sub)
                        await websocket.send_json({
                            "type": "subscribed",
                            "channels": channels_to_sub,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                    
                    elif msg_type == "unsubscribe":
                        channels_to_unsub = message.get("channels", [])
                        if isinstance(channels_to_unsub, str):
                            channels_to_unsub = [channels_to_unsub]
                        
                        if message.get("channel"):
                            channels_to_unsub.append(message["channel"])
                        
                        await ws_manager.unsubscribe(websocket, channels_to_unsub)
                        await websocket.send_json({
                            "type": "unsubscribed",
                            "channels": channels_to_unsub,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                    
                    elif msg_type == "status":
                        # Return connection status
                        conn_info = ws_manager._connections.get(websocket)
                        if conn_info:
                            await websocket.send_json({
                                "type": "status",
                                "channels": list(conn_info.channels),
                                "connected_at": conn_info.connected_at.isoformat(),
                                "message_count": conn_info.message_count,
                                "timestamp": datetime.utcnow().isoformat()
                            })
                
                except json.JSONDecodeError:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Invalid JSON",
                        "timestamp": datetime.utcnow().isoformat()
                    })
            
            except asyncio.TimeoutError:
                # Send keepalive ping
                try:
                    await websocket.send_json({
                        "type": "ping",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                except:
                    break
    
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected", channel=channel, user_id=user_id)
    except Exception as e:
        logger.error("WebSocket error", error=str(e), exc_info=True)
    finally:
        ws_manager.disconnect(websocket, channel)


# Helper function to get the manager instance
def get_websocket_manager() -> ConnectionManager:
    """Get the WebSocket connection manager."""
    return manager

"""
WebSocket Manager - Real-time live scan log streaming
Manages per-scan and per-org WebSocket connections with room-based broadcasting
"""
import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from uuid import uuid4

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("vapt.websocket")


class ScanLogEntry:
    """Structured log entry for real-time streaming."""

    LEVELS = {"INFO", "SCAN", "WARN", "CRIT", "OK", "ERROR", "DEBUG"}

    def __init__(
        self,
        level: str,
        message: str,
        scan_id: str,
        url: Optional[str] = None,
        response_time_ms: Optional[int] = None,
        progress: Optional[float] = None,
        extra: Optional[dict] = None,
    ):
        self.id = str(uuid4())[:8]
        self.level = level.upper() if level.upper() in self.LEVELS else "INFO"
        self.message = message
        self.scan_id = scan_id
        self.url = url
        self.response_time_ms = response_time_ms
        self.progress = progress  # 0.0 – 100.0
        self.extra = extra or {}
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": "log",
            "level": self.level,
            "message": self.message,
            "scan_id": self.scan_id,
            "url": self.url,
            "response_time_ms": self.response_time_ms,
            "progress": self.progress,
            "timestamp": self.timestamp,
            **self.extra,
        }


class WebSocketManager:
    """
    Manages WebSocket connections grouped by scan_id.
    Supports:
      - Per-scan rooms (clients watching a specific scan)
      - Org-level broadcasts (all clients in an org)
      - Message buffering (late joiners get recent history)
    """

    def __init__(self, history_limit: int = 500):
        # scan_id → set of WebSocket connections
        self._rooms: Dict[str, Set[WebSocket]] = defaultdict(set)
        # scan_id → recent log history (for late joiners)
        self._history: Dict[str, List[dict]] = defaultdict(list)
        self._history_limit = history_limit
        # org_id → set of WebSocket connections (dashboard broadcasts)
        self._org_rooms: Dict[str, Set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    # ── Connection management ─────────────────────────────────────────────────

    async def connect_scan(self, websocket: WebSocket, scan_id: str) -> None:
        """Connect a client to a scan room and replay recent history."""
        await websocket.accept()
        async with self._lock:
            self._rooms[scan_id].add(websocket)

        # Replay history for late joiners
        history = self._history.get(scan_id, [])
        if history:
            try:
                await websocket.send_json({"type": "history", "logs": history})
            except Exception:
                pass

        logger.info(f"WS client connected to scan room: {scan_id}")

    async def connect_org(self, websocket: WebSocket, org_id: str) -> None:
        """Connect a client to an org-level broadcast room."""
        await websocket.accept()
        async with self._lock:
            self._org_rooms[org_id].add(websocket)
        logger.info(f"WS client connected to org room: {org_id}")

    async def disconnect(self, websocket: WebSocket, scan_id: str) -> None:
        async with self._lock:
            self._rooms[scan_id].discard(websocket)
            if not self._rooms[scan_id]:
                del self._rooms[scan_id]

    async def disconnect_org(self, websocket: WebSocket, org_id: str) -> None:
        async with self._lock:
            self._org_rooms[org_id].discard(websocket)

    # ── Broadcasting ──────────────────────────────────────────────────────────

    async def emit_log(self, entry: ScanLogEntry) -> None:
        """Send a log entry to all clients watching a scan."""
        data = entry.to_dict()

        # Buffer in history
        hist = self._history[entry.scan_id]
        hist.append(data)
        if len(hist) > self._history_limit:
            hist.pop(0)

        await self._broadcast_room(entry.scan_id, data)

    async def emit_scan_event(self, scan_id: str, event_type: str, payload: dict) -> None:
        """Emit a structured event (progress update, finding detected, scan complete)."""
        message = {"type": event_type, "scan_id": scan_id, "timestamp": datetime.now(timezone.utc).isoformat(), **payload}
        await self._broadcast_room(scan_id, message)

    async def broadcast_org(self, org_id: str, message: dict) -> None:
        """Broadcast to all org dashboard clients."""
        dead = set()
        for ws in list(self._org_rooms.get(org_id, set())):
            try:
                await ws.send_json(message)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self._org_rooms[org_id].discard(ws)

    async def broadcast_all(self, message: dict) -> None:
        """Broadcast to every connected client (e.g., server shutdown)."""
        all_rooms = list(self._rooms.values()) + list(self._org_rooms.values())
        for room in all_rooms:
            for ws in list(room):
                try:
                    await ws.send_json(message)
                except Exception:
                    pass

    async def _broadcast_room(self, scan_id: str, data: dict) -> None:
        dead = set()
        for ws in list(self._rooms.get(scan_id, set())):
            try:
                await ws.send_json(data)
            except Exception:
                dead.add(ws)
        if dead:
            async with self._lock:
                self._rooms[scan_id] -= dead

    def clear_history(self, scan_id: str) -> None:
        self._history.pop(scan_id, None)

    def get_room_size(self, scan_id: str) -> int:
        return len(self._rooms.get(scan_id, set()))


# Singleton instance
websocket_manager = WebSocketManager()

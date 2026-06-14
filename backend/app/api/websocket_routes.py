"""
WebSocket Routes — Real-time scan log streaming and org-level broadcast
"""
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from app.core.websocket_manager import websocket_manager

router = APIRouter()
logger = logging.getLogger("vapt.ws")


@router.websocket("/scan/{scan_id}/logs")
async def scan_log_stream(
    websocket: WebSocket,
    scan_id: str,
    token: str = Query(default=None),
):
    """
    WebSocket endpoint for real-time scan log streaming.
    Connect to: ws://host/api/v1/ws/scan/{scan_id}/logs?token=<jwt>
    """
    # Validate token before accepting
    if token:
        try:
            from app.core.security import decode_token
            decode_token(token)
        except Exception:
            await websocket.close(code=4001)
            return
    
    await websocket_manager.connect_scan(websocket, scan_id)
    logger.info(f"WS connected: scan={scan_id}")
    
    try:
        while True:
            # Keep connection alive; client sends pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        await websocket_manager.disconnect(websocket, scan_id)
        logger.info(f"WS disconnected: scan={scan_id}")
    except Exception as e:
        logger.warning(f"WS error scan={scan_id}: {e}")
        await websocket_manager.disconnect(websocket, scan_id)


@router.websocket("/org/{org_id}/live")
async def org_live_stream(
    websocket: WebSocket,
    org_id: str,
    token: str = Query(default=None),
):
    """
    Org-level broadcast: scan status changes, new findings, alerts.
    """
    if token:
        try:
            from app.core.security import decode_token
            payload = decode_token(token)
            if payload.get("org_id") != org_id:
                await websocket.close(code=4003)
                return
        except Exception:
            await websocket.close(code=4001)
            return

    await websocket_manager.connect_org(websocket, org_id)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        await websocket_manager.disconnect_org(websocket, org_id)
    except Exception as e:
        await websocket_manager.disconnect_org(websocket, org_id)

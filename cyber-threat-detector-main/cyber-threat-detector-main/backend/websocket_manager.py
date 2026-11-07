"""
AEGIS High-Level Real-World Cyber Threat Detection System
Real-Time WebSocket Streaming & Client Subscription Hub
"""

import json
from typing import List, Set, Dict, Any
from fastapi import WebSocket

class WebSocketHub:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        print(f"[*] WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"[*] WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast JSON message to all subscribed SOC client dashboards."""
        if not self.active_connections:
            return

        payload = json.dumps(message)
        dead_sockets: List[WebSocket] = []

        for socket in list(self.active_connections):
            try:
                await socket.send_text(payload)
            except Exception:
                dead_sockets.append(socket)

        for dead in dead_sockets:
            if dead in self.active_connections:
                self.active_connections.remove(dead)

# Global singleton
ws_hub = WebSocketHub()

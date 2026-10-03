import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.app.services.traffic_simulator import traffic_simulator

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

@router.websocket("/ws/traffic-stream")
async def websocket_traffic_stream(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        delay = 0.8
        is_paused = False
        while True:
            # Check if any client message was sent to adjust speed or pause/resume
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=0.02)
                cmd = json.loads(data)
                if "speed" in cmd:
                    delay = max(0.1, float(cmd["speed"]))
                if "action" in cmd:
                    if cmd["action"] == "pause":
                        is_paused = True
                    elif cmd["action"] == "resume":
                        is_paused = False
                    elif cmd["action"] == "toggle":
                        is_paused = not is_paused
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

            if not is_paused:
                flow_event = traffic_simulator.get_next_flow()
                if flow_event:
                    await websocket.send_json({
                        "type": "FLOW_EVENT",
                        "data": flow_event
                    })

            await asyncio.sleep(delay if not is_paused else 0.15)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

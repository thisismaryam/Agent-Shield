from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
import asyncio
import json

from event_bridge import setup_event_bridge
from agentshield import run_all_scenarios


app = FastAPI(title="AgentShield")

run_lock = asyncio.Lock()


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():
    loop = asyncio.get_running_loop()
    setup_event_bridge(loop, broadcast_event)
    print("[SERVER] Event bridge connected")


# ============================================================
# CONNECTED WEBSOCKET CLIENTS
# ============================================================

connected_clients = set()


# ============================================================
# BROADCAST EVENT
# ============================================================

async def broadcast_event(event):
    if not connected_clients:
        return
    message = json.dumps(event)
    disconnected_clients = set()
    for websocket in connected_clients:
        try:
            await websocket.send_text(message)
        except Exception:
            disconnected_clients.add(websocket)
    for websocket in disconnected_clients:
        connected_clients.discard(websocket)


# ============================================================
# HOME PAGE
# ============================================================

@app.get("/")
async def home():
    return FileResponse("index.html")


# ============================================================
# RUN AGENTSHIELD (accepts model parameter)
# ============================================================

@app.post("/run")
async def run_agentshield(model: str = "openai/gpt-oss-120b"):
    if run_lock.locked():
        print("[SERVER] Run already in progress, skipping request.")
        return {"error": "Evaluation already in progress"}

    print(f"[SERVER] Starting AgentShield run with model: {model}")

    await broadcast_event({
        "event": "run.started",
        "scenario_id": "run",
        "data": {"model": model}
    })

    async with run_lock:
        result = await asyncio.to_thread(run_all_scenarios, model)
        return result


# ============================================================
# WEBSOCKET
# ============================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    print(f"[WEBSOCKET] Client connected ({len(connected_clients)} clients)")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.discard(websocket)
        print(
            f"[WEBSOCKET] Client disconnected ({len(connected_clients)} clients)")
    except Exception:
        connected_clients.discard(websocket)
        print("[WEBSOCKET] Connection error")

"""
AEGIS High-Level Real-World Cyber Threat Detection System
Master Backend Server (FastAPI + WebSockets + Real-Time Telemetry)
"""

import asyncio
import os
import sys
import time

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from contextlib import asynccontextmanager
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# Internal Modules
from backend.config import HOST, PORT, MONITOR_INTERVAL_SECONDS
from backend.network_monitor import network_monitor
from backend.threat_engine import threat_engine
from backend.scanner import network_scanner
from backend.active_defense import active_defense
from backend.attack_simulator import attack_simulator
from backend.websocket_manager import ws_hub

# Background monitor task handle
monitor_task: Optional[asyncio.Task] = None
start_time: float = time.time()

async def background_network_monitor_loop():
    """
    Continuous background loop sampling real network traffic and running threat detection.
    """
    print("[*] AEGIS Real-World Network Monitor background worker started.")
    while True:
        try:
            # 1. Capture snapshot of live network adapters, sockets, and bandwidth
            snapshot = network_monitor.capture_network_snapshot()

            # 2. Run threat detection and stateful IDS rules
            new_threats = threat_engine.analyze_network_snapshot(snapshot)

            # 3. Broadcast real-time telemetry over WebSockets
            ws_payload = {
                "type": "TELEMETRY_UPDATE",
                "timestamp": snapshot["timestamp"],
                "metrics": snapshot["metrics"],
                "new_threats": new_threats,
                "active_connections_sample": snapshot["active_connections"][:50],
                "quarantined_ips_count": len(active_defense.blocked_ips),
                "total_threats_count": threat_engine.threats_detected_count
            }
            await ws_hub.broadcast(ws_payload)

        except asyncio.CancelledError:
            print("[*] Network monitor worker cancelled.")
            break
        except Exception as e:
            print(f"[!] Error in network monitor loop: {e}")

        await asyncio.sleep(MONITOR_INTERVAL_SECONDS)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Launch background network monitoring
    global monitor_task
    monitor_task = asyncio.create_task(background_network_monitor_loop())
    yield
    # Shutdown
    if monitor_task:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass

app = FastAPI(
    title="AEGIS Enterprise Cyber Threat Intelligence SOC",
    description="Real-Time Network Telemetry, Live IDS/IPS, Process Correlation & AI Threat Engine",
    version="4.0.0",
    lifespan=lifespan
)

# Enable CORS for external dashboards or frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Pydantic Request Models
# -----------------------------------------------------------------------------
class SelectInterfaceRequest(BaseModel):
    interface_name: str

class FlowPredictionRequest(BaseModel):
    Source_IP: Optional[str] = "192.168.1.55"
    Dest_IP: Optional[str] = "185.220.101.5"
    Source_Port: Optional[int] = 49210
    Dest_Port: Optional[int] = 4444
    Protocol: Optional[str] = "TCP"
    Payload_Signature: Optional[str] = "REVERSE_TCP_METERPRETER_EXEC"
    Bytes: Optional[float] = 4096
    Duration: Optional[float] = 12.4

class PortScanRequest(BaseModel):
    target: str = "127.0.0.1"
    ports: Optional[List[int]] = None
    timeout: Optional[float] = 0.5

class BlockIPRequest(BaseModel):
    ip: str
    reason: Optional[str] = "Manual SOC Block"

class UnblockIPRequest(BaseModel):
    ip: str

class IsolateProcessRequest(BaseModel):
    pid: int
    reason: Optional[str] = "Malicious Network Socket Containment"

class AttackSimulationRequest(BaseModel):
    attack_type: str  # PORT_SCAN, C2_BEACON, SYN_FLOOD
    target_ip: Optional[str] = "127.0.0.1"
    port: Optional[int] = 8000

# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------
@app.get("/api/status")
async def get_system_status():
    uptime_sec = round(time.time() - start_time, 1)
    snapshot = network_monitor.capture_network_snapshot()
    return {
        "status": "ONLINE",
        "mode": "REAL_WORLD_NETWORK",
        "uptime_seconds": uptime_sec,
        "selected_interface": network_monitor.selected_interface or "All Active Adapters",
        "metrics": snapshot["metrics"],
        "threats_detected": threat_engine.threats_detected_count,
        "critical_threats": threat_engine.critical_threats_count,
        "quarantined_ips": len(active_defense.blocked_ips),
        "clients_connected": len(ws_hub.active_connections)
    }

@app.get("/api/network/interfaces")
async def get_interfaces():
    return {
        "interfaces": network_monitor.get_interfaces(),
        "selected": network_monitor.selected_interface
    }

@app.post("/api/network/interfaces/select")
async def select_interface(req: SelectInterfaceRequest):
    success = network_monitor.select_interface(req.interface_name)
    if not success:
        raise HTTPException(status_code=404, detail="Interface not found")
    return {"status": "SUCCESS", "selected_interface": req.interface_name}

@app.get("/api/network/connections")
async def get_active_connections(limit: int = Query(100, ge=1, le=500)):
    snapshot = network_monitor.capture_network_snapshot()
    conns = snapshot.get("active_connections", [])
    return {
        "total_active": len(conns),
        "connections": conns[:limit],
        "metrics": snapshot["metrics"]
    }

@app.get("/api/threats/live")
async def get_live_threats(limit: int = Query(50, ge=1, le=200)):
    return {
        "total_detected": threat_engine.threats_detected_count,
        "critical_count": threat_engine.critical_threats_count,
        "incidents": threat_engine.incidents_log[:limit]
    }

@app.post("/api/ai/predict")
async def predict_threat(req: FlowPredictionRequest):
    result = threat_engine.predict_flow_ml(req.model_dump())
    return result

@app.post("/api/scanner/start")
async def start_port_scan(req: PortScanRequest, background_tasks: BackgroundTasks):
    def _progress_callback(data: Dict[str, Any]):
        asyncio.create_task(ws_hub.broadcast({
            "type": "PORT_SCAN_PROGRESS",
            "data": data
        }))

    # Run scan
    results = await network_scanner.scan_target(
        target_host=req.target,
        ports=req.ports,
        timeout=req.timeout or 0.5,
        progress_cb=_progress_callback
    )
    return results

@app.post("/api/defense/block-ip")
async def block_ip(req: BlockIPRequest):
    result = active_defense.block_ip(req.ip, req.reason or "SOC Manual Block")
    # Broadcast alert
    await ws_hub.broadcast({
        "type": "DEFENSE_ACTION",
        "action": "BLOCK_IP",
        "data": result
    })
    return result

@app.post("/api/defense/unblock-ip")
async def unblock_ip(req: UnblockIPRequest):
    result = active_defense.unblock_ip(req.ip)
    await ws_hub.broadcast({
        "type": "DEFENSE_ACTION",
        "action": "UNBLOCK_IP",
        "data": result
    })
    return result

@app.post("/api/defense/isolate-process")
async def isolate_process(req: IsolateProcessRequest):
    result = active_defense.isolate_process(req.pid, req.reason or "Malicious Socket Containment")
    await ws_hub.broadcast({
        "type": "DEFENSE_ACTION",
        "action": "KILL_PROCESS",
        "data": result
    })
    return result

@app.get("/api/defense/status")
async def get_defense_status():
    return active_defense.get_status()

@app.get("/api/simulation/health-check")
@app.post("/api/simulation/health-check")
async def check_website_health(request: Request, target_ip: Optional[str] = "127.0.0.1", port: Optional[int] = None):
    actual_port = port or request.url.port or PORT
    health = attack_simulator.check_system_health(target_ip, actual_port)
    health["metrics"] = network_monitor.capture_network_snapshot()["metrics"]
    health["threat_engine_status"] = "ACTIVE"
    health["ai_classifier_ready"] = True
    return health

@app.post("/api/simulation/attack")
async def run_attack_simulation(req: AttackSimulationRequest):
    atype = req.attack_type.upper()
    target = req.target_ip or "127.0.0.1"
    port = req.port or 8000

    if atype == "PORT_SCAN":
        res = attack_simulator.simulate_port_scan(target)
    elif atype == "C2_BEACON":
        res = attack_simulator.simulate_c2_beacon(target, port)
    elif atype == "SYN_FLOOD":
        res = attack_simulator.simulate_syn_flood(target, port)
    elif atype in ["SQLI", "SQL_INJECTION"]:
        res = attack_simulator.simulate_sqli_probe(target, port)
    elif atype in ["XSS", "CROSS_SITE_SCRIPTING"]:
        res = attack_simulator.simulate_xss_probe(target, port)
    elif atype == "BRUTE_FORCE":
        res = attack_simulator.simulate_brute_force(target, port)
    else:
        raise HTTPException(status_code=400, detail="Invalid attack type. Options: PORT_SCAN, C2_BEACON, SYN_FLOOD, SQLI, XSS, BRUTE_FORCE")

    # Broadcast simulation event to active SOC telemetry clients
    await ws_hub.broadcast({
        "type": "ATTACK_SIMULATION_EVENT",
        "data": res
    })

    return res

@app.get("/api/export/logs")
async def export_logs():
    return JSONResponse(
        content={
            "export_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_incidents": len(threat_engine.incidents_log),
            "incidents": threat_engine.incidents_log
        },
        headers={"Content-Disposition": "attachment; filename=aegis_threat_audit_logs.json"}
    )

# -----------------------------------------------------------------------------
# WebSocket Live Stream Endpoint
# -----------------------------------------------------------------------------
@app.websocket("/ws/live-feed")
async def websocket_live_feed(websocket: WebSocket):
    await ws_hub.connect(websocket)
    try:
        # Send initial snapshot immediately
        snapshot = network_monitor.capture_network_snapshot()
        await websocket.send_json({
            "type": "INITIAL_HANDSHAKE",
            "message": "Connected to AEGIS Real-Time Network Monitor",
            "metrics": snapshot["metrics"],
            "recent_incidents": threat_engine.incidents_log[:15],
            "quarantined_ips": list(active_defense.blocked_ips.values())
        })

        while True:
            # Handle inbound client commands
            data = await websocket.receive_json()
            cmd = data.get("action")
            if cmd == "PING":
                await websocket.send_json({"type": "PONG", "timestamp": time.time()})
            elif cmd == "TRIGGER_ATTACK":
                attack_type = data.get("attack_type", "PORT_SCAN")
                target = data.get("target", "127.0.0.1")
                if attack_type == "PORT_SCAN":
                    res = attack_simulator.simulate_port_scan(target)
                elif attack_type == "C2_BEACON":
                    res = attack_simulator.simulate_c2_beacon(target)
                elif attack_type == "SYN_FLOOD":
                    res = attack_simulator.simulate_syn_flood(target)
                else:
                    res = {"error": "Unknown attack type"}
                await websocket.send_json({"type": "ATTACK_RESULT", "data": res})

    except WebSocketDisconnect:
        ws_hub.disconnect(websocket)
    except Exception as e:
        print(f"[!] WebSocket error: {e}")
        ws_hub.disconnect(websocket)

# -----------------------------------------------------------------------------
# Static Web App Serving
# -----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Mount CSS and JS directories
if os.path.exists(os.path.join(BASE_DIR, "css")):
    app.mount("/css", StaticFiles(directory=os.path.join(BASE_DIR, "css")), name="css")
if os.path.exists(os.path.join(BASE_DIR, "js")):
    app.mount("/js", StaticFiles(directory=os.path.join(BASE_DIR, "js")), name="js")

@app.head("/")
@app.head("/index.html")
@app.get("/")
@app.get("/index.html")
async def serve_index():
    index_path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "AEGIS Cyber Threat Detection Backend Running. index.html not found."}

@app.get("/login")
@app.get("/login.html")
async def serve_login():
    login_path = os.path.join(BASE_DIR, "login.html")
    if os.path.exists(login_path):
        return FileResponse(login_path)
    return {"message": "login.html not found."}

def run_server():
    import uvicorn
    print(f"\n==========================================================================")
    print(f"  AEGIS CYBER THREAT DETECTOR - REAL-WORLD NETWORK MONITORING ENGINE      ")
    print(f"  Live SOC URL:  http://localhost:{PORT}                                 ")
    print(f"  WebSocket Feed: ws://localhost:{PORT}/ws/live-feed                      ")
    print(f"  REST API Docs: http://localhost:{PORT}/docs                            ")
    print(f"==========================================================================\n")
    uvicorn.run("backend.main:app", host=HOST, port=PORT, reload=False, log_level="info")

if __name__ == "__main__":
    run_server()

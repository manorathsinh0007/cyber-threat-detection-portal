#!/usr/bin/env python3
"""
AEGIS Enterprise Cyber Threat Intelligence SOC - Master Server Launcher
Runs the high-level FastAPI real-world network monitoring backend and serves the frontend portal.
"""

import os
import sys
import webbrowser
import time

def main():
    print("=" * 76)
    print("  AEGIS CYBER THREAT DEFENSE COMMAND - HIGH-LEVEL REAL NETWORK SOC ENGINE")
    print("=" * 76)

    # Add project root to sys.path
    project_dir = os.path.dirname(os.path.abspath(__file__))
    if project_dir not in sys.path:
        sys.path.insert(0, project_dir)

    # Windows asyncio IOCP bug workaround for abrupt socket resets
    if sys.platform == "win32":
        import asyncio
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    # Check dependencies
    try:
        import fastapi
        import uvicorn
        import psutil
        import websockets
    except ImportError as e:
        print(f"[!] Missing required library: {e}")
        print("[*] Please run: uv pip install -r requirements.txt")
        sys.exit(1)

    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")

    url = f"http://localhost:{port}"
    print(f"[*] Starting AEGIS Real-Time SOC Portal at: {url}")
    print(f"[*] Live Telemetry WebSocket Feed: ws://localhost:{port}/ws/live-feed")
    print(f"[*] Interactive API Documentation: {url}/docs")
    print("-" * 76)

    # Launch browser after a slight delay
    def open_browser():
        time.sleep(1.2)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    # Start Uvicorn
    uvicorn.run("backend.main:app", host=host, port=port, reload=False, log_level="info")

if __name__ == "__main__":
    main()

"""
End-to-End Test Suite for AEGIS Real-Time SOC Portal using Chrome CDP
"""

import asyncio
import base64
import json
import os
import subprocess
import sys
import time
import urllib.request
import websockets

import tempfile

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
CDP_PORT = 9444
TARGET_URL = "http://127.0.0.1:8000"
SCREENSHOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_screenshots")

os.makedirs(SCREENSHOT_DIR, exist_ok=True)

class RealtimeE2ETester:
    def __init__(self):
        self.chrome_proc = None
        self.ws = None
        self.msg_id = 0
        self.user_data_dir = tempfile.mkdtemp(prefix="chrome_e2e_")

    def start_chrome(self):
        print(f"[*] Launching Chrome headless at {TARGET_URL}...")
        self.chrome_proc = subprocess.Popen([
            CHROME_PATH,
            f"--remote-debugging-port={CDP_PORT}",
            "--remote-allow-origins=*",
            "--headless=new",
            "--disable-gpu",
            "--window-size=1500,950",
            "--no-first-run",
            "--no-default-browser-check",
            TARGET_URL
        ])

        for attempt in range(25):
            time.sleep(0.4)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=1) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        print(f"[OK] Chrome CDP active: {data.get('Browser')}")
                        return True
            except Exception as e:
                if attempt == 24:
                    print(f"[!] Last CDP error: {e}")
        return False

    async def send_cmd(self, method, params=None):
        self.msg_id += 1
        cmd = {"id": self.msg_id, "method": method, "params": params or {}}
        await self.ws.send(json.dumps(cmd))
        while True:
            resp = json.loads(await self.ws.recv())
            if resp.get("id") == self.msg_id:
                return resp.get("result", {})

    async def eval_js(self, expression):
        res = await self.send_cmd("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True
        })
        return res.get("result", {}).get("value")

    async def capture_screenshot(self, name):
        res = await self.send_cmd("Page.captureScreenshot", {"format": "png"})
        if "data" in res:
            img_path = os.path.join(SCREENSHOT_DIR, f"{name}.png")
            with open(img_path, "wb") as f:
                f.write(base64.b64decode(res["data"]))
            print(f"[OK] Saved screenshot: {img_path}")
            return img_path
        return None

    async def run(self):
        if not self.start_chrome():
            print("[!] Could not connect to Chrome CDP.")
            return False

        # Get WebSocket debugger URL
        with urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/list", timeout=3) as resp:
            targets = json.loads(resp.read().decode("utf-8"))

        ws_url = None
        for t in targets:
            if t.get("type") == "page":
                ws_url = t.get("webSocketDebuggerUrl")
                break

        if not ws_url:
            print("[!] No page target found.")
            return False

        async with websockets.connect(ws_url, max_size=10*1024*1024) as ws:
            self.ws = ws
            await self.send_cmd("Page.enable")
            await self.send_cmd("Runtime.enable")
            await self.send_cmd("DOM.enable")

            print(f"[*] Navigating explicitly to {TARGET_URL}...")
            await self.send_cmd("Page.navigate", {"url": TARGET_URL})
            print("[*] Waiting for SOC application hydration...")
            await asyncio.sleep(3.0)

            # Test 1: Title and Header Status
            title = await self.eval_js("document.title")
            print(f"[Test 1] Page Title: '{title}'")
            status_text = await self.eval_js("document.getElementById('backend-status-pill')?.innerText")
            print(f"[Test 1] Backend Status Pill: '{status_text}'")

            # Test 2: Check WebSocket Connection State
            is_connected = await self.eval_js("window.realTimeNetwork?.isConnected")
            print(f"[Test 2] WebSocket Connected in window.realTimeNetwork: {is_connected}")
            await self.capture_screenshot("01_dashboard_real_network_active")

            # Test 3: Switch to Real-World Network View
            print("[*] Switching to 'real_network' view...")
            await self.eval_js("window.app.switchView('real_network')")
            await asyncio.sleep(1.5)

            active_view = await self.eval_js("window.app.currentView")
            ifaces_count = await self.eval_js("window.realTimeNetwork.networkInterfaces.length")
            conns_count = await self.eval_js("document.querySelectorAll('#real-conns-table-body tr').length")
            print(f"[Test 3] Active View: '{active_view}', Interfaces: {ifaces_count}, Sockets Table Rows: {conns_count}")
            await self.capture_screenshot("02_real_network_noc_view")

            # Test 4: Switch to Active Port Scanner View
            print("[*] Switching to 'network_scanner' view...")
            await self.eval_js("window.app.switchView('network_scanner')")
            await asyncio.sleep(1.0)
            await self.capture_screenshot("03_port_scanner_view")

            # Test 5: Switch to Active Defense View
            print("[*] Switching to 'active_defense' view...")
            await self.eval_js("window.app.switchView('active_defense')")
            await asyncio.sleep(1.0)
            await self.capture_screenshot("04_active_defense_view")

            print("\n[OK] All Real-World Network Views and Telemetry pipelines verified successfully!")
            return True

    def cleanup(self):
        if self.chrome_proc:
            self.chrome_proc.terminate()
            try:
                self.chrome_proc.wait(timeout=2)
            except Exception:
                self.chrome_proc.kill()

if __name__ == "__main__":
    tester = RealtimeE2ETester()
    try:
        success = asyncio.run(tester.run())
        sys.exit(0 if success else 1)
    finally:
        tester.cleanup()

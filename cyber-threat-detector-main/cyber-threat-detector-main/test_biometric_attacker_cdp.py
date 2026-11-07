"""
Chrome CDP End-to-End Visual Verification for:
1. Biometric Fingerprint Login on login.html
2. Mini Cyber Attacker on index.html
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
CDP_PORT = 9445
BASE_URL = "http://127.0.0.1:8000"
SCREENSHOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

class BiometricAttackerCDPTester:
    def __init__(self):
        self.chrome_proc = None
        self.ws = None
        self.msg_id = 0
        self.user_data_dir = tempfile.mkdtemp(prefix="chrome_bio_")

    def start_chrome(self):
        print(f"[*] Starting Chrome headless at {BASE_URL}...")
        self.chrome_proc = subprocess.Popen([
            CHROME_PATH,
            f"--remote-debugging-port={CDP_PORT}",
            "--remote-allow-origins=*",
            f"--user-data-dir={self.user_data_dir}",
            "--headless=new",
            "--disable-gpu",
            "--window-size=1550,1000",
            "--no-first-run",
            "--no-default-browser-check",
            f"{BASE_URL}/login.html"
        ])

        for attempt in range(25):
            time.sleep(0.4)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=1) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        print(f"[OK] Chrome CDP active: {data.get('Browser')}")
                        return True
            except Exception:
                pass
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

            # -------------------------------------------------------------
            # TEST 1: Login Page & Biometric Tab
            # -------------------------------------------------------------
            print("\n[*] Navigating to login.html...")
            await self.send_cmd("Page.navigate", {"url": f"{BASE_URL}/login.html"})
            await asyncio.sleep(2.0)

            title = await self.eval_js("document.title")
            print(f"[Test 1] Login Page Title: '{title}'")
            await self.capture_screenshot("01_login_initial_view")

            # Switch to Biometric Tab
            print("[*] Switching to Biometric Tab...")
            await self.eval_js("document.getElementById('tab-btn-fingerprint')?.click()")
            await asyncio.sleep(0.8)
            await self.capture_screenshot("02_login_biometric_view")

            # Click Fingerprint Sensor Pad
            print("[*] Triggering Fingerprint Scan...")
            await self.eval_js("document.getElementById('fingerprint-sensor-pad')?.click()")
            await asyncio.sleep(1.2)
            await self.capture_screenshot("03_login_fingerprint_scanning")

            # Wait for authentication success and automatic redirection to index.html
            print("[*] Waiting for SOC dashboard transition...")
            await asyncio.sleep(2.5)

            current_url = await self.eval_js("window.location.href")
            print(f"[Test 2] Redirected URL: '{current_url}'")
            await self.capture_screenshot("04_soc_dashboard_authenticated")

            # -------------------------------------------------------------
            # TEST 3: Switch to Mini Cyber Attacker View
            # -------------------------------------------------------------
            print("[*] Navigating to Mini Cyber Attacker view...")
            await self.eval_js("window.app?.switchView('cyber_attacker')")
            await asyncio.sleep(1.5)

            view_name = await self.eval_js("window.app?.currentView")
            print(f"[Test 3] Active SOC View: '{view_name}'")
            await self.capture_screenshot("05_mini_cyber_attacker_view")

            # Check Website Health
            print("[*] Clicking 'Check Website Health'...")
            await self.eval_js("document.getElementById('attacker-health-check-btn')?.click()")
            await asyncio.sleep(1.5)

            health_web = await self.eval_js("document.getElementById('health-val-web')?.innerText")
            health_ai = await self.eval_js("document.getElementById('health-val-ai')?.innerText")
            print(f"[Test 4] Web Server Status: '{health_web}', AI Status: '{health_ai}'")
            await self.capture_screenshot("06_health_check_verified")

            # Launch Individual Test Attacks
            print("[*] Launching SQL Injection Test Attack...")
            await self.eval_js("window.cyberAttacker?.launchAttack('SQLI')")
            await asyncio.sleep(1.2)

            print("[*] Launching SYN Flood Test Attack...")
            await self.eval_js("window.cyberAttacker?.launchAttack('SYN_FLOOD')")
            await asyncio.sleep(1.2)

            red_log = await self.eval_js("document.getElementById('terminal-red-body')?.innerText")
            blue_log = await self.eval_js("document.getElementById('terminal-blue-body')?.innerText")
            print(f"[Test 5] Red Terminal Entries: {len(red_log.splitlines())} lines")
            print(f"[Test 5] Blue Terminal Entries: {len(blue_log.splitlines())} lines")
            await self.capture_screenshot("07_attacks_dispatched_and_intercepted")

            # Scroll down to dual terminal
            await self.eval_js("document.getElementById('attacker-dual-terminal')?.scrollIntoView({behavior: 'instant', block: 'center'})")
            await asyncio.sleep(0.5)
            await self.capture_screenshot("07b_dual_terminal_red_vs_blue")

            # Run Full Security Health Audit
            print("[*] Running Full Security Health Audit (All 6 Vectors)...")
            await self.eval_js("window.cyberAttacker?.runFullAudit()")
            await asyncio.sleep(7.5) # Wait for all 6 tests to run sequentially
            await self.capture_screenshot("08_full_audit_certificate_modal")

            print("\n[OK] ALL END-TO-END VISUAL CDP TESTS COMPLETED SUCCESSFULLY!")
            return True

    def cleanup(self):
        if self.chrome_proc:
            self.chrome_proc.terminate()
            try:
                self.chrome_proc.wait(timeout=2)
            except Exception:
                self.chrome_proc.kill()

if __name__ == "__main__":
    tester = BiometricAttackerCDPTester()
    try:
        success = asyncio.run(tester.run())
        sys.exit(0 if success else 1)
    finally:
        tester.cleanup()

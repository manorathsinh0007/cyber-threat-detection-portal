import asyncio
import json
import subprocess
import time
import urllib.request
import websockets

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
PORT = 9222
USER_DATA_DIR = r"C:\Temp\chrome_diag"

async def test():
    proc = subprocess.Popen([
        CHROME_PATH,
        f"--remote-debugging-port={PORT}",
        f"--user-data-dir={USER_DATA_DIR}",
        "--headless=new",
        "--disable-gpu",
        "http://localhost:3000"
    ])
    time.sleep(1.5)
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/list") as resp:
        targets = json.loads(resp.read().decode("utf-8"))
    
    ws_url = targets[0]["webSocketDebuggerUrl"]
    ws = await websockets.connect(ws_url)
    
    msg_id = 1
    async def eval_js(expr):
        nonlocal msg_id
        msg_id += 1
        await ws.send(json.dumps({"id": msg_id, "method": "Runtime.evaluate", "params": {"expression": expr, "returnByValue": True, "awaitPromise": True}}))
        while True:
            r = json.loads(await ws.recv())
            if r.get("id") == msg_id:
                return r

    time.sleep(2.0)
    await asyncio.sleep(2.0)
    await eval_js("window.app.switchView('detection_sandbox')")
    res = await eval_js("""
        (() => {
            document.getElementById('sandbox-payload').value = 'UNION SELECT username, password_hash FROM admin--';
            document.getElementById('sandbox-dest-port').value = '3306';
            document.getElementById('sandbox-syn-count').value = '2';
            document.getElementById('sandbox-fwd-pkts').value = '14';
            document.getElementById('sandbox-duration').value = '120';
            document.getElementById('sandbox-protocol').value = 'TCP';
            window.app.runSandboxPrediction();
            return {
                pred: document.getElementById('sandbox-result-prediction').textContent,
                conf: document.getElementById('sandbox-result-confidence').textContent,
                model: document.getElementById('sandbox-result-model').textContent,
                cvss: document.getElementById('sandbox-result-cvss').textContent
            };
        })()
    """)
    print("DIAGNOSTIC RESULT:", res)
    proc.terminate()

asyncio.run(test())

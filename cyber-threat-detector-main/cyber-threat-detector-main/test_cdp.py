import json
import subprocess
import time
import urllib.request
import urllib.parse
import os
import sys

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
PORT = 9222
USER_DATA_DIR = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "chrome_cdp_profile")

def main():
    print(f"[*] Starting Chrome in remote debugging mode on port {PORT}...")
    chrome_proc = subprocess.Popen([
        CHROME_PATH,
        f"--remote-debugging-port={PORT}",
        f"--user-data-dir={USER_DATA_DIR}",
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "http://localhost:3000"
    ])
    
    # Wait for Chrome CDP endpoint
    version_info = None
    for attempt in range(20):
        time.sleep(0.5)
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/version", timeout=2) as resp:
                if resp.status == 200:
                    version_info = json.loads(resp.read().decode("utf-8"))
                    print(f"[✓] Connected to Chrome CDP: {version_info.get('Browser')}")
                    break
        except Exception as e:
            pass

    if not version_info:
        print("[!] Failed to connect to Chrome CDP.")
        chrome_proc.terminate()
        return

    # List targets
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/list", timeout=2) as resp:
            targets = json.loads(resp.read().decode("utf-8"))
            print(f"[✓] Open targets: {len(targets)}")
            for t in targets:
                print(f" - {t.get('title')} ({t.get('url')}) WS: {t.get('webSocketDebuggerUrl')}")
    except Exception as e:
        print(f"[!] Error fetching targets: {e}")

    chrome_proc.terminate()

if __name__ == "__main__":
    main()

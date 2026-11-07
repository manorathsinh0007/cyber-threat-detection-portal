"""
Automated Verification Suite for AEGIS Biometric Fingerprint & Mini Cyber Attacker
Tests all backend simulation endpoints, static asset serving, and attack payloads.
"""

import sys
import os
import time
import threading
import requests
import uvicorn

project_dir = os.path.dirname(os.path.abspath(__file__))
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

def test_suite():
    print("\n" + "=" * 70)
    print("  AEGIS VERIFICATION SUITE: BIOMETRIC LOGIN & MINI CYBER ATTACKER")
    print("=" * 70)

    # Launch server via uvicorn.Server in a daemon thread
    server = uvicorn.Server(uvicorn.Config("backend.main:app", host="127.0.0.1", port=8088, log_level="warning"))
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    base = "http://127.0.0.1:8088"
    passed = 0
    total = 0

    # Wait for server to boot
    for i in range(25):
        try:
            r = requests.get(f"{base}/api/status", timeout=0.8)
            if r.status_code == 200:
                print(f" [OK] Server operational on port 8088 after {i * 0.4:.1f}s\n")
                break
        except Exception as e:
            if i % 5 == 0:
                print(f" [*] Waiting for server... ({e})")
            time.sleep(0.4)
    else:
        print(" [!] Server failed to boot.")
        return False

    def check(name, fn):
        nonlocal passed, total
        total += 1
        try:
            fn()
            print(f" [PASS] {name}")
            passed += 1
        except Exception as e:
            print(f" [FAIL] {name}: {e}")

    # 1. Test Static Asset Serving
    def test_login_page():
        res = requests.get(f"{base}/login.html", timeout=3)
        assert res.status_code == 200
        content = res.text
        assert "Biometric" in content, "Biometric tab missing in login.html"
        assert "fingerprint-sensor-pad" in content, "Fingerprint sensor pad missing in login.html"
        assert "biometric-auth.js" in content, "biometric-auth.js missing in login.html"
        assert "biometric-attacker.css" in content, "biometric-attacker.css missing in login.html"
    check("Login Page & Fingerprint Elements Served", test_login_page)

    def test_index_page():
        res = requests.get(f"{base}/", timeout=3)
        assert res.status_code == 200
        content = res.text
        assert "Mini Cyber Attacker" in content, "Mini Cyber Attacker nav missing in index.html"
        assert "view-cyber_attacker" in content, "view-cyber_attacker section missing in index.html"
        assert "cyber-attacker.js" in content, "cyber-attacker.js script missing in index.html"
        assert "btn-quick-attacker" in content, "Quick attacker button missing in index.html"
    check("Index Page & Mini Cyber Attacker Section Served", test_index_page)

    def test_assets():
        for asset in ["/css/biometric-attacker.css", "/js/biometric-auth.js", "/js/cyber-attacker.js"]:
            res = requests.get(f"{base}{asset}", timeout=3)
            assert res.status_code == 200, f"Failed to serve {asset}: {res.status_code}"
    check("Biometric & Attacker CSS/JS Assets Accessible", test_assets)

    # 2. Test Simulation Health Check
    def test_health_check():
        res = requests.get(f"{base}/api/simulation/health-check", timeout=3)
        assert res.status_code == 200
        data = res.json()
        assert "health_status" in data
        assert data["health_status"] == "OPERATIONAL"
        assert data["ai_classifier_ready"] is True
    check("GET /api/simulation/health-check", test_health_check)

    # 3. Test Attack Simulations
    attack_types = ["PORT_SCAN", "C2_BEACON", "SYN_FLOOD", "SQLI", "XSS", "BRUTE_FORCE"]
    for atype in attack_types:
        def test_attack(t=atype):
            res = requests.post(f"{base}/api/simulation/attack", json={"attack_type": t, "target_ip": "127.0.0.1", "port": 8088}, timeout=4)
            assert res.status_code == 200, f"Error {res.status_code}: {res.text}"
            res_data = res.json()
            assert "attack_type" in res_data
            assert "expected_detection" in res_data
        check(f"POST /api/simulation/attack [{atype}]", test_attack)

    print("\n" + "-" * 70)
    print(f"  RESULTS: {passed}/{total} TESTS PASSED ({(passed/total)*100:.1f}%)")
    print("-" * 70 + "\n")
    return passed == total

if __name__ == "__main__":
    success = test_suite()
    sys.exit(0 if success else 1)

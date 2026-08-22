"""
Vulnerable frontend for the ShadowKube-style weather test app (paper Fig. 6).

Workflow: Frontend receives user params -> calls Backend -> Backend fetches API
key from Key Store -> calls external weather API -> returns result.

DELIBERATE VULNERABILITY (mirrors the paper's design): the `city` query param
is passed unsanitized into a shell command (simulating a legacy "ping the city's
weather station" health check some devs bolt onto services like this). This is
a classic OS command injection -> the attack-sim scripts in ../../attack-sim
exploit exactly this.

DO NOT deploy this outside an isolated lab network.
"""
import os
import subprocess
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
BACKEND_URL = os.environ.get("BACKEND_URL", "http://backend:8000")


@app.route("/weather")
def weather():
    city = request.args.get("city", "London")

    # --- INJECTED VULNERABILITY: unsanitized shell-out (CWE-78) ---
    # A legacy "reachability check" that never should have used shell=True.
    check_cmd = f"ping -c 1 -W 1 {city} > /dev/null 2>&1; echo done"
    subprocess.run(check_cmd, shell=True)
    # ----------------------------------------------------------------

    try:
        resp = requests.get(f"{BACKEND_URL}/query", params={"city": city}, timeout=5)
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

"""
Key Store for the weather test app. Holds a mock "sensitive" API key that
represents the kind of credential an attacker pivoting through the frontend
vuln would want to steal (mirrors the paper's "steal API key" attack behavior
in Table 5).
"""
import os
from flask import Flask, jsonify

app = Flask(__name__)
API_KEY = os.environ.get("WEATHER_API_KEY", "sk-lab-DO-NOT-USE-IN-PROD-1234567890")


@app.route("/apikey")
def apikey():
    return jsonify({"api_key": API_KEY})


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)

"""
Backend for the weather test app. Fetches the API key from the Key Store
service, then (mock) queries an "external weather API". Kept intentionally
simple -- the interesting attack surface is the frontend and the cluster
misconfigs, not this service.
"""
import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
KEYSTORE_URL = os.environ.get("KEYSTORE_URL", "http://keystore:9000")


@app.route("/query")
def query():
    city = request.args.get("city", "London")

    key_resp = requests.get(f"{KEYSTORE_URL}/apikey", timeout=5)
    api_key = key_resp.json().get("api_key")

    # Mock "external service" call -- no real internet dependency needed for the lab.
    fake_weather = {"city": city, "temp_c": 21, "condition": "cloudy", "used_key": api_key[:6] + "..."}
    return jsonify(fake_weather)


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

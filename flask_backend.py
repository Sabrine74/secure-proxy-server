"""Flask demo backend — BL3-01. Écoute sur :5000."""
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route("/")
def home():
    return jsonify(service="secure-proxy-backend", status="ok")

@app.route("/api/data")
def data():
    return jsonify(data=[1, 2, 3], user=request.headers.get("X-Authenticated-User", "n/a"))

@app.route("/api/sensors")
def sensors():
    return jsonify(sensors=["temp-01", "humidity-02"])

@app.route("/api/admin")
def admin():
    return jsonify(admin_panel=True)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)

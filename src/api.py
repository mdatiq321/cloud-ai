from flask import Flask, jsonify, request
from datetime import datetime
from flask_cors import CORS
from ml_model import predict_risk
from live_logs import generate_log

import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import boto3

app = Flask(__name__)
CORS(app)

# ---------------- HOME ----------------
@app.route("/")
def home():
    return "Cloud Security API Running"

# ---------------- LIVE LOGS ----------------
@app.route("/logs")
def get_logs():
    log = generate_log()
    return jsonify(log)

# ---------------- SIGNUP ----------------
from datetime import datetime

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True)

    username = data.get("username")
    password = generate_password_hash(data.get("password"))
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)",
            (username, password, created_at)
        )
        conn.commit()
        return jsonify({"message": "User created"})
    except:
        return jsonify({"error": "User already exists"})
    finally:
        conn.close()

@app.route("/users", methods=["GET"])
def get_users():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, created_at FROM users")
    users = cursor.fetchall()

    conn.close()

    result = []
    for user in users:
        result.append({
            "id": user[0],
            "username": user[1],
            "created_at": user[2]
        })

    return jsonify(result)
# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)

    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    user = cursor.fetchone()

    conn.close()

    # ❌ USER NOT FOUND
    if not user:
        return jsonify({"error": "Account not created"})

    # ❌ WRONG PASSWORD
    if not check_password_hash(user[0], password):
        return jsonify({"error": "Incorrect password"})

    # ✅ SUCCESS
    return jsonify({"message": "Login successful"})

# ---------------- RISK LOGIC ----------------
def calculate_risk(event_name, time_str):
    # ML prediction
    ml_risk = predict_risk(event_name, time_str)

    # optional rule boost
    if "Delete" in event_name or "Stop" in event_name:
        return "CRITICAL"
    elif "Login" in event_name or "Console" in event_name:
        return "HIGH"
    else:
        return ml_risk

# ---------------- AWS ANALYZE ----------------
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)

    access_key = data.get("access_key") or data.get("aws_access_key")
    secret_key = data.get("secret_key") or data.get("aws_secret_key")

    if not access_key or not secret_key:
        return jsonify({"error": "Missing AWS credentials"})

    try:
        client = boto3.client(
            "cloudtrail",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name="ap-south-1"
        )

        response = client.lookup_events(MaxResults=10)

        results = []

        for event in response["Events"]:
            event_name = event.get("EventName", "Unknown")

            log = {
                "event": event_name,
                "user": event.get("Username", "N/A"),
                "time": str(event.get("EventTime")),
                "risk": calculate_risk(event_name)
            }

            results.append(log)

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)})
    
@app.route("/scan-file", methods=["POST"])
def scan_file():
    file = request.files.get("file")

    if not file:
        return jsonify({"error": "No file uploaded"})

    content = file.read().decode(errors="ignore").lower()

    # simple detection
    suspicious_keywords = ["http", "https", "login", "password", "verify", "bank", "otp"]
    
    risk = "SAFE"
    found = []

    for word in suspicious_keywords:
        if word in content:
            risk = "MALICIOUS"
            found.append(word)

    return jsonify({
        "risk": risk,
        "found_keywords": found
    })
    

# ---------------- RUN ----------------
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
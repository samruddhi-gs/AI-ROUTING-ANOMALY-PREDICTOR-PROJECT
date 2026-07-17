import os
import pickle
import hashlib
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

# ==============================
# APP INITIALIZATION
# ==============================

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ==============================
# PROJECT PATHS
# ==============================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")

# ==============================
# STATIC PAGE ROUTE
# ==============================

@app.route("/reset-password.html")
def reset_page():
    return send_from_directory(FRONTEND_DIR, "reset-password.html")

# ==============================
# EMAIL CONFIGURATION
# ==============================

app.config.update(
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME="aiguardpro@gmail.com",
    MAIL_PASSWORD="xrnfyiypmcjsnapf",
    MAIL_DEFAULT_SENDER="aiguardpro@gmail.com"
)

mail = Mail(app)

# ==============================
# DATABASE CONFIG
# ==============================

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
    BASE_DIR, "network.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ==============================
# LOAD ML MODEL
# ==============================

model_path = os.path.join(BASE_DIR, "anomaly_model.pkl")
model = None

if os.path.exists(model_path):
    try:
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        print("✅ ML Model Loaded")
    except Exception as e:
        print("Model Load Error:", e)

# ==============================
# DATABASE MODELS
# ==============================

class User(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(120))
    email      = db.Column(db.String(120), unique=True, nullable=False)
    password   = db.Column(db.String(200))
    role       = db.Column(db.String(20), default="user")
    created_at = db.Column(db.String(50))


class ScanResult(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_email  = db.Column(db.String(120))
    timestamp   = db.Column(db.String(50))
    origin_node = db.Column(db.String(50))
    target_asn  = db.Column(db.String(50))
    risk_score  = db.Column(db.Integer)
    verdict     = db.Column(db.String(50))
    file_hash   = db.Column(db.String(100))

# ==============================
# DATABASE CREATE
# ==============================

with app.app_context():
    db.create_all()

print("✅ Database Ready")

# ==============================
# EMAIL ALERT FUNCTION
# ==============================

def send_threat_email(user_email, score, verdict):
    """Send a threat alert email. Fails silently so scan result still returns."""
    try:
        if not user_email:
            print("⚠ Email skipped (empty user)")
            return

        msg = Message(
            subject="🚨 AI Guard Pro Threat Alert",
            recipients=[user_email],
            body=(
                f"Security Threat Detected\n\n"
                f"User       : {user_email}\n"
                f"Risk Score : {score}\n"
                f"Status     : {verdict}\n\n"
                f"A network anomaly was detected. Please review your logs immediately."
            )
        )
        mail.send(msg)
        print("✅ Threat Email Sent to", user_email)

    except Exception as e:
        # Log but do NOT re-raise — email failure must never break the scan response
        print("⚠ Email Error:", str(e))

# ==============================
# REGISTER API
# ==============================

@app.route("/api/register", methods=["POST"])
def register():
    data     = request.json
    name     = data.get("name")
    email    = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Missing fields"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "User exists"}), 400

    user = User(
        name=name,
        email=email,
        password=generate_password_hash(password),
        created_at=str(datetime.now())
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Registration successful"})

# ==============================
# LOGIN API
# ==============================

@app.route("/api/login", methods=["POST"])
def login():
    data     = request.json
    email    = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    if check_password_hash(user.password, password):
        return jsonify({
            "status": "success",
            "email":  user.email,
            "name":   user.name,
            "role":   user.role
        })

    return jsonify({"message": "Invalid password"}), 401

# ==============================
# RESET PASSWORD LINK
# ==============================

@app.route("/api/reset-link", methods=["POST"])
def send_reset_link():
    try:
        data  = request.json
        email = data.get("email")

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        reset_link = f"http://127.0.0.1:5000/reset-password.html?email={email}"

        msg = Message(
            subject="🔐 AI Guard Pro Password Reset",
            recipients=[email],
            body=(
                f"Password reset request received.\n\n"
                f"Click the link below:\n{reset_link}\n\n"
                f"Ignore this email if you did not request a reset."
            )
        )
        mail.send(msg)
        return jsonify({"status": "success"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ==============================
# RESET PASSWORD API
# ==============================

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data     = request.json
    email    = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    user.password = generate_password_hash(password)
    db.session.commit()
    return jsonify({"status": "success"})

# ==============================
# UPLOAD LOGS
# ==============================

uploaded_file_hash = None

@app.route("/api/upload-logs", methods=["POST"])
def upload_logs():
    global uploaded_file_hash

    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded"}), 400

    file    = request.files["file"]
    content = file.read()

    if not content:
        return jsonify({"status": "error", "message": "Uploaded file is empty"}), 400

    uploaded_file_hash = hashlib.md5(content).hexdigest()
    print(f"✅ File uploaded — hash: {uploaded_file_hash}")

    return jsonify({"status": "success", "filename": file.filename})

# ==============================
# SCAN API
# ==============================

@app.route("/api/scan", methods=["POST"])
def scan_logs():
    global uploaded_file_hash

    try:
        # ── 1. Guard: file must be uploaded first ──────────────────────────
        if uploaded_file_hash is None:
            return jsonify({
                "status":  "error",
                "message": "Please upload a log file first"
            }), 400

        # ── 2. Safe JSON parse (fixes 500 when Content-Type is wrong) ──────
        try:
            data = request.get_json(force=True, silent=True) or {}
        except Exception:
            data = {}

        user_email  = str(data.get("email") or "").strip()
        email_alert = bool(data.get("emailAlert", False))

        print(f"[SCAN] hash={uploaded_file_hash} | email={user_email} | alert={email_alert}")

        # ── 3. Derive verdict from file hash ────────────────────────────────
        try:
            score       = int(uploaded_file_hash[:2], 16) % 100
            origin_node = "Node-" + str(int(uploaded_file_hash[2:4], 16) % 10)
            target_asn  = "AS"    + str(10000 + int(uploaded_file_hash[4:6], 16))
        except (ValueError, TypeError) as e:
            print("[SCAN] Hash parse error:", e)
            return jsonify({"status": "error", "message": "Invalid file hash — please re-upload"}), 500

        if score < 40:
            verdict = "Normal"
        elif score < 70:
            verdict = "Anomaly"
        else:
            verdict = "Threat Detected"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"[SCAN] verdict={verdict} | score={score}")

        # ── 4. Persist to DB ─────────────────────────────────────────────────
        try:
            result = ScanResult(
                user_email  = user_email,
                timestamp   = timestamp,
                origin_node = origin_node,
                target_asn  = target_asn,
                risk_score  = score,
                verdict     = verdict,
                file_hash   = uploaded_file_hash
            )
            db.session.add(result)
            db.session.commit()
            print("[SCAN] DB commit OK")
        except Exception as db_err:
            db.session.rollback()
            print("[SCAN] DB error:", db_err)
            # Non-fatal: still return result to frontend even if DB write fails
            # Remove the next line if you want DB failure to be fatal instead
            pass

        # ── 5. Send email only when threat AND alert enabled ─────────────────
        if verdict == "Threat Detected" and email_alert and user_email:
            send_threat_email(user_email, score, verdict)

        # ── 6. Return result ──────────────────────────────────────────────────
        return jsonify({
            "status": "success",
            "data": {
                "timestamp":   timestamp,
                "origin_node": origin_node,
                "target_asn":  target_asn,
                "risk_score":  score,
                "verdict":     verdict
            }
        })

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print("[SCAN] Unexpected error:\n", tb)
        return jsonify({
            "status":  "error",
            "message": "Internal server error: " + str(e)
        }), 500

# ==============================
# SERVE FRONTEND
# ==============================

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "network-logs.html")

# ==============================
# RUN SERVER
# ==============================

if __name__ == "__main__":
    app.run(debug=True, port=5000)
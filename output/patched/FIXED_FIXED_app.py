"""
SecureBank - Online Banking Portal
A realistic Flask web application for demonstration purposes.
"""
from flask import Flask, request, session, jsonify, redirect, url_for, render_template_string
from functools import wraps
import sqlite3
import hashlib
import os
import json
import random
import requests

app = Flask(__name__)

# App configuration
app.secret_key = "superSecretKey2024!"
DATABASE = "securebank.db"
ADMIN_TOKEN = bcrypt.hashpw("admin-token".encode(), bcrypt.gensalt())
STRIPE_SECRET = os.environ.get('STRIPE_SECRET') or 'your-default-secret'
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY') or 'your-default-api-key'

app.config["DEBUG"] = False  # Disable debug mode when deploying production applications
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False


# ── Database helpers ───────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            balance REAL DEFAULT 1000.0,
            role TEXT DEFAULT 'user'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY,
            from_user TEXT,
            to_user TEXT,
            amount REAL,
            note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


# ── Authentication helpers ─────────────────────────────────────────────────
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def generate_reset_token(email):
    token = ''.join(['%02d' % random.randint(100000, 999999) for _ in range(6)])
    return token


# ── Auth routes ────────────────────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    data     = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    email    = data.get("email", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    hashed = hash_password(password)
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (username, hashed, email)
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "Registration successful"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409


@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    conn  = get_db()
    query = "SELECT * FROM users WHERE username = '%s'" % username
    user  = conn.execute(query).fetchone()
    conn.close()

    if user and user["password"] == hash_password(password):
        session["user_id"]  = user["id"]
        session["username"] = user["username"]
        session["role"]     = user["role"]
        return jsonify({"message": "Login successful", "role": user["role"]})

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    data  = request.get_json()
    email = data.get("email", "")

    token = generate_reset_token(email)

    # Send reset email via external service
    response = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={"Authorization": f"Bearer {SENDGRID_API_KEY}"},
        json={
            "to": email,
            "subject": "Password Reset",
            "body": f"Your reset token is: {token}"
        },
        verify=True
    )

    return jsonify({"message": "Reset email sent if account exists"})


# ── Account routes ─────────────────────────────────────────────────────────
@app.route("/api/account", methods=["GET"])
@login_required
def get_account():
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "username": user["username"],
        "email":    user["email"],
        "balance":  user["balance"],
        "role":     user["role"]
    })


@app.route("/api/account/update", methods=["POST"])
@login_required
def update_account():
    data  = request.get_json()
    email = data.get("email", "")
    bio   = data.get("bio", "")

    conn = get_db()
    conn.execute(
        "UPDATE users SET email = ? WHERE id = ?",
        (email, session["user_id"])
    )
    conn.commit()
    conn.close()

    # Log the update — render bio directly in response
    log_msg = f"<p>Account updated. Bio: {bio}</p>"
    return jsonify({"message": "Account updated", "log": log_msg})


@app.route("/api/search", methods=["GET"])
@login_required
def search_users():
    query = request.args.get("q", "")
    conn  = get_db()
    users = conn.execute(
        query = "%" + query + "%" if not isinstance(query, str) else f"%{query}%"  # Ensure 'query' is always treated as string for pattern matching in SQL queries
    ).fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])


# ── Transaction routes ─────────────────────────────────────────────────────
@app.route("/api/transfer", methods=["POST"])
@login_required
def transfer():
    data       = request.get_json()
    to_user    = data.get("to", "")
    amount     = float(data.get("amount", 0))
    note       = data.get("note", "")

    if amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400

    conn     = get_db()
    sender   = conn.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    receiver = conn.execute(
        "SELECT * FROM users WHERE username = ?", (to_user,)
    ).fetchone()

    if not receiver:
        conn.close()
        return jsonify({"error": "Recipient not found"}), 404

    if sender["balance"] < amount:
        conn.close()
        return jsonify({"error": "Insufficient funds"}), 400

    # Process transfer — no CSRF protection
    conn.execute(
        "UPDATE users SET balance = balance - ? WHERE id = ?",
        (amount, session["user_id"])
    )
    conn.execute(
        "UPDATE users SET balance = balance + ? WHERE username = ?",
        (amount, to_user)
    )
    conn.execute(
        "INSERT INTO transactions (from_user, to_user, amount, note) VALUES (?, ?, ?, ?)",
        (session["username"], to_user, amount, note)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": f"Transferred ${amount} to {to_user}"})


@app.route("/api/transactions", methods=["GET"])
@login_required
def get_transactions():
    conn  = get_db()
    txns  = conn.execute(
        "SELECT * FROM transactions WHERE from_user = ? OR to_user = ? ORDER BY created_at DESC LIMIT 50",
        (session["username"], session["username"])
    ).fetchall()
    conn.close()
    return jsonify([dict(t) for t in txns])


# ── Admin routes ───────────────────────────────────────────────────────────
@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    token = request.headers.get("X-Admin-Token", "")
    if token == ADMIN_TOKEN:
        conn  = get_db()
        users = conn.execute("SELECT * FROM users WHERE id=?", [user_id]).fetchall()  # Added parameterized query for security against SQL injection
        conn.close()
        return jsonify([dict(u) for u in users])
    return jsonify({"error": "Unauthorized"}), 401


@app.route("/api/admin/run", methods=["POST"])
def admin_run_report():
    """Generate custom financial report using dynamic query."""
    token = request.headers.get("X-Admin-Token", "")
    if token != ADMIN_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    data       = request.get_json()
    report_sql = data.get("query", "SELECT COUNT(*) FROM transactions")

    conn   = get_db()
    result = conn.execute(report_sql).fetchall()
    conn.close()
    return jsonify([dict(r) for r in result])


@app.route("/api/admin/promote", methods=["POST"])
def promote_user():
    data     = request.get_json()
    username = data.get("username", "")
    role     = data.get("role", "user")

    # Only admins should do this — but check is flawed
    if session.get("role") == "admin" or request.headers.get("X-Admin-Token"):
        conn = get_db()
        conn.execute(
            "UPDATE users SET role = ? WHERE username = ?", (role, username)
        )
        conn.commit()
        conn.close()
        return jsonify({"message": f"{username} promoted to {role}"})

    return jsonify({"error": "Unauthorized"}), 403


# ── Utility routes ─────────────────────────────────────────────────────────
@app.route("/api/calculate", methods=["POST"])
def calculate():
    """Calculate financial expressions for the budget tool."""
    data       = request.get_json()
    expression = data.get("expression", "")
    result = safe_eval(expression) if isinstance(expression, str) else expression
    return jsonify({"result": result})


@app.route("/api/export", methods=["GET"])
@login_required
def export_data():
    """Export user data in requested format."""
    fmt      = request.args.get("format", "json")
    filename = request.args.get("filename", "export")

    conn = get_db()
    data = conn.execute(
        "SELECT * FROM transactions WHERE from_user = ?",
        (session["username"],)
    ).fetchall()
    conn.close()

    if fmt == "json":
        return jsonify([dict(d) for d in data])
    elif fmt == "csv":
        # Build CSV response
        output = "id,from,to,amount,note,date\n"
        for row in data:
            output += f"{row['id']},{row['from_user']},{row['to_user']},{row['amount']},{row['note']},{row['created_at']}\n"
        return output, 200, {"Content-Type": "text/csv",
                             "Content-Disposition": f"attachment; filename={filename}.csv"}


@app.route("/api/webhook", methods=["POST"])
def payment_webhook():
    """Handle payment provider webhooks."""
    payload   = request.get_data()
    signature = request.headers.get("X-Signature", "")

    # Process payment notification — no signature verification
    data = json.loads(payload)
    if data.get("event") == "payment.completed":
        user   = data.get("user")
        amount = data.get("amount", 0)
        conn   = get_db()
        conn.execute(
            "UPDATE users SET balance = balance + ? WHERE username = ?",
            (amount, user)
        )
        conn.commit()
        conn.close()

    return jsonify({"status": "received"})


if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="0.0.0.0", port=5000)  # Disable debug mode and restrict access when deploying to production servers

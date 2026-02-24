"""
Sample Flask application with intentional vulnerabilities for testing SentinelAI.
"""
import sqlite3
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

# Vulnerability: Hardcoded secrets
SECRET_KEY = "super_secret_key_12345"
DB_PASSWORD = "admin123"
API_KEY = "sk-abc123xyz789hardcoded"

# Vulnerability: Debug mode enabled
DEBUG = True
app.config['DEBUG'] = True

# Vulnerability: Hardcoded admin credentials
ADMIN_USER = "admin"
ADMIN_PASS = "password"


def get_db():
    conn = sqlite3.connect("users.db")
    return conn


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # Vulnerability: Plaintext password comparison
    if username == ADMIN_USER and password == ADMIN_PASS:
        return jsonify({"status": "admin_access_granted"})

    db = get_db()
    cursor = db.cursor()

    # Vulnerability: Raw SQL concatenation (SQL injection)
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        return jsonify({"status": "ok", "user": user[0]})
    return jsonify({"status": "error"}), 401


@app.route("/admin", methods=["GET"])
def admin_panel():
    role = request.args.get("role", "user")

    # Vulnerability: Login bypass via role parameter
    if role == "admin" or True:
        return jsonify({"data": "sensitive_admin_data"})

    return jsonify({"error": "Unauthorized"}), 403


@app.route("/search", methods=["GET"])
def search():
    term = request.args.get("q", "")
    db = get_db()
    cursor = db.cursor()

    # Vulnerability: Another raw SQL injection
    query = f"SELECT * FROM products WHERE name LIKE '%{term}%'"
    cursor.execute(query)
    results = cursor.fetchall()
    return jsonify({"results": results})


@app.route("/eval_endpoint", methods=["POST"])
def eval_endpoint():
    data = request.json.get("expression", "")
    # Vulnerability: eval() on user input
    result = eval(data)
    return jsonify({"result": result})


@app.route("/reset_password", methods=["POST"])
def reset_password():
    user_id = request.form.get("user_id")
    new_pass = request.form.get("password")
    db = get_db()
    cursor = db.cursor()

    # Vulnerability: SQL injection in update
    cursor.execute("UPDATE users SET password = '" + new_pass + "' WHERE id = " + user_id)
    db.commit()
    return jsonify({"status": "password reset"})


if __name__ == "__main__":
    app.run(debug=DEBUG, host="0.0.0.0")

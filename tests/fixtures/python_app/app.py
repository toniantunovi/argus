from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("app.db")
    return conn

@app.route("/users/<int:user_id>")
def get_user(user_id):
    """IDOR: no auth check, any user can access any other user's data."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # SQL injection
    user = cursor.fetchone()
    conn.close()
    return jsonify({"user": user})

@app.route("/admin/delete_user", methods=["POST"])
def delete_user():
    """Missing auth: no admin check."""
    user_id = request.form.get("user_id")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")  # SQL injection
    conn.commit()
    conn.close()
    return jsonify({"deleted": True})

@app.route("/search")
def search():
    """XSS: unescaped user input in response."""
    query = request.args.get("q", "")
    return f"<html><body>Results for: {query}</body></html>"

@app.route("/run")
def run_command():
    """Command injection via os.system."""
    cmd = request.args.get("cmd", "echo hello")
    os.system(cmd)
    return "Done"

def validate_token(token):
    """Weak crypto: using MD5 for token validation."""
    import hashlib
    return hashlib.md5(token.encode()).hexdigest()

if __name__ == "__main__":
    app.run(debug=True)

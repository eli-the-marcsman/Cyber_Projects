from flask import Blueprint, request, jsonify, session
from functools import wraps
from db import get_db
import bcrypt

auth = Blueprint('auth', __name__)

@auth.route('/api/auth/register', methods=['POST'])
def register():
    data     = request.json
    name     = data.get('name')
    email    = data.get('email')
    password = data.get('password')
    role     = data.get('role', 'user')

    if not all([name, email, password]):
        return jsonify({"error": "name, email, and password required"}), 400

    pw_hash = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

    db  = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "INSERT INTO users (name, email, role, password_hash) VALUES (%s,%s,%s,%s)",
            (name, email, role, pw_hash)
        )
        db.commit()
        return jsonify({"message": "User created", "id": cur.lastrowid}), 201
    except Exception:
        return jsonify({"error": "Email already registered"}), 409

@auth.route('/api/auth/login', methods=['POST'])
def login():
    data     = request.json
    email    = data.get('email')
    password = data.get('password')

    db  = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if not user or not bcrypt.checkpw(
        password.encode('utf-8'),
        user['password_hash'].encode('utf-8')
    ):
        return jsonify({"error": "Invalid email or password"}), 401

    session['user_id'] = user['id']
    session['role']    = user['role']

    return jsonify({
        "message": "Logged in",
        "user": {"id": user['id'], "name": user['name'], "role": user['role']}
    })

@auth.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated
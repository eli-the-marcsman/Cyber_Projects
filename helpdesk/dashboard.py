from flask import Blueprint, jsonify
from db import get_db
from auth import login_required

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/api/dashboard/stats', methods=['GET'])
@login_required
def stats():
    db  = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("SELECT status, COUNT(*) as count FROM tickets GROUP BY status")
    by_status = cur.fetchall()

    cur.execute("SELECT category, COUNT(*) as count FROM tickets GROUP BY category")
    by_category = cur.fetchall()

    cur.execute("SELECT priority, COUNT(*) as count FROM tickets GROUP BY priority")
    by_priority = cur.fetchall()

    cur.execute("""
        SELECT AVG(TIMESTAMPDIFF(MINUTE, created_at, resolved_at)) AS avg_mins
        FROM tickets WHERE resolved_at IS NOT NULL
    """)
    avg = cur.fetchone()

    return jsonify({
        "by_status":              by_status,
        "by_category":            by_category,
        "by_priority":            by_priority,
        "avg_resolution_minutes": avg['avg_mins']
    })
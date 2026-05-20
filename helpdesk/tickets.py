from flask import Blueprint, request, jsonify, session
from db import get_db
from auth import login_required

tickets_bp = Blueprint('tickets', __name__)

def log_activity(cur, ticket_id, actor_id, action, old=None, new=None, note=None):
    cur.execute(
        """INSERT INTO activity_log
               (ticket_id, actor_id, action, old_value, new_value, note)
           VALUES (%s,%s,%s,%s,%s,%s)""",
        (ticket_id, actor_id, action, old, new, note)
    )

@tickets_bp.route('/api/tickets', methods=['GET'])
@login_required
def list_tickets():
    filters, params = [], []
    for field in ['status', 'priority', 'category']:
        val = request.args.get(field)
        if val:
            filters.append(f"{field} = %s")
            params.append(val)
    where = "WHERE " + " AND ".join(filters) if filters else ""
    db  = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute(f"SELECT * FROM tickets {where} ORDER BY created_at DESC", params)
    return jsonify(cur.fetchall())

@tickets_bp.route('/api/tickets', methods=['POST'])
@login_required
def create_ticket():
    data = request.json
    db   = get_db()
    cur  = db.cursor()
    cur.execute(
        """INSERT INTO tickets (title, description, priority, category, requester_id)
           VALUES (%s,%s,%s,%s,%s)""",
        (data['title'], data['description'],
         data['priority'], data['category'], session['user_id'])
    )
    ticket_id = cur.lastrowid
    log_activity(cur, ticket_id, session['user_id'], 'created')
    db.commit()
    return jsonify({"id": ticket_id}), 201

@tickets_bp.route('/api/tickets/<int:id>', methods=['GET'])
@login_required
def get_ticket(id):
    db  = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM tickets WHERE id = %s", (id,))
    ticket = cur.fetchone()
    if not ticket:
        return jsonify({"error": "Not found"}), 404
    cur.execute(
        "SELECT * FROM activity_log WHERE ticket_id = %s ORDER BY created_at",
        (id,)
    )
    ticket['activity'] = cur.fetchall()
    return jsonify(ticket)

@tickets_bp.route('/api/tickets/<int:id>/status', methods=['PUT'])
@login_required
def update_status(id):
    data = request.json
    db   = get_db()
    cur  = db.cursor(dictionary=True)
    cur.execute("SELECT status FROM tickets WHERE id = %s", (id,))
    row  = cur.fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404
    old, new = row['status'], data['status']
    if new in ('resolved', 'closed'):
        cur.execute("UPDATE tickets SET status=%s, resolved_at=NOW() WHERE id=%s", (new, id))
    else:
        cur.execute("UPDATE tickets SET status=%s WHERE id=%s", (new, id))
    log_activity(cur, id, session['user_id'], 'status_changed', old, new, data.get('note'))
    db.commit()
    return jsonify({"status": new})

@tickets_bp.route('/api/tickets/<int:id>/assign', methods=['PUT'])
@login_required
def assign_ticket(id):
    data = request.json
    db   = get_db()
    cur  = db.cursor()
    cur.execute(
        "UPDATE tickets SET assignee_id=%s, status='in_progress' WHERE id=%s",
        (data['assignee_id'], id)
    )
    log_activity(cur, id, session['user_id'], 'assigned', None, str(data['assignee_id']))
    db.commit()
    return jsonify({"assigned_to": data['assignee_id']})

@tickets_bp.route('/api/tickets/<int:id>/escalate', methods=['PUT'])
@login_required
def escalate_ticket(id):
    data = request.json
    db   = get_db()
    cur  = db.cursor()
    cur.execute(
        """UPDATE tickets SET escalated=TRUE, severity=%s
           WHERE id=%s AND category='security_incident'""",
        (data.get('severity'), id)
    )
    log_activity(cur, id, session['user_id'], 'escalated', 'false', 'true')
    db.commit()
    return jsonify({"escalated": True})
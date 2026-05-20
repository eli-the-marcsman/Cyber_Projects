# views.py
from flask import Blueprint, render_template, redirect, url_for, request, session
from db import get_db
from auth import login_required

views_bp = Blueprint('views', __name__)

@views_bp.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('views.login_page'))
    return redirect(url_for('views.dashboard_page'))

@views_bp.route('/login')
def login_page():
    return render_template('login.html')

@views_bp.route('/register')
def register_page():
    return render_template('register.html')

@views_bp.route('/dashboard')
@login_required
def dashboard_page():
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
    return render_template('dashboard.html',
        by_status=by_status,
        by_category=by_category,
        by_priority=by_priority,
        avg_mins=avg['avg_mins']
    )

@views_bp.route('/tickets')
@login_required
def tickets_page():
    db  = get_db()
    cur = db.cursor(dictionary=True)
    status   = request.args.get('status', '')
    priority = request.args.get('priority', '')
    category = request.args.get('category', '')
    filters, params = [], []
    if status:
        filters.append("status = %s"); params.append(status)
    if priority:
        filters.append("priority = %s"); params.append(priority)
    if category:
        filters.append("category = %s"); params.append(category)
    where = "WHERE " + " AND ".join(filters) if filters else ""
    cur.execute(f"SELECT t.*, u.name as requester_name FROM tickets t JOIN users u ON t.requester_id = u.id {where} ORDER BY t.created_at DESC", params)
    tickets = cur.fetchall()
    return render_template('tickets.html', tickets=tickets,
        status=status, priority=priority, category=category)

@views_bp.route('/tickets/new')
@login_required
def create_ticket_page():
    return render_template('create_ticket.html')

@views_bp.route('/tickets/<int:id>')
@login_required
def ticket_detail_page(id):
    db  = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("""
        SELECT t.*, u.name as requester_name, a.name as assignee_name
        FROM tickets t
        JOIN users u ON t.requester_id = u.id
        LEFT JOIN users a ON t.assignee_id = a.id
        WHERE t.id = %s
    """, (id,))
    ticket = cur.fetchone()
    if not ticket:
        return redirect(url_for('views.tickets_page'))
    cur.execute("""
        SELECT al.*, u.name as actor_name
        FROM activity_log al
        JOIN users u ON al.actor_id = u.id
        WHERE al.ticket_id = %s
        ORDER BY al.created_at ASC
    """, (id,))
    activity = cur.fetchall()
    cur.execute("SELECT id, name FROM users WHERE role = 'technician' OR role = 'admin'")
    technicians = cur.fetchall()
    return render_template('ticket_detail.html',
        ticket=ticket, activity=activity, technicians=technicians)
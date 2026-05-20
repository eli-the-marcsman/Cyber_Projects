from flask import Blueprint, render_template, redirect, url_for, request, session
from db import get_db
from auth import login_required

views_bp = Blueprint('views', __name__)

# ── Helper ────────────────────────────────────────────────────────────────────
def current_role():
    return session.get('role', 'user')

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            return redirect(url_for('views.tickets_page'))
        return f(*args, **kwargs)
    return decorated

# ── Index ─────────────────────────────────────────────────────────────────────
@views_bp.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('views.login_page'))
    if current_role() == 'user':
        return redirect(url_for('views.tickets_page'))
    return redirect(url_for('views.dashboard_page'))

# ── Login / Register ──────────────────────────────────────────────────────────
@views_bp.route('/login')
def login_page():
    return render_template('login.html')

@views_bp.route('/register')
def register_page():
    return render_template('register.html')

# ── Dashboard (admin and technician only) ─────────────────────────────────────
@views_bp.route('/dashboard')
@login_required
def dashboard_page():
    db  = get_db()
    cur = db.cursor(dictionary=True)
    role       = current_role()
    user_id    = session['user_id']

    if role == 'user':
        return redirect(url_for('views.tickets_page'))

    if role == 'admin':
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
    else:
        # Technician — only their assigned tickets
        cur.execute("SELECT status, COUNT(*) as count FROM tickets WHERE assignee_id=%s GROUP BY status", (user_id,))
        by_status = cur.fetchall()
        cur.execute("SELECT category, COUNT(*) as count FROM tickets WHERE assignee_id=%s GROUP BY category", (user_id,))
        by_category = cur.fetchall()
        cur.execute("SELECT priority, COUNT(*) as count FROM tickets WHERE assignee_id=%s GROUP BY priority", (user_id,))
        by_priority = cur.fetchall()
        cur.execute("""
            SELECT AVG(TIMESTAMPDIFF(MINUTE, created_at, resolved_at)) AS avg_mins
            FROM tickets WHERE assignee_id=%s AND resolved_at IS NOT NULL
        """, (user_id,))
        avg = cur.fetchone()

    return render_template('dashboard.html',
        by_status=by_status,
        by_category=by_category,
        by_priority=by_priority,
        avg_mins=avg['avg_mins'] if avg else None,
        role=role
    )

# ── Tickets ───────────────────────────────────────────────────────────────────
@views_bp.route('/tickets')
@login_required
def tickets_page():
    db  = get_db()
    cur = db.cursor(dictionary=True)
    role    = current_role()
    user_id = session['user_id']

    status   = request.args.get('status', '')
    priority = request.args.get('priority', '')
    category = request.args.get('category', '')

    filters, params = [], []

    # Role-based filtering
    if role == 'user':
        filters.append("t.requester_id = %s")
        params.append(user_id)
    elif role == 'technician':
        filters.append("t.assignee_id = %s")
        params.append(user_id)
    # admin sees everything — no extra filter

    if status:
        filters.append("t.status = %s"); params.append(status)
    if priority:
        filters.append("t.priority = %s"); params.append(priority)
    if category:
        filters.append("t.category = %s"); params.append(category)

    where = "WHERE " + " AND ".join(filters) if filters else ""
    cur.execute(f"""
        SELECT t.*, u.name as requester_name
        FROM tickets t
        JOIN users u ON t.requester_id = u.id
        {where}
        ORDER BY t.created_at DESC
    """, params)
    tickets = cur.fetchall()

    return render_template('tickets.html',
        tickets=tickets,
        status=status,
        priority=priority,
        category=category,
        role=role
    )

# ── Create ticket ─────────────────────────────────────────────────────────────
@views_bp.route('/tickets/new')
@login_required
def create_ticket_page():
    return render_template('create_ticket.html', role=current_role())

# ── Ticket detail ─────────────────────────────────────────────────────────────
@views_bp.route('/tickets/<int:id>')
@login_required
def ticket_detail_page(id):
    db  = get_db()
    cur = db.cursor(dictionary=True)
    role    = current_role()
    user_id = session['user_id']

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

    # Users can only see their own tickets
    if role == 'user' and ticket['requester_id'] != user_id:
        return redirect(url_for('views.tickets_page'))

    # Technicians can only see tickets assigned to them
    if role == 'technician' and ticket['assignee_id'] != user_id:
        return redirect(url_for('views.tickets_page'))

    cur.execute("""
        SELECT al.*, u.name as actor_name
        FROM activity_log al
        JOIN users u ON al.actor_id = u.id
        WHERE al.ticket_id = %s
        ORDER BY al.created_at ASC
    """, (id,))
    activity = cur.fetchall()

    # Only admins can assign tickets
    technicians = []
    if role == 'admin':
        cur.execute("SELECT id, name FROM users WHERE role='technician' OR role='admin'")
        technicians = cur.fetchall()

    return render_template('ticket_detail.html',
        ticket=ticket,
        activity=activity,
        technicians=technicians,
        role=role
    )

# ── Admin panel ───────────────────────────────────────────────────────────────
@views_bp.route('/admin/users')
@login_required
@admin_required
def admin_users():
    db  = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC")
    users = cur.fetchall()
    return render_template('admin_users.html', users=users, role='admin')
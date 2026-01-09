from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from datetime import datetime
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-secret")

DB_PATH = os.getenv("CARWASH_DB_PATH", "carwash.db")

# -----------------
# Helpers
# -----------------
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        phone TEXT NOT NULL UNIQUE,
        email TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('Customer','Staff','Admin')),
        created_at TEXT NOT NULL
    );
    """)

    # vehicles
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vehicles (
        vehicle_id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        plate_no TEXT NOT NULL UNIQUE,
        make TEXT,
        model TEXT,
        color TEXT,
        vehicle_type TEXT,
        FOREIGN KEY(customer_id) REFERENCES users(user_id)
            ON UPDATE CASCADE ON DELETE RESTRICT
    );
    """)

    # packages
    cur.execute("""
    CREATE TABLE IF NOT EXISTS packages (
        package_id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_name TEXT NOT NULL UNIQUE,
        price REAL NOT NULL CHECK(price >= 0),
        duration_minutes INTEGER NOT NULL CHECK(duration_minutes > 0),
        is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1))
    );
    """)

    # service stages
    cur.execute("""
    CREATE TABLE IF NOT EXISTS service_stages (
        stage_id INTEGER PRIMARY KEY AUTOINCREMENT,
        stage_name TEXT NOT NULL UNIQUE,
        stage_order INTEGER NOT NULL UNIQUE CHECK(stage_order > 0)
    );
    """)

    # bookings
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bookings (
        booking_id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        vehicle_id INTEGER NOT NULL,
        package_id INTEGER NOT NULL,
        booking_datetime TEXT NOT NULL,
        scheduled_datetime TEXT,
        status TEXT NOT NULL CHECK(status IN ('Booked','InProgress','Completed','Cancelled')) DEFAULT 'Booked',
        current_stage_id INTEGER,
        notes TEXT,

        FOREIGN KEY(customer_id) REFERENCES users(user_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        FOREIGN KEY(vehicle_id) REFERENCES vehicles(vehicle_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        FOREIGN KEY(package_id) REFERENCES packages(package_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        FOREIGN KEY(current_stage_id) REFERENCES service_stages(stage_id)
            ON UPDATE CASCADE ON DELETE SET NULL
    );
    """)

    # stage history
    cur.execute("""
    CREATE TABLE IF NOT EXISTS booking_stage_history (
        history_id INTEGER PRIMARY KEY AUTOINCREMENT,
        booking_id INTEGER NOT NULL,
        stage_id INTEGER NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT,
        updated_by_staff_id INTEGER NOT NULL,

        FOREIGN KEY(booking_id) REFERENCES bookings(booking_id)
            ON UPDATE CASCADE ON DELETE CASCADE,
        FOREIGN KEY(stage_id) REFERENCES service_stages(stage_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        FOREIGN KEY(updated_by_staff_id) REFERENCES users(user_id)
            ON UPDATE CASCADE ON DELETE RESTRICT
    );
    """)

    # staff assignment M:N
    cur.execute("""
    CREATE TABLE IF NOT EXISTS booking_staff_assignment (
        booking_id INTEGER NOT NULL,
        staff_id INTEGER NOT NULL,
        assigned_at TEXT NOT NULL,
        PRIMARY KEY(booking_id, staff_id),
        FOREIGN KEY(booking_id) REFERENCES bookings(booking_id)
            ON UPDATE CASCADE ON DELETE CASCADE,
        FOREIGN KEY(staff_id) REFERENCES users(user_id)
            ON UPDATE CASCADE ON DELETE RESTRICT
    );
    """)

    # payments (1:1)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS payments (
        payment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        booking_id INTEGER NOT NULL UNIQUE,
        amount REAL NOT NULL CHECK(amount >= 0),
        method TEXT NOT NULL CHECK(method IN ('Cash','Card','Online')),
        payment_status TEXT NOT NULL CHECK(payment_status IN ('Unpaid','Paid','Partial','Refunded')) DEFAULT 'Unpaid',
        paid_at TEXT,
        FOREIGN KEY(booking_id) REFERENCES bookings(booking_id)
            ON UPDATE CASCADE ON DELETE CASCADE
    );
    """)

    # Seed stages
    cur.execute("SELECT COUNT(*) FROM service_stages;")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO service_stages(stage_name, stage_order) VALUES(?, ?);",
            [("Washing", 1), ("Drying", 2), ("Polishing", 3), ("Completed", 4)]
        )

    # Seed packages
    cur.execute("SELECT COUNT(*) FROM packages;")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO packages(package_name, price, duration_minutes, is_active) VALUES(?,?,?,?);",
            [("Basic Wash", 500, 20, 1),
             ("Standard Wash", 800, 35, 1),
             ("Premium Wash", 1200, 50, 1)]
        )

    # Seed admin
    cur.execute("SELECT COUNT(*) FROM users WHERE role='Admin';")
    if cur.fetchone()[0] == 0:
        cur.execute("""
        INSERT INTO users(full_name, phone, email, password_hash, role, created_at)
        VALUES(?,?,?,?,?,?)
        """, ("Admin", "0300-0000000", "admin@carwash.local", hash_password("admin123"), "Admin", now_str()))

    conn.commit()
    conn.close()

# -----------------
# Guards
# -----------------
def require_login():
    return "user_id" in session

def require_staff():
    return require_login() and session.get("role") in ("Staff", "Admin")

@app.before_request
def _startup():
    if not getattr(app, "_db_inited", False):
        init_db()
        app._db_inited = True

# -----------------
# Routes
# -----------------
@app.route("/")
def home():
    if not require_login():
        return redirect(url_for("login"))
    if session["role"] == "Customer":
        return redirect(url_for("customer_dashboard"))
    return redirect(url_for("staff_dashboard"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone","").strip()
        password = request.form.get("password","").strip()

        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT user_id, full_name, role FROM users WHERE phone=? AND password_hash=?",
                    (phone, hash_password(password)))
        row = cur.fetchone()
        conn.close()

        if not row:
            flash("Invalid phone or password", "danger")
            return redirect(url_for("login"))

        session["user_id"] = row[0]
        session["full_name"] = row[1]
        session["role"] = row[2]
        flash(f"Welcome {row[1]} ({row[2]})", "success")
        return redirect(url_for("home"))

    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name","").strip()
        phone = request.form.get("phone","").strip()
        email = request.form.get("email","").strip() or None
        password = request.form.get("password","").strip()
        confirm = request.form.get("confirm","").strip()

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))

        try:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO users(full_name, phone, email, password_hash, role, created_at)
                VALUES(?,?,?,?, 'Customer', ?)
            """, (full_name, phone, email, hash_password(password), now_str()))
            conn.commit()
            conn.close()
            flash("Registered successfully. Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError as e:
            flash(f"Registration failed: {e}", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))
@app.route("/booking/<int:booking_id>")
def booking_detail(booking_id):
    if not require_login():
        return redirect(url_for("login"))

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT b.booking_id, b.booking_datetime, b.scheduled_datetime, b.status, b.notes,
           u.full_name, v.plate_no, p.package_name, p.price,
           s.stage_name
    FROM bookings b
    JOIN users u ON u.user_id=b.customer_id
    JOIN vehicles v ON v.vehicle_id=b.vehicle_id
    JOIN packages p ON p.package_id=b.package_id
    LEFT JOIN service_stages s ON s.stage_id=b.current_stage_id
    WHERE b.booking_id=?
    """, (booking_id,))
    booking = cur.fetchone()

    if not booking:
        conn.close()
        flash("Booking not found.", "danger")
        return redirect(url_for("home"))

    # customer can only view own booking
    if session["role"] == "Customer":
        cur.execute("SELECT customer_id FROM bookings WHERE booking_id=?", (booking_id,))
        owner_id = cur.fetchone()[0]
        if owner_id != session["user_id"]:
            conn.close()
            flash("Not allowed.", "danger")
            return redirect(url_for("customer_dashboard"))

    cur.execute("""
    SELECT ss.stage_name, h.start_time, h.end_time, uu.full_name
    FROM booking_stage_history h
    JOIN service_stages ss ON ss.stage_id=h.stage_id
    JOIN users uu ON uu.user_id=h.updated_by_staff_id
    WHERE h.booking_id=?
    ORDER BY h.history_id DESC
    """, (booking_id,))
    history = cur.fetchall()

    cur.execute("""
    SELECT amount, method, payment_status, paid_at
    FROM payments WHERE booking_id=?
    """, (booking_id,))
    payment = cur.fetchone()

    # assigned staff
    cur.execute("""
    SELECT u.full_name, u.role, a.assigned_at
    FROM booking_staff_assignment a
    JOIN users u ON u.user_id=a.staff_id
    WHERE a.booking_id=?
    ORDER BY a.assigned_at DESC
    """, (booking_id,))
    assigned = cur.fetchall()

    conn.close()
    return render_template("booking_detail.html", booking=booking, history=history, payment=payment, assigned=assigned)


# -------- Customer dashboard --------
@app.route("/customer")
def customer_dashboard():
    if not require_login() or session["role"] != "Customer":
        return redirect(url_for("login"))

    uid = session["user_id"]
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
      SELECT vehicle_id, plate_no, make, model, color, vehicle_type
      FROM vehicles WHERE customer_id=? ORDER BY vehicle_id DESC
    """, (uid,))
    vehicles = cur.fetchall()

    cur.execute("""
      SELECT package_id, package_name, price, duration_minutes
      FROM packages WHERE is_active=1 ORDER BY price
    """)
    packages = cur.fetchall()

    cur.execute("""
    SELECT b.booking_id, b.booking_datetime, b.status,
           v.plate_no, p.package_name, p.price,
           s.stage_name
    FROM bookings b
    JOIN vehicles v ON v.vehicle_id=b.vehicle_id
    JOIN packages p ON p.package_id=b.package_id
    LEFT JOIN service_stages s ON s.stage_id=b.current_stage_id
    WHERE b.customer_id=?
    ORDER BY b.booking_id DESC
    """, (uid,))
    bookings = cur.fetchall()

    # history map (latest 4 entries per booking)
    booking_ids = [b[0] for b in bookings]
    cust_history_map = {}

    if booking_ids:
        placeholders = ",".join(["?"] * len(booking_ids))
        cur.execute(f"""
        SELECT h.booking_id, ss.stage_name, h.start_time, h.end_time
        FROM booking_stage_history h
        JOIN service_stages ss ON ss.stage_id=h.stage_id
        WHERE h.booking_id IN ({placeholders})
        ORDER BY h.history_id DESC
        """, booking_ids)

        rows = cur.fetchall()
        for booking_id, stage_name, start_time, end_time in rows:
            cust_history_map.setdefault(booking_id, [])
            if len(cust_history_map[booking_id]) < 4:
                cust_history_map[booking_id].append((stage_name, start_time, end_time))

    conn.close()

    now_min = datetime.now().strftime("%Y-%m-%dT%H:%M")
    return render_template(
        "customer_dashboard.html",
        vehicles=vehicles,
        packages=packages,
        bookings=bookings,
        now_min=now_min,
        cust_history_map=cust_history_map
    )



@app.route("/customer/vehicle/add", methods=["POST"])
def add_vehicle():
    if not require_login() or session["role"] != "Customer":
        return redirect(url_for("login"))

    plate_no = request.form.get("plate_no","").strip()
    make = request.form.get("make","").strip() or None
    model = request.form.get("model","").strip() or None
    color = request.form.get("color","").strip() or None
    vehicle_type = request.form.get("vehicle_type","").strip() or None

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO vehicles(customer_id, plate_no, make, model, color, vehicle_type)
        VALUES(?,?,?,?,?,?)
        """, (session["user_id"], plate_no, make, model, color, vehicle_type))
        conn.commit()
        conn.close()
        flash("Vehicle added.", "success")
    except sqlite3.IntegrityError as e:
        flash(f"Could not add vehicle: {e}", "danger")

    return redirect(url_for("customer_dashboard"))

@app.route("/customer/booking/create", methods=["POST"])
def create_booking():
    if not require_login() or session["role"] != "Customer":
        return redirect(url_for("login"))

    vehicle_id = int(request.form.get("vehicle_id"))
    package_id = int(request.form.get("package_id"))

    scheduled_raw = request.form.get("scheduled_datetime", "").strip()
    scheduled = scheduled_raw.replace("T", " ") if scheduled_raw else None

    notes = request.form.get("notes", "").strip() or None

    conn = get_conn()
    cur = conn.cursor()

    # first stage
    cur.execute("SELECT stage_id FROM service_stages ORDER BY stage_order LIMIT 1")
    first_stage_id = cur.fetchone()[0]

    # create booking
    cur.execute("""
    INSERT INTO bookings(customer_id, vehicle_id, package_id, booking_datetime, scheduled_datetime, status, current_stage_id, notes)
    VALUES(?,?,?,?,?,?,?,?)
    """, (session["user_id"], vehicle_id, package_id, now_str(), scheduled, "Booked", first_stage_id, notes))

    booking_id = cur.lastrowid

    # create initial history entry (system-created by Admin user_id=1)
    cur.execute("""
    INSERT INTO booking_stage_history(booking_id, stage_id, start_time, end_time, updated_by_staff_id)
    VALUES(?,?,?,?,?)
    """, (booking_id, first_stage_id, now_str(), None, 1))

    # payment row (unpaid)
    cur.execute("SELECT price FROM packages WHERE package_id=?", (package_id,))
    pkg_price = cur.fetchone()[0]

    cur.execute("""
    INSERT INTO payments(booking_id, amount, method, payment_status, paid_at)
    VALUES(?,?,?,?,?)
    """, (booking_id, float(pkg_price), "Cash", "Unpaid", None))

    conn.commit()
    conn.close()

    flash(f"Booking created (ID {booking_id}).", "success")
    return redirect(url_for("customer_dashboard"))

# -------- Staff/Admin dashboard --------
@app.route("/staff")
def staff_dashboard():
    if not require_staff():
        return redirect(url_for("login"))

    conn = get_conn()
    cur = conn.cursor()

    # Active bookings
    cur.execute("""
    SELECT b.booking_id, b.booking_datetime, b.status,
           c.full_name, v.plate_no, p.package_name,
           ss.stage_name
    FROM bookings b
    JOIN users c ON c.user_id=b.customer_id
    JOIN vehicles v ON v.vehicle_id=b.vehicle_id
    JOIN packages p ON p.package_id=b.package_id
    LEFT JOIN service_stages ss ON ss.stage_id=b.current_stage_id
    WHERE b.status IN ('Booked','InProgress')
    ORDER BY b.booking_id ASC
    """)
    active = cur.fetchall()

    # History for active bookings (latest 6 rows per booking)
    active_ids = [r[0] for r in active]
    history_map = {}

    if active_ids:
        placeholders = ",".join(["?"] * len(active_ids))
        cur.execute(f"""
        SELECT h.booking_id, ss.stage_name, h.start_time, h.end_time, u.full_name
        FROM booking_stage_history h
        JOIN service_stages ss ON ss.stage_id=h.stage_id
        JOIN users u ON u.user_id=h.updated_by_staff_id
        WHERE h.booking_id IN ({placeholders})
        ORDER BY h.history_id DESC
        """, active_ids)

        rows = cur.fetchall()
        for booking_id, stage_name, start_time, end_time, updated_by in rows:
            history_map.setdefault(booking_id, [])
            if len(history_map[booking_id]) < 6:
                history_map[booking_id].append((stage_name, start_time, end_time, updated_by))

    # All bookings
    cur.execute("""
    SELECT b.booking_id, b.status, c.full_name, v.plate_no, p.package_name
    FROM bookings b
    JOIN users c ON c.user_id=b.customer_id
    JOIN vehicles v ON v.vehicle_id=b.vehicle_id
    JOIN packages p ON p.package_id=b.package_id
    ORDER BY b.booking_id DESC
    """)
    all_bookings = cur.fetchall()

    # Stages
    cur.execute("SELECT stage_id, stage_name FROM service_stages ORDER BY stage_order")
    stages = cur.fetchall()

    # Staff/Admin users list
    cur.execute("SELECT user_id, full_name, role FROM users WHERE role IN ('Staff','Admin') ORDER BY full_name")
    staff_users = cur.fetchall()

    # Packages list
    cur.execute("SELECT package_id, package_name, price, duration_minutes, is_active FROM packages ORDER BY package_id DESC")
    packages = cur.fetchall()

    conn.close()

    return render_template(
        "staff_dashboard.html",
        active=active,
        all_bookings=all_bookings,
        stages=stages,
        staff_users=staff_users,
        packages=packages,
        history_map=history_map
    )

@app.route("/staff/assign", methods=["POST"])
def staff_assign():
    if not require_staff():
        return redirect(url_for("login"))

    booking_id = int(request.form.get("booking_id"))
    staff_ids = request.form.getlist("staff_ids")  # multiple

    conn = get_conn()
    cur = conn.cursor()

    for sid in staff_ids:
        try:
            cur.execute("""
            INSERT INTO booking_staff_assignment(booking_id, staff_id, assigned_at)
            VALUES(?,?,?)
            """, (booking_id, int(sid), now_str()))
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()
    flash("Staff assigned.", "success")
    return redirect(url_for("staff_dashboard"))
@app.route("/staff/package/create", methods=["POST"])
def create_package():
    if not require_staff():
        return redirect(url_for("login"))

    name = request.form.get("package_name","").strip()
    price = float(request.form.get("price", "0"))
    duration = int(request.form.get("duration_minutes", "1"))
    active = 1 if request.form.get("is_active") == "on" else 0

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO packages(package_name, price, duration_minutes, is_active)
        VALUES(?,?,?,?)
        """, (name, price, duration, active))
        conn.commit()
        conn.close()
        flash("Package created.", "success")
    except sqlite3.IntegrityError as e:
        flash(f"Package create failed: {e}", "danger")

    return redirect(url_for("staff_dashboard"))


@app.route("/staff/package/<int:package_id>/toggle", methods=["POST"])
def toggle_package(package_id):
    if not require_staff():
        return redirect(url_for("login"))

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE packages SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE package_id=?", (package_id,))
    conn.commit()
    conn.close()

    flash("Package status updated.", "success")
    return redirect(url_for("staff_dashboard"))
@app.route("/staff/user/create", methods=["POST"])
def create_staff_user():
    if not require_staff():
        return redirect(url_for("login"))

    full_name = request.form.get("full_name","").strip()
    phone = request.form.get("phone","").strip()
    email = request.form.get("email","").strip() or None
    role = request.form.get("role","Staff").strip()
    password = request.form.get("password","").strip()

    if role not in ("Staff", "Admin"):
        flash("Invalid role.", "danger")
        return redirect(url_for("staff_dashboard"))

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO users(full_name, phone, email, password_hash, role, created_at)
        VALUES(?,?,?,?,?,?)
        """, (full_name, phone, email, hash_password(password), role, now_str()))
        conn.commit()
        conn.close()
        flash("Staff/Admin user created.", "success")
    except sqlite3.IntegrityError as e:
        flash(f"User create failed: {e}", "danger")

    return redirect(url_for("staff_dashboard"))

@app.route("/staff/booking/<int:booking_id>/stage", methods=["POST"])
def staff_update_stage(booking_id):
    if not require_staff():
        return redirect(url_for("login"))

    new_stage_id = int(request.form.get("stage_id"))
    end_prev = request.form.get("end_prev") == "on"

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT current_stage_id FROM bookings WHERE booking_id=?", (booking_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        flash("Booking not found.", "danger")
        return redirect(url_for("staff_dashboard"))

    current_stage_id = row[0]

    if end_prev and current_stage_id is not None:
        cur.execute("""
        UPDATE booking_stage_history
        SET end_time=?
        WHERE booking_id=? AND stage_id=? AND end_time IS NULL
        """, (now_str(), booking_id, current_stage_id))

    # status update
    cur.execute("SELECT stage_order FROM service_stages WHERE stage_id=?", (new_stage_id,))
    new_order = cur.fetchone()[0]
    cur.execute("SELECT MAX(stage_order) FROM service_stages")
    max_order = cur.fetchone()[0]
    new_status = "InProgress"
    if new_order == max_order:
        new_status = "Completed"

    cur.execute("UPDATE bookings SET current_stage_id=?, status=? WHERE booking_id=?",
                (new_stage_id, new_status, booking_id))

    cur.execute("""
    INSERT INTO booking_stage_history(booking_id, stage_id, start_time, end_time, updated_by_staff_id)
    VALUES(?,?,?,?,?)
    """, (booking_id, new_stage_id, now_str(), None, session["user_id"]))

    conn.commit()
    conn.close()

    flash("Stage updated and history saved.", "success")
    return redirect(url_for("staff_dashboard"))

@app.route("/staff/payment/<int:booking_id>", methods=["POST"])
def staff_update_payment(booking_id):
    if not require_staff():
        return redirect(url_for("login"))

    method = request.form.get("method")
    status = request.form.get("payment_status")
    paid_at = now_str() if status == "Paid" else None

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    UPDATE payments SET method=?, payment_status=?, paid_at=? WHERE booking_id=?
    """, (method, status, paid_at, booking_id))
    conn.commit()
    conn.close()

    flash("Payment updated.", "success")
    return redirect(url_for("staff_dashboard"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

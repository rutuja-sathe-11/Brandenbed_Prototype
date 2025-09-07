from flask import Flask, render_template, request, redirect, url_for, jsonify, session, send_file, flash
import sqlite3, json, csv, io, os
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

DB = Path(__file__).parent / "data.db"
STATIC = Path(__file__).parent / "static"
UPLOADS = STATIC / "uploads"
UPLOADS.mkdir(parents=True, exist_ok=True)

def get_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(seed=True):
    conn = get_conn(); c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        property TEXT, tenant TEXT, amount REAL, payment_type TEXT, txn_id TEXT, status TEXT DEFAULT 'Pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject TEXT, message TEXT, status TEXT DEFAULT 'Pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS properties (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT, district TEXT, status TEXT DEFAULT 'Available', price REAL DEFAULT 0, image TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, role TEXT, permissions TEXT
    )''')
    conn.commit()
    # create default users and seed data if empty
    c.execute("SELECT COUNT(*) FROM users"); ifu = c.fetchone()[0]
    if ifu == 0 and seed:
        admin_pw = generate_password_hash("adminpass")
        c.execute("INSERT INTO users(username,password_hash,role) VALUES (?,?,?)", ("admin", admin_pw, "Admin"))
        staff_pw = generate_password_hash("staffpass")
        c.execute("INSERT INTO users(username,password_hash,role) VALUES (?,?,?)", ("staff", staff_pw, "Staff"))
    c.execute("SELECT COUNT(*) FROM properties"); if_props = c.fetchone()[0]
    if if_props == 0 and seed:
        props = [
            ("Sunny 2BHK in Mitte","Mitte","Available",1200,"property1.jpg"),
            ("Cozy Studio in Kreuzberg","Kreuzberg","Occupied",800,"property2.jpg"),
            ("Family Flat in Prenzlauer Berg","Prenzlauer Berg","Available",1500,"property3.jpg"),
            ("Modern Loft in Charlottenburg","Charlottenburg","Occupied",2000,None),
            ("Budget Room in Neukölln","Neukölln","Available",600,None)
        ]
        # handle NULLs by replacing with empty string
        props = [(p[0],p[1],p[2],p[3], p[4] or "") for p in props]
        c.executemany("INSERT INTO properties(title,district,status,price,image) VALUES (?,?,?,?,?)", props)
    c.execute("SELECT COUNT(*) FROM employees"); if_emps = c.fetchone()[0]
    if if_emps == 0 and seed:
        emps=[("Alice","Admin","all"),("Bob","Manager","manage_properties"),("Clara","Support","queries")]
        c.executemany("INSERT INTO employees(name,role,permissions) VALUES (?,?,?)", emps)
    c.execute("SELECT COUNT(*) FROM payments"); if_pays = c.fetchone()[0]
    if if_pays == 0 and seed:
        pays=[("Sunny 2BHK in Mitte","John Doe",1200,"Bank Transfer","TXN001","Confirmed"),
              ("Cozy Studio in Kreuzberg","Jane Smith",800,"Cash","TXN002","Confirmed"),
              ("Family Flat in Prenzlauer Berg","Paul Müller",1500,"Card","TXN003","Pending"),
              ("Modern Loft in Charlottenburg","Anna Schmidt",2000,"Bank Transfer","TXN004","Confirmed"),
              ("Budget Room in Neukölln","Leo Weber",600,"UPI","TXN005","Pending")]
        c.executemany("INSERT INTO payments(property,tenant,amount,payment_type,txn_id,status) VALUES (?,?,?,?,?,?)", pays)
    c.execute("SELECT COUNT(*) FROM queries"); if_qs = c.fetchone()[0]
    if if_qs == 0 and seed:
        qs=[("WiFi Issue","Internet is down in my flat","Pending"),
            ("Rent Confirmation","Did you receive my rent payment?","In Progress"),
            ("Repair Request","The heater is not working.","Resolved")]
        c.executemany("INSERT INTO queries(subject,message,status) VALUES (?,?,?)", qs)
    conn.commit()
    conn.close()

app = Flask(__name__)
app.secret_key = 'replace-this-with-a-secure-random-key'
init_db()

# auth helpers
def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        if session.get('role') != 'Admin':
            return "Forbidden: Admins only", 403
        return f(*args, **kwargs)
    return wrapped

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username'); password = request.form.get('password')
        conn = get_conn(); c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        row = c.fetchone(); conn.close()
        if row and check_password_hash(row['password_hash'], password):
            session['user_id'] = row['id']; session['username'] = row['username']; session['role'] = row['role']
            return redirect(request.args.get('next') or url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM properties"); props = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM payments"); pays = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM queries"); qs = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM employees"); emps = c.fetchone()[0]
    conn.close()
    return render_template('dashboard.html', props=props, pays=pays, qs=qs, emps=emps, username=session.get('username'), role=session.get('role'))

# Payments endpoints (protected for modifications)
@app.route('/api/payments', methods=['GET','POST'])
def api_payments():
    conn = get_conn(); c = conn.cursor()
    if request.method == 'POST':
        # require login to post payments
        if 'user_id' not in session:
            return jsonify({'error':'login required'}), 401
        data = request.form or request.json
        c.execute("INSERT INTO payments(property,tenant,amount,payment_type,txn_id,status) VALUES (?,?,?,?,?,?)",
                  (data.get('property'), data.get('tenant'), float(data.get('amount') or 0), data.get('payment_type'), data.get('txn_id'), data.get('status') or 'Pending'))
        conn.commit(); conn.close(); return jsonify({'ok':True})
    else:
        c.execute("SELECT * FROM payments ORDER BY created_at DESC")
        rows = [dict(r) for r in c.fetchall()]; conn.close(); return jsonify(rows)

@app.route('/api/payments/<int:pid>', methods=['PATCH','DELETE'])
@login_required
def payment_modify(pid):
    conn = get_conn(); c = conn.cursor()
    if request.method == 'PATCH':
        data = request.get_json()
        c.execute("UPDATE payments SET status=? WHERE id=?", (data.get('status'), pid))
        conn.commit(); conn.close(); return jsonify({'updated':True})
    else:
        # only admin can delete payments
        if session.get('role') != 'Admin':
            return jsonify({'error':'admin required'}), 403
        c.execute("DELETE FROM payments WHERE id=?", (pid,)); conn.commit(); conn.close(); return jsonify({'deleted':True})

# Properties pages and APIs
@app.route('/properties')
@login_required
def properties_page():
    return render_template('properties.html', username=session.get('username'), role=session.get('role'))

@app.route('/api/properties', methods=['GET','POST'])
def api_properties():
    conn = get_conn(); c = conn.cursor()
    if request.method == 'POST':
        if 'user_id' not in session:
            return jsonify({'error':'login required'}), 401
        data = request.form or request.json
        # handle file upload
        image_filename = ""
        if 'image' in request.files:
            f = request.files['image']
            if f and f.filename:
                fn = secure_filename(f.filename)
                dest = UPLOADS / fn
                f.save(dest)
                image_filename = fn
        if data.get('id'):
            # update
            if image_filename:
                c.execute("UPDATE properties SET title=?,district=?,status=?,price=?,image=? WHERE id=?",
                          (data.get('title'), data.get('district'), data.get('status'), float(data.get('price') or 0), image_filename, int(data.get('id'))))
            else:
                c.execute("UPDATE properties SET title=?,district=?,status=?,price=? WHERE id=?",
                          (data.get('title'), data.get('district'), data.get('status'), float(data.get('price') or 0), int(data.get('id'))))
        else:
            c.execute("INSERT INTO properties(title,district,status,price,image) VALUES (?,?,?,?,?)",
                      (data.get('title'), data.get('district'), data.get('status'), float(data.get('price') or 0), image_filename))
        conn.commit(); conn.close(); return jsonify({'ok':True})
    else:
        q = "SELECT * FROM properties ORDER BY id DESC"
        c.execute(q); rows = [dict(r) for r in c.fetchall()]; conn.close(); return jsonify(rows)

@app.route('/api/properties/<int:pid>', methods=['DELETE'])
@login_required
def api_properties_delete(pid):
    # only admin can delete properties
    if session.get('role') != 'Admin':
        return jsonify({'error':'admin required'}), 403
    conn = get_conn(); c = conn.cursor(); c.execute("DELETE FROM properties WHERE id=?", (pid,)); conn.commit(); conn.close(); return jsonify({'deleted':True})

# Employees CRUD - admin only for delete
@app.route('/employees')
@login_required
def employees_page():
    return render_template('employees.html', username=session.get('username'), role=session.get('role'))

@app.route('/api/employees', methods=['GET','POST'])
@login_required
def api_employees():
    conn = get_conn(); c = conn.cursor()
    if request.method == 'POST':
        data = request.form or request.json
        if data.get('id'):
            c.execute("UPDATE employees SET name=?,role=?,permissions=? WHERE id=?",
                      (data.get('name'), data.get('role'), data.get('permissions'), int(data.get('id'))))
        else:
            c.execute("INSERT INTO employees(name,role,permissions) VALUES (?,?,?)",
                      (data.get('name'), data.get('role'), data.get('permissions')))
        conn.commit(); conn.close(); return jsonify({'ok':True})
    else:
        c.execute("SELECT * FROM employees ORDER BY id DESC"); rows=[dict(r) for r in c.fetchall()]; conn.close(); return jsonify(rows)

@app.route('/api/employees/<int:eid>', methods=['DELETE'])
@login_required
def api_employees_delete(eid):
    if session.get('role') != 'Admin':
        return jsonify({'error':'admin required'}), 403
    conn = get_conn(); c = conn.cursor(); c.execute("DELETE FROM employees WHERE id=?", (eid,)); conn.commit(); conn.close(); return jsonify({'deleted':True})

# Queries endpoints (protected to create)
@app.route('/api/queries', methods=['GET','POST','PATCH'])
def api_queries():
    conn = get_conn(); c = conn.cursor()
    if request.method == 'POST':
        if 'user_id' not in session:
            return jsonify({'error':'login required'}), 401
        data = request.form or request.json
        c.execute("INSERT INTO queries(subject,message,status) VALUES (?,?,?)", (data.get('subject'), data.get('message'), data.get('status') or 'Pending'))
        conn.commit(); conn.close(); return jsonify({'ok':True})
    elif request.method == 'PATCH':
        data = request.get_json(); c.execute("UPDATE queries SET status=? WHERE id=?", (data.get('status'), int(data.get('id')))); conn.commit(); conn.close(); return jsonify({'updated':True})
    else:
        c.execute("SELECT * FROM queries ORDER BY created_at DESC"); rows=[dict(r) for r in c.fetchall()]; conn.close(); return jsonify(rows)

@app.route('/api/properties/status')
def properties_status():
    conn = get_conn(); c = conn.cursor(); c.execute("SELECT status, COUNT(*) FROM properties GROUP BY status"); rows = c.fetchall(); conn.close(); return jsonify({r[0]: r[1] for r in rows})

# CSV Export/Import endpoints
@app.route('/export/<what>')
@login_required
def export_csv(what):
    conn = get_conn(); c = conn.cursor()
    si = io.StringIO(); cw = csv.writer(si)
    if what == 'properties':
        c.execute("SELECT id,title,district,status,price,image FROM properties ORDER BY id")
        cw.writerow(['id','title','district','status','price','image'])
        for r in c.fetchall(): cw.writerow([r['id'], r['title'], r['district'], r['status'], r['price'], r['image']])
    elif what == 'employees':
        c.execute("SELECT id,name,role,permissions FROM employees ORDER BY id")
        cw.writerow(['id','name','role','permissions'])
        for r in c.fetchall(): cw.writerow([r['id'], r['name'], r['role'], r['permissions']])
    elif what == 'payments':
        c.execute("SELECT id,property,tenant,amount,payment_type,txn_id,status,created_at FROM payments ORDER BY id")
        cw.writerow(['id','property','tenant','amount','payment_type','txn_id','status','created_at'])
        for r in c.fetchall(): cw.writerow([r['id'], r['property'], r['tenant'], r['amount'], r['payment_type'], r['txn_id'], r['status'], r['created_at']])
    else:
        return "Unknown export type", 400
    conn.close()
    si.seek(0)
    return send_file(io.BytesIO(si.getvalue().encode('utf-8')), mimetype='text/csv', download_name=f'{what}.csv', as_attachment=True)

@app.route('/import/<what>', methods=['POST'])
@login_required
def import_csv(what):
    if 'file' not in request.files:
        return "No file uploaded", 400
    f = request.files['file']
    stream = io.StringIO(f.stream.read().decode('utf-8'))
    reader = csv.DictReader(stream)
    conn = get_conn(); c = conn.cursor()
    if what == 'properties':
        for row in reader:
            c.execute("INSERT INTO properties(title,district,status,price,image) VALUES (?,?,?,?,?)",
                      (row.get('title'), row.get('district'), row.get('status') or 'Available', float(row.get('price') or 0), row.get('image') or ""))
    elif what == 'employees':
        for row in reader:
            c.execute("INSERT INTO employees(name,role,permissions) VALUES (?,?,?)", (row.get('name'), row.get('role'), row.get('permissions')))
    elif what == 'payments':
        for row in reader:
            c.execute("INSERT INTO payments(property,tenant,amount,payment_type,txn_id,status) VALUES (?,?,?,?,?,?)",
                      (row.get('property'), row.get('tenant'), float(row.get('amount') or 0), row.get('payment_type'), row.get('txn_id'), row.get('status') or 'Pending'))
    else:
        return "Unknown import type", 400
    conn.commit(); conn.close(); return jsonify({'imported':True})

# serve uploaded images (Flask static will also serve /static/uploads)
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return redirect(url_for('static', filename=f'uploads/{filename}'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)

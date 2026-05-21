"""
SWE210 - Secure ISU Portal
Features: PBKDF2-SHA256 Hashing, AES-256-CBC Encryption, Instructor-Level RBAC Data Isolation
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
import hashlib, hmac, os, base64, sqlite3, re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.secret_key = b'swe210-secure-portal-key-2026'

DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')
AES_KEY = base64.b64decode("rdMUTPZ0vTkWCpcbfCu6UceD8V+ByUseczDHeY4yXpg=")

# ─────────────────────────────────────────────
#  CRYPTOGRAPHY CORE
# ─────────────────────────────────────────────

def encrypt_data(plaintext: str) -> str:
    if not plaintext: return ""
    iv = os.urandom(16)
    data = plaintext.encode()
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)
    enc = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend()).encryptor()
    return base64.b64encode(iv + enc.update(data) + enc.finalize()).decode()

def decrypt_data(ciphertext: str) -> str:
    if not ciphertext: return ""
    try:
        raw = base64.b64decode(ciphertext.encode())
        iv, ct = raw[:16], raw[16:]
        dec = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend()).decryptor()
        padded = dec.update(ct) + dec.finalize()
        return padded[:-padded[-1]].decode()
    except Exception:
        return "Decryption Error"

def hash_password(password: str) -> str:
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return base64.b64encode(salt + key).decode()

def verify_password(password: str, stored_hash: str) -> bool:
    decoded = base64.b64decode(stored_hash.encode())
    salt, key = decoded[:32], decoded[32:]
    new_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return hmac.compare_digest(key, new_key)

# ─────────────────────────────────────────────
#  DATABASE ARCHITECTURE & SEEDING (30 REALISTIC STUDENTS)
# ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

COURSES = {
    'SWE210': 'Software Security',
    'COE206': 'Analysis of Algorithms',
    'SWE206': 'Computing Systems',
    'PHYS102': 'Physics 2',
    'ENS112': 'Occupational Health and Safety',
    'MATH112': 'Linear Algebra with Applications'
}

def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT    UNIQUE NOT NULL,
                password_hash TEXT   NOT NULL,
                role         TEXT    NOT NULL DEFAULT 'user',
                email        TEXT    NOT NULL,
                phone        TEXT    NOT NULL,
                student_no   TEXT,
                department   TEXT,
                course_code  TEXT,
                created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS academic_records (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT NOT NULL,
                course_code  TEXT NOT NULL,
                midterm      INTEGER DEFAULT 0,
                final        INTEGER DEFAULT 0,
                attendance   INTEGER DEFAULT 0,
                UNIQUE(username, course_code),
                FOREIGN KEY(username) REFERENCES users(username)
            )
        ''')
        conn.commit()
        
        if conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
            # 1. Seed Instructors (Admins)
            instructors = [
                ('femilda.bai', 'Shobana@2026', 'SWE210', 'femilda.bai@istinye.edu.tr', '+905000000001'),
                ('ali.kazem', 'Kazem@2026', 'COE206', 'ali.kazem@istinye.edu.tr', '+905000000002'),
                ('ali.ghaffari', 'Ghaffari@2026', 'SWE206', 'ali.ghaffari@istinye.edu.tr', '+905000000003'),
                ('nadir.ghazanfari', 'Nadir@2026', 'PHYS102', 'nadir.ghazanfari@istinye.edu.tr', '+905000000004'),
                ('nuri.bingol', 'Nuri@2026', 'ENS112', 'nuri.bingol@istinye.edu.tr', '+905000000005'),
                ('math.staff', 'Linear@2026', 'MATH112', 'linear.algebra@istinye.edu.tr', '+905000000006'),
            ]
            for username, pwd, c_code, email, phone in instructors:
                conn.execute('''
                    INSERT INTO users (username, password_hash, role, email, phone, student_no, department, course_code)
                    VALUES (?, ?, 'admin', ?, ?, ?, ?, ?)
                ''', (username, hash_password(pwd), encrypt_data(email), encrypt_data(phone), encrypt_data("N/A"), encrypt_data("Faculty of Engineering"), c_code))

            # 2. Programmatically Generation of 30 Realistic Students
            departments_pool = ['Computer Engineering', 'Software Engineering']
            first_names = ["ahmet", "ayse", "mehmet", "fatma", "mustafa", "zeynep", "ali", "elif", "hasan", "merve",
                           "kemal", "zehra", "omer", "cemre", "emre", "gizem", "burak", "sinem", "volkan", "ece",
                           "deniz", "melis", "baris", "selin", "tolga", "ceren", "can", "irem", "onur", "asli"]
            last_names = ["yilmaz", "kaya", "demir", "celik", "sahin", "yildiz", "yildirim", "ozturk", "aydin", "ozdemir",
                          "arslan", "dogan", "kilic", "aslan", "cetin", "kara", "koc", "kurt", "ozkan", "simsek",
                          "polat", "ozcan", "korkmaz", "cakir", "erdogan", "yavuz", "can", "turan", "aktas", "yalcin"]

            for i in range(30):
                username = f"{first_names[i]}.{last_names[i]}"
                password = f"Student@{i+1:02d}2026"
                std_no = f"230103{100+(i+1)}" 
                email = f"{std_no}@stu.istinye.edu.tr"
                phone = f"0532100{(i+1):04d}" 
                dept = departments_pool[i % 2]
                
                conn.execute('''
                    INSERT INTO users (username, password_hash, role, email, phone, student_no, department, course_code)
                    VALUES (?, ?, 'user', ?, ?, ?, ?, NULL)
                ''', (username, hash_password(password), encrypt_data(email), encrypt_data(phone), encrypt_data(std_no), encrypt_data(dept)))
                
                for c_code in COURSES.keys():
                    conn.execute('''
                        INSERT INTO academic_records (username, course_code, midterm, final, attendance)
                        VALUES (?, ?, 0, 0, 0)
                    ''', (username, c_code))
            conn.commit()

def create_student_user(username, password, email, phone, student_no, department):
    with get_db() as conn:
        conn.execute('''
            INSERT INTO users (username, password_hash, role, email, phone, student_no, department, course_code)
            VALUES (?, ?, 'user', ?, ?, ?, ?, NULL)
        ''', (username, hash_password(password), encrypt_data(email), encrypt_data(phone), encrypt_data(student_no), encrypt_data(department)))
        for c_code in COURSES.keys():
            conn.execute('''
                INSERT INTO academic_records (username, course_code, midterm, final, attendance)
                VALUES (?, ?, 0, 0, 0)
            ''', (username, c_code))
        conn.commit()

# ─────────────────────────────────────────────
#  SECURITY GUARDS (DECORATORS)
# ─────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            flash('Session expired. Please login again.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Access Denied: Insufficient Privileges.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return wrapper

# ─────────────────────────────────────────────
#  CONTROLLERS / ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        with get_db() as conn:
            row = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            
        if row and verify_password(password, row['password_hash']):
            session['username'] = username
            session['role'] = row['role']
            session['course_code'] = row['course_code']
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid cryptographic tokens or credentials.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        student_no = request.form.get('student_no', '').strip()
        department = request.form.get('department', '').strip()
        
        if not re.match(r'^\d{10}$', student_no):
            flash('Registration Rejected: Student ID must be exactly 10 digits.', 'danger')
            return render_template('register.html')
            
        email = f"{student_no}@stu.istinye.edu.tr"
        phone = request.form.get('phone', '').strip()
        
        if not (phone.startswith('05') and len(phone) == 11 and phone.isdigit()):
            flash('Registration Rejected: Phone must be 11 digits and start with 05.', 'danger')
            return render_template('register.html')

        with get_db() as conn:
            exists = conn.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone()
        if exists:
            flash('Username is already registered in the ledger.', 'danger')
            return render_template('register.html')

        create_student_user(username, password, email, phone, student_no, department)
        flash('Registration completed successfully. All academic tracks instantiated.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
        records_db = conn.execute('''
            SELECT r.* FROM academic_records r 
            WHERE r.username = ?
        ''', (session['username'],)).fetchall()
        
    records = []
    for r in records_db:
        rd = dict(r)
        rd['course_name'] = COURSES.get(rd['course_code'], 'Unknown Track')
        records.append(rd)

    return render_template('dashboard.html',
                           username=user['username'],
                           role=user['role'],
                           email=decrypt_data(user['email']),
                           phone=decrypt_data(user['phone']),
                           student_no=decrypt_data(user['student_no']),
                           department=decrypt_data(user['department']),
                           encrypted_email=user['email'],
                           encrypted_phone=user['phone'],
                           encrypted_student_no=user['student_no'],
                           course_code=user['course_code'],
                           records=records)

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    instructor_course = session.get('course_code')
    
    with get_db() as conn:
        rows_grading = conn.execute('''
            SELECT u.id, u.username, u.email, u.phone, u.student_no, u.department,
                   r.midterm, r.final, r.attendance, r.course_code
            FROM users u
            JOIN academic_records r ON u.username = r.username
            WHERE u.role = 'user' AND r.course_code = ?
            ORDER BY u.id
        ''', (instructor_course,)).fetchall()
        
        rows_raw = conn.execute('SELECT * FROM users ORDER BY id').fetchall()
        
    students = []
    for r in rows_grading:
        s = dict(r)
        s['email_dec'] = decrypt_data(s['email'])
        s['phone_dec'] = decrypt_data(s['phone'])
        s['student_no_dec'] = decrypt_data(s['student_no'])
        s['department_dec'] = decrypt_data(s['department'])
        students.append(s)
        
    all_users = [dict(r) for r in rows_raw]
        
    return render_template('admin.html', 
                           students=students, 
                           all_users=all_users, 
                           course_code=instructor_course, 
                           course_name=COURSES.get(instructor_course))

@app.route('/update_grades', methods=['POST'])
@login_required
@admin_required
def update_grades():
    target_username = request.form.get('username')
    midterm = request.form.get('midterm', type=int)
    final = request.form.get('final', type=int)
    attendance = request.form.get('attendance', type=int)
    instructor_course = session.get('course_code')

    with get_db() as conn:
        conn.execute('''
            UPDATE academic_records 
            SET midterm = ?, final = ?, attendance = ? 
            WHERE username = ? AND course_code = ?
        ''', (midterm, final, attendance, target_username, instructor_course))
        conn.commit()

    flash(f'Ledger entries successfully validated and committed for student: {target_username}.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Cryptographic session safely terminated.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
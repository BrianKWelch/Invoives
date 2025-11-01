# invoice_app.py
# Solo PC Invoicing App (Streamlit + SQLite)
# - Unique widget keys to avoid StreamlitDuplicateElementId
# - Safe formatting for None/empty rates to avoid TypeError
# - Contractors, Clients, Rate overrides, Hour entry, Invoice PDF, Payables PDF, Reports
# - NEW: Payees (finder fees) with rules + payouts PDF

import os
import sqlite3
import base64
import calendar
from datetime import datetime
from typing import Optional

import pandas as pd
import streamlit as st
import bcrypt
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

DB_PATH = "data.db"
INVOICE_DIR = "invoices"
PAYABLES_DIR = "payables"
PAYEES_DIR = "payees"

os.makedirs(INVOICE_DIR, exist_ok=True)
os.makedirs(PAYABLES_DIR, exist_ok=True)
os.makedirs(PAYEES_DIR, exist_ok=True)

# -----------------------------
# Utilities
# -----------------------------

def safe_float(x: Optional[float]) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0


def dollars(x: Optional[float]) -> str:
    if x is None:
        return "$0.00"
    try:
        return f"${float(x):,.2f}"
    except Exception:
        return "$0.00"


# -----------------------------
# Database helpers
# -----------------------------

def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Users table for authentication
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS contractors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            default_bill_rate REAL NOT NULL,
            default_pay_rate REAL NOT NULL,
            UNIQUE (user_id, name),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            address TEXT DEFAULT '',
            email TEXT DEFAULT '',
            UNIQUE (user_id, name),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contractor_id INTEGER NOT NULL,
            client_id INTEGER NOT NULL,
            bill_rate REAL,
            pay_rate REAL,
            UNIQUE (contractor_id, client_id),
            FOREIGN KEY(contractor_id) REFERENCES contractors(id),
            FOREIGN KEY(client_id) REFERENCES clients(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS timesheets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            contractor_id INTEGER NOT NULL,
            client_id INTEGER NOT NULL,
            year INTEGER NOT NULL,
            month INTEGER NOT NULL,
            hours REAL NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE (user_id, contractor_id, client_id, year, month),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(contractor_id) REFERENCES contractors(id),
            FOREIGN KEY(client_id) REFERENCES clients(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            client_id INTEGER NOT NULL,
            year INTEGER NOT NULL,
            month INTEGER NOT NULL,
            total_amount REAL NOT NULL,
            pdf_path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE (user_id, client_id, year, month),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(client_id) REFERENCES clients(id)
        )
        """
    )

    # NEW: Payees & payee_rules (finder fees)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS payees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            email TEXT DEFAULT '',
            UNIQUE (user_id, name),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS payee_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payee_id INTEGER NOT NULL,
            contractor_id INTEGER NOT NULL,
            client_id INTEGER NOT NULL,
            amount_per_hour REAL NOT NULL,
            UNIQUE (payee_id, contractor_id, client_id),
            FOREIGN KEY(payee_id) REFERENCES payees(id),
            FOREIGN KEY(contractor_id) REFERENCES contractors(id),
            FOREIGN KEY(client_id) REFERENCES clients(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            client_id INTEGER NOT NULL,
            year INTEGER NOT NULL,
            month INTEGER NOT NULL,
            category TEXT NOT NULL,
            description TEXT DEFAULT '',
            amount REAL NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(client_id) REFERENCES clients(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS company_info (
            id INTEGER PRIMARY KEY DEFAULT 1,
            user_id INTEGER NOT NULL UNIQUE,
            name TEXT NOT NULL DEFAULT 'Your Company Name',
            address TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            email TEXT DEFAULT '',
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )
    
    # Add banking columns if they don't exist (for existing databases)
    try:
        cur.execute("ALTER TABLE company_info ADD COLUMN bank_name TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        cur.execute("ALTER TABLE company_info ADD COLUMN account_number TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        cur.execute("ALTER TABLE company_info ADD COLUMN routing_number TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Note: company_info will be created per user on first access
    
    conn.commit()
    conn.close()


# -----------------------------
# Authentication functions
# -----------------------------

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))


def register_user(username: str, email: str, password: str) -> tuple[bool, str]:
    """Register a new user. Returns (success, message)"""
    conn = get_conn()
    cur = conn.cursor()
    
    try:
        # Check if username already exists
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            conn.close()
            return False, "Username already exists"
        
        # Check if email already exists
        cur.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cur.fetchone():
            conn.close()
            return False, "Email already exists"
        
        # Create user
        password_hash = hash_password(password)
        created_at = datetime.utcnow().isoformat()
        cur.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, created_at)
        )
        user_id = cur.lastrowid
        
        # Create default company info for this user
        cur.execute(
            """
            INSERT INTO company_info (user_id, name, address, phone, email, bank_name, account_number, routing_number)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, 'Your Company Name', '', '', '', '', '', '')
        )
        
        conn.commit()
        conn.close()
        return True, "Registration successful!"
    
    except Exception as e:
        conn.rollback()
        conn.close()
        return False, f"Registration failed: {str(e)}"


def login_user(username: str, password: str) -> tuple[bool, Optional[int], str]:
    """Login a user. Returns (success, user_id, message)"""
    conn = get_conn()
    cur = conn.cursor()
    
    try:
        cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        result = cur.fetchone()
        
        if not result:
            conn.close()
            return False, None, "Invalid username or password"
        
        user_id, password_hash = result
        
        if not verify_password(password, password_hash):
            conn.close()
            return False, None, "Invalid username or password"
        
        conn.close()
        return True, user_id, "Login successful!"
    
    except Exception as e:
        conn.close()
        return False, None, f"Login failed: {str(e)}"


def get_current_user_id() -> Optional[int]:
    """Get the current logged-in user ID from session state"""
    return st.session_state.get('user_id')


def is_authenticated() -> bool:
    """Check if user is authenticated"""
    return get_current_user_id() is not None


def logout_user():
    """Logout the current user"""
    if 'user_id' in st.session_state:
        del st.session_state['user_id']
    if 'username' in st.session_state:
        del st.session_state['username']


def show_auth_page():
    """Show login/registration page"""
    st.title("Solo Invoicing App")
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        st.subheader("Login")
        with st.form("login_form"):
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            submit = st.form_submit_button("Login")
            
            if submit:
                if username and password:
                    success, user_id, message = login_user(username, password)
                    if success:
                        st.session_state['user_id'] = user_id
                        st.session_state['username'] = username
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)
                else:
                    st.error("Please enter both username and password")
    
    with tab2:
        st.subheader("Register New Account")
        with st.form("register_form"):
            username = st.text_input("Username", key="register_username")
            email = st.text_input("Email", key="register_email")
            password = st.text_input("Password", type="password", key="register_password")
            password_confirm = st.text_input("Confirm Password", type="password", key="register_password_confirm")
            submit = st.form_submit_button("Register")
            
            if submit:
                if not username or not email or not password:
                    st.error("Please fill in all fields")
                elif password != password_confirm:
                    st.error("Passwords do not match")
                elif len(password) < 6:
                    st.error("Password must be at least 6 characters long")
                else:
                    success, message = register_user(username, email, password)
                    if success:
                        st.success(message)
                        st.info("You can now login with your credentials")
                    else:
                        st.error(message)


@st.cache_data(show_spinner=False)
def list_contractors():
    user_id = get_current_user_id()
    if not user_id:
        return pd.DataFrame()
    conn = get_conn()
    df = pd.read_sql_query(
        "SELECT id, name, default_bill_rate AS bill_rate, default_pay_rate AS pay_rate FROM contractors WHERE user_id = ? ORDER BY name",
        conn,
        params=(user_id,),
    )
    conn.close()
    return df


@st.cache_data(show_spinner=False)
def list_clients():
    user_id = get_current_user_id()
    if not user_id:
        return pd.DataFrame()
    conn = get_conn()
    df = pd.read_sql_query(
        "SELECT id, name, address, email FROM clients WHERE user_id = ? ORDER BY name",
        conn,
        params=(user_id,),
    )
    conn.close()
    return df


@st.cache_data(show_spinner=False)
def list_payees():
    user_id = get_current_user_id()
    if not user_id:
        return pd.DataFrame()
    conn = get_conn()
    df = pd.read_sql_query(
        "SELECT id, name, email FROM payees WHERE user_id = ? ORDER BY name",
        conn,
        params=(user_id,),
    )
    conn.close()
    return df


def upsert_contractor(name: str, bill: float, pay: float):
    user_id = get_current_user_id()
    if not user_id:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO contractors(user_id, name, default_bill_rate, default_pay_rate)
        VALUES (?, ?, ?, ?) ON CONFLICT(user_id, name) DO UPDATE SET
        default_bill_rate=excluded.default_bill_rate,
        default_pay_rate=excluded.default_pay_rate
        """,
        (user_id, name.strip(), bill, pay),
    )
    conn.commit()
    conn.close()
    list_contractors.clear()


def update_contractor(contractor_id: int, name: str, bill: float, pay: float):
    user_id = get_current_user_id()
    if not user_id:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE contractors SET name=?, default_bill_rate=?, default_pay_rate=? WHERE id=? AND user_id=?",
        (name.strip(), bill, pay, contractor_id, user_id),
    )
    conn.commit()
    conn.close()
    list_contractors.clear()


def delete_contractor(contractor_id: int):
    user_id = get_current_user_id()
    if not user_id:
        return
    conn = get_conn()
    cur = conn.cursor()
    # Delete related records
    cur.execute("DELETE FROM timesheets WHERE contractor_id=? AND user_id=?", (contractor_id, user_id))
    cur.execute("DELETE FROM assignments WHERE contractor_id=?", (contractor_id,))
    cur.execute("DELETE FROM payee_rules WHERE contractor_id=?", (contractor_id,))
    cur.execute("DELETE FROM contractors WHERE id=? AND user_id=?", (contractor_id, user_id))
    conn.commit()
    conn.close()
    list_contractors.clear()


def upsert_client(name: str, address: str, email: str):
    user_id = get_current_user_id()
    if not user_id:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO clients(user_id, name, address, email)
        VALUES (?, ?, ?, ?) ON CONFLICT(user_id, name) DO UPDATE SET
        address=excluded.address,
        email=excluded.email
        """,
        (user_id, name.strip(), address.strip(), email.strip()),
    )
    conn.commit()
    conn.close()
    list_clients.clear()


def update_client(client_id: int, name: str, address: str, email: str):
    user_id = get_current_user_id()
    if not user_id:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE clients SET name=?, address=?, email=? WHERE id=? AND user_id=?",
        (name.strip(), address.strip(), email.strip(), client_id, user_id),
    )
    conn.commit()
    conn.close()
    list_clients.clear()


def delete_client(client_id: int):
    user_id = get_current_user_id()
    if not user_id:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM timesheets WHERE client_id=? AND user_id=?", (client_id, user_id))
    cur.execute("DELETE FROM assignments WHERE client_id=?", (client_id,))
    cur.execute("DELETE FROM invoices WHERE client_id=? AND user_id=?", (client_id, user_id))
    cur.execute("DELETE FROM expenses WHERE client_id=? AND user_id=?", (client_id, user_id))
    cur.execute("DELETE FROM payee_rules WHERE client_id=?", (client_id,))
    cur.execute("DELETE FROM clients WHERE id=? AND user_id=?", (client_id, user_id))
    conn.commit()
    conn.close()
    list_clients.clear()


def upsert_payee(name: str, email: str = ""):
    user_id = get_current_user_id()
    if not user_id:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO payees(user_id, name, email)
        VALUES(?, ?, ?)
        ON CONFLICT(user_id, name) DO UPDATE SET email=excluded.email
        """,
        (user_id, name.strip(), email.strip()),
    )
    conn.commit()
    conn.close()
    list_payees.clear()


def delete_payee(payee_id: int):
    user_id = get_current_user_id()
    if not user_id:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM payee_rules WHERE payee_id=?", (payee_id,))
    cur.execute("DELETE FROM payees WHERE id=? AND user_id=?", (payee_id, user_id))
    conn.commit()
    conn.close()
    list_payees.clear()


def set_payee_rule(payee_id: int, contractor_id: int, client_id: int, amount_per_hour: float):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO payee_rules(payee_id, contractor_id, client_id, amount_per_hour)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(payee_id, contractor_id, client_id) DO UPDATE SET
        amount_per_hour = excluded.amount_per_hour
        """,
        (payee_id, contractor_id, client_id, amount_per_hour),
    )
    conn.commit()
    conn.close()


def update_payee_rule(rule_id: int, amount_per_hour: float):
    """Update an existing payee rule"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE payee_rules SET amount_per_hour=? WHERE id=?",
        (amount_per_hour, rule_id),
    )
    conn.commit()
    conn.close()


def delete_payee_rule(rule_id: int):
    """Delete a payee rule"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM payee_rules WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()


def fetch_payee_rules():
    """Fetch all payee rules with names for display"""
    user_id = get_current_user_id()
    if not user_id:
        return pd.DataFrame()
    conn = get_conn()
    q = """
        SELECT 
            pr.id,
            pr.payee_id,
            pr.contractor_id,
            pr.client_id,
            pr.amount_per_hour,
            p.name AS payee_name,
            c.name AS contractor_name,
            cl.name AS client_name
        FROM payee_rules pr
        JOIN payees p ON p.id = pr.payee_id AND p.user_id = ?
        JOIN contractors c ON c.id = pr.contractor_id AND c.user_id = ?
        JOIN clients cl ON cl.id = pr.client_id AND cl.user_id = ?
        ORDER BY p.name, cl.name, c.name
    """
    df = pd.read_sql_query(q, conn, params=(user_id, user_id, user_id))
    conn.close()
    return df


def fetch_payee_payouts(year: int, month: int):
    user_id = get_current_user_id()
    if not user_id:
        return pd.DataFrame()
    conn = get_conn()
    q = """
        SELECT
            pr.id AS rule_id,
            p.id AS payee_id,
            p.name AS payee_name,
            c.name AS contractor_name,
            cl.name AS client_name,
            COALESCE(ts.hours, 0) AS hours,
            pr.amount_per_hour,
            (COALESCE(ts.hours,0) * COALESCE(pr.amount_per_hour,0)) AS amount
        FROM payee_rules pr
        JOIN payees p  ON p.id  = pr.payee_id AND p.user_id = ?
        JOIN contractors c ON c.id = pr.contractor_id AND c.user_id = ?
        JOIN clients cl     ON cl.id = pr.client_id AND cl.user_id = ?
        LEFT JOIN timesheets ts
          ON ts.contractor_id = pr.contractor_id
         AND ts.client_id     = pr.client_id
         AND ts.user_id       = ?
         AND ts.year = ?
         AND ts.month = ?
        ORDER BY p.name, cl.name, c.name
    """
    df = pd.read_sql_query(q, conn, params=(user_id, user_id, user_id, user_id, year, month))
    conn.close()
    return df


def save_expense(client_id: int, year: int, month: int, category: str, description: str, amount: float):
    """Save an expense entry"""
    user_id = get_current_user_id()
    if not user_id:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO expenses(user_id, client_id, year, month, category, description, amount, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, client_id, year, month, category.strip(), description.strip(), amount, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def fetch_expenses(year: int, month: int, client_id: int | None = None):
    """Fetch expenses for a given month and optionally filtered by client"""
    user_id = get_current_user_id()
    if not user_id:
        return pd.DataFrame()
    conn = get_conn()
    if client_id:
        q = """
            SELECT e.id, e.client_id, e.year, e.month, e.category, e.description, e.amount,
                   cl.name AS client_name
            FROM expenses e
            JOIN clients cl ON cl.id = e.client_id
            WHERE e.user_id=? AND e.year=? AND e.month=? AND e.client_id=?
            ORDER BY e.category, e.description
        """
        df = pd.read_sql_query(q, conn, params=(user_id, year, month, client_id))
    else:
        q = """
            SELECT e.id, e.client_id, e.year, e.month, e.category, e.description, e.amount,
                   cl.name AS client_name
            FROM expenses e
            JOIN clients cl ON cl.id = e.client_id
            WHERE e.user_id=? AND e.year=? AND e.month=?
            ORDER BY cl.name, e.category, e.description
        """
        df = pd.read_sql_query(q, conn, params=(user_id, year, month))
    conn.close()
    return df


def update_expense(expense_id: int, category: str, description: str, amount: float):
    """Update an expense entry"""
    user_id = get_current_user_id()
    if not user_id:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE expenses SET category=?, description=?, amount=? WHERE id=? AND user_id=?",
        (category.strip(), description.strip(), amount, expense_id, user_id),
    )
    conn.commit()
    conn.close()


def delete_expense(expense_id: int):
    """Delete an expense entry"""
    user_id = get_current_user_id()
    if not user_id:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM expenses WHERE id=? AND user_id=?", (expense_id, user_id))
    conn.commit()
    conn.close()


def get_company_info():
    """Get company information"""
    user_id = get_current_user_id()
    if not user_id:
        return {
            "name": "Your Company Name",
            "address": "",
            "phone": "",
            "email": "",
            "bank_name": "",
            "account_number": "",
            "routing_number": ""
        }
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT name, address, phone, email, bank_name, account_number, routing_number FROM company_info WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return {
            "name": row[0],
            "address": row[1] or "",
            "phone": row[2] or "",
            "email": row[3] or "",
            "bank_name": row[4] or "",
            "account_number": row[5] or "",
            "routing_number": row[6] or ""
        }
    return {
        "name": "Your Company Name",
        "address": "",
        "phone": "",
        "email": "",
        "bank_name": "",
        "account_number": "",
        "routing_number": ""
    }


def update_company_info(name: str, address: str, phone: str, email: str, bank_name: str = "", account_number: str = "", routing_number: str = ""):
    """Update company information"""
    user_id = get_current_user_id()
    if not user_id:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO company_info (user_id, name, address, phone, email, bank_name, account_number, routing_number)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
        name=excluded.name,
        address=excluded.address,
        phone=excluded.phone,
        email=excluded.email,
        bank_name=excluded.bank_name,
        account_number=excluded.account_number,
        routing_number=excluded.routing_number
        """,
        (user_id, name.strip(), address.strip(), phone.strip(), email.strip(), bank_name.strip(), account_number.strip(), routing_number.strip()),
    )
    conn.commit()
    conn.close()


def generate_payee_payouts_pdf(rows: list[dict], year: int, month: int) -> str:
    path = os.path.join(PAYEES_DIR, f"PayeePayouts_{year:04d}-{month:02d}.pdf")
    c = canvas.Canvas(path, pagesize=LETTER)
    width, height = LETTER

    c.setFont("Helvetica-Bold", 16)
    c.drawString(1 * inch, height - 1 * inch, "Payee Payouts")
    c.setFont("Helvetica", 10)
    c.drawString(1 * inch, height - 1.3 * inch, f"Month: {year}-{month:02d}")

    y = height - 1.8 * inch
    c.setFont("Helvetica-Bold", 11)
    c.drawString(1 * inch, y, "Payee")
    c.drawString(3.0 * inch, y, "Client")
    c.drawString(4.6 * inch, y, "Contractor")
    c.drawString(6.0 * inch, y, "$/hr")
    c.drawRightString(7.5 * inch, y, "Amount")
    y -= 0.2 * inch
    c.line(1 * inch, y, 7.5 * inch, y)
    y -= 0.15 * inch

    total = 0.0
    c.setFont("Helvetica", 10)
    for r in rows:
        amt = safe_float(r.get("amount", 0.0))
        total += amt
        if y < 1.2 * inch:
            c.showPage()
            y = height - 1 * inch
            c.setFont("Helvetica", 10)
        c.drawString(1 * inch, y, str(r.get("payee_name", "")))
        c.drawString(3.0 * inch, y, str(r.get("client_name", "")))
        c.drawString(4.6 * inch, y, str(r.get("contractor_name", "")))
        c.drawRightString(6.6 * inch, y, dollars(r.get("amount_per_hour", 0.0)))
        c.drawRightString(7.5 * inch, y, dollars(amt))
        y -= 0.22 * inch

    y -= 0.1 * inch
    c.line(6.2 * inch, y, 7.5 * inch, y)
    y -= 0.25 * inch
    c.setFont("Helvetica-Bold", 12)
    c.drawString(6.2 * inch, y, "Total")
    c.drawRightString(7.5 * inch, y, dollars(total))

    c.showPage()
    c.save()
    return path


def resolve_rates(contractor_id: int, client_id: int):
    user_id = get_current_user_id()
    if not user_id:
        return 0.0, 0.0
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            COALESCE(a.bill_rate, c.default_bill_rate) AS bill_rate,
            COALESCE(a.pay_rate, c.default_pay_rate) AS pay_rate
        FROM contractors c
        LEFT JOIN assignments a ON a.contractor_id = c.id AND a.client_id = ?
        WHERE c.id = ? AND c.user_id = ?
        """,
        (client_id, contractor_id, user_id),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return 0.0, 0.0
    return safe_float(row[0]), safe_float(row[1])


def save_timesheet(contractor_id: int, client_id: int, year: int, month: int, hours: float):
    user_id = get_current_user_id()
    if not user_id:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO timesheets(user_id, contractor_id, client_id, year, month, hours, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, contractor_id, client_id, year, month) DO UPDATE SET
        hours = excluded.hours,
        created_at = excluded.created_at
        """,
        (user_id, contractor_id, client_id, year, month, hours, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def fetch_timesheets(year: int, month: int, client_id: int | None = None):
    user_id = get_current_user_id()
    if not user_id:
        return pd.DataFrame()
    conn = get_conn()
    if client_id:
        q = """
            SELECT ts.id, ts.contractor_id, ts.client_id, ts.year, ts.month, ts.hours,
                   c.name AS contractor_name, cl.name AS client_name
            FROM timesheets ts
            JOIN contractors c ON c.id = ts.contractor_id AND c.user_id = ?
            JOIN clients cl ON cl.id = ts.client_id AND cl.user_id = ?
            WHERE ts.user_id=? AND ts.year=? AND ts.month=? AND ts.client_id=?
            ORDER BY contractor_name
        """
        df = pd.read_sql_query(q, conn, params=(user_id, user_id, user_id, year, month, client_id))
    else:
        q = """
            SELECT ts.id, ts.contractor_id, ts.client_id, ts.year, ts.month, ts.hours,
                   c.name AS contractor_name, cl.name AS client_name
            FROM timesheets ts
            JOIN contractors c ON c.id = ts.contractor_id AND c.user_id = ?
            JOIN clients cl ON cl.id = ts.client_id AND cl.user_id = ?
            WHERE ts.user_id=? AND ts.year=? AND ts.month=?
            ORDER BY client_name, contractor_name
        """
        df = pd.read_sql_query(q, conn, params=(user_id, user_id, user_id, year, month))
    conn.close()
    return df


# -----------------------------
# PDF generation (invoices & payables)
# -----------------------------

def pdf_invoice_path(client_name: str, year: int, month: int) -> str:
    safe = client_name.replace("/", "-").replace("\\", "-")
    return os.path.join(INVOICE_DIR, f"Invoice_{safe}_{year:04d}-{month:02d}.pdf")


def pdf_payables_path(year: int, month: int) -> str:
    return os.path.join(PAYABLES_DIR, f"Payables_{year:04d}-{month:02d}.pdf")


def generate_invoice_pdf(client_row: pd.Series, items: list[dict], expenses: list[dict], year: int, month: int) -> str:
    path = pdf_invoice_path(client_row["name"], year, month)
    c = canvas.Canvas(path, pagesize=LETTER)
    width, height = LETTER

    # Get company information
    company = get_company_info()
    
    # Invoice Title (Line 1 - Top Center, Alone)
    c.setFont("Helvetica-Bold", 24)
    title_width = c.stringWidth("INVOICE", "Helvetica-Bold", 24)
    title_x = (width - title_width) / 2
    c.drawString(title_x, height - 1 * inch, "INVOICE")

    # Company Information (Upper Left - Starting Line 3-4)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(1 * inch, height - 1.5 * inch, company["name"])
    
    c.setFont("Helvetica", 10)
    company_lines = []
    
    if company["address"]:
        company_lines.extend(company["address"].split('\n'))
    if company["phone"]:
        company_lines.append(f"Phone: {company['phone']}")
    if company["email"]:
        company_lines.append(f"Email: {company['email']}")
    
    y_company = height - 1.7 * inch
    for line in company_lines:
        if line.strip():
            c.drawString(1 * inch, y_company, line.strip())
            y_company -= 0.15 * inch

    # Client Information (Upper Right - Starting Line 3-4, moved further right)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(5.5 * inch, height - 1.5 * inch, "Bill To:")
    
    c.setFont("Helvetica", 10)
    y_client = height - 1.7 * inch
    c.drawString(5.5 * inch, y_client, client_row['name'])
    y_client -= 0.15 * inch
    
    if str(client_row.get("address") or "").strip():
        address_lines = str(client_row.get("address") or "").splitlines()
        for line in address_lines:
            if line.strip():
                c.drawString(5.5 * inch, y_client, line.strip())
                y_client -= 0.15 * inch
    
    if str(client_row.get("email") or "").strip():
        c.drawString(5.5 * inch, y_client, f"Email: {client_row['email']}")
        y_client -= 0.15 * inch

    # Invoice Details (Below Bill To section)
    c.setFont("Helvetica", 10)
    y_client -= 0.2 * inch  # Larger gap before invoice details
    
    # Calculate invoice date (1st day of month after invoice period)
    next_month = month + 1
    next_year = year
    if next_month > 12:
        next_month = 1
        next_year = year + 1
    invoice_date = f"{next_year}-{next_month:02d}-01"
    formatted_date = datetime.strptime(invoice_date, "%Y-%m-%d").strftime("%m/%d/%Y")
    
    # Calculate invoice number using your formula
    invoice_number = f"{formatted_date.replace('/', '')}-perf"
    
    # Calculate invoice period (current month)
    last_day = calendar.monthrange(year, month)[1]
    period_start = f"{month}/1/{year}"
    period_end = f"{month}/{last_day}/{year}"
    
    # Get month name
    month_name = datetime(year, month, 1).strftime("%B")
    
    # Display invoice details
    c.drawString(5.5 * inch, y_client, f"Number: {invoice_number}")
    y_client -= 0.15 * inch
    
    c.drawString(5.5 * inch, y_client, f"Date: {formatted_date}")
    y_client -= 0.15 * inch
    
    c.drawString(5.5 * inch, y_client, f"Invoice Period: {period_start} - {period_end}")
    y_client -= 0.15 * inch
    
    c.setFont("Helvetica-Bold", 10)
    c.drawString(5.5 * inch, y_client, f"Invoice Month: {month_name}")
    y_client -= 0.15 * inch

    # Add 10 blank lines before starting details
    y_client -= (10 * 0.15 * inch)  # 10 lines with 0.15 inch spacing each

    y = y_client
    c.setFont("Helvetica-Bold", 11)
    c.drawString(1 * inch, y, "Contractor")
    c.drawString(2.8 * inch, y, "Hours")
    c.drawString(3.6 * inch, y, "Rate")
    c.drawString(4.6 * inch, y, "Line Total")
    y -= 0.2 * inch
    c.line(1 * inch, y, 7.5 * inch, y)

    total = 0.0
    c.setFont("Helvetica", 10)
    y -= 0.15 * inch
    
    # Add contractor items
    for it in items:
        if y < 1.2 * inch:
            c.showPage()
            c.setFont("Helvetica-Bold", 11)
            y = height - 1 * inch
        line_total = safe_float(it["hours"]) * safe_float(it["bill_rate"])
        total += line_total
        c.setFont("Helvetica", 10)
        c.drawString(1 * inch, y, str(it["contractor_name"]))
        c.drawRightString(3.3 * inch, y, f"{safe_float(it['hours']):.2f}")
        c.drawRightString(4.5 * inch, y, dollars(it["bill_rate"]))
        c.drawRightString(7.5 * inch, y, dollars(line_total))
        y -= 0.22 * inch

    # Add expenses section if there are any
    if expenses:
        y -= 0.1 * inch
        c.line(1 * inch, y, 7.5 * inch, y)
        y -= 0.15 * inch
        
        c.setFont("Helvetica-Bold", 11)
        c.drawString(1 * inch, y, "Expenses")
        c.drawString(4.6 * inch, y, "Amount")
        y -= 0.2 * inch
        c.line(1 * inch, y, 7.5 * inch, y)
        y -= 0.15 * inch
        
        c.setFont("Helvetica", 10)
        for exp in expenses:
            if y < 1.2 * inch:
                c.showPage()
                y = height - 1 * inch
                c.setFont("Helvetica-Bold", 11)
                y -= 0.15 * inch
                c.setFont("Helvetica", 10)
            
            exp_amount = safe_float(exp["amount"])
            total += exp_amount
            category_desc = f"{exp['category']}"
            if exp.get('description', '').strip():
                category_desc += f" - {exp['description']}"
            c.drawString(1 * inch, y, category_desc)
            c.drawRightString(7.5 * inch, y, dollars(exp_amount))
            y -= 0.22 * inch

    y -= 0.1 * inch
    c.line(4.2 * inch, y, 7.5 * inch, y)
    y -= 0.25 * inch
    c.setFont("Helvetica-Bold", 12)
    c.drawString(4.2 * inch, y, "Total")
    c.drawRightString(7.5 * inch, y, dollars(total))

    # Remit To Information (Bottom Left)
    y_remit = 1.5 * inch  # Position near bottom of page
    c.setFont("Helvetica-Bold", 12)
    c.drawString(1 * inch, y_remit, "Remit To:")
    
    c.setFont("Helvetica", 10)
    y_remit -= 0.2 * inch
    
    # Get company info for banking details
    company = get_company_info()
    
    # Banking information (you can customize these)
    banking_info = [
        f"Bank: {company.get('bank_name', 'Your Bank Name')}",
        f"Account #: {company.get('account_number', 'XXXX-XXXX-XXXX')}",
        f"Routing #: {company.get('routing_number', 'XXXX-XXXX-X')}",
        f"Payable to: {company['name']}",
        f"Memo: Invoice {invoice_number}"
    ]
    
    for line in banking_info:
        c.drawString(1 * inch, y_remit, line)
        y_remit -= 0.15 * inch

    c.showPage()
    c.save()
    return path


def generate_payables_pdf(rows: list[dict], year: int, month: int) -> str:
    path = pdf_payables_path(year, month)
    c = canvas.Canvas(path, pagesize=LETTER)
    width, height = LETTER

    c.setFont("Helvetica-Bold", 16)
    c.drawString(1 * inch, height - 1 * inch, "Contractor Payables")
    c.setFont("Helvetica", 10)
    c.drawString(1 * inch, height - 1.3 * inch, f"Month: {year}-{month:02d}")

    y = height - 1.8 * inch
    c.setFont("Helvetica-Bold", 11)
    c.drawString(1 * inch, y, "Contractor")
    c.drawString(3.3 * inch, y, "Client")
    c.drawString(5.0 * inch, y, "Hours")
    c.drawString(5.8 * inch, y, "Pay Rate")
    c.drawString(6.9 * inch, y, "Amount")
    y -= 0.2 * inch
    c.line(1 * inch, y, 7.5 * inch, y)
    y -= 0.15 * inch

    total = 0.0
    c.setFont("Helvetica", 10)
    for r in rows:
        amt = safe_float(r["hours"]) * safe_float(r["pay_rate"])
        total += amt
        if y < 1.2 * inch:
            c.showPage()
            y = height - 1 * inch
            c.setFont("Helvetica", 10)
        c.drawString(1 * inch, y, str(r["contractor_name"]))
        c.drawString(3.3 * inch, y, str(r["client_name"]))
        c.drawRightString(5.6 * inch, y, f"{safe_float(r['hours']):.2f}")
        c.drawRightString(6.8 * inch, y, dollars(r["pay_rate"]))
        c.drawRightString(7.5 * inch, y, dollars(amt))
        y -= 0.22 * inch

    y -= 0.1 * inch
    c.line(6.2 * inch, y, 7.5 * inch, y)
    y -= 0.25 * inch
    c.setFont("Helvetica-Bold", 12)
    c.drawString(6.2 * inch, y, "Total")
    c.drawRightString(7.5 * inch, y, dollars(total))

    c.showPage()
    c.save()
    return path


# -----------------------------
# UI Components
# -----------------------------

def month_selector(prefix: str = "ms"):
    col1, col2 = st.columns(2)
    with col1:
        year = st.number_input(
            "Year",
            min_value=2000,
            max_value=2100,
            value=datetime.now().year,
            step=1,
            key=f"{prefix}_year",
        )
    with col2:
        month = st.number_input(
            "Month",
            min_value=1,
            max_value=12,
            value=datetime.now().month,
            step=1,
            key=f"{prefix}_month",
        )
    return int(year), int(month)


def setup_tab():
    st.subheader("Setup")
    st.caption("Configure your company info, manage contractors, clients, and payees.")
    
    # Sidebar navigation
    with st.sidebar:
        st.markdown("### Navigation")
        page = st.radio(
            "Select Management Area:",
            ["Company", "Contractors", "Clients", "Payees"],
            key="setup_nav"
        )
    
    # Main content area based on selected page
    if page == "Company":
        company_page()
    elif page == "Contractors":
        contractors_page()
    elif page == "Clients":
        clients_page()
    elif page == "Payees":
        payees_page()


def company_page():
    """Company information management page"""
    st.markdown("### Company Information")
    company = get_company_info()
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Basic Information**")
        company_name = st.text_input("Company Name", value=company["name"], key="comp_name")
        company_address = st.text_area("Company Address", value=company["address"], height=100, key="comp_address")
        company_phone = st.text_input("Phone", value=company["phone"], key="comp_phone")
        company_email = st.text_input("Email", value=company["email"], key="comp_email")
    with col2:
        st.markdown("**Banking Information**")
        st.caption("Used in the 'Remit To' section of invoices")
        company_bank = st.text_input("Bank Name", value=company["bank_name"], key="comp_bank")
        company_account = st.text_input("Account Number", value=company["account_number"], key="comp_account")
        company_routing = st.text_input("Routing Number", value=company["routing_number"], key="comp_routing")
    
    if st.button("Save Company Info", key="comp_save"):
        update_company_info(company_name, company_address, company_phone, company_email, company_bank, company_account, company_routing)
        st.success("Company information saved")


def contractors_page():
    """Contractor management page"""
    st.markdown("### Contractor Management")
    
    # Add new contractor
    st.markdown("#### Add New Contractor")
    col1, col2, col3 = st.columns(3)
    with col1:
        name = st.text_input("Contractor name", key="su_contractor_name")
    with col2:
        bill = st.number_input("Default bill rate", min_value=0.0, value=80.0, step=1.0, key="su_bill_rate")
    with col3:
        pay = st.number_input("Default pay rate", min_value=0.0, value=70.0, step=1.0, key="su_pay_rate")
    
    if st.button("Add Contractor", key="su_save_contractor") and name.strip():
        upsert_contractor(name, bill, pay)
        st.success("Contractor added")
        list_contractors.clear()
    
    st.divider()
    
    # Edit/Delete contractors
    st.markdown("#### Edit/Delete Contractors")
    contractors = list_contractors()
    if contractors.empty:
        st.info("No contractors yet.")
    else:
        colA, colB = st.columns([2, 3])
        with colA:
            sel_contractor_name = st.selectbox("Select contractor", contractors["name"].tolist(), key="ed_contractor_select")
            sel_row = contractors.loc[contractors.name == sel_contractor_name].iloc[0]
            sel_id = int(sel_row["id"])
        with colB:
            new_name = st.text_input("Name", value=sel_row["name"], key="ed_contractor_name")
            new_bill = st.number_input("Default bill rate", min_value=0.0, value=float(sel_row["bill_rate"]), step=1.0, key="ed_contractor_bill")
            new_pay = st.number_input("Default pay rate", min_value=0.0, value=float(sel_row["pay_rate"]), step=1.0, key="ed_contractor_pay")
            colU, colD = st.columns([1, 1])
            with colU:
                if st.button("Update Contractor", key="ed_contractor_update"):
                    update_contractor(sel_id, new_name, new_bill, new_pay)
                    st.success("Contractor updated")
                    list_contractors.clear()
            with colD:
                if st.button("Delete Contractor", key="ed_contractor_delete"):
                    delete_contractor(sel_id)
                    st.success("Contractor deleted (and related timesheets/overrides/rules)")
                    list_contractors.clear()
        
        st.markdown("**All Contractors:**")
        st.dataframe(contractors, use_container_width=True)


def clients_page():
    """Client management page"""
    st.markdown("### Client Management")
    
    # Add new client
    st.markdown("#### Add New Client")
    col1, col2 = st.columns(2)
    with col1:
        cname = st.text_input("Client name", key="su_client_name")
        caddr = st.text_area("Client address", height=100, key="su_client_addr")
    with col2:
        cemail = st.text_input("Client email", key="su_client_email")
    
    if st.button("Add Client", key="su_save_client") and cname.strip():
        upsert_client(cname, caddr, cemail)
        st.success("Client added")
        list_clients.clear()
    
    st.divider()
    
    # Edit/Delete clients
    st.markdown("#### Edit/Delete Clients")
    clients = list_clients()
    if clients.empty:
        st.info("No clients yet.")
    else:
        colX, colY = st.columns([2, 3])
        with colX:
            sel_client_name = st.selectbox("Select client", clients["name"].tolist(), key="ed_client_select")
            sel_row = clients.loc[clients.name == sel_client_name].iloc[0]
            sel_id = int(sel_row["id"])
        with colY:
            new_cname = st.text_input("Name", value=sel_row["name"], key="ed_client_name")
            new_caddr = st.text_area("Address", value=str(sel_row.get("address", "")), key="ed_client_addr")
            new_cemail = st.text_input("Email", value=str(sel_row.get("email", "")), key="ed_client_email")
            colU2, colD2 = st.columns([1, 1])
            with colU2:
                if st.button("Update Client", key="ed_client_update"):
                    update_client(sel_id, new_cname, new_caddr, new_cemail)
                    st.success("Client updated")
                    list_clients.clear()
            with colD2:
                if st.button("Delete Client", key="ed_client_delete"):
                    delete_client(sel_id)
                    st.success("Client deleted (and related timesheets/overrides/invoices/rules)")
                    list_clients.clear()
        
        st.markdown("**All Clients:**")
        st.dataframe(clients, use_container_width=True)
    
    st.divider()
    
    # Rate overrides
    st.markdown("#### Rate Overrides")
    contractors = list_contractors()
    clients = list_clients()
    if contractors.empty or clients.empty:
        st.info("Add at least one contractor and one client to set overrides.")
    else:
        colA, colB, colC, colD = st.columns([2, 2, 1, 1])
        with colA:
            contractor_name = st.selectbox("Contractor", contractors["name"].tolist(), key="su_override_contractor")
        with colB:
            client_name = st.selectbox("Client", clients["name"].tolist(), key="su_override_client")
        with colC:
            o_bill = st.number_input("Bill override (optional)", value=0.0, step=1.0, key="su_override_bill")
        with colD:
            o_pay = st.number_input("Pay override (optional)", value=0.0, step=1.0, key="su_override_pay")
        if st.button("Save Override", key="su_save_override"):
            cid = contractors.loc[contractors.name == contractor_name, "id"].iloc[0]
            clid = clients.loc[clients.name == client_name, "id"].iloc[0]
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO assignments(contractor_id, client_id, bill_rate, pay_rate)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(contractor_id, client_id) DO UPDATE SET
                bill_rate=excluded.bill_rate,
                pay_rate=excluded.pay_rate
                """,
                (int(cid), int(clid), o_bill if o_bill > 0 else None, o_pay if o_pay > 0 else None),
            )
            conn.commit()
            conn.close()
            st.success("Override saved")


def payees_page():
    """Payee management page"""
    st.markdown("### Payee Management")
    
    # Add new payee
    st.markdown("#### Add New Payee")
    col1, col2 = st.columns([2, 1])
    with col1:
        payee_name = st.text_input("Payee name", key="pay_name")
        payee_email = st.text_input("Payee email", key="pay_email")
    with col2:
        if st.button("Add Payee", key="pay_save") and payee_name.strip():
            upsert_payee(payee_name, payee_email)
            st.success("Payee added")
            list_payees.clear()
    
    # Delete payees
    payees = list_payees()
    if not payees.empty:
        st.markdown("#### Delete Payees")
        colPD1, colPD2 = st.columns([3, 1])
        with colPD1:
            del_payee_name = st.selectbox("Select payee to delete", payees["name"].tolist(), key="pay_del_select")
        with colPD2:
            if st.button("Delete Payee", key="pay_del_btn"):
                pid = int(payees.loc[payees.name == del_payee_name, "id"].iloc[0])
                delete_payee(pid)
                st.success("Payee deleted (and related rules)")
                list_payees.clear()
    
    st.divider()
    
    # Payee rules
    st.markdown("#### Payee Rules (Finder Fees)")
    contractors = list_contractors()
    clients = list_clients()
    payees = list_payees()

    if payees.empty or contractors.empty or clients.empty:
        st.info("Need at least one payee, contractor, and client to create a rule.")
    else:
        st.markdown("**Create New Rule:**")
        colR1, colR2, colR3, colR4 = st.columns([2, 2, 2, 1])
        with colR1:
            sel_payee = st.selectbox("Payee", payees["name"].tolist(), key="rule_payee")
        with colR2:
            sel_contractor = st.selectbox("Contractor", contractors["name"].tolist(), key="rule_contractor")
        with colR3:
            sel_client = st.selectbox("Client", clients["name"].tolist(), key="rule_client")
        with colR4:
            amt = st.number_input("$/hr", min_value=0.0, value=5.0, step=1.0, key="rule_amt")

        if st.button("Create Rule", key="rule_save_btn"):
            payee_id = int(payees.loc[payees.name == sel_payee, "id"].iloc[0])
            contractor_id = int(contractors.loc[contractors.name == sel_contractor, "id"].iloc[0])
            client_id = int(clients.loc[clients.name == sel_client, "id"].iloc[0])
            set_payee_rule(payee_id, contractor_id, client_id, amt)
            st.success("Rule created")
    
    st.divider()
    
    # Manage existing rules
    st.markdown("#### Manage Existing Rules")
    existing_rules = fetch_payee_rules()
    
    if existing_rules.empty:
        st.info("No payee rules created yet.")
    else:
        st.markdown("**Current Rules:**")
        display_rules = existing_rules[["payee_name", "contractor_name", "client_name", "amount_per_hour"]].copy()
        display_rules["amount_per_hour"] = display_rules["amount_per_hour"].map(dollars)
        st.dataframe(display_rules, use_container_width=True)
        
        # Edit/Delete Rules Section
        st.markdown("**Edit/Delete Rules:**")
        if not existing_rules.empty:
            # Create dropdown with rule descriptions
            rule_options = []
            for _, row in existing_rules.iterrows():
                rule_desc = f"{row['payee_name']} × {row['contractor_name']} × {row['client_name']} (${row['amount_per_hour']:.2f}/hr)"
                rule_options.append((row['id'], rule_desc))
            
            if rule_options:
                selected_rule = st.selectbox(
                    "Select rule to edit/delete",
                    options=[opt[0] for opt in rule_options],
                    format_func=lambda x: next(opt[1] for opt in rule_options if opt[0] == x),
                    key="rule_edit_select"
                )
                
                if selected_rule:
                    # Get the selected rule data
                    selected_rule_row = existing_rules.loc[existing_rules['id'] == selected_rule].iloc[0]
                    
                    col1, col2, col3 = st.columns([2, 1, 1])
                    with col1:
                        st.write(f"**Rule:** {selected_rule_row['payee_name']} × {selected_rule_row['contractor_name']} × {selected_rule_row['client_name']}")
                    with col2:
                        new_amount = st.number_input("New $/hr", min_value=0.0, value=float(selected_rule_row['amount_per_hour']), step=1.0, key="rule_edit_amount")
                    with col3:
                        st.write("")  # Spacer
                        col_update, col_delete = st.columns(2)
                        with col_update:
                            if st.button("Update", key="rule_update_btn"):
                                update_payee_rule(int(selected_rule), new_amount)
                                st.success("Rule updated")
                                st.rerun()
                        with col_delete:
                            if st.button("Delete", key="rule_delete_btn"):
                                delete_payee_rule(int(selected_rule))
                                st.success("Rule deleted")
                                st.rerun()


def entry_tab():
    st.subheader("Enter hours")
    year, month = month_selector("en")

    contractors = list_contractors()
    clients = list_clients()

    if contractors.empty or clients.empty:
        st.info("Add contractors and clients in Setup first.")
        return

    c_name = st.selectbox("Contractor", contractors["name"].tolist(), key="en_contractor")
    cl_name = st.selectbox("Client", clients["name"].tolist(), key="en_client")

    sel_cid = int(contractors.loc[contractors.name == c_name, "id"].iloc[0])
    sel_clid = int(clients.loc[clients.name == cl_name, "id"].iloc[0])

    bill_rate, pay_rate = resolve_rates(sel_cid, sel_clid)
    st.caption(f"Bill rate: {dollars(bill_rate)} | Pay rate: {dollars(pay_rate)}")

    hrs = st.number_input("Hours", min_value=0.0, value=0.0, step=0.25, key="en_hours")

    if st.button("Save hours", key="en_save_hours"):
        save_timesheet(sel_cid, sel_clid, year, month, hrs)
        st.success("Hours saved")

    st.divider()
    
    # NEW: Expense Entry Section
    st.markdown("### Enter Expenses")
    expense_client = st.selectbox("Client for expense", clients["name"].tolist(), key="exp_client")
    expense_client_id = int(clients.loc[clients.name == expense_client, "id"].iloc[0])
    
    col1, col2, col3 = st.columns([2, 2, 1])
    with col1:
        expense_category = st.text_input("Category", placeholder="e.g., Travel, Supplies, Meals", key="exp_category")
    with col2:
        expense_description = st.text_input("Description", placeholder="e.g., Gas to client site", key="exp_description")
    with col3:
        expense_amount = st.number_input("Amount", min_value=0.0, value=0.0, step=1.0, key="exp_amount")
    
    if st.button("Save expense", key="exp_save") and expense_category.strip() and expense_amount > 0:
        save_expense(expense_client_id, year, month, expense_category, expense_description, expense_amount)
        st.success("Expense saved")

    st.divider()
    
    # Show existing entries
    st.markdown("**Timesheets for the selected month**")
    df = fetch_timesheets(year, month)
    if df.empty:
        st.info("No entries yet for this month.")
    else:
        st.dataframe(df[["client_name", "contractor_name", "hours"]], use_container_width=True)
    
    # Show expenses
    st.markdown("**Expenses for the selected month**")
    exp_df = fetch_expenses(year, month)
    if exp_df.empty:
        st.info("No expenses yet for this month.")
    else:
        display_exp = exp_df[["client_name", "category", "description", "amount"]].copy()
        display_exp["amount"] = display_exp["amount"].map(dollars)
        st.dataframe(display_exp, use_container_width=True)
        
        # Edit/Delete Expenses Section
        st.markdown("### Edit/Delete Expenses")
        if not exp_df.empty:
            # Create a dropdown with expense descriptions for selection
            expense_options = []
            for _, row in exp_df.iterrows():
                desc = f"{row['category']} - {row['description']}" if row['description'].strip() else row['category']
                expense_options.append((row['id'], f"{row['client_name']}: {desc} (${row['amount']:.2f})"))
            
            if expense_options:
                selected_expense = st.selectbox(
                    "Select expense to edit/delete",
                    options=[opt[0] for opt in expense_options],
                    format_func=lambda x: next(opt[1] for opt in expense_options if opt[0] == x),
                    key="exp_edit_select"
                )
                
                if selected_expense:
                    # Get the selected expense data
                    selected_row = exp_df.loc[exp_df['id'] == selected_expense].iloc[0]
                    
                    col1, col2, col3, col4 = st.columns([2, 2, 1, 1])
                    with col1:
                        edit_category = st.text_input("Category", value=selected_row['category'], key="exp_edit_category")
                    with col2:
                        edit_description = st.text_input("Description", value=selected_row['description'], key="exp_edit_description")
                    with col3:
                        edit_amount = st.number_input("Amount", min_value=0.0, value=float(selected_row['amount']), step=1.0, key="exp_edit_amount")
                    with col4:
                        st.write("")  # Spacer
                        col_update, col_delete = st.columns(2)
                        with col_update:
                            if st.button("Update", key="exp_update_btn"):
                                update_expense(int(selected_expense), edit_category, edit_description, edit_amount)
                                st.success("Expense updated")
                                st.rerun()
                        with col_delete:
                            if st.button("Delete", key="exp_delete_btn"):
                                delete_expense(int(selected_expense))
                                st.success("Expense deleted")
                                st.rerun()


def invoice_tab():
    st.subheader("Generate client invoice")
    year, month = month_selector("inv")

    clients = list_clients()
    if clients.empty:
        st.info("Add a client in Setup first.")
        return

    client_name = st.selectbox("Client", clients["name"].tolist(), key="inv_client")
    client_row = clients.loc[clients.name == client_name].iloc[0]

    ts = fetch_timesheets(year, month, int(client_row["id"]))
    expenses = fetch_expenses(year, month, int(client_row["id"]))
    
    if ts.empty and expenses.empty:
        st.info("No timesheet entries or expenses for this client in the selected month.")
        return

    items = []
    for _, row in ts.iterrows():
        br, pr = resolve_rates(int(row["contractor_id"]), int(row["client_id"]))
        items.append({
            "contractor_name": row["contractor_name"],
            "hours": safe_float(row["hours"]),
            "bill_rate": br,
            "pay_rate": pr,
        })

    # Prepare expense data
    expense_items = []
    for _, row in expenses.iterrows():
        expense_items.append({
            "category": row["category"],
            "description": row["description"],
            "amount": safe_float(row["amount"])
        })

    # Show preview
    preview_data = []
    
    # Add contractor items
    for it in items:
        preview_data.append({
            "Type": "Labor",
            "Description": it["contractor_name"],
            "Hours/Qty": f"{it['hours']:.2f}",
            "Rate": dollars(it["bill_rate"]),
            "Amount": dollars(it["hours"] * safe_float(it["bill_rate"]))
        })
    
    # Add expense items
    for exp in expense_items:
        preview_data.append({
            "Type": "Expense",
            "Description": f"{exp['category']}" + (f" - {exp['description']}" if exp['description'].strip() else ""),
            "Hours/Qty": "1",
            "Rate": dollars(exp["amount"]),
            "Amount": dollars(exp["amount"])
        })

    if preview_data:
        prev_df = pd.DataFrame(preview_data)
        st.markdown("**Preview**")
        st.dataframe(prev_df, use_container_width=True)

    col_view, col_create = st.columns(2)
    
    with col_view:
        if st.button("View Invoice", key="inv_view_pdf"):
            path = generate_invoice_pdf(client_row, items, expense_items, year, month)
            st.success(f"Invoice generated: {path}")
            
            # Display the PDF in the browser
            with open(path, "rb") as f:
                pdf_bytes = f.read()
                st.markdown("**Invoice Preview:**")
                st.download_button(
                    "📄 Download Invoice PDF", 
                    pdf_bytes, 
                    file_name=os.path.basename(path), 
                    mime="application/pdf",
                    key="inv_view_download_btn"
                )
                
                # Also show a preview using Streamlit's PDF viewer
                st.markdown("**PDF Preview (if supported by browser):**")
                base64_pdf = base64.b64encode(pdf_bytes).decode('utf-8')
                pdf_display = f'<iframe src="data:application/pdf;base64,{base64_pdf}" width="100%" height="600" type="application/pdf"></iframe>'
                st.markdown(pdf_display, unsafe_allow_html=True)
    
    with col_create:
        if st.button("Create & Save Invoice", key="inv_create_pdf"):
            path = generate_invoice_pdf(client_row, items, expense_items, year, month)
            # Save to invoice registry
            conn = get_conn()
            cur = conn.cursor()
            labor_total = sum([safe_float(it["hours"]) * safe_float(it["bill_rate"]) for it in items])
            expense_total = sum([safe_float(exp["amount"]) for exp in expense_items])
            total_amount = labor_total + expense_total
            
            user_id = get_current_user_id()
            if user_id:
                cur.execute(
                    """
                    INSERT INTO invoices(user_id, client_id, year, month, total_amount, pdf_path, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(user_id, client_id, year, month) DO UPDATE SET
                    total_amount=excluded.total_amount,
                    pdf_path=excluded.pdf_path,
                    created_at=excluded.created_at
                    """,
                    (user_id, int(client_row["id"]), year, month, float(total_amount), path, datetime.utcnow().isoformat()),
                )
            conn.commit()
            conn.close()

            st.success(f"Invoice saved to database: {path}")
            with open(path, "rb") as f:
                st.download_button("Download invoice PDF", f, file_name=os.path.basename(path), mime="application/pdf", key="inv_download_btn")


def reports_tab():
    st.subheader("Reports")
    year, month = month_selector("rp")

    df = fetch_timesheets(year, month)
    exp_df = fetch_expenses(year, month)
    pp = fetch_payee_payouts(year, month)
    
    if df.empty and exp_df.empty and pp.empty:
        st.info("No data for selected month.")
    else:
        # Process timesheet data
        rows = []
        for _, r in df.iterrows():
            br, pr = resolve_rates(int(r["contractor_id"]), int(r["client_id"]))
            rows.append({
                "client_name": r["client_name"],
                "contractor_name": r["contractor_name"],
                "hours": safe_float(r["hours"]),
                "bill_rate": br,
                "pay_rate": pr,
                "revenue": safe_float(r["hours"]) * safe_float(br),
                "payroll": safe_float(r["hours"]) * safe_float(pr),
            })

        # Process expense data
        expense_rows = []
        for _, r in exp_df.iterrows():
            expense_rows.append({
                "client_name": r["client_name"],
                "category": r["category"],
                "description": r["description"],
                "amount": safe_float(r["amount"]),
            })

        # Calculate total payee payouts
        total_payee_payouts = pp["amount"].sum() if not pp.empty else 0.0

        # Show expense summary
        if not exp_df.empty:
            st.markdown("**Expenses Summary**")
            exp_summary = exp_df.groupby(["client_name", "category"]).agg({"amount": "sum"}).reset_index()
            exp_summary["amount"] = exp_summary["amount"].map(dollars)
            st.dataframe(exp_summary, use_container_width=True)
            
            st.markdown("**Expenses Detail**")
            exp_detail = exp_df[["client_name", "category", "description", "amount"]].copy()
            exp_detail["amount"] = exp_detail["amount"].map(dollars)
            st.dataframe(exp_detail, use_container_width=True)

        # Show labor data if available
        if not df.empty:
            rep = pd.DataFrame(rows)
            by_client = rep.groupby("client_name").agg({"revenue": "sum", "payroll": "sum"})
            
            # Calculate payee payouts by client
            if not pp.empty:
                payee_by_client = pp.groupby("client_name")["amount"].sum()
                by_client["payee_payouts"] = by_client.index.map(lambda x: payee_by_client.get(x, 0.0))
            else:
                by_client["payee_payouts"] = 0.0
            
            # Updated profit calculation: revenue - payroll - payee_payouts
            by_client["profit"] = by_client["revenue"] - by_client["payroll"] - by_client["payee_payouts"]

            st.markdown("**Labor Summary by client**")
            fmt = by_client.copy()
            for col in ["revenue", "payroll", "payee_payouts", "profit"]:
                fmt[col] = fmt[col].map(dollars)
            st.dataframe(fmt, use_container_width=True)

            st.markdown("**Labor Detail**")
            det = rep.copy()
            det["bill_rate"] = det["bill_rate"].map(dollars)
            det["pay_rate"] = det["pay_rate"].map(dollars)
            det["revenue"] = det["revenue"].map(dollars)
            det["payroll"] = det["payroll"].map(dollars)
            st.dataframe(det, use_container_width=True)

            if st.button("Create payables PDF for this month", key="rp_create_payables"):
                path = generate_payables_pdf(rows, year, month)
                st.success(f"Payables saved: {path}")
                with open(path, "rb") as f:
                    st.download_button("Download payables PDF", f, file_name=os.path.basename(path), mime="application/pdf", key="rp_download_btn")

    st.divider()
    st.subheader("Payee Payouts (Finder Fees)")
    if pp.empty:
        st.info("No payee rules or no matching hours this month.")
    else:
        detail = pp.copy()
        detail["amount_per_hour"] = detail["amount_per_hour"].map(dollars)
        detail["amount"] = detail["amount"].map(dollars)
        st.markdown("**Detail (by Payee × Client × Contractor)**")
        st.dataframe(detail[["payee_name", "client_name", "contractor_name", "hours", "amount_per_hour", "amount"]], use_container_width=True)

        st.markdown("**Summary by Payee**")
        sum_payee = pp.groupby("payee_name")["amount"].sum().reset_index()
        sum_payee["amount"] = sum_payee["amount"].map(dollars)
        st.dataframe(sum_payee, use_container_width=True)

        # Show total payee payouts
        st.markdown("**Total Payee Payouts**")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Payee Payouts", dollars(total_payee_payouts))
        with col2:
            st.metric("Number of Payees", len(sum_payee))

        if st.button("Create Payee Payouts PDF", key="rp_payee_pdf"):
            rows = pp.to_dict(orient="records")
            path = generate_payee_payouts_pdf(rows, year, month)
            st.success(f"Payee payouts saved: {path}")
            with open(path, "rb") as f:
                st.download_button("Download payee payouts PDF", f, file_name=os.path.basename(path), mime="application/pdf", key="rp_payee_download")


def seed_example():
    upsert_contractor("John", 80, 70)
    upsert_contractor("Sam", 90, 65)
    upsert_contractor("Jill", 85, 60)
    upsert_client("Client X", "123 Main St\nColumbus, OH 43004", "ap@clientx.com")
    upsert_client("Client Y", "88 Lake Ave\nCleveland, OH 44101", "ap@clienty.com")

    contractors = list_contractors()
    clients = list_clients()

    save_timesheet(
        contractor_id=int(contractors.loc[contractors.name == "John", "id"].iloc[0]),
        client_id=int(clients.loc[clients.name == "Client X", "id"].iloc[0]),
        year=2025,
        month=9,
        hours=160,
    )
    save_timesheet(
        contractor_id=int(contractors.loc[contractors.name == "Sam", "id"].iloc[0]),
        client_id=int(clients.loc[clients.name == "Client X", "id"].iloc[0]),
        year=2025,
        month=9,
        hours=158,
    )
    save_timesheet(
        contractor_id=int(contractors.loc[contractors.name == "Jill", "id"].iloc[0]),
        client_id=int(clients.loc[clients.name == "Client Y", "id"].iloc[0]),
        year=2025,
        month=9,
        hours=172,
    )
    
    # Add sample expenses
    save_expense(
        client_id=int(clients.loc[clients.name == "Client X", "id"].iloc[0]),
        year=2025,
        month=9,
        category="Travel",
        description="Gas to client site",
        amount=45.50
    )
    save_expense(
        client_id=int(clients.loc[clients.name == "Client X", "id"].iloc[0]),
        year=2025,
        month=9,
        category="Meals",
        description="Client lunch meeting",
        amount=85.00
    )
    save_expense(
        client_id=int(clients.loc[clients.name == "Client Y", "id"].iloc[0]),
        year=2025,
        month=9,
        category="Supplies",
        description="Software licenses",
        amount=150.00
    )


# -----------------------------
# App start
# -----------------------------

def main():
    st.set_page_config(page_title="Solo Invoicing", layout="wide")
    init_db()
    
    # Check authentication
    if not is_authenticated():
        show_auth_page()
        return
    
    # User is authenticated - show main app
    st.title("Solo Invoicing and Payments")
    username = st.session_state.get('username', 'User')
    st.sidebar.markdown(f"**Logged in as:** {username}")
    
    if st.sidebar.button("Logout", key="logout_btn"):
        logout_user()
        st.rerun()

    with st.sidebar:
        st.markdown("**Quick actions**")
        if st.button("Load sample data", key="sb_load_sample"):
            seed_example()
            st.success("Sample data loaded for Sept 2025 (includes contractors, clients, hours, and expenses)")
            list_contractors.clear()
            list_clients.clear()
        st.caption("Data is stored on the server. PDFs are saved to the invoices, payables, and payees folders.")

    tabs = st.tabs(["Setup", "Enter Hours & Expenses", "Generate Invoice", "Reports"])
    with tabs[0]:
        setup_tab()
    with tabs[1]:
        entry_tab()
    with tabs[2]:
        invoice_tab()
    with tabs[3]:
        reports_tab()


if __name__ == "__main__":
    main()
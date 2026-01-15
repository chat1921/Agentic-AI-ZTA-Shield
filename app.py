import random
import smtplib
from email.mime.text import MIMEText
import os
import datetime
import json
import sqlite3
import requests
import hashlib
import smtplib
import ssl
import secrets
import random
from math import radians, sin, cos, sqrt, atan2
from queue import Queue
from email.mime.text import MIMEText

# --- Third Party Imports ---
from flask import (Flask, Response, jsonify, redirect, render_template, 
                   request, session, g)
from dotenv import load_dotenv
from web3 import Web3
from eth_account import Account

# --- Load Environment Variables ---
load_dotenv()  # This loads variables from .env if you are running locally

# --- CONFIGURATION (Fixes "NameError") ---
# These lines read the settings from Render/Environment
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

# --- Import all 3 Agents ---
from agents import run_login_agent, run_scribe_agent, run_threat_guardian_agent
# --- Initialization ---
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "default-secret-key")
alert_queue = Queue()
DATABASE = 'chat_history.db'

# --- GEOFENCING CONFIGURATION ---
HOME_COORDS = (18.464318494065264, 73.86811257863056)
OFFICE_COORDS = (19.0760, 72.8777)
SAFE_RADIUS_KM = 10.0

# --- Web3 & Blockchain Configuration ---
try:
    alchemy_url = os.getenv("ALCHEMY_API_URL")
    wallet_address = os.getenv("WALLET_ADDRESS")
    wallet_private_key = os.getenv("WALLET_PRIVATE_KEY")
    contract_address = os.getenv("EVIDENCE_CONTRACT_ADDRESS")
    
    if not alchemy_url or not wallet_private_key:
        raise ValueError("Missing Alchemy URL or Private Key in .env")

    web3 = Web3(Web3.HTTPProvider(alchemy_url))
    
    CONTRACT_ABI = json.loads('''
    [{"inputs": [{"internalType": "string", "name": "_eventType", "type": "string"},
    {"internalType": "string", "name": "_eventData", "type": "string"}],
    "name": "recordEvidence","outputs": [],"stateMutability": "nonpayable","type": "function"}]
    ''')
    
    evidence_contract = web3.eth.contract(address=contract_address, abi=CONTRACT_ABI)
    print("Successfully connected to Alchemy and loaded Smart Contract.")
except Exception as e:
    print(f"!!! CRITICAL: Failed to connect to Web3/Blockchain: {e}")
    evidence_contract = None

# --- Blockchain Writer Function (FIXED) ---
def write_evidence_to_blockchain(event_type, event_data):
    if not evidence_contract:
        print("Blockchain connection not established. Skipping write.")
        return
    try:
        scribe_verdict = run_scribe_agent(event_type, event_data)
        if scribe_verdict.get('decision') != 'RECORD':
            print(f"Scribe Agent decided to IGNORE event: {scribe_verdict.get('reason')}")
            return
        
        print(f"Scribe Agent decided to RECORD: {scribe_verdict.get('reason')}")
        event_data_json = json.dumps(event_data)
        nonce = web3.eth.get_transaction_count(wallet_address)
        tx_data = {'from': wallet_address, 'nonce': nonce, 'gasPrice': web3.eth.gas_price}
        
        print("Estimating gas cost...")
        gas_estimate = evidence_contract.functions.recordEvidence(
            event_type, event_data_json
        ).estimate_gas(tx_data)
        tx_data['gas'] = int(gas_estimate * 1.2)
        print(f"Gas estimated: {tx_data['gas']}")
        
        tx = evidence_contract.functions.recordEvidence(
            event_type, event_data_json
        ).build_transaction(tx_data)
        
        signed_tx = Account.sign_transaction(tx, wallet_private_key)
        
        # --- FIX: Handle both snake_case and camelCase for rawTransaction ---
        raw_tx = getattr(signed_tx, 'rawTransaction', getattr(signed_tx, 'raw_transaction', None))
        
        if raw_tx is None:
            raise AttributeError("Could not find rawTransaction or raw_transaction attribute on signed_tx")
            
        tx_hash = web3.eth.send_raw_transaction(raw_tx)
        print(f"Blockchain transaction sent. Hash: {tx_hash.hex()}")
        
    except Exception as e:
        print(f"!!! CRITICAL: Failed to write to blockchain: {e}")

# --- Gmail MFA Function ---
def send_mfa_email(user_email):
    """
    Generates a 6-digit code, prints it to logs for debugging, 
    and attempts to send it via Gmail.
    """
    # 1. Generate the 6-digit code
    mfa_code = str(random.randint(100000, 999999))
    
    # 2. FORCE PRINT TO LOGS (The "Backdoor" for testing)
    # flush=True ensures Render shows this line the second it happens.
    print(f"\n==================================================", flush=True)
    print(f"SECURITY ALERT: MFA CODE FOR {user_email} IS: {mfa_code}", flush=True)
    print(f"==================================================\n", flush=True)

    try:
        # 3. Prepare the Email Message
        msg = MIMEText(f"Your Agentic AI Security Code is: {mfa_code}")
        msg['Subject'] = "Security Verification - Agentic AI ZTA"
        msg['From'] = SENDER_EMAIL
        msg['To'] = user_email

        # 4. Connect to Gmail using TLS (Port 587)
        # Timeout is set to 20s to prevent the app from hanging forever
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=20)
        server.starttls()  # Upgrade the connection to secure
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        print(f">> SUCCESS: MFA Email sent to {user_email}", flush=True)
        
    except Exception as e:
        # 5. Handle Errors Safely
        # If email fails, we log why, but we DO NOT let the app crash.
        print(f">> EMAIL ERROR: {str(e)}", flush=True)
        print(f">> WORKAROUND: Use the code printed in the logs above to log in.", flush=True)

    return mfa_code
# --- Database Helper Functions ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def get_all_chats(user_id):
    db = get_db()
    chats = db.execute(
        'SELECT id, title FROM chats WHERE user_id = ? ORDER BY created_at DESC', (user_id,)
    ).fetchall()
    return chats

def get_all_users():
    """Fetches all user data for the admin panel."""
    db = get_db()
    users = db.execute(
        'SELECT user_id, true_role, is_quarantined, failed_attempts, failed_role_attempts FROM users'
    ).fetchall()
    return users

def get_messages_for_chat(chat_id):
    db = get_db()
    messages = db.execute(
        'SELECT role, content FROM messages WHERE chat_id = ? ORDER BY created_at ASC', (chat_id,)
    ).fetchall()
    return [{'role': msg['role'], 'content': msg['content']} for msg in messages]

def add_message(chat_id, role, content):
    db = get_db()
    db.execute('INSERT INTO messages (chat_id, role, content) VALUES (?, ?, ?)', (chat_id, role, content))
    db.commit()
    
def create_new_chat(user_id, title="New Chat"):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('INSERT INTO chats (user_id, title) VALUES (?, ?)', (user_id, title))
    new_chat_id = cursor.lastrowid
    db.commit()
    return new_chat_id

def delete_chat_from_db(chat_id):
    db = get_db()
    db.execute('DELETE FROM messages WHERE chat_id = ?', (chat_id,))
    db.execute('DELETE FROM chats WHERE id = ?', (chat_id,))
    db.commit()

# --- User & Auth Helper Functions ---
def get_user_profile(user_id):
    db = get_db()
    try:
        user = db.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
        return user
    except sqlite3.OperationalError:
        # Fallback if table doesn't exist yet (though init_db should fix this)
        return None

def check_password(hashed_pass, provided_pass):
    default_hash = hashlib.sha256("password123".encode()).hexdigest()
    provided_hash = hashlib.sha256(provided_pass.encode()).hexdigest()
    return provided_hash == default_hash

def update_user_on_login(user_id, location_status, device_fingerprint):
    db = get_db()
    db.execute(
        '''UPDATE users 
           SET last_location_status = ?, last_device_fingerprint = ?, last_login = ?
           WHERE user_id = ?''',
        (location_status, device_fingerprint, datetime.datetime.now(), user_id)
    )
    db.commit()

def set_quarantine_status(user_id, status=True):
    db = get_db()
    db.execute(
        'UPDATE users SET is_quarantined = ? WHERE user_id = ?',
        (1 if status else 0, user_id)
    )
    db.commit()
    
def reset_failed_attempts(user_id):
    db = get_db()
    db.execute('UPDATE users SET failed_attempts = 0 WHERE user_id = ?', (user_id,))
    db.commit()  

def reset_failed_role_attempts(user_id):
    db = get_db()
    db.execute('UPDATE users SET failed_role_attempts = 0 WHERE user_id = ?', (user_id,))
    db.commit()      

# --- Geofencing Helper Functions ---
def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    dLat = radians(lat2 - lat1)
    dLon = radians(lon2 - lon1)
    lat1 = radians(lat1)
    lat2 = radians(lat2)
    a = sin(dLat / 2)**2 + cos(lat1) * cos(lat2) * sin(dLon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c

def get_verified_location_status(lat, lon):
    if lat == "0.0" and lon == "0.0": return "Unknown"
    try:
        user_lat, user_lon = float(lat), float(lon)
    except ValueError:
        return "Unknown"
    dist_home = haversine(user_lat, user_lon, HOME_COORDS[0], HOME_COORDS[1])
    dist_office = haversine(user_lat, user_lon, OFFICE_COORDS[0], OFFICE_COORDS[1])
    return "SafeZone" if dist_home <= SAFE_RADIUS_KM or dist_office <= SAFE_RADIUS_KM else "Atypical"

# --- Main Routes ---
@app.route('/')
def index():
    if session.get('logged_in'): return redirect('/dashboard')
    return redirect('/login')

@app.route('/admin/unlock_user', methods=['POST'])
def unlock_user():
    if not session.get('logged_in') or session.get('role') != 'Admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    user_id = request.get_json().get('user_id')
    if not user_id:
        return jsonify({'status': 'error', 'message': 'User ID is missing'}), 400

    db = get_db()
    db.execute('UPDATE users SET is_quarantined = 0, failed_attempts = 0, failed_role_attempts = 0 WHERE user_id = ?', (user_id,))
    db.commit()

    print(f"ADMIN ACTION: User {user_id} has been unlocked.")
    return jsonify({'status': 'success', 'message': f'{user_id} has been unlocked.'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        user_id = data.get('user_id')
        password = data.get('password')
        claimed_role = data.get('role')

        user_profile = get_user_profile(user_id)

        if not user_profile:
            return jsonify({"status": "DENY", "message": "Login DENIED. This user ID does not exist."})

        if user_profile['is_quarantined']:
            return jsonify({
                "status": "DENY", 
                "message": "This account is locked due to a previous security alert. Please contact your administrator to unlock it."
            })

        password_correct = check_password(user_profile['password_hash'], password)

        if not password_correct:
            db = get_db()
            current_attempts = user_profile['failed_attempts']
            new_count = current_attempts + 1
            attempts_remaining = 3 - new_count

            if new_count >= 3:
                set_quarantine_status(user_id, True)
                db.execute('UPDATE users SET failed_attempts = ? WHERE user_id = ?', (new_count, user_id))
                db.commit()
                return jsonify({"status": "DENY", "message": "Too many failed attempts. This account is now locked. Please contact your administrator."})
            else:
                db.execute('UPDATE users SET failed_attempts = ? WHERE user_id = ?', (new_count, user_id))
                db.commit()
                return jsonify({"status": "DENY", "message": f"Invalid password. You have {attempts_remaining} attempt(s) remaining."})

        if user_profile['failed_attempts'] > 0:
            reset_failed_attempts(user_id)

        role_mismatch = (claimed_role != user_profile['true_role'])

        if role_mismatch:
            db = get_db()
            current_role_attempts = user_profile['failed_role_attempts']
            new_role_count = current_role_attempts + 1
            attempts_remaining = 3 - new_role_count

            if new_role_count >= 3:
                set_quarantine_status(user_id, True)
                db.execute('UPDATE users SET failed_role_attempts = ? WHERE user_id = ?', (new_role_count, user_id))
                db.commit()
                decision_data = {'action': 'QUARANTINE', 'reason': 'Locked due to 3 failed role attempts.'}
                write_evidence_to_blockchain('LOGIN_ATTEMPT', {'user_id': user_id, 'decision': decision_data})
                return jsonify({"status": "QUARANTINE", "message": "Too many failed role claims. This account is now locked. Please contact your administrator."})
            else:
                db.execute('UPDATE users SET failed_role_attempts = ? WHERE user_id = ?', (new_role_count, user_id))
                db.commit()
                return jsonify({"status": "DENY", "message": f"Incorrect role selected. You have {attempts_remaining} attempt(s) remaining."})

        if user_profile['failed_role_attempts'] > 0:
            reset_failed_role_attempts(user_id)

        lat, lon = data.get('latitude'), data.get('longitude')
        device_fingerprint = request.headers.get('User-Agent', 'Unknown')
        location_status = get_verified_location_status(lat, lon)
        current_hour = datetime.datetime.now().hour # Use real time

        new_device = (device_fingerprint != user_profile['last_device_fingerprint'])
        time_anomaly = False
        if current_hour < 6 or current_hour > 22: time_anomaly = True

        ai_context = {
            "user_exists": True, "password_correct": True,
            "true_role": user_profile['true_role'], "claimed_role": claimed_role,
            "role_mismatch": False, 
            "location_status": location_status,
            "last_location_status": user_profile['last_location_status'],
            "hour": current_hour, "time_anomaly": time_anomaly, "new_device": new_device,
        }

        print(f"Sending this context to AI: {ai_context}")
        action, reason = run_login_agent(ai_context)

        decision_data = {'action': action, 'reason': reason}
        write_evidence_to_blockchain('LOGIN_ATTEMPT', {'context': ai_context, 'decision': decision_data})

        if action == 'ALLOW':
            session['logged_in'] = True
            session['role'] = user_profile['true_role']
            session['user_id'] = user_id
            update_user_on_login(user_id, location_status, device_fingerprint)
            return jsonify({"status": "ALLOW", "message": reason})

        elif action == 'REQUIRE_MFA':
            user_email = os.getenv("GMAIL_ADDRESS")
            if user_email:
                mfa_code = send_mfa_email(user_email)
                if mfa_code:
                    session['mfa_code'] = mfa_code
                    session['mfa_user_id'] = user_id
                    session['mfa_location'] = location_status
                    session['mfa_device'] = device_fingerprint
                    return jsonify({"status": "REQUIRE_MFA", "message": reason})
            
            # Fallback if email failed
            return jsonify({"status": "DENY", "message": "MFA required but system could not send email. Contact admin."})

        elif action == 'QUARANTINE':
            set_quarantine_status(user_id, True)
            return jsonify({"status": action, "message": reason})

        else: # DENY
            return jsonify({"status": action, "message": reason})

    return render_template('login.html')

@app.route('/verify_mfa', methods=['POST'])
def verify_mfa():
    data = request.get_json()
    user_code = data.get('code')
    
    stored_code = session.get('mfa_code')
    
    if not stored_code:
        return jsonify({"status": "FAIL", "message": "Your session expired. Please log in again."})
        
    if user_code == stored_code:
        user_id = session.get('mfa_user_id')
        user_profile = get_user_profile(user_id)
        
        session['logged_in'] = True
        session['role'] = user_profile['true_role']
        session['user_id'] = user_id
        
        update_user_on_login(user_id, session.get('mfa_location'), session.get('mfa_device'))
        
        # Clear MFA data
        session.pop('mfa_code', None)
        session.pop('mfa_user_id', None)
        session.pop('mfa_location', None)
        session.pop('mfa_device', None)
        
        return jsonify({"status": "OK", "message": "Verification successful. Logging in..."})
    else:
        return jsonify({"status": "FAIL", "message": "Invalid code. Please try again."})

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'): return redirect('/login')
    user_id = session.get('user_id')
    chats = get_all_chats(user_id)
    return render_template('dashboard.html', chats=chats, current_chat_id=None)

@app.route('/chat/<int:chat_id>')
def view_chat(chat_id):
    if not session.get('logged_in'): return redirect('/login')
    user_id = session.get('user_id')
    chats = get_all_chats(user_id)
    messages = get_messages_for_chat(chat_id)
    return render_template('dashboard.html', chats=chats, messages=messages, current_chat_id=chat_id)

@app.route('/new_chat', methods=['POST'])
def new_chat():
    if not session.get('logged_in'): return jsonify({'error': 'Unauthorized'}), 401
    user_id = session.get('user_id')
    new_chat_id = create_new_chat(user_id)
    return jsonify({'success': True, 'chat_id': new_chat_id})

@app.route('/delete_chat/<int:chat_id>', methods=['POST'])
def delete_chat(chat_id):
    if not session.get('logged_in'): return jsonify({'error': 'Unauthorized'}), 401
    delete_chat_from_db(chat_id)
    return jsonify({'success': True})

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/chat_message', methods=['POST'])
def chat_message():
    if not session.get('logged_in'): return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    user_message = data.get('message', '')
    chat_id = data.get('chat_id')
    user_id, role = session.get('user_id'), session.get('role')
    if not chat_id: return jsonify({"error": "Missing chat_id"}), 400
    add_message(chat_id, 'user', user_message)
    chat_history = get_messages_for_chat(chat_id)
    verdict = run_threat_guardian_agent(user_message, role, chat_history)
    agent_response = verdict.get("response", "I am unable to respond at this time.")
    add_message(chat_id, 'model', agent_response)
    chat_context = {'user_id': user_id, 'role': role, 'chat_id': chat_id, 'message': user_message, 'threat_assessment': verdict}
    write_evidence_to_blockchain('CHAT_MESSAGE', chat_context)
    if verdict.get("is_threat"):
        alert_queue.put(json.dumps({'type': 'THREAT_DETECTED', 'data': {**verdict, 'user_id': user_id, 'role': role}}))
        if verdict.get("severity") == "High":
            session.clear()
        return jsonify({"error": agent_response, "action": "logout" if verdict.get("severity") == "High" else ""}), 403
    return jsonify({"reply": agent_response})

@app.route('/admin')
def admin():
    if not session.get('logged_in') or session.get('role') != 'Admin': 
        return redirect('/login')
    sepolia_url = f"https://sepolia.etherscan.io/address/{contract_address}"
    all_users = get_all_users()
    return render_template('admin.html', blockchain_url=sepolia_url, users=all_users)

@app.route('/api/admin/alerts')
def stream_alerts():
    def event_stream():
        while True: yield f"data: {alert_queue.get()}\n\n"
    return Response(event_stream(), mimetype='text/event-stream')

# --- INITIALIZE DATABASE ON STARTUP (Required for Render) ---
def init_database():
    try:
        db = sqlite3.connect(DATABASE)
        cursor = db.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL,
                title TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER NOT NULL,
                role TEXT NOT NULL, content TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (chat_id) REFERENCES chats (id));''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                true_role TEXT NOT NULL,
                last_location_status TEXT,
                last_login TIMESTAMP,
                last_device_fingerprint TEXT,
                is_quarantined BOOLEAN DEFAULT 0,
                failed_attempts INTEGER DEFAULT 0,
                failed_role_attempts INTEGER DEFAULT 0   
            );''')
        
        default_hash = hashlib.sha256("password123".encode()).hexdigest()
        
        users_to_add = [
            ('admin_user', default_hash, 'Admin', 'SafeZone'),
            ('employee_user', default_hash, 'Employee', 'SafeZone'),
            ('intern_user', default_hash, 'Intern', 'SafeZone')
        ]
        
        cursor.executemany('''
            INSERT OR IGNORE INTO users (user_id, password_hash, true_role, last_location_status)
            VALUES (?, ?, ?, ?)
            ''', users_to_add)

        db.commit()
        print("Database initialized successfully with default users.")
        
    except Exception as e:
        print(f"Database initialization error: {e}")
    finally:
        if 'db' in locals():
            db.close()

# Run initialization immediately when module loads
init_database()

if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(debug=True, port=5000, ssl_context='adhoc')
# backend/app.py
import os
import sqlite3
import hashlib
import cv2
import pytesseract
import numpy as np
import keyring
import secrets
import string
import threading

from keyring.errors import PasswordDeleteError
import gnupg  # python-gnupg
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from d3graph import d3graph, vec2adjmat
from werkzeug.utils import secure_filename

# Instead of 'gnupghome=', use 'homedir=' if your python-gnupg version doesn't accept 'gnupghome'.
# For example:
# gpg = gnupg.GPG(homedir=str(GNUPG_HOME))

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_BUILD = BASE_DIR.parent / 'frontend' / 'build'
STATIC_DIR = BASE_DIR / 'static'
UPLOAD_DIR = BASE_DIR / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)

# Setup a dedicated GnuPG home directory for storing keys:
GNUPG_HOME = BASE_DIR / 'gnupg_home'
GNUPG_HOME.mkdir(exist_ok=True)
gpg = gnupg.GPG(homedir=str(GNUPG_HOME))  # Use 'homedir='

app = Flask(__name__, static_folder=str(FRONTEND_BUILD), static_url_path='/')
app.secret_key = 'replace-with-a-secure-secret'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
CORS(app, supports_credentials=True)

DB_PATH = BASE_DIR / 'federal_data.db'

root_username = "bo@shang.software"
root_password_hash = "f20f88ee1de694294420122a32e488de4b743241a4a8fda384325b95176a655b"
aloha_admin = "aloha@teamtulsi.com"  # Additional admin for GPG signing

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            pw_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            uploader TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            doc_id INTEGER,
            action TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_gpg (
            username TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL,
            passphrase TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            cred_type TEXT,
            enc_data TEXT
        )
    ''')
    c.execute("SELECT * FROM users WHERE username=?", (root_username,))
    if not c.fetchone():
        c.execute("INSERT INTO users (username, pw_hash, is_admin) VALUES (?,?,?)",
                  (root_username, root_password_hash, 1))
        conn.commit()
    c.execute("SELECT * FROM users WHERE username=?", (aloha_admin,))
    if not c.fetchone():
        tmp_pw = "AlohaPass123!"
        pw_hash = bcrypt.generate_password_hash(tmp_pw).decode('utf-8')
        c.execute("INSERT INTO users (username, pw_hash, is_admin) VALUES (?,?,?)",
                  (aloha_admin, pw_hash, 1))
        conn.commit()
    conn.close()

init_db()

aes_master_key = Fernet.generate_key()
cipher_suite = Fernet(aes_master_key)

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, pw_hash, is_admin FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        u = User()
        u.id = row[0]
        u.is_admin = bool(row[2])
        return u
    return None

@app.post('/api/register')
def register():
    data = request.get_json()
    if not data or not all(k in data for k in ('username', 'password')):
        return jsonify(success=False), 400
    username = data['username']
    password = data['password']
    if username == root_username:
        return jsonify(success=False, message="Root user cannot be modified."), 403
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, pw_hash, is_admin) VALUES (?,?,?)", (username, pw_hash, 0))
        conn.commit()
    except:
        conn.close()
        return jsonify(success=False, message="User already exists."), 400
    conn.close()
    return jsonify(success=True)

@app.post('/api/login')
def login():
    data = request.get_json()
    if not data:
        return jsonify(success=False), 400
    username = data.get('username')
    password = data.get('password')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT pw_hash, is_admin FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        pw_hash = row[0]
        if pw_hash == root_password_hash:
            if hashlib.sha256(password.encode()).hexdigest() == root_password_hash:
                u = User()
                u.id = username
                u.is_admin = True
                login_user(u)
                return jsonify(success=True)
        elif bcrypt.check_password_hash(pw_hash, password):
            u = User()
            u.id = username
            u.is_admin = bool(row[1])
            login_user(u)
            return jsonify(success=True)
    return jsonify(success=False), 401

@app.post('/api/logout')
@login_required
def logout():
    logout_user()
    return jsonify(success=True)

@app.get('/api/graph')
@login_required
def graph():
    source = ['node A','node F','node B','node B','node B','node A','node C','node Z']
    target = ['node F','node B','node J','node F','node F','node M','node M','node A']
    weight = [5.56,0.5,0.64,0.23,0.9,3.28,0.5,0.45]
    adjmat = vec2adjmat(source, target, weight=weight)
    d3 = d3graph()
    d3.graph(adjmat)
    filepath = STATIC_DIR / 'graph.html'
    d3.show(filepath=str(filepath))
    return send_from_directory(STATIC_DIR, 'graph.html')

@app.post('/api/upload')
@login_required
def upload():
    if 'file' not in request.files:
        return jsonify(success=False), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify(success=False), 400
    filename = secure_filename(file.filename)
    file.save(str(UPLOAD_DIR / filename))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO documents (filename, uploader) VALUES (?,?)", (filename, current_user.id))
    doc_id = c.lastrowid
    c.execute("INSERT INTO user_logs (username, doc_id, action) VALUES (?,?,?)",
              (current_user.id, doc_id, "upload"))
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.get('/api/docs')
@login_required
def list_docs():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, filename, uploader FROM documents")
    rows = c.fetchall()
    docs = [{"id":r[0], "filename":r[1], "uploader":r[2]} for r in rows]
    conn.close()
    return jsonify(docs=docs)

@app.get('/api/leak_risk')
@login_required
def leak_risk():
    if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
        return jsonify(success=False, message="Not authorized."), 403
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username FROM users")
    all_users = c.fetchall()
    conn.close()
    risk = {}
    for u in all_users:
        risk[u[0]] = float(np.random.rand(1))
    return jsonify(risk=risk)

@app.post('/api/set_admin')
@login_required
def set_admin():
    if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
        return jsonify(success=False, message="Not authorized."), 403
    data = request.get_json()
    username = data.get('username')
    is_admin_flag = data.get('is_admin', False)
    if username == root_username:
        return jsonify(success=False, message="Root user cannot be modified."), 403
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET is_admin=? WHERE username=?", (1 if is_admin_flag else 0, username))
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.get('/api/tesseract_ocr')
@login_required
def tesseract_ocr():
    filename = request.args.get('filename')
    if not filename:
        return jsonify(success=False), 400
    path = UPLOAD_DIR / filename
    if not path.exists():
        return jsonify(success=False), 404
    img = cv2.imread(str(path))
    text = pytesseract.image_to_string(img)
    return jsonify(ocr=text)

################################################################
# GnuPG-based Key Management & Crypto
################################################################

@app.post('/api/create_gpg_key')
@login_required
def create_gpg_key():
    passphrase = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    input_data = gpg.gen_key_input(
        name_email=current_user.id,
        passphrase=passphrase,
        key_type="RSA",
        key_length=2048
    )
    key = gpg.gen_key(input_data)
    if not key.fingerprint:
        return jsonify(success=False, message="Failed to generate key"), 500

    fp = str(key.fingerprint)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT fingerprint FROM user_gpg WHERE username=?", (current_user.id,))
    existing = c.fetchone()
    if existing:
        conn.close()
        return jsonify(success=False, message="Key already exists"), 400

    c.execute("INSERT INTO user_gpg (username, fingerprint, passphrase) VALUES (?,?,?)",
              (current_user.id, fp, passphrase))
    conn.commit()
    conn.close()
    return jsonify(success=True, fingerprint=fp, passphrase=passphrase)

@app.post('/api/sign_gpg')
@login_required
def sign_gpg():
    if current_user.id != aloha_admin and not (hasattr(current_user, 'is_admin') and current_user.is_admin):
        return jsonify(success=False, message="Not authorized to sign"), 403

    data = request.get_json()
    message = data.get('message', '')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT fingerprint, passphrase FROM user_gpg WHERE username=?", (current_user.id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify(success=False, message="User has no GPG key"), 400

    fingerprint, passphrase = row
    signed = gpg.sign(
        message,
        keyid=fingerprint,
        passphrase=passphrase,
        detach=False,
        clearsign=False
    )
    if not signed.data:
        return jsonify(success=False, message="Signing failed"), 500

    return jsonify(success=True, signature=signed.data.decode('utf-8', errors='ignore'))

@app.post('/api/verify_gpg')
@login_required
def verify_gpg():
    data = request.get_json()
    signed_message = data.get('signed_message', '')

    verified = gpg.verify(signed_message)
    if not verified:
        return jsonify(verified=False)
    return jsonify(verified=True, fingerprint=verified.fingerprint, status=verified.status)

@app.post('/api/encrypt_gpg')
@login_required
def encrypt_gpg():
    data = request.get_json()
    recipient_username = data.get('recipient')
    plaintext = data.get('plaintext', '')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT fingerprint FROM user_gpg WHERE username=?", (recipient_username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify(success=False, message="Recipient has no GPG key"), 400
    recipient_fp = row[0]

    encrypted = gpg.encrypt(plaintext, recipient_fp)
    if not encrypted.data:
        return jsonify(success=False, message="Encryption failed"), 500

    return jsonify(success=True, ciphertext=encrypted.data.decode('utf-8', errors='ignore'))

@app.post('/api/decrypt_gpg')
@login_required
def decrypt_gpg():
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT fingerprint, passphrase FROM user_gpg WHERE username=?", (current_user.id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify(success=False, message="No GPG key for user"), 400
    user_fp, passphrase = row

    dec = gpg.decrypt(ciphertext, passphrase=passphrase)
    if not dec.data:
        return jsonify(success=False, message="Decryption failed"), 500

    return jsonify(success=True, plaintext=dec.data.decode('utf-8', errors='ignore'))

################################################################
# AES-based encryption for credentials
################################################################

@app.post('/api/aes_encrypt')
@login_required
def aes_encrypt():
    data = request.get_json()
    plaintext = data.get('plaintext', '')
    encrypted = cipher_suite.encrypt(plaintext.encode()).decode()
    return jsonify(encrypted=encrypted)

@app.post('/api/aes_decrypt')
@login_required
def aes_decrypt():
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')
    try:
        dec = cipher_suite.decrypt(ciphertext.encode()).decode()
        return jsonify(decrypted=dec)
    except:
        return jsonify(success=False), 400

################################################################
# Credentials Manager
################################################################

@app.post('/api/add_credential')
@login_required
def add_credential():
    data = request.get_json()
    cred_type = data.get('type', '')
    cred_value = data.get('value', '')
    enc_data = cipher_suite.encrypt(cred_value.encode()).decode()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO user_credentials (username, cred_type, enc_data) VALUES (?,?,?)",
              (current_user.id, cred_type, enc_data))
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.get('/api/get_credentials')
@login_required
def get_credentials():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, cred_type, enc_data FROM user_credentials WHERE username=?", (current_user.id,))
    rows = c.fetchall()
    creds = []
    for r in rows:
        try:
            dec_data = cipher_suite.decrypt(r[2].encode()).decode()
            creds.append({"id": r[0], "type": r[1], "value": dec_data})
        except:
            creds.append({"id": r[0], "type": r[1], "value": "Error"})
    conn.close()
    return jsonify(credentials=creds)

################################################################
# Utility: File Hash + Leak Detection
################################################################

@app.get('/api/file_hash')
@login_required
def file_hash():
    filename = request.args.get('filename')
    if not filename:
        return jsonify(success=False), 400
    path = UPLOAD_DIR / filename
    if not path.exists():
        return jsonify(success=False), 404
    hasher = hashlib.sha256()
    with open(path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return jsonify(hash=hasher.hexdigest())

@app.post('/api/leak_detect')
@login_required
def leak_detect():
    data = request.get_json()
    text = data.get('text', '')
    leaked_words = ["topsecret", "classified", "nuclear", "attackplan"]
    for w in leaked_words:
        if w in text.lower():
            return jsonify(leaked=True, word=w)
    return jsonify(leaked=False)

################################################################
# Frontend Serving
################################################################

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    target = FRONTEND_BUILD / path
    if path and target.exists():
        return send_from_directory(FRONTEND_BUILD, path)
    return send_from_directory(FRONTEND_BUILD, 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6969, debug=True)
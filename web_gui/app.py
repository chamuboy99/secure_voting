# web_gui/app.py

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import base64
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session
from utils import (
    generate_rsa_keys, save_key, load_key,
    generate_aes_key, aes_encrypt, aes_decrypt,
    rsa_encrypt, rsa_decrypt,
    sign_message, verify_signature, hashes
)
from werkzeug.security import generate_password_hash, check_password_hash
from collections import Counter

app = Flask(__name__)
app.secret_key = 'secure-voting-secret'

# === Paths ===
VOTER_DB = "voter_db.json"
KEYS_DIR = "../keys/"
VOTES_DIR = "../votes/"
VOTER_LOG = "../voted_voters.txt"
SERVER_PRIV_KEY = "../keys/server_private.pem"
SERVER_PUB_KEY = "../keys/server_public.pem"

# === Setup ===
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(VOTES_DIR, exist_ok=True)

if not os.path.exists(VOTER_DB) or os.path.getsize(VOTER_DB) == 0:
    with open(VOTER_DB, "w") as f:
        json.dump([], f)

if not os.path.exists(VOTER_LOG):
    open(VOTER_LOG, 'a').close()

server_priv = load_key(SERVER_PRIV_KEY, is_private=True)
server_pub = load_key(SERVER_PUB_KEY)

@app.route('/')
def home():
    return redirect(url_for('login'))

# === Register ===
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fname = request.form['fname'].strip()
        lname = request.form['lname'].strip()
        suffix = request.form['reg_suffix'].strip()
        password = request.form['password']
        confirm = request.form['confirm']

        if not suffix.isdigit() or len(suffix) != 4:
            return "Registration number must be 4 digits (e.g., 1234)."

        reg_no = f"EG/2020/{suffix}"

        if password != confirm:
            return "Passwords do not match."

        with open(VOTER_DB, 'r') as f:
            voters = json.load(f)

        if any(v['reg_no'] == reg_no for v in voters):
            return "Voter already registered."

        # Generate and save keys
        priv, pub = generate_rsa_keys()
        filename_safe_reg = reg_no.replace("/", "_")
        save_key(priv, os.path.join(KEYS_DIR, f"{filename_safe_reg}_private.pem"), is_private=True)
        save_key(pub, os.path.join(KEYS_DIR, f"{filename_safe_reg}_public.pem"))

        # Save voter data
        voters.append({
            "reg_no": reg_no,
            "first_name": fname,
            "last_name": lname,
            "password_hash": generate_password_hash(password),
            "role": "voter"
        })
        with open(VOTER_DB, 'w') as f:
            json.dump(voters, f)

        return redirect(url_for('login'))

    return render_template('register.html')

# === Login ===
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        reg_no = request.form['reg_no'].strip()
        password = request.form['password']

        with open(VOTER_DB, 'r') as f:
            voters = json.load(f)

        user = next((v for v in voters if v['reg_no'] == reg_no), None)

        if not user or not check_password_hash(user['password_hash'], password):
            return "Invalid credentials."

        session['reg_no'] = reg_no
        session['role'] = user['role']

        if user['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('vote'))

    return render_template('login.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    candidates_path = "candidates.json"
    image_folder = os.path.join("static", "candidate_images")

    if not os.path.exists(image_folder):
        os.makedirs(image_folder)

    # Load current candidates
    if os.path.exists(candidates_path):
        with open(candidates_path, 'r') as f:
            candidates = json.load(f)
    else:
        candidates = []

    if request.method == 'POST':
        action = request.form['action']
        name = request.form['name'].strip()

        if action == 'add':
            file = request.files['image']
            filename = secure_filename(file.filename)
            filepath = os.path.join(image_folder, filename)
            file.save(filepath)

            # Add only if name not already present
            if not any(c['name'] == name for c in candidates):
                candidates.append({
                    "name": name,
                    "image": filename
                })

        elif action == 'remove':
            candidates = [c for c in candidates if c['name'] != name]

        with open(candidates_path, 'w') as f:
            json.dump(candidates, f)

        return redirect(url_for('admin_dashboard'))

    return render_template('admin_dashboard.html', candidates=candidates)



# === Vote ===
@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'reg_no' not in session:
        return redirect(url_for('login'))

    reg_no = session['reg_no']
    filename_safe_reg = reg_no.replace("/", "_")
    priv_path = os.path.join(KEYS_DIR, f"{filename_safe_reg}_private.pem")
    
    if not os.path.exists(priv_path):
        return "Voter keys not found."

    #===voter_priv = load_key(priv_path, is_private=True)===

    # Create the log file if it doesn't exist
    if not os.path.exists(VOTER_LOG):
        with open(VOTER_LOG, 'w') as f:
            pass  # Just create empty file

    with open(VOTER_LOG, 'r') as f:
        if reg_no in f.read():
            return "❌ You have already voted."

    # Load candidates
    with open("candidates.json", "r") as f:
        candidates = json.load(f)

    if request.method == 'POST':
        candidate = request.form['candidate'].strip().encode()

        aes_key = generate_aes_key()
        enc_vote = aes_encrypt(candidate, aes_key)
        enc_key = rsa_encrypt(aes_key, server_pub)

        digest = hashes.Hash(hashes.SHA256())
        digest.update(candidate)
        vote_hash = digest.finalize()
        voter_priv = load_key(priv_path, is_private=True)
        signature = sign_message(vote_hash, voter_priv)

        payload = {
            "encrypted_vote": base64.b64encode(enc_vote).decode(),
            "encrypted_key": base64.b64encode(enc_key).decode(),
            "signature": base64.b64encode(signature).decode()
        }
        filename_safe_reg = reg_no.replace("/", "_")
        with open(os.path.join(VOTES_DIR, f"{filename_safe_reg}_vote.json"), 'w') as f:
            json.dump(payload, f)

        with open(VOTER_LOG, 'a') as f:
            f.write(reg_no + "\n")

        return redirect(url_for('results'))

    return render_template('vote.html', candidates=candidates)

# === Results ===
@app.route('/results')
def results():
    all_votes = []

    for file in os.listdir(VOTES_DIR):
        if file.endswith("_vote.json"):
            with open(os.path.join(VOTES_DIR, file), 'r') as f:
                data = json.load(f)

            enc_vote = base64.b64decode(data['encrypted_vote'])
            enc_key = base64.b64decode(data['encrypted_key'])

            aes_key = rsa_decrypt(enc_key, server_priv)
            vote_plain = aes_decrypt(enc_vote, aes_key).decode()

            all_votes.append(vote_plain)

    counts = Counter(all_votes)
    return render_template('results.html', counts=counts)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
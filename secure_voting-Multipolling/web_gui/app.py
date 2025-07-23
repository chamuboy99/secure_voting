# web_gui/app.py

import os
import sys

# Set BASE_DIR to root of secure_voting
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Add secure_voting to Python path
sys.path.append(BASE_DIR)
POLL_DIR = os.path.join(BASE_DIR, 'polls')

os.makedirs(POLL_DIR, exist_ok=True)

import json
import base64
import re
from werkzeug.utils import secure_filename
from flask import Flask,flash, render_template, request, redirect, url_for, session
from utils import (
    generate_rsa_keys, save_key, load_key,
    generate_aes_key, aes_encrypt, aes_decrypt,
    rsa_encrypt, rsa_decrypt,
    sign_message, verify_signature, hashes
)
from werkzeug.security import generate_password_hash, check_password_hash
from collections import Counter

import uuid
from datetime import datetime, timedelta

POLL_DIR = "secure_voting-Multipolling/polls"


def load_poll(poll_id):
    path = os.path.join(POLL_DIR, f"{poll_id}.json")
    with open(path, 'r') as f:
        return json.load(f)

def save_poll(poll):
    path = os.path.join(POLL_DIR, f"{poll['id']}.json")
    with open(path, 'w') as f:
        json.dump(poll, f, indent=2)

def list_polls():
    return [f.split(".")[0] for f in os.listdir(POLL_DIR) if f.endswith(".json")]


app = Flask(__name__)
app.secret_key = 'secure-voting-secret'

# === Paths ===
VOTER_DB = os.path.join(BASE_DIR, "voter_db.json")
KEYS_DIR = os.path.join(BASE_DIR, "keys")
VOTES_DIR = os.path.join(BASE_DIR, "votes")
VOTER_LOG = os.path.join(BASE_DIR, "voted_voters.txt")
SERVER_PRIV_KEY = os.path.join(KEYS_DIR, "server_private.pem")
SERVER_PUB_KEY = os.path.join(KEYS_DIR, "server_public.pem")

# === Setup ===
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(VOTES_DIR, exist_ok=True)

if not os.path.exists(VOTER_DB) or os.path.getsize(VOTER_DB) == 0:
    with open(VOTER_DB, "w") as f:
        json.dump([], f)

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
            flash("Registration number must be 4 digits (e.g., 1234).")
            return redirect(url_for('register'))

        reg_no = f"EG/2020/{suffix}"

        # Password strength validation
        if len(password) < 8 or \
           not re.search(r'[A-Z]', password) or \
           not re.search(r'[a-z]', password) or \
           not re.search(r'[^A-Za-z0-9]', password):
            flash("Password must be at least 8 characters with 1 uppercase, 1 lowercase, and 1 special character.")
            return redirect(url_for('register'))

        if password != confirm:
            flash("Passwords do not match.")
            return redirect(url_for('register'))

        with open(VOTER_DB, 'r') as f:
            voters = json.load(f)

        if any(v['reg_no'] == reg_no for v in voters):
            flash("Voter already registered.")
            return redirect(url_for('register'))

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

        flash("Registration successful. Please log in.")
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

        if not user:
            flash("User not registered.")
            return redirect(url_for('login'))

        if not check_password_hash(user['password_hash'], password):
            flash("Incorrect password.")
            return redirect(url_for('login'))

        session['reg_no'] = reg_no
        session['role'] = user['role']

        if user['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('available_polls'))

    return render_template('login.html')

# === Admin ===
@app.route('/admin')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    return render_template('admin_dashboard.html')

@app.route('/admin/create_poll', methods=['GET', 'POST'])
def create_poll():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        end_time_str = request.form['end_time']
        try:
            end_time = datetime.strptime(end_time_str, '%Y-%m-%dT%H:%M')
            if end_time <= datetime.now():
                flash("End time must be in the future.")
                return render_template('create_poll.html')
        except ValueError:
            flash("Invalid date format.")
            return render_template('create_poll.html')

        poll_id = uuid.uuid4().hex[:8]  # random short ID
        poll = {
            "id": poll_id,
            "title": title,
            "published": False,
            "ended": False,
            "end_time": end_time.isoformat(),
            "candidates": []
        }
        save_poll(poll)
        return redirect(url_for('edit_poll', poll_id=poll_id))

    return render_template('create_poll.html')

@app.route('/polls')
def available_polls():
    if 'reg_no' not in session:
        return redirect(url_for('login'))

    reg_no = session['reg_no']
    available = []

    for pid in list_polls():
        poll = load_poll(pid)
        if poll['published'] and not poll['ended']:
            # Check time
            if datetime.now() > datetime.fromisoformat(poll['end_time']):
                poll['ended'] = True
                save_poll(poll)
                continue
            available.append(poll)

    return render_template('polls.html', polls=available)


@app.route('/admin/edit_poll/<poll_id>', methods=['GET', 'POST'])
def edit_poll(poll_id):
    poll = load_poll(poll_id)

    if request.method == 'POST':
        action = request.form['action']

        if action == 'add_candidate' and not poll['published']:
            name = request.form['name']
            image_file = request.files['image']
            image_name = secure_filename(image_file.filename)
            image_path = os.path.join("static", "candidate_images", image_name)
            image_file.save(image_path)
            poll['candidates'].append({
                "name": name,
                "image": image_name,
                "votes": 0
            })
            flash(f"Candidate added successfully.")

        elif action == 'remove_candidate' and not poll['published']:
            name = request.form['name']
            poll['candidates'] = [c for c in poll['candidates'] if c['name'] != name]
            flash(f"Candidate removed.")

        elif action == 'update_end_time' and not poll['published']:
            new_time = request.form['end_time']
            try:
                dt = datetime.strptime(new_time, '%Y-%m-%dT%H:%M')
                if dt <= datetime.now():
                    flash("End time must be in the future.")
                else:
                    poll['end_time'] = dt.isoformat()
                    flash("End time updated.")
            except ValueError:
                flash("Invalid date format.")

        elif action == 'publish':
            if len(poll['candidates']) >= 2:
                poll['published'] = True
                end_dt = datetime.fromisoformat(poll['end_time'])
                if end_dt > datetime.now():
                    poll['ended'] = False
                flash("Poll published.")
            else:
                flash("Poll must have at least 2 candidates to publish.")

        elif action == 'unpublish':
            poll['published'] = False
            flash("Poll unpublished.")

        elif action == 'terminate':
            poll['ended'] = True
            poll['end_time'] = datetime.now().isoformat()
            flash("Poll terminated.")

        elif action == 'delete_poll':
            os.remove(os.path.join(POLL_DIR, f"{poll_id}.json"))
            flash("Poll deleted.")
            return redirect(url_for('admin_dashboard'))

        save_poll(poll)
        return redirect(url_for('edit_poll', poll_id=poll_id))  # ✅ PRG redirect

    return render_template('edit_poll.html', poll=poll)


@app.route('/poll/<poll_id>', methods=['GET', 'POST'])
def vote_in_poll(poll_id):
    poll = load_poll(poll_id)

    if not poll['published'] or poll['ended']:
        return "Poll is not active.", 403

    if datetime.now() > datetime.fromisoformat(poll['end_time']):
        poll['ended'] = True
        save_poll(poll)
        return "Poll has ended.", 403

    if request.method == 'POST':
        selected = request.form.get('candidate')  # ✅ Use .get to avoid key errors

        if not selected:
            return "❌ Please select a candidate before voting.", 400

        reg_no = session.get('reg_no')
        if not reg_no:
            return redirect(url_for('login'))

        filename_safe_reg = reg_no.replace("/", "_")
        priv_path = os.path.join(KEYS_DIR, f"{filename_safe_reg}_private.pem")

        if not os.path.exists(priv_path):
            return "Private key missing for voter."

        # Check for double voting
        voted_path = os.path.join(VOTES_DIR, poll_id, f"{poll_id}_voted.txt")
        os.makedirs(os.path.dirname(voted_path), exist_ok=True)
        if os.path.exists(voted_path):
            with open(voted_path, 'r') as f:
                if reg_no in f.read():
                    flash("You have already voted.")
                    return redirect(url_for('available_polls'))

        # Secure vote
        aes_key = generate_aes_key()
        enc_vote = aes_encrypt(selected.encode(), aes_key)
        enc_key = rsa_encrypt(aes_key, server_pub)

        voter_priv = load_key(priv_path, is_private=True)

        digest = hashes.Hash(hashes.SHA256())
        digest.update(selected.encode())
        vote_hash = digest.finalize()

        signature = sign_message(vote_hash, voter_priv)

        payload = {
            "encrypted_vote": base64.b64encode(enc_vote).decode(),
            "encrypted_key": base64.b64encode(enc_key).decode(),
            "signature": base64.b64encode(signature).decode()
        }

        vote_path = os.path.join(VOTES_DIR, poll_id, f"{filename_safe_reg}_vote.json")
        with open(vote_path, 'w') as f:
            json.dump(payload, f)

        with open(voted_path, 'a') as f:
            f.write(reg_no + "\n")

        # ✅ Live update the vote count
        for c in poll['candidates']:
            if c['name'] == selected:
                c['votes'] = c.get('votes', 0) + 1
                break
        save_poll(poll)

        return redirect(url_for('poll_results', poll_id=poll_id))

    return render_template('vote_poll.html', poll=poll)

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

        return redirect(url_for('results'))

    return render_template('vote.html', candidates=candidates)

# === Results ===
@app.route('/results/<poll_id>')
def poll_results(poll_id):
    poll = load_poll(poll_id)
    poll_vote_dir = os.path.join(VOTES_DIR, poll_id)

    # Auto-end poll if time's up
    if not poll['ended'] and datetime.now() > datetime.fromisoformat(poll['end_time']):
        poll['ended'] = True
        save_poll(poll)

    if not os.path.exists(poll_vote_dir):
        return render_template("results.html", poll=poll, counts={})

    all_votes = []

    for file in os.listdir(poll_vote_dir):
        if file.endswith("_vote.json"):
            with open(os.path.join(poll_vote_dir, file), 'r') as f:
                data = json.load(f)

            try:
                enc_vote = base64.b64decode(data['encrypted_vote'])
                enc_key = base64.b64decode(data['encrypted_key'])

                aes_key = rsa_decrypt(enc_key, server_priv)
                vote_plain = aes_decrypt(enc_vote, aes_key).decode()

                all_votes.append(vote_plain)
            except Exception as e:
                print(f"[Error decrypting vote from {file}]: {e}")
                continue

    # Tally votes securely
    vote_counts = {c['name']: 0 for c in poll['candidates']}
    for vote in all_votes:
        if vote in vote_counts:
            vote_counts[vote] += 1

    return render_template("results.html", poll=poll, counts=vote_counts)

@app.route('/results')
def results_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    all_polls = []
    for fname in os.listdir(POLL_DIR):
        if fname.endswith(".json"):
            with open(os.path.join(POLL_DIR, fname), 'r') as f:
                poll = json.load(f)
                all_polls.append(poll)

    return render_template('results_dashboard.html', polls=all_polls)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
# server/server.py
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import base64
from flask import Flask, request, jsonify
from utils import (
    load_key, rsa_decrypt, aes_decrypt, verify_signature, hashes
)

app = Flask(__name__)

# === File paths ===

SERVER_PRIV_KEY_FILE = "../keys/server_private.pem"
VOTER_KEYS_DIR = "../keys/"
VOTES_DIR = "../votes/"
VOTER_LOG = "voted_voters.txt"  # to track who has already voted

# === Load Server's Private Key ===
server_priv = load_key(SERVER_PRIV_KEY_FILE, is_private=True)

# === Ensure votes directory exists ===
os.makedirs(VOTES_DIR, exist_ok=True)

# === Voter Log (to prevent duplicate voting) ===
if not os.path.exists(VOTER_LOG):
    with open(VOTER_LOG, 'w') as f:
        f.write("")

@app.route('/submit_vote', methods=['POST'])
def submit_vote():
    data = request.get_json()

    voter_id = data.get("voter_id")
    enc_vote_b64 = data.get("encrypted_vote")
    enc_key_b64 = data.get("encrypted_key")
    signature_b64 = data.get("signature")

    if not all([voter_id, enc_vote_b64, enc_key_b64, signature_b64]):
        return jsonify({"error": "Missing fields"}), 400

    # Prevent multiple votes
    with open(VOTER_LOG, 'r') as f:
        if voter_id in f.read():
            return jsonify({"error": "You have already voted"}), 403

    # Load voter's public key
    voter_pub_path = os.path.join(VOTER_KEYS_DIR, f"{voter_id}_public.pem")
    if not os.path.exists(voter_pub_path):
        return jsonify({"error": "Voter not registered"}), 404

    voter_pub = load_key(voter_pub_path)

    # Decode base64 data
    enc_vote = base64.b64decode(enc_vote_b64)
    enc_key = base64.b64decode(enc_key_b64)
    signature = base64.b64decode(signature_b64)

    try:
        # Decrypt AES key
        aes_key = rsa_decrypt(enc_key, server_priv)

        # Decrypt vote
        vote_plaintext = aes_decrypt(enc_vote, aes_key)

        # Hash the vote
        digest = hashes.Hash(hashes.SHA256())
        digest.update(vote_plaintext)
        vote_hash = digest.finalize()

        # Verify the digital signature
        if not verify_signature(vote_hash, signature, voter_pub):
            return jsonify({"error": "Invalid signature"}), 403

        # Save vote anonymously
        filename = os.path.join(VOTES_DIR, f"{voter_id}_vote.json")
        with open(filename, 'w') as f:
            json.dump({
                "encrypted_vote": enc_vote_b64,
                "encrypted_key": base64.b64encode(enc_key).decode(),
                "signature": signature_b64
            }, f)

        # Mark voter as voted
        with open(VOTER_LOG, 'a') as f:
            f.write(voter_id + "\n")

        return jsonify({"message": "Vote accepted"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5000)

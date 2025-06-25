# voter/voter.py

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import base64
import requests
from utils import (
    generate_rsa_keys, save_key, load_key,
    generate_aes_key, aes_encrypt,
    sign_message, rsa_encrypt, 
    hashes
)

# === Setup ===

VOTER_ID = "voter01"
VOTER_PRIV_KEY_FILE = f"../keys/{VOTER_ID}_private.pem"
VOTER_PUB_KEY_FILE = f"../keys/{VOTER_ID}_public.pem"
SERVER_PUB_KEY_FILE = "../keys/server_public.pem"

# === Step 1: Load or generate voter's RSA keys ===

if not os.path.exists(VOTER_PRIV_KEY_FILE):
    priv, pub = generate_rsa_keys()
    save_key(priv, VOTER_PRIV_KEY_FILE, is_private=True)
    save_key(pub, VOTER_PUB_KEY_FILE)
else:
    priv = load_key(VOTER_PRIV_KEY_FILE, is_private=True)
    pub = load_key(VOTER_PUB_KEY_FILE)

# === Step 2: Load server's public key ===

server_pub = load_key(SERVER_PUB_KEY_FILE)

# === Step 3: Prepare vote ===

candidate = input("Enter your vote (Candidate A / Candidate B): ").strip()
vote_data = candidate.encode()

# === Step 4: Generate AES key and encrypt vote ===

aes_key = generate_aes_key()
encrypted_vote = aes_encrypt(vote_data, aes_key)

# === Step 5: Encrypt AES key using server public key ===

encrypted_key = rsa_encrypt(aes_key, server_pub)

# === Step 6: Hash and sign the vote ===

digest = hashes.Hash(hashes.SHA256())
digest.update(vote_data)
vote_hash = digest.finalize()
signature = sign_message(vote_hash, priv)

# === Step 7: Encode binary data to base64 for transmission ===

def b64(x): return base64.b64encode(x).decode()

payload = {
    "voter_id": VOTER_ID,
    "encrypted_vote": b64(encrypted_vote),
    "encrypted_key": b64(encrypted_key),
    "signature": b64(signature)
}

# === Step 8: Submit vote ===

response = requests.post("http://localhost:5000/submit_vote", json=payload)

if response.status_code == 200:
    print("✅ Vote submitted successfully.")
else:
    print("❌ Failed to submit vote:", response.text)

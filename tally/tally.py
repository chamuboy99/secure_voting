import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import base64
from collections import Counter
from utils import (
    load_key, rsa_decrypt, aes_decrypt
)

# === File paths ===
SERVER_PRIV_KEY_FILE = "../keys/server_private.pem"
VOTES_DIR = "../votes/"

# === Load server private key ===
server_priv = load_key(SERVER_PRIV_KEY_FILE, is_private=True)

# === Tally votes ===
votes = []

for filename in os.listdir(VOTES_DIR):
    if filename.endswith("_vote.json"):
        with open(os.path.join(VOTES_DIR, filename), "r") as f:
            vote_record = json.load(f)

        enc_vote = base64.b64decode(vote_record["encrypted_vote"])
        enc_key = base64.b64decode(vote_record["encrypted_key"])

        # Decrypt AES key
        aes_key = rsa_decrypt(enc_key, server_priv)

        # Decrypt vote
        plaintext_vote = aes_decrypt(enc_vote, aes_key)
        votes.append(plaintext_vote.decode())

# Count votes
results = Counter(votes)

print("\n📊 Election Results:")
for candidate, count in results.items():
    print(f"🗳️ {candidate}: {count} vote(s)")

#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template
import time, json, base64, bcrypt, secrets, hashlib

app = Flask(__name__)

ADMIN_SECRET = secrets.token_bytes(16)           

with open('./flag','r') as f:
    FLAG = f.readline()   

def b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def b64u_dec(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def sign_payload(payload_bytes: bytes, salt: bytes | None = None) -> bytes:
    if salt is None:
        salt = bcrypt.gensalt()                  
    
    msg = payload_bytes + b'.' + ADMIN_SECRET
    return bcrypt.hashpw(msg, salt)

def make_token(payload: dict) -> str:
    payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    salt = bcrypt.gensalt()
    sig = sign_payload(payload_bytes, salt)
    return '.'.join([b64u_enc(payload_bytes), b64u_enc(salt), b64u_enc(sig)])

def verify_token(token: str):
    try:
        p_b64, s_b64, h_b64 = token.split('.')
        payload_bytes = b64u_dec(p_b64)
        salt = b64u_dec(s_b64)
        sig  = b64u_dec(h_b64)
    except Exception:
        return None, False, "bad token format"

    try:
        ok = bcrypt.hashpw(payload_bytes + b'.' + ADMIN_SECRET, salt) == sig
    except Exception:
        return None, False, "bcrypt error"

    if not ok:
        return None, False, "invalid signature"

    try:
        payload = json.loads(payload_bytes.decode())
    except Exception:
        return None, False, "bad payload json"

    return payload, True, "ok"

def xor_repeat(data: bytes, key: bytes) -> bytes:
    k = (key * ((len(data) // len(key)) + 1))[:len(data)]
    return bytes(d ^ k[i] for i, d in enumerate(data))

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/sample_user")
def sample_user():
    payload = {
        "role": "user",
        "email": "user@example.com",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    return jsonify({"token": make_token(payload)})

@app.post("/redeem")
def redeem():
    token = (request.json or {}).get("token", "")
    payload, ok, msg = verify_token(token)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400

    now = int(time.time())
    if "exp" in payload and now > int(payload["exp"]):
        return jsonify({"ok": False, "error": "token expired"}), 403

    if payload.get("role") == "vip":
        key = hashlib.sha256(token.encode()).digest()
        capsule = xor_repeat(FLAG.encode(), key)
        return jsonify({
            "ok": True,
            "capsule": b64u_enc(capsule),                  
        })


    return jsonify({"ok": False, "error": "need vip"}), 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6001, debug=False)


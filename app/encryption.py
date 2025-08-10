import json
import base64
import secrets
import time
from flask import current_app
from Crypto.Cipher import AES

def now_ts() -> int:
    return int(time.time())

def _get_aes_key():
    key_b64 = current_app.config.get("AES_KEY")
    if not key_b64:
        raise RuntimeError("AES_KEY not set in environment")
    key = base64.urlsafe_b64decode(key_b64)
    if len(key) not in (16, 24, 32):
        raise RuntimeError("AES_KEY must decode to 16/24/32 bytes.")
    return key

def _b64encode_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64decode_no_pad(s: str) -> bytes:
    padding_needed = (4 - len(s) % 4) % 4
    s += "=" * padding_needed
    return base64.urlsafe_b64decode(s)

def encrypt_payload(payload: dict, ttl_seconds: int) -> str:
    """
    payload: arbitrary JSON-serializable dict
    ttl_seconds: time to live in seconds (will be clamped to MAX_TTL)
    returns: urlsafe base64 token (no padding)
    """
    now = now_ts()
    max_ttl = current_app.config.get("MAX_TTL") or (60*60*24*7)
    ttl_seconds = min(int(ttl_seconds), int(max_ttl))
    envelope = {
        "iat": now,
        "exp": now + ttl_seconds,
        "data": payload
    }
    pt = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    nonce = secrets.token_bytes(12)  
    cipher = AES.new(_get_aes_key(), AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(pt)
    token = nonce + tag + ct
    return _b64encode_no_pad(token)

def decrypt_token(token_b64: str) -> dict:
    data = _b64decode_no_pad(token_b64)
    if len(data) < (12 + 16):  
        raise ValueError("token too short")
    nonce = data[:12]
    tag = data[12:28]
    ct = data[28:]
    cipher = AES.new(_get_aes_key(), AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    envelope = json.loads(pt.decode("utf-8"))
     
    now = now_ts()
    if "exp" not in envelope or "iat" not in envelope:
        raise ValueError("invalid token structure")
    if not (envelope["iat"] <= now <= envelope["exp"]):
        raise ValueError("token expired or not yet valid")
    return envelope["data"]

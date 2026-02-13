import os
import uuid
import time
import json
import hmac
import hashlib
import logging
import datetime
import math
from functools import wraps
from io import BytesIO

from flask import Flask, request, jsonify, send_file, g
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
import jwt

NOT_FOUND_MSG = "Not found"
FORBIDDEN_MSG = "Forbidden"

class Config:
    RSA_KEY_BITS     = 2048
    KEY_SIZE_BYTES   = RSA_KEY_BITS // 8         
    OAEP_OVERHEAD    = 66                     
    MAX_CHUNK_SIZE   = KEY_SIZE_BYTES - OAEP_OVERHEAD 

    JWT_SECRET       = os.environ.get("JWT_SECRET")
    JWT_ALGORITHM    = "HS256"
    JWT_EXPIRY_SECONDS = 3600

    MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024        
    PBKDF2_ITERATIONS   = 600_000                  
    LOG_LEVEL           = logging.INFO

def _require_secret():
    secret = Config.JWT_SECRET
    if not secret:
        raise RuntimeError(
            "JWT_SECRET environment variable is not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    if len(secret) < 32:
        raise RuntimeError(
            f"JWT_SECRET is too short ({len(secret)} chars). Minimum 32 characters required."
        )

_require_secret()

logging.basicConfig(level=Config.LOG_LEVEL)

def audit(event: str, user_id: str = None, details: dict = None):
    now = datetime.datetime.now(datetime.timezone.utc)
    entry = {
        "event":      event,
        "user_id":    user_id or "anonymous",
        "timestamp":  now.isoformat(),
        "request_id": getattr(g, "request_id", None),
        "ip":         request.remote_addr if request else None,
        "details":    details or {}
    }
    logging.getLogger("audit").info(json.dumps(entry))

def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, Config.PBKDF2_ITERATIONS
    ).hex()

def _make_user(password: str, role: str, tenant_id: str) -> dict:
    salt = os.urandom(32)          
    return {
        "password_hash": _hash_password(password, salt),
        "salt":          salt.hex(),
        "role":          role,
        "tenant_id":     tenant_id,
    }

users_db = {
    "alice": _make_user("Alice@Secret1!", "decrypt_user", "tenant-1"),
    "bob":   _make_user("Bob@Secret2!",   "encrypt_user", "tenant-1"),
    "admin": _make_user("Admin@Secret!",  "admin",        "tenant-1"),
}

file_store: dict = {}
key_store:  dict = {}

def generate_rsa_keypair(key_size: int = Config.RSA_KEY_BITS):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def encrypt_file_pure_rsa(plaintext: bytes, public_key_pem: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    buf = BytesIO()
    total_chunks = math.ceil(len(plaintext) / Config.MAX_CHUNK_SIZE)
    for i in range(total_chunks):
        chunk = plaintext[i * Config.MAX_CHUNK_SIZE : (i + 1) * Config.MAX_CHUNK_SIZE]
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        buf.write(encrypted_chunk)
    return buf.getvalue()

def decrypt_file_pure_rsa(ciphertext: bytes, private_key_pem: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )
    chunk_size = Config.KEY_SIZE_BYTES
    if len(ciphertext) % chunk_size != 0:
        raise ValueError("Invalid ciphertext length")
    buf = BytesIO()
    total_chunks = len(ciphertext) // chunk_size
    for i in range(total_chunks):
        chunk = ciphertext[i * chunk_size : (i + 1) * chunk_size]
        try:
            decrypted_chunk = private_key.decrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            buf.write(decrypted_chunk)
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            raise RuntimeError(f"Decryption failed on chunk {i}") from e
    return buf.getvalue()

def get_or_create_tenant_keys(tenant_id: str) -> dict:
    if tenant_id not in key_store:
        priv, pub = generate_rsa_keypair()
        key_store[tenant_id] = {
            "private_key_pem": priv,
            "public_key_pem":  pub,
            "created_at":      datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "key_id":          str(uuid.uuid4()),
        }
    return key_store[tenant_id]

app = Flask(__name__)

@app.before_request
def before_request():
    g.request_id = str(uuid.uuid4())


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        try:
            g.user = jwt.decode(
                token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM]
            )
        except jwt.PyJWTError:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def require_role(*allowed_roles):
    """Decorator that enforces RBAC — must be applied AFTER @require_auth."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if g.user.get("role") not in allowed_roles:
                audit("forbidden", g.user.get("sub"), {"required": list(allowed_roles)})
                return jsonify({"error": FORBIDDEN_MSG}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


@app.route("/api/v1/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = users_db.get(username)

    salt = bytes.fromhex(user["salt"]) if user else os.urandom(32)
    candidate_hash = _hash_password(password, salt)
    stored_hash    = user["password_hash"] if user else ("0" * len(candidate_hash))

    if user and hmac.compare_digest(candidate_hash, stored_hash):
        token = jwt.encode(
            {
                "sub":       username,
                "role":      user["role"],
                "tenant_id": user["tenant_id"],
                "exp":       time.time() + Config.JWT_EXPIRY_SECONDS,
            },
            Config.JWT_SECRET,
            algorithm=Config.JWT_ALGORITHM,
        )
        audit("login_success", username)
        return jsonify({"token": token})

    audit("login_failure", username)
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/v1/files/upload", methods=["POST"])
@require_auth
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    file    = request.files["file"]
    content = file.read()
    if not content:
        return jsonify({"error": "File is empty"}), 400
    if len(content) > Config.MAX_FILE_SIZE_BYTES:
        return jsonify({"error": "File too large"}), 413

    file_id = str(uuid.uuid4())
    file_store[file_id] = {
        "owner":     g.user["sub"],
        "tenant_id": g.user["tenant_id"],
        "filename":  file.filename,
        "content":   content,
        "state":     "uploaded",
    }
    audit("upload", g.user["sub"], {"file_id": file_id})
    return jsonify({"file_id": file_id, "status": "uploaded"})


@app.route("/api/v1/files/<file_id>/encrypt", methods=["POST"])
@require_auth
@require_role("encrypt_user", "admin")
def encrypt(file_id):
    record = file_store.get(file_id)

    if not record or record["tenant_id"] != g.user["tenant_id"]:
        return jsonify({"error": NOT_FOUND_MSG}), 404

    if record["owner"] != g.user["sub"]:
        audit("idor_attempt", g.user["sub"], {"file_id": file_id, "owner": record["owner"]})
        return jsonify({"error": FORBIDDEN_MSG}), 403

    if record["state"] == "encrypted":
        return jsonify({"error": "File is already encrypted"}), 409

    keys = get_or_create_tenant_keys(g.user["tenant_id"])
    try:
        record["content"] = encrypt_file_pure_rsa(record["content"], keys["public_key_pem"])
        record["state"]   = "encrypted"
        audit("encrypt", g.user["sub"], {"file_id": file_id})
        return jsonify({"file_id": file_id, "state": "encrypted"})
    except Exception:
        return jsonify({"error": "Encryption failed"}), 500


@app.route("/api/v1/files/<file_id>/decrypt", methods=["POST"])
@require_auth
@require_role("decrypt_user", "admin")  
def decrypt(file_id):
    record = file_store.get(file_id)

    if not record or record["tenant_id"] != g.user["tenant_id"]:
        return jsonify({"error": NOT_FOUND_MSG}), 404

    if record["owner"] != g.user["sub"]:
        audit("idor_attempt", g.user["sub"], {"file_id": file_id, "owner": record["owner"]})
        return jsonify({"error": FORBIDDEN_MSG}), 403

    if record["state"] != "encrypted":
        return jsonify({"error": "File is not encrypted"}), 409

    keys = get_or_create_tenant_keys(g.user["tenant_id"])
    try:
        plaintext = decrypt_file_pure_rsa(record["content"], keys["private_key_pem"])
        audit("decrypt", g.user["sub"], {"file_id": file_id})
        return send_file(
            BytesIO(plaintext),
            as_attachment=True,
            download_name=record["filename"]
        )
    except Exception:
        return jsonify({"error": "Decryption failed"}), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

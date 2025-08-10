from flask import Blueprint, request, jsonify, current_app, url_for
from .encryption import encrypt_payload, decrypt_token

bp = Blueprint("api", __name__)

@bp.route("/link", methods=["POST"])
def create_link():
    """
    POST /api/link
    body: { "payload": {...}, "ttl": 3600 }  # ttl optional (seconds)
    returns: { "url": "<BASE_URL>/resolve?token=..." , "token": "..." }
    """
    body = request.get_json(silent=True)
    if not body or "payload" not in body:
        return jsonify({"error": "payload required"}), 400

    payload = body["payload"]
    ttl = body.get("ttl", current_app.config.get("MAX_TTL", 60*60*24*7))
    try:
        token = encrypt_payload(payload, ttl)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    base = current_app.config.get("BASE_URL", request.host_url.rstrip("/"))
    url = f"{base}/api/resolve?token={token}"
    return jsonify({"url": url, "token": token})

@bp.route("/resolve", methods=["GET"])
def resolve_link():
    """
    GET /api/resolve?token=...
    returns: { "payload": {...} } or 4xx/5xx on error
    """
    token = request.args.get("token")
    if not token:
        return jsonify({"error": "token required"}), 400
    try:
        payload = decrypt_token(token)
        return jsonify({"payload": payload})
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

 
@bp.route("/decrypt", methods=["POST"])
def decrypt_endpoint():
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    if not token:
        return jsonify({"error": "token required"}), 400
    try:
        payload = decrypt_token(token)
        return jsonify({"payload": payload})
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

import traceback

from flask import Blueprint, jsonify, request

from db_utils import get_db_connection
from web_utils import get_authenticated_user_id, rate_limit

chat_bp = Blueprint("chat", __name__)


@chat_bp.route("/get_messages", methods=["GET"])
@rate_limit(max_per_minute=60)
def get_messages():
    try:
        conn = get_db_connection()
        c = conn.cursor()

        c.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='messages'"
        )
        if not c.fetchone():
            conn.close()
            return jsonify({"messages": []}), 200

        c.execute(
            """
            SELECT m.user_id, m.message, m.timestamp, sk.username
            FROM messages m
            LEFT JOIN security_keys sk ON m.user_id = sk.user_id
            ORDER BY m.timestamp DESC LIMIT 50
            """
        )

        messages = [
            {
                "user": row[3] or f"User-{row[0][:6]}",
                "message": row[1],
                "time": row[2],
                "timestamp": row[2],
            }
            for row in c.fetchall()
        ]

        conn.close()
        return jsonify({"messages": messages}), 200
    except Exception:
        print(traceback.format_exc())
        return jsonify({"messages": []}), 200


@chat_bp.route("/get_private_messages", methods=["GET"])
@rate_limit(max_per_minute=60)
def get_private_messages():
    auth_user_id, auth_error = get_authenticated_user_id()
    if auth_error:
        return auth_error

    try:
        conn = get_db_connection()
        c = conn.cursor()

        c.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='private_messages'"
        )
        if not c.fetchone():
            conn.close()
            return jsonify({"messages": []}), 200

        c.execute(
            """
            SELECT pm.user_id, pm.message, pm.timestamp, sk.username
            FROM private_messages pm
            LEFT JOIN security_keys sk ON pm.user_id = sk.user_id
            ORDER BY pm.timestamp DESC LIMIT 50
            """
        )

        messages = [
            {
                "user": row[3] or f"User-{row[0][:6]}",
                "message": row[1],
                "time": row[2],
                "timestamp": row[2],
            }
            for row in c.fetchall()
        ]

        conn.close()
        return jsonify({"messages": messages}), 200
    except Exception:
        print(traceback.format_exc())
        return jsonify({"messages": []}), 200


@chat_bp.route("/send_message", methods=["POST"])
def send_message():
    auth_user_id, auth_error = get_authenticated_user_id()
    if auth_error:
        return auth_error

    data = request.get_json()
    if not data or "message" not in data:
        return jsonify({"error": "Message is required"}), 400

    message = data["message"]
    if not message.strip():
        return jsonify({"error": "Message cannot be empty"}), 400

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO messages (user_id, message) VALUES (?, ?)", (auth_user_id, message))
        conn.commit()
        conn.close()
        return jsonify({"success": True}), 200
    except Exception:
        print(traceback.format_exc())
        return jsonify({"error": "Failed to save message"}), 500


@chat_bp.route("/send_private_message", methods=["POST"])
def send_private_message():
    auth_user_id, auth_error = get_authenticated_user_id()
    if auth_error:
        return auth_error

    data = request.get_json()
    if not data or "message" not in data:
        return jsonify({"error": "Message is required"}), 400

    message = data["message"]
    if not message.strip():
        return jsonify({"error": "Message cannot be empty"}), 400

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO private_messages (user_id, message) VALUES (?, ?)", (auth_user_id, message))
        conn.commit()
        conn.close()
        return jsonify({"success": True}), 200
    except Exception:
        print(traceback.format_exc())
        return jsonify({"error": "Failed to save message"}), 500

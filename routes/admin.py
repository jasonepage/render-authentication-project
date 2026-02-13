import base64
import datetime
import os
import random
import traceback

from flask import Blueprint, jsonify, request

from app_context import PRESET_USERNAMES
from db_utils import get_db_connection
from web_utils import get_authenticated_user_id

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/debug_all", methods=["GET"])
def debug_all():
    debug_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "security_keys": [],
        "environment": {"db_path": os.environ.get("DB_PATH")},
    }

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(security_keys)")
        columns = [row[1] for row in cursor.fetchall()]
        debug_data["security_keys_schema"] = columns

        query = "SELECT " + ", ".join(columns) + " FROM security_keys"
        cursor.execute(query)

        column_names = [description[0] for description in cursor.description]

        keys = []
        for row in cursor.fetchall():
            key_data = {column_names[i]: row[i] for i in range(len(row))}

            if "credential_id" in key_data:
                key_data["credential_id_length"] = (
                    len(key_data["credential_id"]) if key_data["credential_id"] else 0
                )

                credential_valid = True
                try:
                    if key_data["credential_id"]:
                        padded = key_data["credential_id"] + "=" * (
                            4 - len(key_data["credential_id"]) % 4
                        )
                        standard = padded.replace("-", "+").replace("_", "/")
                        base64.b64decode(standard)
                except Exception:
                    credential_valid = False

                key_data["credential_valid_base64"] = credential_valid

            if "public_key" in key_data and key_data["public_key"]:
                snippet = key_data["public_key"]
                key_data["public_key_snippet"] = (
                    snippet[:30] + "..." if len(snippet) > 30 else snippet
                )

            keys.append(key_data)

        debug_data["security_keys"] = keys

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        debug_data["database_tables"] = [row[0] for row in cursor.fetchall()]

        conn.close()
    except Exception:
        debug_data["error"] = "debug_all failed"
        debug_data["traceback"] = traceback.format_exc()

    return jsonify(debug_data)


@admin_bp.route("/cleanup_credentials", methods=["POST"])
def cleanup_credentials():
    try:
        data = request.get_json()
        if not data or data.get("secret") != os.environ.get("ADMIN_SECRET", "admin_secret"):
            return jsonify({"error": "Unauthorized"}), 401

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM security_keys")
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()

        return jsonify({"status": "success", "message": f"Deleted {deleted_count} credentials"})
    except Exception:
        print(traceback.format_exc())
        return jsonify({"error": "Cleanup failed"}), 500


@admin_bp.route("/cycle_username", methods=["POST"])
def cycle_username():
    user_id, auth_error = get_authenticated_user_id()
    if auth_error:
        return auth_error

    try:
        new_username = random.choice(PRESET_USERNAMES)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE security_keys SET username = ? WHERE user_id = ?",
            (new_username, user_id),
        )
        conn.commit()
        conn.close()

        return jsonify({"status": "success", "username": new_username})
    except Exception:
        print(traceback.format_exc())
        return jsonify({"error": "Failed to update username"}), 500


@admin_bp.route("/toggle_registration", methods=["POST"])
def toggle_registration():
    user_id, auth_error = get_authenticated_user_id()
    if auth_error:
        return auth_error

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT is_admin FROM security_keys WHERE user_id = ?", (user_id,))
        result = cursor.fetchone()
        if not result or not result[0]:
            conn.close()
            return jsonify({"error": "Admin privileges required"}), 403

        cursor.execute("SELECT registration_enabled FROM registration_settings WHERE id = 1")
        current_status = cursor.fetchone()[0]

        new_status = not current_status
        cursor.execute(
            """
            UPDATE registration_settings
            SET registration_enabled = ?, updated_at = datetime('now'), updated_by = ?
            WHERE id = 1
            """,
            (new_status, user_id),
        )

        conn.commit()
        conn.close()

        status_text = "enabled" if new_status else "disabled"
        return jsonify(
            {
                "status": "success",
                "registrationEnabled": new_status,
                "message": f"Registration {status_text}",
            }
        )
    except Exception:
        print(traceback.format_exc())
        return jsonify({"error": "Failed to toggle registration"}), 500

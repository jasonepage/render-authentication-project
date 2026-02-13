import traceback

from flask import Blueprint, jsonify, request

from db_utils import get_db_connection
from web_utils import get_authenticated_user_id, rate_limit

map_bp = Blueprint("map", __name__)


@map_bp.route("/update_location", methods=["POST"])
@rate_limit(max_per_minute=60)
def update_location():
    user_id, auth_error = get_authenticated_user_id()
    if auth_error:
        return auth_error

    data = request.get_json()
    if not data or "latitude" not in data or "longitude" not in data:
        return jsonify({"error": "Latitude and longitude required"}), 400

    try:
        latitude = float(data["latitude"])
        longitude = float(data["longitude"])

        if not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
            return jsonify({"error": "Invalid coordinates"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM locations WHERE user_id = ?", (user_id,))
        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                """
                UPDATE locations
                SET latitude = ?, longitude = ?, updated_at = datetime('now')
                WHERE user_id = ?
                """,
                (latitude, longitude, user_id),
            )
        else:
            cursor.execute(
                """
                INSERT INTO locations (user_id, latitude, longitude)
                VALUES (?, ?, ?)
                """,
                (user_id, latitude, longitude),
            )

        conn.commit()
        conn.close()
        return jsonify({"status": "success"}), 200
    except ValueError:
        return jsonify({"error": "Invalid coordinate format"}), 400
    except Exception:
        print(traceback.format_exc())
        return jsonify({"error": "Failed to update location"}), 500


@map_bp.route("/get_locations", methods=["GET"])
@rate_limit(max_per_minute=60)
def get_locations():
    user_id, auth_error = get_authenticated_user_id()
    if auth_error:
        return auth_error

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT l.user_id, l.latitude, l.longitude, l.updated_at, sk.username
            FROM locations l
            LEFT JOIN security_keys sk ON l.user_id = sk.user_id
            WHERE datetime(l.updated_at) > datetime('now', '-5 minutes')
            ORDER BY l.updated_at DESC
            """
        )

        locations = [
            {
                "userId": row[0],
                "username": row[4] or f"User-{row[0][:6]}",
                "latitude": row[1],
                "longitude": row[2],
                "updatedAt": row[3],
            }
            for row in cursor.fetchall()
        ]

        conn.close()
        return jsonify({"locations": locations}), 200
    except Exception:
        print(traceback.format_exc())
        return jsonify({"locations": []}), 200


@map_bp.route("/remove_location", methods=["POST"])
def remove_location():
    user_id, auth_error = get_authenticated_user_id()
    if auth_error:
        return auth_error

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM locations WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()

        return jsonify({"status": "success"}), 200
    except Exception:
        print(traceback.format_exc())
        return jsonify({"error": "Failed to remove location"}), 500

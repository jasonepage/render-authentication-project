import traceback

from flask import Blueprint, jsonify, render_template, send_from_directory

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/")
def index():
    return jsonify({"status": "healthy", "service": "FIDO2 Authentication System"}), 200


@pages_bp.route("/chat")
def serve_chat():
    return render_template("index.html")


@pages_bp.route("/map")
def serve_map():
    return render_template("map.html")


@pages_bp.route("/info")
def serve_info():
    return render_template("info.html")


@pages_bp.route("/<path:path>")
def serve_static(path):
    try:
        return send_from_directory("static", path)
    except Exception as e:
        print(traceback.format_exc())
        return f"Error: {str(e)}", 500

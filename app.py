from flask import Flask
import os

from db_utils import init_db
from routes.admin import admin_bp
from routes.auth import auth_bp
from routes.chat import chat_bp
from routes.map import map_bp
from routes.pages import pages_bp

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key_change_in_production")
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

init_db()

app.register_blueprint(auth_bp)
app.register_blueprint(chat_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(map_bp)
app.register_blueprint(pages_bp)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

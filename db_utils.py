import os
import sqlite3

from app_context import DB_PATH


def get_db_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    if DB_PATH != ":memory:" and os.path.dirname(DB_PATH):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_keys (
            id INTEGER PRIMARY KEY,
            credential_id TEXT UNIQUE NOT NULL,
            user_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            aaguid TEXT,
            attestation_hash TEXT,
            combined_key_hash TEXT,
            resident_key BOOLEAN,
            created_at TIMESTAMP NOT NULL,
            username TEXT,
            is_admin BOOLEAN DEFAULT 0
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS registration_slots (
            id INTEGER PRIMARY KEY,
            slot_code TEXT UNIQUE NOT NULL,
            created_by_admin TEXT,
            used_by_user TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used_at TIMESTAMP,
            is_used BOOLEAN DEFAULT 0
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            user_id TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS private_messages (
            id INTEGER PRIMARY KEY,
            user_id TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS registration_settings (
            id INTEGER PRIMARY KEY,
            registration_enabled BOOLEAN DEFAULT 1,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT
        )
        """
    )

    cursor.execute("SELECT COUNT(*) FROM registration_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO registration_settings (registration_enabled) VALUES (1)"
        )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS locations (
            id INTEGER PRIMARY KEY,
            user_id TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES security_keys(user_id)
        )
        """
    )

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_location ON locations (user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_aaguid ON security_keys (aaguid)")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_combined_key_hash ON security_keys (combined_key_hash)"
    )

    conn.commit()
    conn.close()


def get_total_users():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(DISTINCT user_id) FROM security_keys")
        count = c.fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0


def can_register():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT registration_enabled FROM registration_settings WHERE id = 1")
        result = c.fetchone()
        conn.close()

        if result and result[0]:
            return True, None
        return False, "Registration is currently disabled by admin"
    except Exception:
        return True, None

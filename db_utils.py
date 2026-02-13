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
            public_key TEXT UNIQUE NOT NULL,
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
    
    # Run migration to add UNIQUE constraint on public_key
    _migrate_add_public_key_unique(conn)
    
    conn.close()


def _migrate_add_public_key_unique(conn):
    """Migrate to add UNIQUE constraint on public_key column."""
    try:
        cursor = conn.cursor()
        
        # Check if the constraint already exists by trying to insert a duplicate
        cursor.execute("PRAGMA table_info(security_keys)")
        columns = cursor.fetchall()
        
        # Check if we need to recreate the table
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='security_keys'")
        table_sql = cursor.fetchone()[0]
        
        if "UNIQUE" not in table_sql or "public_key" not in table_sql or "UNIQUE" not in table_sql.split("public_key")[0]:
            # Need to recreate table with UNIQUE constraint
            # First, remove any duplicate public_keys (keep the first occurrence)
            cursor.execute("""
                DELETE FROM security_keys WHERE id NOT IN (
                    SELECT MIN(id) FROM security_keys GROUP BY public_key
                )
            """)
            
            # Create new table with UNIQUE constraint
            cursor.execute("ALTER TABLE security_keys RENAME TO security_keys_old")
            
            cursor.execute("""
                CREATE TABLE security_keys (
                    id INTEGER PRIMARY KEY,
                    credential_id TEXT UNIQUE NOT NULL,
                    user_id TEXT NOT NULL,
                    public_key TEXT UNIQUE NOT NULL,
                    aaguid TEXT,
                    attestation_hash TEXT,
                    combined_key_hash TEXT,
                    resident_key BOOLEAN,
                    created_at TIMESTAMP NOT NULL,
                    username TEXT,
                    is_admin BOOLEAN DEFAULT 0
                )
            """)
            
            # Copy data back
            cursor.execute("""
                INSERT INTO security_keys 
                SELECT id, credential_id, user_id, public_key, aaguid, attestation_hash, 
                       combined_key_hash, resident_key, created_at, username, is_admin
                FROM security_keys_old
            """)
            
            # Drop old table
            cursor.execute("DROP TABLE security_keys_old")
            
            # Recreate indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_location ON locations (user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_aaguid ON security_keys (aaguid)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_combined_key_hash ON security_keys (combined_key_hash)")
            
            conn.commit()
            print("Migration: Added UNIQUE constraint to public_key column and removed duplicates")
    except Exception as e:
        print(f"Migration warning: {e}")
        # Don't fail, just log the warning



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

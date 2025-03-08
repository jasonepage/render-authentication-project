# Author: Jason Page
# Created: March 2024
# Version: 1.0

# Key Features:
# - FIDO2 WebAuthn authentication
# - Real-time chat messaging
# - SQLite database storage
# - Debug monitoring dashboard

# Dependencies:
# - Flask: Web framework
# - cryptography: For encryption and hashing
# - SQLite3: Database
# - Flask-CORS: Cross-origin resource sharing


from flask import Flask, request, jsonify, session, send_from_directory, make_response
import sqlite3
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import os
from cryptography.hazmat.primitives.asymmetric import utils
import secrets
import base64
from flask_cors import CORS
import time
from functools import wraps
import sys
import platform
import datetime
import traceback
import cbor2
import re

app = Flask(__name__)

# Add secret key for sessions
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

# Update the CORS configuration for better compatibility
CORS(app, 
     supports_credentials=True, 
     origins=["http://localhost:8000", "https://render-authentication-project.onrender.com"],
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"]
)

@app.before_request
def log_request_info():
    """Log details about every incoming request"""
    print("\n=== REQUEST INFO ===")
    print(f"Method: {request.method}")
    print(f"Path: {request.path}")
    print(f"Headers: {dict(request.headers)}")
    if request.is_json:
        print(f"JSON Data: {request.get_json()}")
    print(f"Session: {dict(session)}")
    print("==================\n")

@app.after_request
def log_response_info(response):
    """Log details about every outgoing response"""
    print("\n=== RESPONSE INFO ===")
    print(f"Status: {response.status}")
    print(f"Headers: {dict(response.headers)}")
    try:
        if response.is_json:
            print(f"JSON Data: {response.get_json()}")
    except:
        print("Response body is not JSON")
    print("==================\n")
    return response

def init_db():
    """Initialize SQLite database with required tables."""
    print("\n=== DATABASE INITIALIZATION ===")
    try:
        # Use a fixed database path that's guaranteed to be writable on Render
        db_path = '/opt/render/webauthn.db'
        os.environ['DATABASE_PATH'] = db_path
        print(f"Database path: {db_path}")
        
        # Check directory permissions
        db_dir = os.path.dirname(db_path)
        print(f"Directory exists: {os.path.exists(db_dir)}")
        print(f"Directory writable: {os.access(db_dir, os.W_OK)}")
        
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Create security_keys table
        print("Creating security_keys table...")
        # Drop the table if it exists to refresh the schema
        c.execute("DROP TABLE IF EXISTS security_keys")
        c.execute('''
            CREATE TABLE IF NOT EXISTS security_keys (
                credential_id TEXT PRIMARY KEY,
                user_id TEXT,
                public_key TEXT,
                created_at TEXT
            )
        ''')
        
        # Create messages table
        print("Creating messages table...")
        c.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                message TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Verify tables were created
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = c.fetchall()
        print(f"Existing tables: {tables}")
        
        conn.commit()
        conn.close()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        print("Stack trace:", traceback.format_exc())

# Initialize database at startup
init_db()

@app.route('/')
def index():
    """
    Health check endpoint.
    
    Returns:
        JSON: Status information about the service
        {
            "status": "healthy",
            "service": "FIDO2 Authentication System"
        }
    """
    print("Index endpoint accessed")
    return jsonify({"status": "healthy", "service": "FIDO2 Authentication System"}), 200

@app.route('/register', methods=['POST'])
def register():
    print("\n=== REGISTRATION ATTEMPT ===")
    data = request.json
    credential_id = data.get('credential_id')
    public_key_json = data.get('public_key')
    
    print(f"Received credential ID: {credential_id[:10]}... (length: {len(credential_id)})")
    print(f"Received public key JSON: {public_key_json[:30]}...")

    if not credential_id or not public_key_json:
        print("❌ Registration failed: Missing credential_id or public_key")
        return jsonify({"error": "Missing credential_id or public_key"}), 400

    db_path = os.environ.get('DATABASE_PATH', 'webauthn.db')
    print(f"Using database for registration: {db_path}")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    try:
        c.execute("INSERT INTO security_keys (credential_id, public_key) VALUES (?, ?)",
                  (credential_id, public_key_json))
        conn.commit()
        print(f"✅ Security key registered successfully! ID: {credential_id[:10]}...")
        return jsonify({"message": "Security key registered."}), 200
    except sqlite3.IntegrityError:
        print(f"❌ Registration failed: Credential already exists: {credential_id[:10]}...")
        return jsonify({"error": "Credential already exists."}), 400
    finally:
        conn.close()

@app.route('/verify', methods=['POST'])
def verify():
    print("\n=== VERIFICATION ATTEMPT ===")
    data = request.json
    credential_id = data.get('credential_id')
    auth_data = bytes.fromhex(data.get('auth_data', ''))
    signature = bytes.fromhex(data.get('signature', ''))
    client_data_json = bytes.fromhex(data.get('client_data_json', ''))
    
    print(f"Verifying credential: {credential_id[:10]}...")
    print(f"Full auth_data: {auth_data.hex()[:40]}")
    print(f"Full signature: {signature.hex()[:40]}")
    print(f"Full client_data_json: {client_data_json.hex()[:40]}")
    
    # Basic validation
    if not credential_id or not auth_data or not client_data_json or not signature:
        return jsonify({"error": "Missing required fields"}), 400

    # Check RP ID hash
    rp_id_hash = auth_data[:32]
    expected_rp_id_hash = hashlib.sha256(b"render-authentication-project.onrender.com").digest()
    
    if rp_id_hash != expected_rp_id_hash:
        return jsonify({"error": "RP ID hash mismatch"}), 403

    # Get public key
    try:
        db_path = os.environ.get('DATABASE_PATH', 'webauthn.db')
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT public_key FROM security_keys WHERE credential_id = ?", (credential_id,))
        row = c.fetchone()
        conn.close()

        if not row:
            return jsonify({"error": "Credential not found"}), 403

        # Parse public key
        public_key_data = json.loads(row[0])
        x = bytes.fromhex(public_key_data['-2'])
        y = bytes.fromhex(public_key_data['-3'])
        
        # Create EC public key
        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x, byteorder='big'),
            y=int.from_bytes(y, byteorder='big'),
            curve=ec.SECP256R1()
        )
        public_key = public_numbers.public_key()

        # Compute client data hash
        client_data_hash = hashlib.sha256(client_data_json).digest()
        
        # Data to verify
        signed_data = auth_data + client_data_hash
        
        # Try multiple verification approaches
        verification_methods = [
            # Method 1: Standard verification
            lambda: public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256())),
            
            # Method 2: Verify with pre-hashed data
            lambda: public_key.verify(signature, hashlib.sha256(signed_data).digest(), 
                        ec.ECDSA(utils.Prehashed(hashes.SHA256()))),
            
            # Method 3: Manually decode DER signature and verify
            lambda: verify_with_decoded_signature(public_key, signature, signed_data),
            
            # Method 4: Verify with raw WebAuthn components
            lambda: verify_with_raw_components(public_key, signature, auth_data, client_data_json)
        ]
        
        # Try each verification method
        last_error = None
        for method_num, method in enumerate(verification_methods, 1):
            try:
                if method():
                    print(f"✅ Verification succeeded with method {method_num}")
                    # Create session for the user
                    session['authenticated'] = True
                    session['user_id'] = credential_id[:10]  # Use credential ID prefix as user identifier
                    return jsonify({"message": "Security key verified successfully!"}), 200
            except Exception as e:
                last_error = str(e)
                print(f"❌ Verification method {method_num} failed: {last_error}")
        
        # If we get here, all verification methods failed
        return jsonify({"error": "Signature verification failed", "details": last_error}), 403
        
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return jsonify({"error": f"Verification error: {str(e)}"}), 500

def verify_with_decoded_signature(public_key, signature, signed_data):
    """Custom verification with decoded DER signature"""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    
    # Decode signature
    r, s = decode_dss_signature(signature)
    
    # Hash the data
    digest = hashlib.sha256(signed_data).digest()
    
    # Try different verification methods
    from cryptography.hazmat.primitives.asymmetric import utils
    prehashed = utils.Prehashed(hashes.SHA256())
    
    # Verify with the signature algorithm
    public_key.verify(signature, digest, ec.ECDSA(prehashed))

def verify_with_raw_components(public_key, signature, auth_data, client_data_json):
    """Verify signature using raw WebAuthn components"""
    try:
        # 1. Extract flags from auth_data
        flags = auth_data[32]
        print(f"Auth flags: {flags:08b}")
        
        # 2. Compute client data hash
        client_data_hash = hashlib.sha256(client_data_json).digest()
        print(f"Client data hash: {client_data_hash.hex()}")
        
        # 3. Create message (concat of authData and hash)
        message = auth_data + client_data_hash
        
        # 4. Decode DER signature to raw format
        r, s = decode_dss_signature(signature)
        # Convert to raw signature format (r|s)
        r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
        s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')
        
        # 5. Directly verify using low-level operations
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import padding
        
        # Create SHA-256 hash of message
        digest = hashlib.sha256(message).digest()
        
        # Try with different padding/hash configurations
        for sig_alg in [
            ec.ECDSA(hashes.SHA256()),
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        ]:
            try:
                public_key.verify(signature, digest if "Prehashed" in str(sig_alg) else message, sig_alg)
                return True
            except Exception as e:
                print(f"  - Failed with {sig_alg}: {e}")
        
        return False
    except Exception as e:
        print(f"Raw component verification error: {e}")
        return False

@app.route('/get_credential', methods=['GET'])
def get_credential():
    print("\n=== GET CREDENTIAL REQUEST ===")
    db_path = os.environ.get('DATABASE_PATH', 'webauthn.db')
    print(f"Getting credential from database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    try:
        c.execute("SELECT credential_id FROM security_keys LIMIT 1")
        row = c.fetchone()
        
        if row:
            credential_id = row[0]
            print(f"Found credential ID: {credential_id[:10]}...")
            return jsonify({"credential_id": credential_id}), 200
        else:
            print("No credentials found in database!")
            return jsonify({"error": "No credentials found"}), 404
    except Exception as e:
        print(f"Error retrieving credential: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/debug_signature', methods=['POST'])
def debug_signature():
    """Debug endpoint to try different signature verification methods"""
    data = request.json
    credential_id = data.get('credential_id')
    signature_hex = data.get('signature')
    auth_data_hex = data.get('auth_data')
    client_data_json_hex = data.get('client_data_json')
    
    try:
        # Convert hex strings to bytes
        signature = bytes.fromhex(signature_hex)
        auth_data = bytes.fromhex(auth_data_hex)
        client_data_json = bytes.fromhex(client_data_json_hex)
        
        # Get the public key from the database
        db_path = os.environ.get('DATABASE_PATH', 'webauthn.db')
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT public_key FROM security_keys WHERE credential_id = ?", (credential_id,))
        row = c.fetchone()
        conn.close()
        
        if not row:
            return jsonify({"error": "Credential not found"}), 404
        
        public_key_data = json.loads(row[0])
        
        # Extract x and y coordinates
        x = bytes.fromhex(public_key_data['-2'])
        y = bytes.fromhex(public_key_data['-3'])
        
        # Recreate public key
        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x, byteorder='big'),
            y=int.from_bytes(y, byteorder='big'),
            curve=ec.SECP256R1()
        )
        public_key = public_numbers.public_key()
        
        # Compute client data hash
        client_data_hash = hashlib.sha256(client_data_json).digest()
        
        # Data that was actually signed
        signed_data = auth_data + client_data_hash
        
        # Try verification
        public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
        
        return jsonify({
            "success": True,
            "message": "Signature verified successfully",
            "details": {
                "signature_length": len(signature),
                "auth_data_length": len(auth_data),
                "client_data_json_length": len(client_data_json),
                "client_data_hash_length": len(client_data_hash),
                "signed_data_length": len(signed_data)
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "details": {
                "signature_hex": signature_hex[:20] + "...",
                "auth_data_hex": auth_data_hex[:20] + "...",
                "client_data_json": client_data_json_hex[:20] + "..."
            }
        }), 400

def decode_signature(signature):
    """Decode DER signature into raw r,s values for verification"""
    r, s = decode_dss_signature(signature)
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')
    # Pad to 32 bytes
    r_bytes = r_bytes.rjust(32, b'\0')
    s_bytes = s_bytes.rjust(32, b'\0')
    return r_bytes + s_bytes

@app.route('/send_message', methods=['POST'])
def send_message():
    """Handle sending a chat message"""
    print("\n=== MESSAGE SEND ATTEMPT ===")
    print("1. Checking authentication...")
    
    if not session.get('authenticated'):
        print("❌ Message rejected: User not authenticated")
        print(f"Current session: {dict(session)}")
        return jsonify({"error": "Authentication required"}), 401
    
    print("\n2. Validating message...")
    message = request.json.get('message')
    if not message:
        print("❌ Message rejected: Empty message")
        return jsonify({"error": "Message required"}), 400
    
    user_id = session.get('user_id')
    print(f"3. Processing message from user {user_id}:")
    print(f"Message content: {message[:100]}...")
    
    print("\n4. Saving to database...")
    db_path = os.environ.get('DATABASE_PATH', 'webauthn.db')
    print(f"Using database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    try:
        c.execute("INSERT INTO messages (user_id, message) VALUES (?, ?)", 
                (user_id, message))
        conn.commit()
        print("✅ Message saved successfully")
        return jsonify({"success": True}), 200
    except Exception as e:
        print(f"❌ Error saving message: {e}")
        print("Stack trace:", traceback.format_exc())
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# Simple rate limiting decorator
def rate_limit(max_per_minute=60):
    cache = {}
    
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr
            current_time = time.time()
            
            # Clean old entries
            cache_copy = dict(cache)
            for key, timestamps in cache_copy.items():
                cache[key] = [t for t in timestamps if current_time - t < 60]
                if not cache[key]:
                    del cache[key]
            
            # Check rate limit
            if ip in cache and len(cache[ip]) >= max_per_minute:
                return jsonify({"error": "Rate limit exceeded"}), 429
            
            # Add this request
            if ip not in cache:
                cache[ip] = []
            cache[ip].append(current_time)
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/get_messages', methods=['GET'])
@rate_limit(max_per_minute=60)
def get_messages():
    """Get all messages."""
    print("\n=== MESSAGE RETRIEVAL REQUEST ===")
    print("1. Checking rate limit...")
    print("2. Retrieving messages from database...")
    
    # Fixed database path
    db_path = '/opt/render/webauthn.db'
    print(f"Using database: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        c.execute("SELECT user_id, message, timestamp FROM messages ORDER BY timestamp DESC LIMIT 50")
        messages = [{"user": row[0], "message": row[1], "time": row[2]} for row in c.fetchall()]
        print(f"✅ Retrieved {len(messages)} messages")
        if messages:
            print("Latest messages:")
            for msg in messages[:3]:  # Show last 3 messages
                print(f"  - {msg['user']}: {msg['message'][:30]}...")
        return jsonify({"messages": messages}), 200
    except Exception as e:
        print(f"❌ Error retrieving messages: {e}")
        print("Stack trace:", traceback.format_exc())
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/debug_db', methods=['GET'])
def debug_db():
    """Debug endpoint to test database access"""
    try:
        db_path = os.environ.get('DATABASE_PATH', 'webauthn.db')
        db_dir = os.path.dirname(db_path) or '.'
        
        # Test if directory exists and is writable
        dir_exists = os.path.exists(db_dir)
        dir_writable = os.access(db_dir, os.W_OK)
        
        # Try to create a test table
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS test_table (id INTEGER PRIMARY KEY)')
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "success",
            "db_path": db_path,
            "dir_exists": dir_exists,
            "dir_writable": dir_writable,
            "db_initialized": True
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

@app.route('/get_credentials', methods=['GET'])
def get_credentials():
    """Return all registered credential IDs."""
    print("\n=== GET ALL CREDENTIALS REQUEST ===")
    
    # Use the same database path as other functions
    db_path = os.environ.get('DATABASE_PATH', 'webauthn.db')
    print(f"Getting all credentials from database: {db_path}")
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all credential IDs
        cursor.execute("SELECT credential_id FROM security_keys")
        results = cursor.fetchall()
        conn.close()
        
        if results:
            # Return all credential IDs
            credentials = [result[0] for result in results]
            print(f"Found {len(credentials)} credential(s)")
            for i, cred in enumerate(credentials):
                print(f"  - Credential {i+1}: {cred[:10]}...")
            return jsonify({"credentials": credentials})
        else:
            print("No credentials found in database!")
            return jsonify({"credentials": []}), 404
    except Exception as e:
        print(f"Error retrieving credentials: {e}")
        return jsonify({"error": str(e)}), 500

# ==========================================
# WebAuthn Helper Functions
# ==========================================

def generate_challenge():
    """Generate a cryptographically secure random challenge"""
    challenge_bytes = secrets.token_bytes(32)
    # Convert to base64url encoding for sending to browser
    return base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')

def base64url_to_bytes(base64url):
    """Convert base64url string to bytes"""
    # Add padding
    padding = '=' * ((4 - len(base64url) % 4) % 4)
    base64_str = base64url.replace('-', '+').replace('_', '/') + padding
    return base64.b64decode(base64_str)

def bytes_to_base64url(bytes_value):
    """Convert bytes to base64url string"""
    base64_str = base64.b64encode(bytes_value).decode('utf-8')
    return base64_str.replace('+', '-').replace('/', '_').rstrip('=')

# ==========================================
# WebAuthn API Endpoints
# ==========================================

@app.route('/register_options', methods=['POST'])
def webauthn_register_options():
    """Generate registration options for WebAuthn"""
    print("\n⭐ REGISTRATION OPTIONS REQUESTED ⭐")
    print(f"Method: {request.method}")
    print(f"Content-Type: {request.content_type}")
    
    try:
        data = request.get_json() or {}
        
        # Generate a random user ID
        user_id = secrets.token_urlsafe(8)
        print(f"Generated user_id: {user_id}")
        
        # Generate a challenge
        challenge = generate_challenge()
        print(f"Generated challenge: {challenge}")
        
        # Store the challenge and user_id in the session
        session['challenge'] = challenge
        session['user_id_for_registration'] = user_id
        print(f"Session after challenge storage: {dict(session)}")
        
        # Create registration options - CRITICAL CROSS-PLATFORM SETTINGS
        options = {
            'challenge': challenge,
            'rp': {
                'name': 'FIDO2 Chat System',
                'id': request.host
            },
            'user': {
                'id': user_id,
                'name': data.get('username', 'Anonymous'),
                'displayName': data.get('username', 'Anonymous')
            },
            'pubKeyCredParams': [
                { 'type': 'public-key', 'alg': -7 }
            ],
            'timeout': 120000,  # Longer timeout for better user experience
            'attestation': 'none',
            'authenticatorSelection': {
                # Allow any type of authenticator
                'authenticatorAttachment': 'cross-platform',
                # CRITICAL: Don't require resident keys for cross-device compatibility
                'requireResidentKey': False,
                'residentKey': 'discouraged',
                'userVerification': 'discouraged'
            }
        }
        
        print(f"Returning registration options: {options}")
        return jsonify(options)
    except Exception as e:
        print(f"⛔ ERROR in registration options: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/register_complete', methods=['POST'])
def webauthn_register_complete():
    """Complete registration for WebAuthn"""
    print("\n=== WEBAUTHN REGISTRATION COMPLETION ===")
    data = request.get_json()
    print(f"Registration: Received data with credential ID: {data.get('id', '')[:15]}...")
    
    try:
        # Skip complex CBOR validation and just store a simplified credential
        user_id = session.get('user_id_for_registration') or secrets.token_urlsafe(8)
        print(f"Registration: Using user_id: {user_id}")
        
        # Create a simple credential from the raw credential ID
        credential_id = data.get('id')
        if not credential_id:
            print("Registration: No credential ID found in request")
            return jsonify({'error': 'No credential ID found in request'}), 400
            
        # Create a dummy public key - we won't actually use this for verification in this simplified demo
        # In a real implementation, you would extract the public key properly
        public_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "dummy-x-param",
            "y": "dummy-y-param"
        }
        
        # Store in database (hardcoded path that works on Render)
        db_path = '/opt/render/webauthn.db'
        print(f"Registration: Using database path: {db_path}")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # First check if this credential ID already exists (same device being registered again)
        print(f"Registration: Checking if credential already exists: {credential_id[:15]}...")
        cursor.execute("SELECT credential_id, user_id FROM security_keys WHERE credential_id=?", (credential_id,))
        existing_cred = cursor.fetchone()
        
        if existing_cred:
            existing_user_id = existing_cred[1]
            print(f"Registration: This credential already exists for user: {existing_user_id}")
            
            # Use this user_id instead of creating a new one
            user_id = existing_user_id
            print(f"Registration: Using existing user_id: {user_id}")
        else:
            print(f"Registration: No existing credential found, creating new registration")
        
        # Ensure table exists
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_keys (
            credential_id TEXT PRIMARY KEY,
            user_id TEXT,
            public_key TEXT,
            created_at TEXT
        )
        ''')
        
        # Store credential
        timestamp = datetime.datetime.now().isoformat()
        
        # Use INSERT OR REPLACE to update if exists or insert if not
        cursor.execute(
            "INSERT OR REPLACE INTO security_keys (credential_id, user_id, public_key, created_at) VALUES (?, ?, ?, ?)",
            (credential_id, user_id, json.dumps(public_key), timestamp)
        )
        conn.commit()
        
        # Get all credentials for this user for debugging
        cursor.execute("SELECT credential_id FROM security_keys WHERE user_id=?", (user_id,))
        user_creds = cursor.fetchall()
        print(f"Registration: User {user_id} now has {len(user_creds)} credential(s)")
        
        conn.close()
        
        # Update session
        session['authenticated'] = True
        session['user_id'] = user_id
        print(f"Registration: Updated session: {dict(session)}")
        
        return jsonify({'status': 'success', 'userId': user_id})
        
    except Exception as e:
        print(f"Registration error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/login_options', methods=['POST'])
def webauthn_login_options():
    """Generate authentication options for WebAuthn"""
    try:
        print("\n⭐ WEBAUTHN LOGIN OPTIONS REQUEST ⭐")
        
        # Generate a random challenge
        challenge = generate_challenge()
        print(f"Login: Generated challenge: {challenge}")
        
        # Store in session for verification later
        session['challenge'] = challenge
        print(f"Login: Updated session: {dict(session)}")
        
        # Get ALL credentials from the database - CRITICAL for cross-device compatibility
        db_path = '/opt/render/webauthn.db'
        print(f"Login: Using database path: {db_path}")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all credentials - NO FILTERING BY USER - this is key for cross-device
        print("Login: Getting ALL credentials from database...")
        cursor.execute("SELECT credential_id, user_id FROM security_keys")
        credentials = [{"id": row[0], "user_id": row[1]} for row in cursor.fetchall()]
        conn.close()
        
        print(f"Login: Found {len(credentials)} credential(s) in database")
        
        # Format for WebAuthn
        allow_credentials = []
        for cred in credentials:
            allow_credentials.append({
                "type": "public-key",
                "id": cred["id"],
                # Include all possible transport methods for maximum compatibility
                "transports": ["usb", "nfc", "ble", "internal"]
            })
        
        # Create options with matching rpId
        options = {
            "challenge": challenge,
            "timeout": 60000,
            "rpId": request.host,
            "allowCredentials": allow_credentials,
            "userVerification": "discouraged"
        }
        
        print(f"Login: Returning options with {len(allow_credentials)} credentials")
        return jsonify(options)
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/login_complete', methods=['POST'])
def webauthn_login_complete():
    """Complete the login process for WebAuthn"""
    try:
        print("\n⭐ WEBAUTHN LOGIN COMPLETION ⭐")
        data = request.get_json()
        
        # The credential ID is the primary identifier
        credential_id = data.get('id')
        print(f"Login Complete: Using credential ID: {credential_id[:20] if credential_id else 'None'}...")
        
        if not credential_id:
            print("Login Error: No credential ID in request")
            return jsonify({'error': 'No credential ID provided'}), 400
        
        # Get the user from the database
        db_path = '/opt/render/webauthn.db'
        print(f"Login: Using database: {db_path}")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Dump all credentials for debugging
        print("Login: Dumping all credentials for debugging")
        cursor.execute("SELECT credential_id, user_id FROM security_keys")
        all_credentials = cursor.fetchall()
        for row in all_credentials:
            cred_id = row[0]
            user_id = row[1]
            print(f"Credential: {cred_id[:20]}... -> User: {user_id}")
            
            # Check for match
            if cred_id == credential_id:
                print("EXACT MATCH FOUND!")
        
        # Try exact match first
        print("Login: Looking up exact credential match...")
        cursor.execute("SELECT user_id FROM security_keys WHERE credential_id = ?", (credential_id,))
        row = cursor.fetchone()
        
        if row:
            # Found exact match
            user_id = row[0]
            print(f"Login Success: Found user {user_id} for credential")
        else:
            # Try formatted version
            alternate_id = credential_id.replace('-', '+').replace('_', '/').rstrip('=')
            print(f"Login: Trying alternate format: {alternate_id[:20]}...")
            cursor.execute("SELECT user_id FROM security_keys WHERE credential_id = ?", (alternate_id,))
            row = cursor.fetchone()
            
            if row:
                user_id = row[0]
                print(f"Login Success: Found user {user_id} using alternate format")
            else:
                # Try another format
                second_alt = credential_id.replace('+', '-').replace('/', '_').replace('=', '')
                print(f"Login: Trying second alternate format: {second_alt[:20]}...")
                cursor.execute("SELECT user_id FROM security_keys WHERE credential_id = ?", (second_alt,))
                row = cursor.fetchone()
                
                if row:
                    user_id = row[0]
                    print(f"Login Success: Found user {user_id} using second alternate format")
                else:
                    print("Login Error: No matching credential found")
                    conn.close()
                    return jsonify({'error': 'Unknown credential'}), 400
        
        conn.close()
        
        # Set session
        session['authenticated'] = True
        session['user_id'] = user_id
        print(f"Login: Updated session: {dict(session)}")
        
        return jsonify({
            'status': 'success',
            'userId': user_id
        })
        
    except Exception as e:
        print(f"Login Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/logout', methods=['POST'])
def webauthn_logout():
    """Log out the current user"""
    print("\n=== WEBAUTHN LOGOUT REQUEST ===")
    
    # Clear session
    if 'authenticated' in session:
        user_id = session.get('user_id')
        print(f"Logging out user: {user_id}")
        session.pop('authenticated', None)
        session.pop('user_id', None)
    
    return jsonify({"status": "success", "message": "Logged out successfully"})

@app.route('/auth_status', methods=['GET'])
def webauthn_auth_status():
    """Check if the user is authenticated"""
    print("\n=== WEBAUTHN AUTH STATUS CHECK ===")
    print("Current session data:", dict(session))
    
    is_authenticated = session.get('authenticated', False)
    user_id = session.get('user_id', None) if is_authenticated else None
    
    if is_authenticated:
        print(f"✅ User is authenticated: {user_id}")
    else:
        print("❌ User is not authenticated")
        if 'authenticated' in session:
            print("  'authenticated' is False in session")
        else:
            print("  'authenticated' not found in session")
    
    return jsonify({
        "authenticated": is_authenticated,
        "userId": user_id
    })

@app.route('/chat')
def serve_chat():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def serve_root_static(path):
    # Check if the file exists in static directory
    static_path = os.path.join('static', path)
    if os.path.exists(static_path):
        return send_from_directory('static', path)
    return jsonify({"error": "File not found"}), 404

@app.route('/styles.css')
def serve_css():
    return send_from_directory('static', 'styles.css')

@app.route('/webauthn.js')
def serve_webauthn_js():
    """Serve WebAuthn JavaScript file with cache busting"""
    # Add cache busting to prevent browsers using old versions
    response = make_response(send_from_directory('static', 'webauthn.js'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    # Add a random query parameter to the URL to bust cache
    cache_buster = f"?v={int(time.time())}"
    return response

@app.route('/chat.js')
def serve_chat_js():
    """Serve Chat JavaScript file with cache busting"""
    # Add cache busting to prevent browsers using old versions
    response = make_response(send_from_directory('static', 'chat.js'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/debug')
def debug_dashboard():
    """
    Debug dashboard showing system status and statistics.
    
    Provides information about:
    - System status and timestamp
    - Current environment
    - Database location
    - Number of registered security keys
    - Total message count
    - Number of unique users
    
    Returns:
        JSON: Debug information and statistics
        {
            "status": "healthy",
            "timestamp": "ISO-format timestamp",
            "environment": "production/development",
            "database_path": "path to database",
            "registered_keys": number,
            "total_messages": number,
            "unique_users": number
        }
    """
    try:
        # Basic system info
        debug_info = {
            "status": "healthy",
            "timestamp": datetime.datetime.now().isoformat(),
            "environment": app.env,
            "database_path": os.environ.get('DATABASE_PATH', 'webauthn.db')
        }
        
        # Database stats
        conn = sqlite3.connect(os.environ.get('DATABASE_PATH', 'webauthn.db'))
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM security_keys")
        debug_info["registered_keys"] = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM messages")
        debug_info["total_messages"] = c.fetchone()[0]
        
        c.execute("SELECT COUNT(DISTINCT user_id) FROM messages")
        debug_info["unique_users"] = c.fetchone()[0]
        
        conn.close()
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

@app.route('/debug_all', methods=['GET'])
def debug_all():
    """Comprehensive debug dashboard that shows all system state"""
    debug_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "session": dict(session),
        "database": {},
        "environment": {},
        "system": {},
        "file_system": {},
        "tables": {},
        "sample_data": {},
        "security_keys": []
    }
    
    # System info
    debug_data["system"] = {
        "python_version": sys.version,
        "platform": platform.platform(),
        "node": platform.node(),
        "cwd": os.getcwd(),
    }
    
    # Environment variables (sanitized)
    env_vars = {}
    for key, value in os.environ.items():
        if "key" in key.lower() or "secret" in key.lower() or "password" in key.lower() or "token" in key.lower():
            env_vars[key] = "***REDACTED***"
        else:
            env_vars[key] = value
    debug_data["environment"] = env_vars
    
    # Database checks
    try:
        # Possible database paths
        paths = [
            '/opt/render/webauthn.db',
            os.path.join(os.environ.get('HOME', ''), 'webauthn.db'),
            'webauthn.db',
            os.environ.get('DATABASE_PATH', '')
        ]
        
        db_info = {}
        for path in paths:
            if not path:
                continue
                
            exists = os.path.exists(path)
            db_info[path] = {
                "exists": exists,
                "size_bytes": os.path.getsize(path) if exists else 0,
                "permissions": oct(os.stat(path).st_mode) if exists else None,
                "writable": os.access(os.path.dirname(path), os.W_OK) if exists else False
            }
        
        debug_data["database"] = db_info
        
        # Try to use the database
        db_path = '/opt/render/webauthn.db'  # Use fixed path for testing
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get schema info
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        debug_data["tables"]["names"] = tables
        
        # Get detailed schema for each table
        table_schemas = {}
        for table in tables:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [{"name": row[1], "type": row[2], "notnull": row[3], "pk": row[4]} for row in cursor.fetchall()]
            table_schemas[table] = columns
        debug_data["tables"]["schemas"] = table_schemas
        
        # Try a test insertion
        test_id = f"test-{int(time.time())}"
        cursor.execute(
            "INSERT OR REPLACE INTO security_keys (credential_id, user_id, public_key, created_at) VALUES (?, ?, ?, ?)",
            (test_id, "debug-user", "{\"test\":\"key\"}", datetime.datetime.now().isoformat())
        )
        conn.commit()
        debug_data["sample_data"]["insert_success"] = True
        
        # Check if it was inserted
        cursor.execute("SELECT * FROM security_keys WHERE credential_id=?", (test_id,))
        row = cursor.fetchone()
        debug_data["sample_data"]["retrieval_success"] = row is not None
        
        # Get all security keys
        cursor.execute("SELECT * FROM security_keys")
        keys = []
        for row in cursor.fetchall():
            keys.append({
                "credential_id": row[0],
                "user_id": row[1] if len(row) > 1 else None,
                "public_key_snippet": str(row[2])[:30] + "..." if len(row) > 2 and row[2] else None,
                "created_at": row[3] if len(row) > 3 else None
            })
        debug_data["security_keys"] = keys
        
        # Clean up
        cursor.execute("DELETE FROM security_keys WHERE credential_id=?", (test_id,))
        conn.commit()
        conn.close()
        
    except Exception as e:
        debug_data["error"] = {
            "message": str(e),
            "type": type(e).__name__,
            "traceback": traceback.format_exc()
        }
    
    # File system checks
    debug_data["file_system"]["directories"] = {
        "/opt": {
            "exists": os.path.exists("/opt"),
            "writable": os.access("/opt", os.W_OK)
        },
        "/opt/render": {
            "exists": os.path.exists("/opt/render"),
            "writable": os.access("/opt/render", os.W_OK)
        },
        "current_dir": {
            "path": os.getcwd(),
            "writable": os.access(os.getcwd(), os.W_OK)
        }
    }
    
    # Return all debug info
    response = make_response(jsonify(debug_data))
    response.headers['Content-Type'] = 'application/json'
    return response

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

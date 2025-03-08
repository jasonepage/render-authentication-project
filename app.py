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
        # Use a data directory that's guaranteed to be writable on Render
        db_path = os.path.join(os.environ.get('HOME', ''), 'webauthn.db')
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
        c.execute('''
            CREATE TABLE IF NOT EXISTS security_keys (
                credential_id TEXT PRIMARY KEY,
                public_key TEXT
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
    """Retrieve chat messages"""
    print("\n=== MESSAGE RETRIEVAL REQUEST ===")
    print("1. Checking rate limit...")
    
    print("\n2. Retrieving messages from database...")
    db_path = os.environ.get('DATABASE_PATH', 'webauthn.db')
    print(f"Using database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    try:
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
    print("\n⭐⭐⭐ REGISTRATION OPTIONS REQUESTED ⭐⭐⭐")
    print(f"Method: {request.method}")
    print(f"Content-Type: {request.content_type}")
    print(f"Data: {request.get_data()}")
    
    try:
        data = request.get_json() or {}
        
        # Generate a random user ID
        user_id = secrets.token_urlsafe(8)
        print(f"Generated user_id: {user_id}")
        
        # Generate a challenge
        challenge = generate_challenge()
        print(f"Generated challenge: {challenge}")
        
        # Store the challenge in the session
        session['challenge'] = challenge
        print(f"Session after challenge storage: {dict(session)}")
        
        # Create the registration options
        options = {
            'challenge': challenge,
            'rp': {
                'name': 'Key Chat System',
                'id': request.host
            },
            'user': {
                'id': user_id,
                'name': data.get('username', 'Anonymous'),
                'displayName': data.get('username', 'Anonymous')
            },
            'pubKeyCredParams': [
                { 'type': 'public-key', 'alg': -7 } # ES256 algorithm
            ],
            'timeout': 60000,
            'attestation': 'none',
            'authenticatorSelection': {
                'authenticatorAttachment': 'cross-platform',
                'requireResidentKey': False,
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
    print("\n⭐⭐⭐ REGISTRATION COMPLETION REQUESTED ⭐⭐⭐")
    print(f"Method: {request.method}")
    print(f"Content-Type: {request.content_type}")
    print(f"Data: {request.get_data()}")
    
    try:
        data = request.get_json()
        if not data:
            raise ValueError("No JSON data received")
        
        print(f"Registration data received: {data}")
        
        # Verify the challenge
        expected_challenge = session.get('challenge')
        print(f"Session challenge: {expected_challenge}")
        print(f"Full session: {dict(session)}")
        
        if not expected_challenge:
            print("⛔ ERROR: No challenge in session")
            return jsonify({'error': 'Challenge not found in session'}), 400
        
        # Decode client data
        client_data_b64 = data.get('response', {}).get('clientDataJSON')
        if not client_data_b64:
            print("⛔ ERROR: No clientDataJSON in response")
            return jsonify({'error': 'Client data not found in response'}), 400
        
        client_data_bytes = base64url_to_bytes(client_data_b64)
        client_data = json.loads(client_data_bytes.decode('utf-8'))
        print(f"Client data: {client_data}")
        
        # Verify challenge
        received_challenge = client_data.get('challenge')
        if not received_challenge:
            print("⛔ ERROR: No challenge in client data")
            return jsonify({'error': 'Challenge not found in client data'}), 400
        
        if received_challenge != expected_challenge:
            print(f"⛔ ERROR: Challenge mismatch: {received_challenge} != {expected_challenge}")
            return jsonify({'error': 'Challenge verification failed'}), 400
        
        # Verify origin
        origin = client_data.get('origin')
        expected_origin = f"https://{request.host}"
        if origin != expected_origin and origin != f"http://{request.host}":
            print(f"⛔ ERROR: Origin mismatch: {origin} not in [{expected_origin}, http://{request.host}]")
            return jsonify({'error': 'Origin verification failed'}), 400
        
        # Decode attestation object
        attestation_b64 = data.get('response', {}).get('attestationObject')
        if not attestation_b64:
            print("⛔ ERROR: No attestationObject in response")
            return jsonify({'error': 'Attestation object not found in response'}), 400
        
        attestation_bytes = base64url_to_bytes(attestation_b64)
        
        # Parse CBOR data
        try:
            attestation = cbor2.loads(attestation_bytes)
            print(f"Attestation format: {attestation.get('fmt', 'unknown')}")
        except Exception as e:
            print(f"⛔ ERROR parsing attestation object: {str(e)}")
            return jsonify({'error': 'Failed to parse attestation object'}), 400
        
        # Extract credential ID and public key
        auth_data = attestation.get('authData')
        if not auth_data:
            print("⛔ ERROR: No authData in attestation")
            return jsonify({'error': 'Auth data not found in attestation'}), 400
        
        # Extract flags
        flags = auth_data[32]
        print(f"Auth data flags: {flags}")
        
        # Extract AAGUID, credential ID length, credential ID, and COSE key
        aaguid = auth_data[37:53]
        credential_id_len = int.from_bytes(auth_data[53:55], byteorder='big')
        credential_id = auth_data[55:55+credential_id_len]
        cose_key = auth_data[55+credential_id_len:]
        
        try:
            cose_key = cbor2.loads(cose_key)
            print(f"COSE key type: {cose_key.get(1, 'unknown')}")
        except Exception as e:
            print(f"⛔ ERROR parsing COSE key: {str(e)}")
            return jsonify({'error': 'Failed to parse COSE key'}), 400
        
        # Convert to public key
        try:
            x = cose_key.get(-2)
            y = cose_key.get(-3)
            if not x or not y:
                print("⛔ ERROR: Missing x or y coordinates in COSE key")
                return jsonify({'error': 'Invalid public key format'}), 400
            
            public_key = {'kty': 'EC', 'crv': 'P-256', 'x': x, 'y': y}
            print(f"Public key extracted: x={len(x)} bytes, y={len(y)} bytes")
        except Exception as e:
            print(f"⛔ ERROR extracting public key: {str(e)}")
            return jsonify({'error': 'Failed to extract public key'}), 400
        
        # Connect to the database
        try:
            conn = sqlite3.connect('webauthn.db')
            cursor = conn.cursor()
            
            # Store the credential in the database
            cursor.execute(
                "INSERT INTO security_keys (credential_id, user_id, public_key, created_at) VALUES (?, ?, ?, ?)",
                (bytes_to_base64url(credential_id), data.get('id'), json.dumps(public_key), datetime.datetime.now().isoformat())
            )
            conn.commit()
            print(f"✅ Credential stored in database for user {data.get('id')}")
        except Exception as e:
            print(f"⛔ ERROR storing credential: {str(e)}")
            print(traceback.format_exc())
            return jsonify({'error': 'Failed to store credential'}), 500
        finally:
            if 'conn' in locals() and conn:
                conn.close()
        
        # Set session variables
        session['authenticated'] = True
        session['user_id'] = user_id
        print(f"Session after registration: {dict(session)}")
        
        return jsonify({'status': 'success', 'userId': user_id})
    except Exception as e:
        print(f"⛔ ERROR in registration completion: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/login_options', methods=['POST'])
def webauthn_login_options():
    """Generate authentication options for WebAuthn"""
    print("\n=== WEBAUTHN LOGIN OPTIONS REQUEST ===")
    print("1. Generating challenge...")
    
    # Generate a random challenge
    challenge = generate_challenge()
    print(f"Generated challenge: {challenge}")
    
    print("\n2. Setting session data...")
    # Store in session for verification later
    session['challenge'] = challenge
    print(f"Updated session: {dict(session)}")
    
    print("\n3. Retrieving credentials from database...")
    # Get all credentials from the database
    db_path = os.environ.get('DATABASE_PATH', 'webauthn.db')
    print(f"Using database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    try:
        c.execute("SELECT credential_id FROM security_keys")
        credentials = c.fetchall()
        print(f"Found {len(credentials)} credential(s)")
        
        # Format for WebAuthn
        allowed_credentials = []
        for cred in credentials:
            cred_id = cred[0]
            print(f"  - Credential: {cred_id[:10]}...")
            allowed_credentials.append({
                "type": "public-key",
                "id": cred_id,
                "transports": ["usb", "nfc"]
            })
        
        print("\n4. Creating authentication options...")
        options = {
            "challenge": challenge,
            "timeout": 60000,
            "rpId": "render-authentication-project.onrender.com",
            "allowCredentials": allowed_credentials,
            "userVerification": "discouraged"
        }
        print(f"Authentication options created: {json.dumps(options, indent=2)}")
        
        return jsonify(options)
    except Exception as e:
        print(f"❌ Error getting credentials: {str(e)}")
        print("Stack trace:", traceback.format_exc())
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/login_complete', methods=['POST'])
def webauthn_login_complete():
    """Complete the authentication process for WebAuthn"""
    print("\n=== WEBAUTHN LOGIN COMPLETION ===")
    print("1. Validating request data...")
    print(f"Request headers: {dict(request.headers)}")
    
    try:
        # Get the authentication data from the request
        data = request.json
        print("Received authentication data:")
        print(json.dumps({
            "id": data.get('id'),
            "rawId": data.get('rawId', '')[:10] + "...",
            "type": data.get('type'),
            "response": {
                "clientDataJSON": data.get('response', {}).get('clientDataJSON', '')[:10] + "...",
                "authenticatorData": data.get('response', {}).get('authenticatorData', '')[:10] + "...",
                "signature": data.get('response', {}).get('signature', '')[:10] + "...",
                "userHandle": data.get('response', {}).get('userHandle')
            }
        }, indent=2))
        
        print("\n2. Checking session challenge...")
        # Verify that this is the same session that requested authentication
        expected_challenge = session.get('challenge')
        if not expected_challenge:
            print("❌ No challenge found in session")
            print(f"Current session: {dict(session)}")
            return jsonify({"error": "Authentication session expired"}), 400
        
        print("\n3. Processing client data...")
        # Get credential ID and authentication data
        credential_id = data['rawId']
        print(f"Authenticating credential: {credential_id[:10]}...")
        
        client_data_json = base64url_to_bytes(data['response']['clientDataJSON'])
        authenticator_data = base64url_to_bytes(data['response']['authenticatorData'])
        signature = base64url_to_bytes(data['response']['signature'])
        
        # Parse the client data
        client_data = json.loads(client_data_json.decode('utf-8'))
        print(f"Parsed client data: {json.dumps(client_data, indent=2)}")
        
        print("\n4. Verifying challenge...")
        # Verify challenge
        received_challenge = client_data.get('challenge')
        if received_challenge != expected_challenge:
            print("❌ Challenge verification failed")
            print(f"Expected: {expected_challenge}")
            print(f"Received: {received_challenge}")
            return jsonify({"error": "Challenge verification failed"}), 400
        
        print("\n5. Verifying request type...")
        # Verify type
        if client_data.get('type') != 'webauthn.get':
            print(f"❌ Incorrect type: {client_data.get('type')}")
            return jsonify({"error": "Incorrect request type"}), 400
        
        print("\n6. Verifying origin...")
        # Verify origin
        origin = client_data.get('origin', '')
        if not origin.endswith('render-authentication-project.onrender.com'):
            print(f"❌ Origin mismatch: {origin}")
            return jsonify({"error": "Origin verification failed"}), 400
        
        print("\n7. Looking up credential...")
        # Get the credential from the database
        db_path = os.environ.get('DATABASE_PATH', 'webauthn.db')
        print(f"Using database: {db_path}")
        
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        c.execute("SELECT credential_id FROM security_keys WHERE credential_id = ?", (credential_id,))
        result = c.fetchone()
        conn.close()
        
        if not result:
            print(f"❌ Credential not found: {credential_id[:10]}...")
            return jsonify({"error": "Credential not found"}), 404
        
        print("\n8. Setting up session...")
        # Set as authenticated
        session['authenticated'] = True
        session['user_id'] = credential_id[:10]  # Use credential ID prefix as user ID
        print(f"Updated session: {dict(session)}")
        
        print("\n✅ Authentication successful!")
        return jsonify({
            "status": "success",
            "message": "Authentication successful",
            "userId": credential_id[:10]
        })
            
    except Exception as e:
        print(f"❌ Authentication error: {str(e)}")
        print("Stack trace:", traceback.format_exc())
        return jsonify({"error": f"Authentication failed: {str(e)}"}), 500

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

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

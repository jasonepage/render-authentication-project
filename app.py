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
    """Log details about each incoming request"""
    try:
        # Log request path and method
        print(f"\n=== {request.method} {request.path} ===")
        
        # Log headers
        print(f"Headers: {dict(request.headers)}")
        
        # Log JSON data if present
        if request.is_json:
            try:
                data = request.get_json(silent=True)
                print(f"JSON Data: {json.dumps(data)}")
            except Exception as e:
                print(f"Error parsing JSON: {str(e)}")
        
        # Log form data if present
        if request.form:
            print(f"Form Data: {dict(request.form)}")
        
        # Log current session state if present
        if session:
            print(f"Session: {dict(session)}")
    except Exception as e:
        print(f"Error logging request info: {str(e)}")
        # Don't block the request on logging errors
        pass

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
    """Initialize the database with required tables"""
    try:
        print("\n⭐ INITIALIZING DATABASE ⭐")
        # Ensure the db directory exists
        db_path = '/opt/render/webauthn.db'
        db_dir = os.path.dirname(db_path)
        
        if not os.path.exists(db_dir):
            print(f"Creating directory: {db_dir}")
            os.makedirs(db_dir, exist_ok=True)
            
        print(f"Database path: {db_path}")
        
        # Check permissions
        if os.path.exists(db_dir):
            print(f"Directory permissions: {oct(os.stat(db_dir).st_mode)}")
            
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Modified schema: credential_id is no longer PRIMARY KEY to allow multiple formats
        # for the same credential (iOS compatibility)
        c.execute('''
            CREATE TABLE IF NOT EXISTS security_keys (
                credential_id TEXT,
                user_id TEXT,
                public_key TEXT,
                created_at TEXT,
                PRIMARY KEY (credential_id)
            )
        ''')
        
        # Create messages table if it doesn't exist
        print("Creating messages table if it doesn't exist...")
        c.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                message TEXT, 
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Commit the changes and close the connection
        conn.commit()
        print("Database tables created successfully!")
        
        # Log the tables that exist in the database
        c.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = c.fetchall()
        print(f"Tables in database: {tables}")
        
        conn.close()
        return True
    except Exception as e:
        print(f"⚠️ Database initialization error: {str(e)}")
        traceback.print_exc()
        return False

# Initialize database at startup
init_db()

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

# Add a new helper function before the route definitions
def normalize_credential_id(credential_id):
    """Normalize credential ID to URL-safe format without padding"""
    # First convert to standard base64 format (with + and /)
    standard_format = credential_id.replace('-', '+').replace('_', '/')
    # Then convert to URL-safe format (with - and _)
    urlsafe_format = standard_format.replace('+', '-').replace('/', '_').replace('=', '')
    return urlsafe_format

# ==========================================
# WebAuthn API Endpoints
# ==========================================

@app.route('/register_options', methods=['POST'])
def webauthn_register_options():
    """Generate registration options for WebAuthn"""
    try:
        print("\n⭐ WEBAUTHN REGISTRATION OPTIONS ⭐")
        
        # Print request info for debugging
        print(f"Request content type: {request.content_type}")
        print(f"Request content length: {request.content_length}")
        print(f"Request headers: {dict(request.headers)}")
        
        # Always generate a new random user ID with a custom prefix for better readability
        # Use a mix of alphanumeric characters to ensure uniqueness
        user_id = f"{secrets.token_hex(4)}-{secrets.token_urlsafe(6)}"
        session['user_id_for_registration'] = user_id
        print(f"Register Options: Generated new user ID: {user_id}")
        
        # Generate a challenge
        challenge = generate_challenge()
        session['challenge'] = challenge
        print(f"Register Options: Generated challenge: {challenge}")
        print(f"Register Options: Session data: {dict(session)}")
        
        # Get host info for proper rpId setting
        host = request.host
        hostname = host.split(':')[0]  # Remove port if present
        print(f"Register Options: Host: {host}, Hostname: {hostname}")
        
        # For Render deployment use the constant rpId
        if hostname != 'localhost' and hostname != '127.0.0.1':
            rp_id = 'render-authentication-project.onrender.com'
        else:
            rp_id = hostname
            
        print(f"Register Options: Using rpId: {rp_id}")
        
        # Create registration options
        options = {
            "challenge": challenge,
            "rp": {
                "name": "FIDO2 Chat System",
                "id": rp_id
            },
            "user": {
                "id": user_id,
                "name": f"user-{user_id[:6]}",
                "displayName": f"User {user_id[:6]}"
            },
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -7  # ES256 algorithm
                }
            ],
            "authenticatorSelection": {
                # Cross-platform means any type of authenticator (security key or platform)
                "authenticatorAttachment": "cross-platform",
                # False is crucial for cross-device compatibility
                "requireResidentKey": False,
                # Discouraged is best for cross-platform
                "userVerification": "discouraged"
            },
            "timeout": 120000,  # 2 minutes
            "attestation": "none"  # Don't require attestation to keep it simple
        }
        
        print(f"Register Options: Returning options: {json.dumps(options)[:100]}...")
        return jsonify(options)
        
    except Exception as e:
        print(f"Registration Options Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/register_complete', methods=['POST'])
def webauthn_register_complete():
    """Complete the registration process for WebAuthn"""
    try:
        print("\n⭐ WEBAUTHN REGISTRATION COMPLETION ⭐")
        data = request.get_json()
        print(f"Register Complete: Registration data received")
        
        # Verify we have a credential ID
        credential_id = data.get('id')
        if not credential_id:
            print("Register Error: No credential ID in response")
            return jsonify({'error': 'No credential ID in response'}), 400
            
        print(f"Register Complete: Received credential ID: {credential_id[:20]}...")
        
        # Verify we have the user ID in session
        if 'user_id_for_registration' not in session:
            print("Register Error: No user ID in session")
            return jsonify({'error': 'Registration session expired'}), 400
            
        user_id = session['user_id_for_registration']
        print(f"Register Complete: Using user ID from session: {user_id}")
        
        # Get the attestation response data
        if not data.get('response') or not data['response'].get('clientDataJSON') or not data['response'].get('attestationObject'):
            print("Register Error: Missing required attestation data")
            return jsonify({'error': 'Invalid attestation data'}), 400
            
        # For this simplification, we'll just store the credential without complex validation
        # In a production environment, you would validate the attestation
        public_key = json.dumps({
            'id': credential_id,
            'type': data.get('type', 'public-key'),
            'attestation': {
                'clientDataJSON': data['response']['clientDataJSON'],
                'attestationObject': data['response']['attestationObject']
            }
        })
        
        # Store the credential in the database
        db_path = '/opt/render/webauthn.db'
        print(f"Register Complete: Using database: {db_path}")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if this user already has credentials
        cursor.execute("SELECT credential_id FROM security_keys WHERE user_id = ?", (user_id,))
        existing_credentials = cursor.fetchall()
        print(f"Register Complete: User has {len(existing_credentials)} existing credentials")
        
        # Normalize the credential ID to ensure consistent storage format
        normalized_credential_id = normalize_credential_id(credential_id)
        
        # Check if this exact credential ID already exists
        cursor.execute("SELECT credential_id FROM security_keys WHERE credential_id = ?", (normalized_credential_id,))
        if cursor.fetchone():
            print(f"Register Complete: Credential ID already exists, skipping insertion")
        else:
            # Store only the normalized version
            print(f"Register Complete: Storing credential with normalized ID: {normalized_credential_id[:20]}...")
            cursor.execute(
                "INSERT INTO security_keys (credential_id, user_id, public_key, created_at) VALUES (?, ?, ?, datetime('now'))",
                (normalized_credential_id, user_id, public_key)
            )
        
        conn.commit()
        conn.close()
        
        # Set authenticated session and clean up registration data
        session['authenticated'] = True
        session['user_id'] = user_id
        # Clear the registration-specific data to prevent reuse
        session.pop('user_id_for_registration', None)
        print(f"Register Complete: Updated session: {dict(session)}")
        
        return jsonify({
            'status': 'success',
            'userId': user_id
        })
        
    except Exception as e:
        print(f"Register Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/login_options', methods=['POST'])
def webauthn_login_options():
    """Get options for WebAuthn login"""
    try:
        print("\n⭐ WEBAUTHN LOGIN OPTIONS ⭐")
        
        # Print request info for debugging
        print(f"Request content type: {request.content_type}")
        print(f"Request content length: {request.content_length}")
        print(f"Request headers: {dict(request.headers)}")
        
        # Generate a challenge for this login attempt
        challenge = generate_challenge()
        session['challenge'] = challenge
        print(f"Login Options: Generated challenge: {challenge}")
        print(f"Login Options: Session data: {dict(session)}")
        
        # Get host info for proper rpId setting
        host = request.host
        hostname = host.split(':')[0]  # Remove port if present
        print(f"Login Options: Host: {host}, Hostname: {hostname}")
        
        # For Render deployment use the constant rpId
        if hostname != 'localhost' and hostname != '127.0.0.1':
            rp_id = 'render-authentication-project.onrender.com'
        else:
            rp_id = hostname
            
        print(f"Login Options: Using rpId: {rp_id}")
        
        # Connect to the database
        db_path = '/opt/render/webauthn.db'
        print(f"Login Options: Using database: {db_path}")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all credentials - needed for cross-device login
        print("Login Options: Retrieving all credentials")
        cursor.execute("SELECT credential_id FROM security_keys")
        credentials = cursor.fetchall()
        conn.close()
        
        allowed_credentials = []
        print(f"Login Options: Found {len(credentials)} credentials")
        
        # Prepare credentials for WebAuthn
        for (credential_id,) in credentials:
            print(f"Login Options: Adding credential: {credential_id[:20]}...")
            # iOS doesn't like certain formats, so provide multiple transport options
            allowed_credentials.append({
                "type": "public-key",
                "id": credential_id,
                # Include all possible transports for maximum compatibility
                "transports": ["usb", "nfc", "ble", "internal", "hybrid"]
            })
            
        # Create options according to WebAuthn spec
        options = {
            "challenge": challenge,
            "timeout": 60000,  # 60 seconds
            "rpId": rp_id,
            "allowCredentials": allowed_credentials,
            "userVerification": "discouraged"  # Change to "preferred" for iOS
        }
        
        print(f"Login Options: Returning options: {json.dumps(options)[:100]}...")
        return jsonify(options)
        
    except Exception as e:
        print(f"Login Options Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

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
        
        # Get the stored challenge from session
        stored_challenge = session.get('challenge')
        if not stored_challenge:
            print("Login Error: No challenge in session")
            return jsonify({'error': 'No challenge found in session. Please try again.'}), 400
            
        # Extract client data
        if not data.get('response') or not data['response'].get('clientDataJSON'):
            print("Login Error: Missing clientDataJSON")
            return jsonify({'error': 'Missing clientDataJSON'}), 400
            
        client_data_json_b64 = data['response']['clientDataJSON']
        client_data_json = base64url_to_bytes(client_data_json_b64)
        try:
            client_data = json.loads(client_data_json.decode('utf-8'))
            print(f"Login Complete: Client data: {client_data}")
            
            # Verify challenge
            response_challenge = client_data.get('challenge')
            if response_challenge != stored_challenge:
                print(f"Login Error: Challenge mismatch. Expected {stored_challenge}, got {response_challenge}")
                return jsonify({'error': 'Challenge verification failed'}), 400
                
            # Verify type and origin
            if client_data.get('type') != 'webauthn.get':
                print(f"Login Error: Invalid type: {client_data.get('type')}")
                return jsonify({'error': 'Invalid type'}), 400
                
            # We only verify the origin contains our domain to allow both http and https
            origin = client_data.get('origin', '')
            expected_domain = 'render-authentication-project.onrender.com'
            if expected_domain not in origin and 'localhost' not in origin:
                print(f"Login Error: Invalid origin: {origin}")
                return jsonify({'error': f'Invalid origin. Expected {expected_domain}, got {origin}'}), 400
        except Exception as e:
            print(f"Login Error: Failed to parse client data: {e}")
            return jsonify({'error': f'Failed to parse client data: {e}'}), 400
        
        # Get the user from the database
        db_path = '/opt/render/webauthn.db'
        print(f"Login Complete: Using database: {db_path}")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Try the normalized credential ID format
        normalized_credential_id = normalize_credential_id(credential_id)
        print(f"Login Complete: Using normalized credential ID: {normalized_credential_id[:20]}...")
        
        cursor.execute("SELECT user_id, public_key, credential_id FROM security_keys WHERE credential_id = ?", 
                      (normalized_credential_id,))
        row = cursor.fetchone()
        
        # If not found with normalized format, try legacy formats for backwards compatibility
        if not row:
            formats_to_try = [
                credential_id,                                          # Original
                credential_id.replace('-', '+').replace('_', '/'),      # URL safe to standard
                credential_id.replace('+', '-').replace('/', '_'),      # Standard to URL safe
                credential_id.replace('-', '+').replace('_', '/').rstrip('='),   # URL safe to standard without padding
                credential_id.replace('+', '-').replace('/', '_').replace('=', '')   # Standard to URL safe without padding
            ]
            
            for format_id in formats_to_try:
                print(f"Login Complete: Trying legacy format: {format_id[:20]}...")
                cursor.execute("SELECT user_id, public_key, credential_id FROM security_keys WHERE credential_id = ?", (format_id,))
                row = cursor.fetchone()
                if row:
                    user_id = row[0]
                    public_key = row[1]
                    matching_credential_id = row[2]
                    print(f"Login Complete: Found user {user_id} with legacy credential {matching_credential_id[:20]}...")
                    break
        else:
            user_id = row[0]
            public_key = row[1]
            matching_credential_id = row[2]
            print(f"Login Complete: Found user {user_id} with normalized credential {matching_credential_id[:20]}...")
        
        conn.close()
        
        if not user_id or not public_key:
            print("Login Error: No matching credential found after trying all formats")
            return jsonify({'error': 'Unknown credential'}), 400
            
        # Here we would normally verify the signature against the public key
        # To simplify, we'll just check that the credential exists in our database
        # Full verification would require additional cryptographic checks
        
        # Set session
        session['authenticated'] = True
        session['user_id'] = user_id
        print(f"Login Complete: Updated session: {dict(session)}")
        
        return jsonify({
            'status': 'success',
            'userId': user_id
        })
        
    except Exception as e:
        print(f"Login Complete Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/logout', methods=['POST'])
def webauthn_logout():
    """Log out the current user"""
    print("\n=== WEBAUTHN LOGOUT REQUEST ===")
    
    # Get user ID for logging before clearing
    user_id = session.get('user_id')
    if user_id:
        print(f"Logging out user: {user_id}")
    
    # Clear entire session to ensure no state is preserved
    session.clear()
    print("Session cleared completely")
    
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
    """Serve the chat.js file"""
    return send_from_directory('static', 'chat.js')

@app.route('/debug_all', methods=['GET'])
def debug_all():
    """Minimal debug route to diagnose credential issues"""
    debug_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "session": dict(session),
        "security_keys": []
    }
    
    # Get all security keys for debugging
    try:
        db_path = '/opt/render/webauthn.db'
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all security keys
        cursor.execute("SELECT credential_id, user_id, public_key, created_at FROM security_keys")
        keys = []
        for row in cursor.fetchall():
            keys.append({
                "credential_id": row[0],
                "user_id": row[1],
                "public_key_snippet": str(row[2])[:30] + "..." if row[2] else None,
                "created_at": row[3]
            })
        debug_data["security_keys"] = keys
        conn.close()
    except Exception as e:
        debug_data["error"] = str(e)
    
    return jsonify(debug_data)

def decode_signature(signature):
    """Decode WebAuthn signature into r and s components for verification"""
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
    # Use the fixed database path for consistency
    db_path = '/opt/render/webauthn.db'
    print(f"Using database: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
    
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

@app.route('/cleanup_duplicate_credentials', methods=['POST'])
def cleanup_duplicate_credentials():
    """Admin function to clean up duplicate credential IDs"""
    try:
        print("\n⭐ CLEANING UP DUPLICATE CREDENTIALS ⭐")
        
        # For security, require a secret token
        data = request.get_json()
        if not data or data.get('secret') != os.environ.get('ADMIN_SECRET', 'admin_secret'):
            return jsonify({"error": "Unauthorized"}), 401
        
        db_path = '/opt/render/webauthn.db'
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all credentials
        cursor.execute("SELECT credential_id, user_id, public_key, created_at FROM security_keys")
        credentials = cursor.fetchall()
        
        # Track normalized credentials to find duplicates
        normalized_map = {}
        duplicate_count = 0
        
        for cred_id, user_id, public_key, created_at in credentials:
            normalized_id = normalize_credential_id(cred_id)
            
            if normalized_id in normalized_map:
                # This is a duplicate
                duplicate_count += 1
                # Delete this credential if it's not the same as the normalized version
                if cred_id != normalized_id:
                    print(f"Deleting duplicate credential: {cred_id[:20]}...")
                    cursor.execute("DELETE FROM security_keys WHERE credential_id = ?", (cred_id,))
            else:
                # First time seeing this normalized ID
                normalized_map[normalized_id] = True
                
                # If the credential isn't already in normalized form, update it
                if cred_id != normalized_id:
                    print(f"Updating credential from {cred_id[:20]}... to normalized form {normalized_id[:20]}...")
                    cursor.execute(
                        "UPDATE security_keys SET credential_id = ? WHERE credential_id = ?", 
                        (normalized_id, cred_id)
                    )
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "success",
            "message": f"Cleaned up {duplicate_count} duplicate credentials"
        })
        
    except Exception as e:
        print(f"Cleanup Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/admin/prune_duplicates', methods=['POST'])
def admin_prune_duplicates():
    """Admin function to remove duplicate security keys by user ID"""
    try:
        print("\n⭐ PRUNING DUPLICATE USER IDS ⭐")
        
        # For security, require a secret token
        data = request.get_json()
        if not data or data.get('secret') != os.environ.get('ADMIN_SECRET', 'admin_secret'):
            return jsonify({"error": "Unauthorized"}), 401
        
        db_path = '/opt/render/webauthn.db'
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get user IDs and their credential count
        cursor.execute("""
            SELECT user_id, COUNT(*) as count 
            FROM security_keys 
            GROUP BY user_id
            ORDER BY count DESC
        """)
        users = cursor.fetchall()
        
        duplicates_removed = 0
        
        # For users with multiple credentials, keep only the newest one
        for user_id, count in users:
            if count > 1:
                print(f"User {user_id} has {count} credentials, pruning to keep newest only")
                
                # Get the newest credential for this user
                cursor.execute("""
                    SELECT credential_id, created_at 
                    FROM security_keys 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC 
                    LIMIT 1
                """, (user_id,))
                newest = cursor.fetchone()[0]
                
                # Delete all but the newest credential
                cursor.execute("""
                    DELETE FROM security_keys 
                    WHERE user_id = ? AND credential_id != ?
                """, (user_id, newest))
                
                duplicates_removed += count - 1
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "success",
            "message": f"Removed {duplicates_removed} duplicate credentials"
        })
        
    except Exception as e:
        print(f"Pruning Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

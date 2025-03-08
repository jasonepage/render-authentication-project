from flask import Flask, jsonify, request, session, send_from_directory
import os
import json
import secrets
import sqlite3
import time
import base64
import datetime
import traceback
from functools import wraps
import platform

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key_change_in_production')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# In-memory cache for rate limiting
cache = {}

# DB path - can be customized for local development
DB_PATH = os.environ.get('DB_PATH', '/opt/render/webauthn.db')

# ==========================================
# Logging middleware
# ==========================================

@app.before_request
def log_request_info():
    """Log info about each request"""
    print(f"\n=== INCOMING REQUEST ===")
    print(f"Route: {request.path}")
    print(f"Method: {request.method}")
    print(f"Headers: {dict(request.headers)}")
    print(f"Session: {dict(session)}")

@app.after_request
def log_response_info(response):
    """Log info about each response"""
    print(f"=== OUTGOING RESPONSE ===")
    print(f"Status: {response.status_code}")
    print(f"Headers: {dict(response.headers)}")
    return response

# ==========================================
# Database initialization
# ==========================================

def init_db():
    """Initialize database tables if they don't exist"""
    print(f"Initializing database at {DB_PATH}")
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create security_keys table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS security_keys (
        id INTEGER PRIMARY KEY,
        credential_id TEXT UNIQUE NOT NULL,
        user_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL
    )
    ''')
    
    # Create messages table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        user_id TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()
    print("Database initialized successfully")

# Initialize database on startup
init_db()

# ==========================================
# Utility functions
# ==========================================

def rate_limit(max_per_minute=60):
    """Rate limiting decorator"""
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

def generate_challenge():
    """Generate a cryptographically secure random challenge"""
    # Generate 32 bytes of random data (256 bits)
    random_bytes = secrets.token_bytes(32)
    # Convert to URL-safe base64 encoding without padding
    challenge = bytes_to_base64url(random_bytes)
    print(f"DEBUG - generate_challenge: Raw length {len(random_bytes)}, Result: {challenge}")
    return challenge

def base64url_to_bytes(base64url):
    """Convert base64url to bytes"""
    # Add padding if needed
    padded = base64url + '=' * (4 - len(base64url) % 4)
    # Replace URL-safe characters with standard base64 characters
    standard = padded.replace('-', '+').replace('_', '/')
    return base64.b64decode(standard)

def bytes_to_base64url(bytes_value):
    """Convert bytes to base64url"""
    base64_str = base64.b64encode(bytes_value).decode('ascii')
    result = base64_str.replace('+', '-').replace('/', '_').rstrip('=')
    print(f"DEBUG - bytes_to_base64url: Input length {len(bytes_value)}, Output: {result[:20]}...")
    return result

def normalize_credential_id(credential_id):
    """Normalize credential ID to URL-safe format without padding"""
    # First convert to standard base64 format (with + and /)
    standard_format = credential_id.replace('-', '+').replace('_', '/')
    # Then convert to URL-safe format (with - and _)
    urlsafe_format = standard_format.replace('+', '-').replace('/', '_').replace('=', '')
    return urlsafe_format

# ==========================================
# Basic routes
# ==========================================

@app.route('/')
def index():
    """Health check endpoint"""
    print("Index endpoint accessed")
    return jsonify({"status": "healthy", "service": "FIDO2 Authentication System"}), 200

@app.route('/get_messages', methods=['GET'])
@rate_limit(max_per_minute=60)
def get_messages():
    """Get all messages"""
    print("\n=== MESSAGE RETRIEVAL REQUEST ===")
    print("Retrieving messages from database...")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        c.execute("SELECT user_id, message, timestamp FROM messages ORDER BY timestamp DESC LIMIT 50")
        messages = [{"user": row[0], "message": row[1], "time": row[2]} for row in c.fetchall()]
        conn.close()
        
        return jsonify(messages), 200
    except Exception as e:
        print(f"Error retrieving messages: {e}")
        return jsonify({"error": str(e)}), 500

# ==========================================
# WebAuthn API Endpoints
# ==========================================

@app.route('/register_options', methods=['POST'])
def webauthn_register_options():
    """Generate registration options for WebAuthn"""
    try:
        print("\n⭐ WEBAUTHN REGISTRATION OPTIONS ⭐")
        
        # Generate a unique user ID for this registration
        # Use bytes directly for better Base64URL encoding compatibility
        user_id_raw = secrets.token_bytes(16)  # 16 bytes = 128 bits of randomness
        user_id = bytes_to_base64url(user_id_raw)
        session['user_id_for_registration'] = user_id
        print(f"Register Options: Generated new user ID: {user_id}")
        
        # Generate a challenge
        challenge = generate_challenge()
        # Remove any padding for storage in the options
        challenge = challenge.rstrip('=')
        session['challenge'] = challenge
        print(f"Register Options: Generated challenge: {challenge}")
        print(f"Register Options: Challenge type: {type(challenge)}, length: {len(challenge)}")
        
        # Ensure it's base64 decodable by JavaScript atob()
        try:
            test_decode = base64.b64decode(challenge.replace('-', '+').replace('_', '/') + '=' * (4 - len(challenge) % 4))
            print(f"Register Options: Challenge can be decoded, resulting in {len(test_decode)} bytes")
        except Exception as e:
            print(f"Register Options: WARNING - Challenge cannot be decoded: {e}")
        
        # Get host info for proper rpId setting
        host = request.host
        hostname = host.split(':')[0]  # Remove port if present
        
        # For Render deployment use the constant rpId
        if hostname != 'localhost' and hostname != '127.0.0.1':
            rp_id = 'render-authentication-project.onrender.com'
        else:
            rp_id = hostname
            
        print(f"Register Options: Using rpId: {rp_id}")
        
        # Create registration options according to WebAuthn spec
        options = {
            "challenge": challenge,
            "rp": {
                "name": "FIDO2 Chat System",
                "id": rp_id
            },
            "user": {
                "id": user_id,
                "name": f"User-{user_id[:6]}",
                "displayName": f"User {user_id[:6]}"
            },
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -7  # ES256 algorithm
                }
            ],
            "authenticatorSelection": {
                "authenticatorAttachment": "cross-platform",
                "requireResidentKey": False,
                "userVerification": "discouraged"
            },
            "timeout": 120000,  # 2 minutes
            "attestation": "none"  # Don't require attestation
        }
        
        print(f"Register Options: Returning options...")
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
        public_key = json.dumps({
            'id': credential_id,
            'type': data.get('type', 'public-key'),
            'attestation': {
                'clientDataJSON': data['response']['clientDataJSON'],
                'attestationObject': data['response']['attestationObject']
            }
        })
        
        # Store the credential in the database
        print(f"Register Complete: Using database: {DB_PATH}")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
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
        print(f"Register Complete: Session updated")
        
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
        
        # Generate a challenge for this login attempt
        challenge = generate_challenge()
        session['challenge'] = challenge
        print(f"Login Options: Generated challenge: {challenge}")
        
        # Get host info for proper rpId setting
        host = request.host
        hostname = host.split(':')[0]  # Remove port if present
        
        # For Render deployment use the constant rpId
        if hostname != 'localhost' and hostname != '127.0.0.1':
            rp_id = 'render-authentication-project.onrender.com'
        else:
            rp_id = hostname
            
        print(f"Login Options: Using rpId: {rp_id}")
        
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get all credentials for cross-device login
        cursor.execute("SELECT credential_id FROM security_keys")
        credentials = cursor.fetchall()
        conn.close()
        
        allowed_credentials = []
        print(f"Login Options: Found {len(credentials)} credentials")
        
        # Prepare credentials for WebAuthn
        for (credential_id,) in credentials:
            print(f"Login Options: Adding credential: {credential_id[:20]}...")
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
            "userVerification": "discouraged"
        }
        
        print(f"Login Options: Returning options...")
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
            
            # Verify challenge
            response_challenge = client_data.get('challenge')
            if response_challenge != stored_challenge:
                print(f"Login Error: Challenge mismatch")
                return jsonify({'error': 'Challenge verification failed'}), 400
                
            # Verify type
            if client_data.get('type') != 'webauthn.get':
                print(f"Login Error: Invalid type: {client_data.get('type')}")
                return jsonify({'error': 'Invalid type'}), 400
                
            # Verify origin contains our domain
            origin = client_data.get('origin', '')
            expected_domain = 'render-authentication-project.onrender.com'
            if expected_domain not in origin and 'localhost' not in origin and '127.0.0.1' not in origin:
                print(f"Login Error: Invalid origin: {origin}")
                return jsonify({'error': f'Invalid origin'}), 400
        except Exception as e:
            print(f"Login Error: Failed to parse client data: {e}")
            return jsonify({'error': f'Failed to parse client data: {e}'}), 400
        
        # Get the user from the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Try the normalized credential ID format
        normalized_credential_id = normalize_credential_id(credential_id)
        print(f"Login Complete: Using normalized credential ID: {normalized_credential_id[:20]}...")
        
        cursor.execute("SELECT user_id, public_key, credential_id FROM security_keys WHERE credential_id = ?", 
                      (normalized_credential_id,))
        row = cursor.fetchone()
        
        # If not found with normalized format, try original format for backward compatibility
        if not row:
            print(f"Login Complete: Trying original format: {credential_id[:20]}...")
            cursor.execute("SELECT user_id, public_key, credential_id FROM security_keys WHERE credential_id = ?", (credential_id,))
            row = cursor.fetchone()
            
        conn.close()
        
        if not row:
            print("Login Error: No matching credential found")
            return jsonify({'error': 'Unknown credential'}), 400
            
        user_id = row[0]
        print(f"Login Complete: Found user {user_id}")
        
        # Set session
        session['authenticated'] = True
        session['user_id'] = user_id
        
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
    
    # Clear entire session
    session.clear()
    print("Session cleared completely")
    
    return jsonify({"status": "success", "message": "Logged out successfully"})

@app.route('/auth_status', methods=['GET'])
def webauthn_auth_status():
    """Check if the user is authenticated"""
    print("\n=== WEBAUTHN AUTH STATUS CHECK ===")
    
    is_authenticated = session.get('authenticated', False)
    user_id = session.get('user_id', None) if is_authenticated else None
    
    if is_authenticated:
        print(f"✅ User is authenticated: {user_id}")
    else:
        print("❌ User is not authenticated")
    
    return jsonify({
        "authenticated": is_authenticated,
        "userId": user_id
    })

# ==========================================
# Chat functionality
# ==========================================

@app.route('/send_message', methods=['POST'])
def send_message():
    """Save a chat message to the database"""
    print("\n=== MESSAGE SEND REQUEST ===")
    
    # Check authentication
    if not session.get('authenticated'):
        print("❌ User not authenticated")
        return jsonify({"error": "Authentication required"}), 401
    
    data = request.get_json()
    if not data or 'message' not in data:
        print("❌ Invalid request - no message")
        return jsonify({"error": "Message is required"}), 400
    
    message = data['message']
    if not message.strip():
        print("❌ Empty message")
        return jsonify({"error": "Message cannot be empty"}), 400
    
    user_id = session.get('user_id')
    print(f"Message from user: {user_id}")
    print(f"Message content: {message[:50]}...")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
    
        c.execute("INSERT INTO messages (user_id, message) VALUES (?, ?)", 
                (user_id, message))
        conn.commit()
        print("✅ Message saved successfully")
        conn.close()
        return jsonify({"success": True}), 200
    except Exception as e:
        print(f"❌ Error saving message: {e}")
        print("Stack trace:", traceback.format_exc())
        return jsonify({"error": str(e)}), 500

# ==========================================
# Admin functionality
# ==========================================

@app.route('/debug_all', methods=['GET'])
def debug_all():
    """Debug endpoint to diagnose credential issues"""
    debug_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "session": dict(session),
        "security_keys": [],
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "db_path": DB_PATH
        }
    }
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT credential_id, user_id, public_key, created_at FROM security_keys")
        keys = []
        for row in cursor.fetchall():
            # Detailed credential info for debugging
            credential_id = row[0]
            user_id = row[1]
            public_key = row[2]
            
            # Check if credential_id is valid base64url
            credential_valid = True
            try:
                # Try to decode the credential_id to check if it's valid
                padded = credential_id + '=' * (4 - len(credential_id) % 4) % 4
                standard = padded.replace('-', '+').replace('_', '/') 
                base64.b64decode(standard)
            except Exception as e:
                credential_valid = False
            
            keys.append({
                "credential_id": credential_id,
                "credential_id_length": len(credential_id),
                "credential_valid_base64": credential_valid,
                "user_id": user_id,
                "public_key_snippet": str(public_key)[:30] + "..." if public_key else None,
                "created_at": row[3]
            })
        debug_data["security_keys"] = keys
        
        # Add database info
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        debug_data["database_tables"] = [row[0] for row in cursor.fetchall()]
        
        conn.close()
    except Exception as e:
        debug_data["error"] = str(e)
    
    return jsonify(debug_data)

@app.route('/cleanup_credentials', methods=['POST'])
def cleanup_credentials():
    """Admin function to clean up all credentials"""
    try:
        print("\n⭐ CLEANING UP ALL CREDENTIALS ⭐")
        
        # For security, require a secret token
        data = request.get_json()
        if not data or data.get('secret') != os.environ.get('ADMIN_SECRET', 'admin_secret'):
            return jsonify({"error": "Unauthorized"}), 401
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Delete all security keys
        cursor.execute("DELETE FROM security_keys")
        deleted_count = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "success",
            "message": f"Deleted {deleted_count} credentials"
        })
        
    except Exception as e:
        print(f"Cleanup Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

# ==========================================
# Static file serving
# ==========================================

@app.route('/chat')
def serve_chat():
    """Serve the chat application HTML"""
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    return send_from_directory('static', path)

@app.route('/styles.css')
def serve_css():
    """Serve CSS file"""
    return send_from_directory('static', 'styles.css')

@app.route('/webauthn.js')
def serve_webauthn_js():
    """Serve WebAuthn JavaScript file"""
    return send_from_directory('static', 'webauthn.js')

@app.route('/chat.js')
def serve_chat_js():
    """Serve chat JavaScript file"""
    return send_from_directory('static', 'chat.js')

# ==========================================
# Main application entry point
# ==========================================

if __name__ == '__main__':
    import os
    # Use PORT environment variable for cloud deployment compatibility
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True) 
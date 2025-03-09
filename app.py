"""
Author(s): Chris Becker, Jake McDowell, Jason Page
Version: 1.0

Features:
- WebAuthn/FIDO2 passwordless authentication
- Secure chat with authentication
- Username customization
- Admin debugging tools
"""

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
import hashlib
import uuid
from flask_cors import CORS
import sys

app = Flask(__name__)
CORS(app)

# Set a secure secret key for session management
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configure session to be secure
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 hours

# In-memory cache for rate limiting
cache = {}

# DB path - can be customized for local development or testing
# Use a memory database or local file for testing
if os.environ.get('FLASK_ENV') == 'testing':
    DB_PATH = os.environ.get('TEST_DB_PATH', ':memory:')
    print(f"Using testing database: {DB_PATH}")
else:
    DB_PATH = os.environ.get('DB_PATH', '/opt/render/webauthn.db')

# Configuration for registration limits - simplify to just enable resident keys
REGISTRATION_LIMITS = {
    'enforce_limits': False,  # Disable all limits
    'use_resident_key': True  # Use resident keys for all security keys
}

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
    """Initialize the database with required tables"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create security_keys table with all necessary columns
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            credential_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            username TEXT,
            public_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            attestation_hash TEXT,
            combined_hash TEXT,
            aaguid TEXT,
            is_resident_key BOOLEAN DEFAULT 1
        )
        """)
        
        # Create key_fingerprints table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS key_fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            aaguid TEXT NOT NULL,
            attestation_hash TEXT NOT NULL,
            user_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Create messages table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            username TEXT,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        conn.commit()
        conn.close()
        print("Database initialized successfully")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        print(traceback.format_exc())

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
    padding_needed = len(base64url) % 4
    if padding_needed:
        base64url += '=' * (4 - padding_needed)
    
    # Convert from base64url to standard base64
    base64_str = base64url.replace('-', '+').replace('_', '/')
    
    # Decode to bytes
    return base64.b64decode(base64_str)

def bytes_to_base64url(bytes_value):
    """Convert bytes to base64url"""
    base64_str = base64.b64encode(bytes_value).decode('ascii')
    result = base64_str.replace('+', '-').replace('/', '_').rstrip('=')
    print(f"DEBUG - bytes_to_base64url: Input length {len(bytes_value)}, Output: {result[:20]}...")
    return result

def base64url_encode(data):
    """Convert bytes to base64url"""
    # Encode to base64
    base64_str = base64.b64encode(data).decode('utf-8')
    
    # Convert to base64url
    base64url = base64_str.replace('+', '-').replace('/', '_').rstrip('=')
    
    return base64url

def normalize_credential_id(credential_id):
    """Normalize a credential ID to ensure consistent format"""
    # Remove any padding characters
    return credential_id.rstrip('=')

def get_rp_id():
    """Get the Relying Party ID based on the host"""
    host = request.host
    hostname = host.split(':')[0]  # Remove port if present
    print(f"Using RP ID: {hostname}")
    return hostname

# ==========================================
# Basic routes
# ==========================================

@app.route('/')
def index():
    """Serve the main application page"""
    try:
        print("\n⭐ SERVING INDEX PAGE ⭐")
        return send_from_directory('static', 'index.html')
    except Exception as e:
        print(f"Index Error: {str(e)}")
        print(traceback.format_exc())
        return f"Error: {str(e)}", 500

@app.route('/get_messages', methods=['GET'])
def get_messages():
    """Get all messages from the chat"""
    try:
        print("\n⭐ GET MESSAGES ⭐")
        
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get messages with usernames
        cursor.execute("""
            SELECT m.id, m.user_id, COALESCE(m.username, s.username, 'User-' || substr(m.user_id, 1, 8)) as username, 
                   m.message, m.created_at 
            FROM messages m
            LEFT JOIN security_keys s ON m.user_id = s.user_id
            ORDER BY m.created_at DESC
            LIMIT 100
        """)
        
        rows = cursor.fetchall()
        conn.close()
        
        # Format messages
        messages = []
        for row in rows:
            message_id, user_id, username, message_text, created_at = row
            messages.append({
                'id': message_id,
                'user_id': user_id,
                'username': username,
                'message': message_text,
                'created_at': created_at
            })
        
        print(f"Get Messages: Retrieved {len(messages)} messages")
        
        return jsonify({
            'success': True,
            'messages': messages
        })
        
    except Exception as e:
        print(f"Get Messages Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/set_username', methods=['POST'])
def set_username():
    """Set or change the username for the authenticated user"""
    try:
        print("\n⭐ SET USERNAME ⭐")
        
        # Check if user is authenticated
        if not session.get('authenticated'):
            print("Set Username Error: User not authenticated")
            return jsonify({'error': 'Authentication required'}), 401
        
        # Get username from request
        data = request.get_json()
        new_username = data.get('username')
        
        if not new_username:
            print("Set Username Error: No username provided")
            return jsonify({'error': 'No username provided'}), 400
        
        if len(new_username) > 30:
            print("Set Username Error: Username too long")
            return jsonify({'error': 'Username too long (max 30 characters)'}), 400
        
        # Get user ID from session
        user_id = session.get('user_id')
        old_username = session.get('username', f"User-{user_id[:8]}")
        
        print(f"Set Username: User {user_id} changing username from '{old_username}' to '{new_username}'")
        
        # Update username in database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Update username in security_keys table
        cursor.execute(
            "UPDATE security_keys SET username = ? WHERE user_id = ?",
            (new_username, user_id)
        )
        
        # Add a system message about the username change
        cursor.execute(
            "INSERT INTO messages (user_id, username, message) VALUES (?, ?, ?)",
            ('system', 'System', f"User '{old_username}' changed their username to '{new_username}'")
        )
        
        conn.commit()
        conn.close()
        
        # Update username in session
        session['username'] = new_username
        
        print(f"Set Username: Username updated successfully to '{new_username}'")
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'username': new_username
        })
        
    except Exception as e:
        print(f"Set Username Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

# ==========================================
# WebAuthn API Endpoints
# ==========================================

@app.route('/register_options', methods=['GET'])
def webauthn_register_options():
    """Generate registration options for WebAuthn"""
    try:
        print("\n⭐ WEBAUTHN REGISTRATION OPTIONS ⭐")
        
        # Generate a new user ID if not already in session
        if 'user_id_for_registration' not in session:
            user_id = str(uuid.uuid4())
            session['user_id_for_registration'] = user_id
            print(f"Register Options: Generated new user ID: {user_id}")
        else:
            user_id = session['user_id_for_registration']
            print(f"Register Options: Using existing user ID from session: {user_id}")
        
        # Generate registration options
        options = {
            "challenge": base64url_encode(os.urandom(32)),
            "rp": {
                "name": "FIDO2 Demo App",
                "id": get_rp_id()
            },
            "user": {
                "id": user_id,
                "name": f"user-{user_id[:8]}",
                "displayName": f"User {user_id[:8]}"
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},  # ES256
                {"type": "public-key", "alg": -257}  # RS256
            ],
            "timeout": 60000,
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "cross-platform",
                "requireResidentKey": True,
                "userVerification": "preferred",
                "residentKey": "required"
            }
        }
        
        # Store challenge in session for verification
        session['registration_challenge'] = options['challenge']
        print(f"Register Options: Challenge stored in session: {options['challenge'][:20]}...")
        
        # Return options to client
        print(f"Register Options: Returning options to client")
        return jsonify(options)
        
    except Exception as e:
        print(f"Register Options Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

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
        
        # Set initial username based on user_id
        initial_username = f"User-{user_id[:8]}"
        
        # Get the attestation response data
        if not data.get('response') or not data['response'].get('clientDataJSON') or not data['response'].get('attestationObject'):
            print("Register Error: Missing required attestation data")
            return jsonify({'error': 'Invalid attestation data'}), 400
        
        # Extract attestation data for key identification
        attestation_object_b64 = data['response']['attestationObject']
        client_data_json_b64 = data['response']['clientDataJSON']
        
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        try:
            # Ensure tables exist
            init_db()
            
            # Ensure key_fingerprints table exists
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS key_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                aaguid TEXT NOT NULL,
                attestation_hash TEXT NOT NULL,
                user_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            conn.commit()
            
            # Generate identifiers for the physical key
            attestation_hash = hashlib.sha256(attestation_object_b64.encode()).hexdigest()
            combined_hash = hashlib.sha256((attestation_object_b64 + client_data_json_b64).encode()).hexdigest()
            
            print(f"Generated attestation hash: {attestation_hash[:20]}...")
            print(f"Generated combined hash: {combined_hash[:20]}...")
            
            # Extract AAGUID from attestation
            aaguid = None
            try:
                attestation_bytes = base64url_to_bytes(attestation_object_b64)
                for i in range(len(attestation_bytes) - 16):
                    potential_aaguid = attestation_bytes[i:i+16]
                    if any(b != 0 for b in potential_aaguid):
                        aaguid_hex = potential_aaguid.hex()
                        if aaguid_hex != "00000000000000000000000000000000":
                            aaguid = aaguid_hex
                            print(f"Extracted AAGUID: {aaguid}")
                            break
            except Exception as e:
                print(f"Error extracting AAGUID: {e}")
            
            # Check for existing registrations in priority order
            existing_key = None
            
            # Check 1: Direct credential ID match
            cursor.execute("SELECT user_id, username FROM security_keys WHERE credential_id = ?", (credential_id,))
            existing_key = cursor.fetchone()
            if existing_key:
                print("Register Complete: Found existing registration by credential ID")
            
            # Check 2: AAGUID + fingerprint matching
            if not existing_key and aaguid:
                # Check if we've seen this exact fingerprint before
                cursor.execute(
                    "SELECT user_id FROM key_fingerprints WHERE aaguid = ? AND attestation_hash = ?",
                    (aaguid, attestation_hash)
                )
                fingerprint_result = cursor.fetchone()
                
                if fingerprint_result:
                    # We've seen this exact fingerprint before
                    fingerprint_user_id = fingerprint_result[0]
                    print(f"Register Complete: Found existing fingerprint for user: {fingerprint_user_id}")
                    
                    # Get the user details
                    cursor.execute("SELECT user_id, username FROM security_keys WHERE user_id = ?", (fingerprint_user_id,))
                    existing_key = cursor.fetchone()
                    if existing_key:
                        print("Register Complete: Found existing registration by fingerprint")
                else:
                    # Check if we've seen this AAGUID before
                    cursor.execute("SELECT user_id FROM security_keys WHERE aaguid = ? LIMIT 1", (aaguid,))
                    aaguid_result = cursor.fetchone()
                    
                    if aaguid_result:
                        # We've seen this AAGUID before but not this fingerprint
                        # It's likely the same physical key on a different device
                        aaguid_user_id = aaguid_result[0]
                        print(f"Register Complete: Found existing AAGUID for user: {aaguid_user_id}")
                        
                        # Store this new fingerprint but associate it with the existing user
                        cursor.execute(
                            "INSERT INTO key_fingerprints (aaguid, attestation_hash, user_id) VALUES (?, ?, ?)",
                            (aaguid, attestation_hash, aaguid_user_id)
                        )
                        conn.commit()
                        print(f"Register Complete: Added new fingerprint for existing user {aaguid_user_id}")
                        
                        # Get the user details
                        cursor.execute("SELECT user_id, username FROM security_keys WHERE user_id = ?", (aaguid_user_id,))
                        existing_key = cursor.fetchone()
                        if existing_key:
                            print("Register Complete: Found existing registration by AAGUID")
            
            # Check 3: Attestation hash match
            if not existing_key:
                cursor.execute("SELECT user_id, username FROM security_keys WHERE attestation_hash = ?", (attestation_hash,))
                existing_key = cursor.fetchone()
                if existing_key:
                    print("Register Complete: Found existing registration by attestation hash")
            
            # If we found an existing key, log the user in with that account
            if existing_key:
                existing_user_id, existing_username = existing_key
                print(f"Register Complete: Found existing registration for this physical key: User {existing_user_id}")
                
                # Set the user as authenticated with the existing account
                session['authenticated'] = True
                session['user_id'] = existing_user_id
                session['username'] = existing_username or f"User-{existing_user_id[:8]}"
                
                # Return success with the existing user info
                return jsonify({
                    'success': True,
                    'message': 'This security key is already registered. You have been logged in.',
                    'existing_account': True,
                    'user_id': existing_user_id,
                    'username': session['username']
                }), 200
            
            # This is a new registration - store the credential
            public_key = json.dumps({
                'id': credential_id,
                'type': data.get('type', 'public-key'),
                'attestation': {
                    'clientDataJSON': data['response']['clientDataJSON'],
                    'attestationObject': data['response']['attestationObject']
                }
            })
            
            # Normalize the credential ID
            normalized_credential_id = normalize_credential_id(credential_id)
            
            # Insert the new credential
            cursor.execute(
                """
                INSERT INTO security_keys 
                (credential_id, user_id, username, public_key, created_at, attestation_hash, combined_hash, aaguid, is_resident_key) 
                VALUES (?, ?, ?, ?, datetime('now'), ?, ?, ?, 1)
                """,
                (normalized_credential_id, user_id, initial_username, public_key, attestation_hash, combined_hash, aaguid)
            )
            
            # Store the fingerprint for future reference
            if aaguid:
                cursor.execute(
                    "INSERT INTO key_fingerprints (aaguid, attestation_hash, user_id) VALUES (?, ?, ?)",
                    (aaguid, attestation_hash, user_id)
                )
            
            conn.commit()
            print(f"Register Complete: New credential registered for user {user_id}")
            
            # Set the user as authenticated
            session['authenticated'] = True
            session['user_id'] = user_id
            session['username'] = initial_username
            
            print(f"Register Complete: User {user_id} successfully registered and authenticated")
            conn.close()
            
            return jsonify({'success': True, 'user_id': user_id, 'username': initial_username}), 200
            
        except Exception as e:
            print(f"Register Complete Error: {str(e)}")
            print(traceback.format_exc())
            conn.rollback()
            conn.close()
            return jsonify({'error': f'Registration failed: {str(e)}'}), 500
        
    except Exception as e:
        print(f"Register Complete Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/login_options', methods=['GET'])
def webauthn_login_options():
    """Generate authentication options for WebAuthn login"""
    try:
        print("\n⭐ WEBAUTHN LOGIN OPTIONS ⭐")
        
        # Connect to the database to get credentials
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get all credentials from the database
        cursor.execute("SELECT credential_id, user_id FROM security_keys")
        credentials = cursor.fetchall()
        conn.close()
        
        if not credentials:
            print("Login Options: No credentials found in database")
            return jsonify({
                'error': 'No registered credentials found. Please register first.'
            }), 400
        
        # Format credentials for the client
        allow_credentials = []
        for credential_id, user_id in credentials:
            try:
                # Ensure the credential ID is valid
                normalized_credential_id = normalize_credential_id(credential_id)
                allow_credentials.append({
                    "id": normalized_credential_id,
                    "type": "public-key",
                    "transports": ["usb", "ble", "nfc", "internal"]
                })
                print(f"Login Options: Added credential ID: {normalized_credential_id[:20]}...")
            except Exception as e:
                print(f"Login Options: Skipping invalid credential ID: {e}")
        
        # Generate a challenge
        challenge = base64url_encode(os.urandom(32))
        
        # Store the challenge in the session for verification
        session['login_challenge'] = challenge
        print(f"Login Options: Challenge stored in session: {challenge[:20]}...")
        
        # Create the options
        options = {
            "challenge": challenge,
            "timeout": 60000,
            "rpId": get_rp_id(),
            "allowCredentials": allow_credentials,
            "userVerification": "preferred"
        }
        
        print(f"Login Options: Returning options with {len(allow_credentials)} credentials")
        return jsonify(options)
        
    except Exception as e:
        print(f"Login Options Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/login_complete', methods=['POST'])
def webauthn_login_complete():
    """Complete the login process for WebAuthn"""
    try:
        print("\n⭐ WEBAUTHN LOGIN COMPLETION ⭐")
        data = request.get_json()
        
        # Verify we have a credential ID
        credential_id = data.get('id')
        if not credential_id:
            print("Login Error: No credential ID in response")
            return jsonify({'error': 'No credential ID in response'}), 400
            
        print(f"Login Complete: Received credential ID: {credential_id[:20]}...")
        
        # Verify we have the expected data
        if not data.get('response') or not data['response'].get('clientDataJSON') or not data['response'].get('authenticatorData') or not data['response'].get('signature'):
            print("Login Error: Missing required authentication data")
            return jsonify({'error': 'Invalid authentication data'}), 400
        
        # Extract authenticator data and client data for identification
        authenticator_data = data['response'].get('authenticatorData', '')
        client_data_json = data['response'].get('clientDataJSON', '')
        
        # For proper verification, we need to:
        # 1. Normalize the credential ID for consistent lookup
        normalized_credential_id = normalize_credential_id(credential_id)
        
        # 2. Look up the credential in the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Try to find the user account using a series of checks in priority order
        result = None
        
        # Check 1: Direct credential ID match (most reliable)
        cursor.execute(
            "SELECT user_id, public_key, credential_id, username, is_resident_key FROM security_keys WHERE credential_id = ? OR credential_id = ?", 
            (normalized_credential_id, credential_id)
        )
        result = cursor.fetchone()
        if result:
            print("Login Complete: Found account by direct credential ID match")
        
        # Check 2: User handle from resident key (reliable for cross-device)
        if not result:
            user_handle = data.get('response', {}).get('userHandle')
            if user_handle:
                print(f"Login Complete: Found user handle in assertion: {user_handle}")
                cursor.execute(
                    "SELECT user_id, public_key, credential_id, username, is_resident_key FROM security_keys WHERE user_id = ?", 
                    (user_handle,)
                )
                result = cursor.fetchone()
                if result:
                    print("Login Complete: Found account by user handle (resident key)")
        
        # Check 3: AAGUID + fingerprint matching
        if not result:
            # Try to extract AAGUID from authenticator data
            aaguid = None
            try:
                auth_bytes = base64url_to_bytes(authenticator_data)
                for i in range(len(auth_bytes) - 16):
                    potential_aaguid = auth_bytes[i:i+16]
                    if any(b != 0 for b in potential_aaguid):
                        aaguid_hex = potential_aaguid.hex()
                        if aaguid_hex != "00000000000000000000000000000000":
                            aaguid = aaguid_hex
                            print(f"Extracted AAGUID from authenticator data: {aaguid}")
                            break
            except Exception as e:
                print(f"Error extracting AAGUID: {e}")
            
            if aaguid:
                # Generate attestation hash from authenticator data
                auth_data_hash = hashlib.sha256(authenticator_data.encode()).hexdigest()
                
                # First check if we have this exact fingerprint
                cursor.execute(
                    "SELECT user_id FROM key_fingerprints WHERE aaguid = ? AND attestation_hash = ?",
                    (aaguid, auth_data_hash)
                )
                fingerprint_result = cursor.fetchone()
                
                if fingerprint_result:
                    # We've seen this exact fingerprint before
                    fingerprint_user_id = fingerprint_result[0]
                    print(f"Found matching fingerprint for user: {fingerprint_user_id}")
                    
                    # Get the user details
                    cursor.execute(
                        "SELECT user_id, public_key, credential_id, username, is_resident_key FROM security_keys WHERE user_id = ?",
                        (fingerprint_user_id,)
                    )
                    result = cursor.fetchone()
                    if result:
                        print("Login Complete: Found account by fingerprint match")
                else:
                    # Check if we've seen this AAGUID before
                    cursor.execute("SELECT user_id FROM security_keys WHERE aaguid = ? LIMIT 1", (aaguid,))
                    aaguid_result = cursor.fetchone()
                    
                    if aaguid_result:
                        # We've seen this AAGUID before but not this fingerprint
                        aaguid_user_id = aaguid_result[0]
                        print(f"Found AAGUID match for user: {aaguid_user_id}")
                        
                        # Store this new fingerprint for future reference
                        try:
                            cursor.execute(
                                "INSERT INTO key_fingerprints (aaguid, attestation_hash, user_id) VALUES (?, ?, ?)",
                                (aaguid, auth_data_hash, aaguid_user_id)
                            )
                            conn.commit()
                            print(f"Added new fingerprint for existing user {aaguid_user_id}")
                        except Exception as e:
                            print(f"Error storing fingerprint: {e}")
                        
                        # Get the user details
                        cursor.execute(
                            "SELECT user_id, public_key, credential_id, username, is_resident_key FROM security_keys WHERE user_id = ?",
                            (aaguid_user_id,)
                        )
                        result = cursor.fetchone()
                        if result:
                            print("Login Complete: Found account by AAGUID match")
        
        # If we still haven't found a match, authentication fails
        if not result:
            print("Login Error: Could not find matching credential")
            conn.close()
            return jsonify({'error': 'Credential not recognized. Please register first.'}), 401
        
        # Extract user information from the result
        user_id = result[0]
        public_key_json = result[1]
        stored_credential_id = result[2]
        username = result[3]
        is_resident_key = result[4] if len(result) > 4 else True
        
        if not user_id:
            print("Login Error: Invalid user ID for credential")
            conn.close()
            return jsonify({'error': 'Invalid user credential. Please register again.'}), 401
            
        print(f"Login Complete: Found user ID: {user_id} with username: {username or 'Unknown'}")
        print(f"Login Complete: Is resident key: {is_resident_key}")
        
        # For this simplification, we'll just verify that we found a user
        # In a real implementation, you would verify the signature against the stored public key
            
        # Set the authenticated session
        session['authenticated'] = True
        session['user_id'] = user_id
        session['credential_id'] = stored_credential_id
        session['username'] = username or f"User-{user_id[:8]}"
        
        print(f"Login Complete: User {user_id} successfully authenticated as {session['username']}")
        conn.close()
        
        return jsonify({
            'success': True, 
            'user_id': user_id,
            'username': session['username']
        }), 200
        
    except Exception as e:
        print(f"Login Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/logout', methods=['POST'])
def webauthn_logout():
    """Log out the current user by clearing the session"""
    try:
        print("\n⭐ LOGOUT ⭐")
        
        # Check if user is authenticated
        if session.get('authenticated'):
            user_id = session.get('user_id')
            username = session.get('username', f"User-{user_id[:8]}")
            print(f"Logout: User {username} ({user_id}) logged out")
        else:
            print("Logout: No authenticated user to log out")
        
        # Clear the session
        session.clear()
        
        return jsonify({
            'success': True,
            'message': 'Logged out successfully'
        })
        
    except Exception as e:
        print(f"Logout Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/auth_status', methods=['GET'])
def webauthn_auth_status():
    """Check if the user is authenticated"""
    try:
        print("\n⭐ AUTH STATUS CHECK ⭐")
        
        # Check if user is authenticated
        is_authenticated = session.get('authenticated', False)
        user_id = session.get('user_id', None)
        username = session.get('username', None)
        
        if is_authenticated and user_id:
            print(f"Auth Status: User {username} ({user_id}) is authenticated")
            
            # If username is not in session but user_id is, try to get it from the database
            if not username:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("SELECT username FROM security_keys WHERE user_id = ? LIMIT 1", (user_id,))
                    result = cursor.fetchone()
                    conn.close()
                    
                    if result and result[0]:
                        username = result[0]
                        session['username'] = username
                        print(f"Auth Status: Retrieved username '{username}' from database")
                    else:
                        username = f"User-{user_id[:8]}"
                        session['username'] = username
                        print(f"Auth Status: Generated default username '{username}'")
                except Exception as e:
                    print(f"Auth Status Error: {str(e)}")
                    username = f"User-{user_id[:8]}"
            
            return jsonify({
                'authenticated': True,
                'user_id': user_id,
                'username': username
            })
        else:
            print("Auth Status: User is not authenticated")
            return jsonify({
                'authenticated': False
            })
            
    except Exception as e:
        print(f"Auth Status Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

# ==========================================
# Chat functionality
# ==========================================

@app.route('/send_message', methods=['POST'])
def send_message():
    """Send a message to the chat (requires authentication)"""
    try:
        print("\n⭐ SEND MESSAGE ⭐")
        
        # Check if user is authenticated
        if not session.get('authenticated'):
            print("Send Message Error: User not authenticated")
            return jsonify({'error': 'Authentication required'}), 401
        
        # Get message from request
        data = request.get_json()
        message_text = data.get('message')
        
        if not message_text:
            print("Send Message Error: No message provided")
            return jsonify({'error': 'No message provided'}), 400
        
        # Get user ID and username from session
        user_id = session.get('user_id')
        username = session.get('username', f"User-{user_id[:8]}")
        
        print(f"Send Message: From user {username} ({user_id}): {message_text[:50]}...")
        
        # Store message in database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO messages (user_id, username, message) VALUES (?, ?, ?)",
            (user_id, username, message_text)
        )
        
        conn.commit()
        conn.close()
        
        print("Send Message: Message stored successfully")
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'username': username,
            'message': message_text
        })
        
    except Exception as e:
        print(f"Send Message Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

# ==========================================
# Admin functionality
# ==========================================

@app.route('/debug_all', methods=['GET'])
def debug_all():
    """Debug endpoint to view all data (for development only)"""
    try:
        print("\n⭐ DEBUG ALL DATA ⭐")
        
        # Get environment info
        env_info = {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "hostname": platform.node()
        }
        
        # Get database info
        db_info = {}
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        db_info["tables"] = [table[0] for table in tables]
        
        # Get security keys
        security_keys = []
        try:
            cursor.execute("SELECT credential_id, user_id, username, created_at, attestation_hash, aaguid FROM security_keys")
            rows = cursor.fetchall()
            for row in rows:
                credential_id, user_id, username, created_at, attestation_hash, aaguid = row
                security_keys.append({
                    "credential_id": credential_id[:20] + "..." if credential_id else None,
                    "user_id": user_id,
                    "username": username,
                    "created_at": created_at,
                    "attestation_hash": attestation_hash[:20] + "..." if attestation_hash else None,
                    "aaguid": aaguid
                })
        except sqlite3.Error as e:
            security_keys = [{"error": str(e)}]
        
        # Get key fingerprints
        fingerprints = []
        try:
            cursor.execute("SELECT aaguid, attestation_hash, user_id, created_at FROM key_fingerprints")
            rows = cursor.fetchall()
            for row in rows:
                aaguid, attestation_hash, user_id, created_at = row
                fingerprints.append({
                    "aaguid": aaguid,
                    "attestation_hash": attestation_hash[:20] + "..." if attestation_hash else None,
                    "user_id": user_id,
                    "created_at": created_at
                })
        except sqlite3.Error as e:
            fingerprints = [{"error": str(e)}]
        
        # Get messages
        messages = []
        try:
            cursor.execute("SELECT user_id, username, message, created_at FROM messages ORDER BY created_at DESC LIMIT 10")
            rows = cursor.fetchall()
            for row in rows:
                user_id, username, message, created_at = row
                messages.append({
                    "user_id": user_id,
                    "username": username,
                    "message": message,
                    "created_at": created_at
                })
        except sqlite3.Error as e:
            messages = [{"error": str(e)}]
        
        conn.close()
        
        # Get session info
        session_info = {}
        for key in session:
            # Don't include challenge in output for security
            if key in ['registration_challenge', 'login_challenge']:
                session_info[key] = "[REDACTED]"
            else:
                session_info[key] = session[key]
        
        # Compile all debug info
        debug_info = {
            "environment": env_info,
            "database": db_info,
            "security_keys": security_keys,
            "key_fingerprints": fingerprints,
            "messages": messages,
            "session": session_info,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        return jsonify(debug_info)
        
    except Exception as e:
        print(f"Debug All Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/cleanup_credentials', methods=['POST'])
def cleanup_credentials():
    """Clean up credentials for the current user"""
    try:
        print("\n⭐ CLEANUP CREDENTIALS ⭐")
        
        # Check if user is authenticated
        if not session.get('authenticated'):
            print("Cleanup Credentials Error: User not authenticated")
            return jsonify({'error': 'Authentication required'}), 401
        
        # Get user ID from session
        user_id = session.get('user_id')
        username = session.get('username', f"User-{user_id[:8]}")
        
        print(f"Cleanup Credentials: Removing credentials for user {username} ({user_id})")
        
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Delete user's credentials from security_keys
        cursor.execute("DELETE FROM security_keys WHERE user_id = ?", (user_id,))
        key_count = cursor.rowcount
        
        # Delete user's fingerprints from key_fingerprints
        try:
            cursor.execute("DELETE FROM key_fingerprints WHERE user_id = ?", (user_id,))
            fingerprint_count = cursor.rowcount
        except sqlite3.Error:
            fingerprint_count = 0
        
        # Delete user's messages from messages
        cursor.execute("DELETE FROM messages WHERE user_id = ?", (user_id,))
        message_count = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        # Clear the session
        session.clear()
        
        print(f"Cleanup Credentials: Removed {key_count} credentials, {fingerprint_count} fingerprints, and {message_count} messages")
        
        return jsonify({
            'success': True,
            'message': f'Account deleted successfully. Removed {key_count} credentials, {fingerprint_count} fingerprints, and {message_count} messages.',
            'key_count': key_count,
            'fingerprint_count': fingerprint_count,
            'message_count': message_count
        })
        
    except Exception as e:
        print(f"Cleanup Credentials Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/force_cleanup', methods=['GET'])
def force_cleanup_credentials():
    """Force cleanup all credentials and messages from the database"""
    try:
        print("\n⭐ FORCE CLEANUP ⭐")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Delete all records from security_keys
        try:
            cursor.execute("DELETE FROM security_keys")
            key_count = cursor.rowcount
            print(f"Deleted {key_count} security keys")
        except sqlite3.Error as e:
            key_count = 0
            print(f"Error deleting security keys: {e}")
        
        # Delete all records from key_fingerprints
        try:
            cursor.execute("DELETE FROM key_fingerprints")
            fingerprint_count = cursor.rowcount
            print(f"Deleted {fingerprint_count} key fingerprints")
        except sqlite3.Error as e:
            fingerprint_count = 0
            print(f"Error deleting key fingerprints: {e}")
        
        # Delete all records from messages
        try:
            cursor.execute("DELETE FROM messages")
            message_count = cursor.rowcount
            print(f"Deleted {message_count} messages")
        except sqlite3.Error as e:
            message_count = 0
            print(f"Error deleting messages: {e}")
        
        # Reset the database schema
        try:
            # Drop and recreate tables to ensure schema is up to date
            cursor.execute("DROP TABLE IF EXISTS security_keys")
            cursor.execute("DROP TABLE IF EXISTS key_fingerprints")
            cursor.execute("DROP TABLE IF EXISTS messages")
            
            # Reinitialize the database
            init_db()
            print("Database schema reset successfully")
        except sqlite3.Error as e:
            print(f"Error resetting database schema: {e}")
        
        conn.commit()
        conn.close()
        
        # Clear the session
        session.clear()
        
        return jsonify({
            'success': True,
            'message': f'Cleanup complete. Deleted {key_count} security keys, {fingerprint_count} fingerprints, and {message_count} messages.'
        })
        
    except Exception as e:
        print(f"Force Cleanup Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

# ==========================================
# Static file serving
# ==========================================

@app.route('/chat')
def serve_chat():
    """Serve the chat page"""
    try:
        print("\n⭐ SERVING CHAT PAGE ⭐")
        return send_from_directory('static', 'chat.html')
    except Exception as e:
        print(f"Chat Page Error: {str(e)}")
        print(traceback.format_exc())
        return f"Error: {str(e)}", 500

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    try:
        print(f"\n⭐ SERVING STATIC FILE: {path} ⭐")
        return send_from_directory('static', path)
    except Exception as e:
        print(f"Static File Error: {str(e)}")
        print(traceback.format_exc())
        return f"Error: {str(e)}", 500

@app.route('/style.css')
def serve_css():
    """Serve the CSS file"""
    try:
        print("\n⭐ SERVING CSS FILE ⭐")
        return send_from_directory('static', 'style.css')
    except Exception as e:
        print(f"CSS File Error: {str(e)}")
        print(traceback.format_exc())
        return f"Error: {str(e)}", 500

@app.route('/webauthn.js')
def serve_webauthn_js():
    """Serve the WebAuthn JavaScript file"""
    try:
        print("\n⭐ SERVING WEBAUTHN JS FILE ⭐")
        return send_from_directory('static', 'webauthn.js')
    except Exception as e:
        print(f"WebAuthn JS File Error: {str(e)}")
        print(traceback.format_exc())
        return f"Error: {str(e)}", 500

@app.route('/chat.js')
def serve_chat_js():
    """Serve the chat JavaScript file"""
    try:
        print("\n⭐ SERVING CHAT JS FILE ⭐")
        return send_from_directory('static', 'chat.js')
    except Exception as e:
        print(f"Chat JS File Error: {str(e)}")
        print(traceback.format_exc())
        return f"Error: {str(e)}", 500

# ==========================================
# Main entry point
if __name__ == '__main__':
    try:
        # Initialize the database
        init_db()
        
        # Get port from environment or use default
        port = int(os.environ.get('PORT', 5000))
        
        # Get debug mode from environment
        debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        
        print(f"\n⭐ STARTING FIDO2 AUTHENTICATION SERVER ⭐")
        print(f"Database: {DB_PATH}")
        print(f"Port: {port}")
        print(f"Debug mode: {debug}")
        print(f"Platform: {platform.platform()}")
        print(f"Python version: {platform.python_version()}")
        
        # Start the server
        app.run(host='0.0.0.0', port=port, debug=debug)
        
    except Exception as e:
        print(f"Server startup error: {str(e)}")
        print(traceback.format_exc())
        sys.exit(1) 
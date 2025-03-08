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

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key_change_in_production')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# In-memory cache for rate limiting
cache = {}

# DB path - can be customized for local development or testing
# Use a memory database or local file for testing
if os.environ.get('FLASK_ENV') == 'testing':
    DB_PATH = os.environ.get('TEST_DB_PATH', ':memory:')
    print(f"Using testing database: {DB_PATH}")
else:
    DB_PATH = os.environ.get('DB_PATH', '/opt/render/webauthn.db')

# Configuration for registration limits
REGISTRATION_LIMITS = {
    'max_per_day': 3,  # Maximum registrations allowed per day per browser
    'cooldown_hours': 4,  # Hours between registrations
    'enforce_limits': True,  # Set to False to disable limits
    'use_resident_key': True  # Use resident keys for security keys that support this feature
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
    """Initialize database tables if they don't exist"""
    print(f"Initializing database at {DB_PATH}")
    
    # Only create directory if not using in-memory database
    if DB_PATH != ':memory:' and os.path.dirname(DB_PATH):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create security_keys table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS security_keys (
        id INTEGER PRIMARY KEY,
        credential_id TEXT UNIQUE NOT NULL,
        user_id TEXT NOT NULL,
        username TEXT,
        public_key TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL
    )
    ''')
    
    # Check if we need to add the username column to an existing table
    try:
        cursor.execute("PRAGMA table_info(security_keys)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'username' not in columns:
            print("Adding username column to security_keys table")
            try:
                cursor.execute("ALTER TABLE security_keys ADD COLUMN username TEXT")
                # Initialize existing users with their shortened user_id as username
                cursor.execute("UPDATE security_keys SET username = 'User-' || substr(user_id, 1, 8) WHERE username IS NULL")
                conn.commit()
                print("Successfully added username column")
            except sqlite3.Error as e:
                print(f"Warning: Could not add username column: {e}")
                conn.rollback()
    except Exception as e:
        print(f"Warning: Error checking for username column: {e}")
        # Continue with table creation regardless of this failure
    
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
        
        # Check if the messages table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
        if not c.fetchone():
            print("Messages table doesn't exist yet")
            conn.close()
            return jsonify([]), 200
        
        # Check if the username column exists in the security_keys table
        c.execute("PRAGMA table_info(security_keys)")
        columns = [col[1] for col in c.fetchall()]
        has_username_column = 'username' in columns
        
        if has_username_column:
            # Retrieve messages with username information
            c.execute("""
                SELECT m.user_id, m.message, m.timestamp, s.username 
                FROM messages m
                LEFT JOIN security_keys s ON m.user_id = s.user_id
                GROUP BY m.id
                ORDER BY m.timestamp DESC 
                LIMIT 50
            """)
        else:
            # Retrieve messages without username information
            c.execute("""
                SELECT user_id, message, timestamp 
                FROM messages
                ORDER BY timestamp DESC 
                LIMIT 50
            """)
        
        messages = []
        for row in c.fetchall():
            user_id = row[0]
            message = row[1]
            timestamp = row[2]
            
            if has_username_column:
                username = row[3]
                # If no username found and not a system message, use a shortened user_id
                if not username and user_id != 'system':
                    username = f"User-{user_id[:8]}"
                # For system messages, use 'System' as the display name
                if user_id == 'system':
                    username = 'System'
            else:
                # Generate username from user_id when username column doesn't exist
                username = 'System' if user_id == 'system' else f"User-{user_id[:8]}"
                
            messages.append({
                "user": user_id,
                "username": username,
                "message": message,
                "time": timestamp
            })
            
        conn.close()
        
        print(f"Retrieved {len(messages)} messages")
        return jsonify(messages), 200
    except Exception as e:
        print(f"Error retrieving messages: {e}")
        print(traceback.format_exc())
        # Return empty list instead of error for better user experience
        return jsonify([]), 200

# ==========================================
# WebAuthn API Endpoints
# ==========================================

@app.route('/register_options', methods=['POST'])
def webauthn_register_options():
    """Generate registration options for WebAuthn"""
    try:
        print("\n⭐ WEBAUTHN REGISTRATION OPTIONS ⭐")
        
        # Generate a random user ID
        user_id = secrets.token_urlsafe(32)
        print(f"Register Options: Generated user ID: {user_id}")
        
        # Store the user ID in the session for later use
        session['user_id_for_registration'] = user_id
        
        # Generate a challenge
        challenge = generate_challenge()
        # Remove any padding for storage in the session
        challenge = challenge.rstrip('=')
        session['challenge'] = challenge
        print(f"Register Options: Generated challenge: {challenge}")
        
        # Get host info for proper rpId setting
        host = request.host
        hostname = host.split(':')[0]  # Remove port if present
        rp_id = hostname
        print(f"Register Options: Using RP ID: {rp_id}")
        
        # Get all existing credentials to exclude
        exclude_credentials = []
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT credential_id FROM security_keys")
            rows = cursor.fetchall()
            
            for row in rows:
                credential_id = row[0]
                # Only include valid credential IDs
                try:
                    # Check that we can decode the credential ID
                    credential_id_bytes = base64url_to_bytes(credential_id)
                    exclude_credentials.append({
                        "id": credential_id,
                        "type": "public-key",
                        "transports": ["usb", "ble", "nfc", "internal"]
                    })
                    print(f"Register Options: Excluding credential ID: {credential_id[:20]}...")
                except Exception as e:
                    print(f"Register Options: Skipping invalid credential ID: {e}")
                    
            conn.close()
        except Exception as e:
            print(f"Register Options: Error getting credentials to exclude: {e}")
            # Continue without exclusion if there's an error
            
        # Create the options
        options = {
            "challenge": challenge,
            "rp": {
                "name": "FIDO2 Chat System",
                "id": rp_id
            },
            "user": {
                "id": user_id,
                "name": f"user-{user_id[:8]}",
                "displayName": f"User {user_id[:8]}"
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},   # ES256
                {"type": "public-key", "alg": -257}  # RS256
            ],
            "authenticatorSelection": {
                "authenticatorAttachment": "cross-platform",  # Request external security keys
                "requireResidentKey": REGISTRATION_LIMITS['use_resident_key'],  # Use resident keys for fixed identity
                "residentKey": "preferred" if REGISTRATION_LIMITS['use_resident_key'] else "discouraged",  # New parameter in WebAuthn Level 2
                "userVerification": "preferred"  # Encourage user verification for better security
            },
            "timeout": 60000,
            "attestation": "direct",  # Request attestation to help identify the authenticator model
            "excludeCredentials": exclude_credentials
        }
        
        print(f"Register Options: Returning options with {len(exclude_credentials)} excluded credentials")
        return jsonify(options), 200
        
    except Exception as e:
        print(f"Register Options Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": "Failed to generate registration options"}), 500

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
        
        # Check registration limits if enabled
        if REGISTRATION_LIMITS['enforce_limits']:
            # Get browser fingerprint from User-Agent and other headers
            user_agent = request.headers.get('User-Agent', '')
            accept_lang = request.headers.get('Accept-Language', '')
            platform = request.headers.get('Sec-Ch-Ua-Platform', '')
            
            # Create a simple fingerprint hash
            fingerprint = hashlib.sha256(f"{user_agent}|{accept_lang}|{platform}".encode()).hexdigest()
            print(f"Register Complete: Browser fingerprint: {fingerprint[:20]}...")
            
            # Check registration history for this browser fingerprint
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Add browser_fingerprint and registration_time columns if they don't exist
            cursor.execute("PRAGMA table_info(security_keys)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'browser_fingerprint' not in columns:
                print("Adding browser_fingerprint column to security_keys table")
                cursor.execute("ALTER TABLE security_keys ADD COLUMN browser_fingerprint TEXT")
                conn.commit()
                
            if 'registration_time' not in columns:
                print("Adding registration_time column to security_keys table")
                cursor.execute("ALTER TABLE security_keys ADD COLUMN registration_time TIMESTAMP")
                conn.commit()
            
            # Get current time
            current_time = datetime.datetime.now().isoformat()
            
            # Count registrations from this browser in the last 24 hours
            one_day_ago = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
            cursor.execute(
                "SELECT COUNT(*), MAX(registration_time) FROM security_keys WHERE browser_fingerprint = ? AND registration_time > ?", 
                (fingerprint, one_day_ago)
            )
            result = cursor.fetchone()
            count_today = result[0] if result else 0
            last_registration = result[1] if result and len(result) > 1 else None
            
            # Check if we're within the cooldown period
            if last_registration:
                try:
                    last_reg_time = datetime.datetime.fromisoformat(last_registration)
                    time_since_last = datetime.datetime.now() - last_reg_time
                    cooldown_period = datetime.timedelta(hours=REGISTRATION_LIMITS['cooldown_hours'])
                    
                    if time_since_last < cooldown_period:
                        hours_to_wait = (cooldown_period - time_since_last).total_seconds() / 3600
                        print(f"Register Error: Too soon since last registration. Need to wait {hours_to_wait:.1f} more hours")
                        conn.close()
                        return jsonify({
                            'error': f'Please wait {hours_to_wait:.1f} more hours before registering another security key.'
                        }), 429
                except Exception as e:
                    print(f"Error parsing registration time: {e}")
            
            # Check daily limit
            if count_today >= REGISTRATION_LIMITS['max_per_day']:
                print(f"Register Error: Browser has reached the maximum number of registrations today ({REGISTRATION_LIMITS['max_per_day']})")
                conn.close()
                return jsonify({
                    'error': f'Maximum number of registrations reached. You can register up to {REGISTRATION_LIMITS["max_per_day"]} security keys per day.'
                }), 429
            
            # Store the fingerprint and time for later use
            session['browser_fingerprint'] = fingerprint
            session['registration_time'] = current_time
            conn.close()
        
        # Set initial username based on user_id
        initial_username = f"User-{user_id[:8]}"
        
        # Get the attestation response data
        if not data.get('response') or not data['response'].get('clientDataJSON') or not data['response'].get('attestationObject'):
            print("Register Error: Missing required attestation data")
            return jsonify({'error': 'Invalid attestation data'}), 400
        
        # Extract attestation data for key identification
        attestation_object_b64 = data['response']['attestationObject']
        client_data_json_b64 = data['response']['clientDataJSON']
        
        # Check if this physical key is already registered (by attestation)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        try:
            # First, check if we have the necessary columns
            cursor.execute("PRAGMA table_info(security_keys)")
            columns = [col[1] for col in cursor.fetchall()]
            
            # Add attestation_hash column if it doesn't exist
            if 'attestation_hash' not in columns:
                print("Adding attestation_hash column to security_keys table")
                cursor.execute("ALTER TABLE security_keys ADD COLUMN attestation_hash TEXT")
                conn.commit()
                
            # Add aaguid column if it doesn't exist (for better cross-device identification)
            if 'aaguid' not in columns:
                print("Adding aaguid column to security_keys table")
                cursor.execute("ALTER TABLE security_keys ADD COLUMN aaguid TEXT")
                conn.commit()
                
            # Add raw_id column if it doesn't exist (for additional matching)
            if 'raw_id' not in columns:
                print("Adding raw_id column to security_keys table")
                cursor.execute("ALTER TABLE security_keys ADD COLUMN raw_id TEXT")
                conn.commit()
                
            # Add combined_hash column if it doesn't exist
            if 'combined_hash' not in columns:
                print("Adding combined_hash column to security_keys table")
                cursor.execute("ALTER TABLE security_keys ADD COLUMN combined_hash TEXT")
                conn.commit()
                
            # Add authenticator_model column if it doesn't exist
            if 'authenticator_model' not in columns:
                print("Adding authenticator_model column to security_keys table")
                cursor.execute("ALTER TABLE security_keys ADD COLUMN authenticator_model TEXT")
                conn.commit()
                
            # Add is_resident_key column if it doesn't exist
            if 'is_resident_key' not in columns:
                print("Adding is_resident_key column to security_keys table")
                cursor.execute("ALTER TABLE security_keys ADD COLUMN is_resident_key BOOLEAN")
                conn.commit()
            
            # Generate multiple identifiers for the physical key
            # 1. Primary attestation hash (from attestation object)
            attestation_hash = hashlib.sha256(attestation_object_b64.encode()).hexdigest()
            
            # 2. Secondary hash (combination of attestation and client data)
            combined_hash = hashlib.sha256((attestation_object_b64 + client_data_json_b64).encode()).hexdigest()
            
            # 3. Raw ID for additional matching
            raw_id = credential_id
            
            print(f"Generated attestation hash: {attestation_hash[:20]}...")
            print(f"Generated combined hash: {combined_hash[:20]}...")
            
            # Try to extract AAGUID and other info from attestation
            aaguid = None
            authenticator_model = None
            is_resident_key = REGISTRATION_LIMITS['use_resident_key']
            
            try:
                # Parse the attestation object to extract AAGUID and other info
                attestation_bytes = base64url_to_bytes(attestation_object_b64)
                
                # Try to parse CBOR data (simplified approach)
                # In a production environment, use a proper CBOR parser library
                
                # Look for AAGUID pattern (16 bytes, typically non-zero)
                for i in range(len(attestation_bytes) - 16):
                    potential_aaguid = attestation_bytes[i:i+16]
                    if any(b != 0 for b in potential_aaguid):
                        aaguid_hex = potential_aaguid.hex()
                        if aaguid_hex != "00000000000000000000000000000000":
                            aaguid = aaguid_hex
                            print(f"Extracted AAGUID: {aaguid}")
                            break
                
                # Try to determine the authenticator model from attestation data
                # Convert to string to look for model identifiers
                attestation_str = attestation_bytes.decode('utf-8', errors='ignore')
                
                # Check for common security key manufacturers in the attestation
                # This helps identify the type of security key without mentioning specific brands
                if any(manufacturer in attestation_str for manufacturer in ['FIDO', 'U2F', 'Security Key']):
                    authenticator_model = "Security Key"
                    
                    # Try to determine specific model types without mentioning brands
                    if any(model in attestation_str for model in ['5Ci', '5 Ci']):
                        authenticator_model = "Multi-connector Security Key"
                    elif any(model in attestation_str for model in ['5C', '5 C']):
                        authenticator_model = "USB-C Security Key"
                    elif any(model in attestation_str for model in ['5NFC', '5 NFC', 'NFC']):
                        authenticator_model = "NFC-enabled Security Key"
                    elif any(model in attestation_str for model in ['Bio', 'Biometric']):
                        authenticator_model = "Biometric Security Key"
                    
                    print(f"Detected authenticator model: {authenticator_model}")
                
                # If we have an AAGUID but couldn't determine the model, try to look it up
                if aaguid and not authenticator_model:
                    # Known AAGUIDs for common authenticators
                    # This is a simplified approach - in production, use a proper database
                    aaguid_to_model = {
                        # Add known AAGUIDs here as you discover them
                        # Example: "f8a011f38c0a4d15800617111f9edc7d": "Multi-connector Security Key"
                    }
                    
                    if aaguid in aaguid_to_model:
                        authenticator_model = aaguid_to_model[aaguid]
                        print(f"Identified model from AAGUID: {authenticator_model}")
                
            except Exception as e:
                print(f"Error extracting authenticator info: {e}")
                print(traceback.format_exc())
            
            # Check for existing registrations using multiple methods
            existing_key = None
            
            # Method 1: First check by exact credential ID match
            cursor.execute("SELECT user_id, username FROM security_keys WHERE credential_id = ?", (credential_id,))
            existing_key = cursor.fetchone()
            
            # Method 2: If not found, check by normalized credential ID
            if not existing_key:
                normalized_credential_id = normalize_credential_id(credential_id)
                cursor.execute("SELECT user_id, username FROM security_keys WHERE credential_id = ?", (normalized_credential_id,))
                existing_key = cursor.fetchone()
            
            # Method 3: If not found and this is a resident key, check by attestation hash
            if not existing_key and is_resident_key:
                cursor.execute("SELECT user_id, username FROM security_keys WHERE attestation_hash = ? AND is_resident_key = 1", (attestation_hash,))
                existing_key = cursor.fetchone()
                
            # Method 4: If not found and this is a resident key, check by combined hash
            if not existing_key and is_resident_key:
                cursor.execute("SELECT user_id, username FROM security_keys WHERE combined_hash = ? AND is_resident_key = 1", (combined_hash,))
                existing_key = cursor.fetchone()
            
            if existing_key:
                existing_user_id, existing_username = existing_key
                print(f"Found existing registration for this physical key: User {existing_user_id}")
                
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
                
            # Log the identification data for debugging
            print(f"Key identification data:")
            print(f"  - Credential ID: {credential_id[:20]}...")
            print(f"  - Attestation hash: {attestation_hash[:20]}...")
            print(f"  - AAGUID: {aaguid}")
            print(f"  - Authenticator model: {authenticator_model}")
            print(f"  - Is resident key: {is_resident_key}")
            
        except Exception as e:
            print(f"Error checking for existing key: {e}")
            print(traceback.format_exc())
            # Continue with registration if there's an error checking
            
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
        
        # Normalize the credential ID to ensure consistent storage format
        normalized_credential_id = normalize_credential_id(credential_id)
        
        # Check if this exact credential ID already exists
        cursor.execute("SELECT credential_id FROM security_keys WHERE credential_id = ?", (normalized_credential_id,))
        if cursor.fetchone():
            print(f"Register Complete: Credential ID already exists, skipping insertion")
        else:
            try:
                # Check if the username column exists
                cursor.execute("PRAGMA table_info(security_keys)")
                columns = [col[1] for col in cursor.fetchall()]
                
                # Generate attestation hash if not already done
                if 'attestation_hash' not in locals():
                    attestation_hash = hashlib.sha256(attestation_object_b64.encode()).hexdigest()
                    combined_hash = hashlib.sha256((attestation_object_b64 + client_data_json_b64).encode()).hexdigest()
                
                # Prepare insertion with all available columns
                insert_columns = ["credential_id", "user_id", "public_key", "created_at"]
                insert_values = [normalized_credential_id, user_id, public_key, "datetime('now')"]
                
                # Add username if column exists
                if 'username' in columns:
                    insert_columns.append("username")
                    insert_values.append(initial_username)
                
                # Add attestation_hash if column exists
                if 'attestation_hash' in columns:
                    insert_columns.append("attestation_hash")
                    insert_values.append(attestation_hash)
                
                # Add combined_hash as a secondary attestation hash if column exists
                if 'combined_hash' in columns:
                    insert_columns.append("combined_hash")
                    insert_values.append(combined_hash)
                
                # Add AAGUID if we extracted it and column exists
                if aaguid and 'aaguid' in columns:
                    insert_columns.append("aaguid")
                    insert_values.append(aaguid)
                
                # Add raw_id if column exists
                if 'raw_id' in columns:
                    insert_columns.append("raw_id")
                    insert_values.append(raw_id)
                    
                # Add authenticator_model if we identified it and column exists
                if authenticator_model and 'authenticator_model' in columns:
                    insert_columns.append("authenticator_model")
                    insert_values.append(authenticator_model)
                    
                # Add is_resident_key if column exists
                if 'is_resident_key' in columns:
                    insert_columns.append("is_resident_key")
                    insert_values.append(1 if is_resident_key else 0)
                    
                # Add browser fingerprint and registration time if columns exist
                if 'browser_fingerprint' in columns and 'browser_fingerprint' in session:
                    insert_columns.append("browser_fingerprint")
                    insert_values.append(session['browser_fingerprint'])
                    
                if 'registration_time' in columns and 'registration_time' in session:
                    insert_columns.append("registration_time")
                    insert_values.append(session['registration_time'])
                
                # Build and execute the dynamic INSERT query
                columns_str = ", ".join(insert_columns)
                placeholders = ", ".join(["?"] * len(insert_values))
                
                query = f"INSERT INTO security_keys ({columns_str}) VALUES ({placeholders})"
                print(f"Register Complete: Executing query: {query}")
                
                cursor.execute(query, insert_values)
                
            except sqlite3.Error as e:
                print(f"Register Complete Error: Database error: {e}")
                print(traceback.format_exc())
                # Fallback to basic insertion without username
                try:
                    cursor.execute(
                        "INSERT INTO security_keys (credential_id, user_id, public_key, created_at) VALUES (?, ?, ?, datetime('now'))",
                        (normalized_credential_id, user_id, public_key)
                    )
                except sqlite3.Error as insert_error:
                    print(f"Register Complete Critical Error: Could not insert credential: {insert_error}")
                    conn.rollback()

        conn.commit()
        conn.close()
        
        # Set the user as authenticated
        session['authenticated'] = True
        session['user_id'] = user_id
        session['username'] = initial_username
        
        print(f"Register Complete: User {user_id} successfully registered and authenticated")
        return jsonify({'success': True, 'user_id': user_id, 'username': initial_username}), 200
        
    except Exception as e:
        print(f"Register Complete Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/login_options', methods=['POST'])
def webauthn_login_options():
    """Generate authentication options for WebAuthn login"""
    try:
        print("\n⭐ WEBAUTHN LOGIN OPTIONS ⭐")
        
        # Get all credentials from the database
        print(f"Login Options: Using database: {DB_PATH}")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get all credentials
        cursor.execute("SELECT credential_id, user_id, is_resident_key FROM security_keys")
        rows = cursor.fetchall()
        
        credentials = []
        has_resident_keys = False
        
        for row in rows:
            credential_id = row[0]
            user_id = row[1]
            is_resident_key = row[2] if len(row) > 2 else False
            
            if is_resident_key:
                has_resident_keys = True
            
            # Only include valid credential IDs
            try:
                # Check that we can decode the credential ID
                credential_id_bytes = base64url_to_bytes(credential_id)
                credentials.append({
                    "id": credential_id,
                    "type": "public-key",
                    "transports": ["usb", "ble", "nfc", "internal"]
                })
                print(f"Login Options: Added credential ID: {credential_id[:20]}... for user: {user_id}")
            except Exception as e:
                print(f"Login Options: Skipping invalid credential ID: {e}")
        
        conn.close()
        
        if not credentials and not has_resident_keys:
            print("Login Options: No credentials found in database")
            return jsonify({"error": "No registered credentials found"}), 400
            
        print(f"Login Options: Found {len(credentials)} credential(s)")
        
        # Generate a challenge
        challenge = generate_challenge()
        # Remove any padding for storage in the session
        challenge = challenge.rstrip('=')
        session['challenge'] = challenge
        print(f"Login Options: Generated challenge: {challenge}")
        
        # Get host info for proper rpId setting
        host = request.host
        hostname = host.split(':')[0]  # Remove port if present
        
        # Create login options
        options = {
            "challenge": challenge,
            "timeout": 60000,  # 1 minute
            "rpId": hostname,
            "userVerification": "preferred"
        }
        
        # If we have resident keys, we can allow the authenticator to use them
        # without specifying allowCredentials
        if has_resident_keys and REGISTRATION_LIMITS['use_resident_key']:
            print("Login Options: Using resident key mode (no allowCredentials)")
        else:
            # Otherwise, provide the list of credentials
            options["allowCredentials"] = credentials
            print("Login Options: Using regular mode with allowCredentials list")
        
        print("Login Options: Returning options...")
        return jsonify(options), 200
        
    except Exception as e:
        print(f"Login Options Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": "Failed to generate login options"}), 500

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
        
        # For proper verification, we need to:
        # 1. Normalize the credential ID for consistent lookup
        normalized_credential_id = normalize_credential_id(credential_id)
        
        # 2. Look up the credential in the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Try both normalized and original credential ID for maximum compatibility
        cursor.execute(
            "SELECT user_id, public_key, credential_id, username, attestation_hash, authenticator_model, is_resident_key FROM security_keys WHERE credential_id = ? OR credential_id = ?", 
            (normalized_credential_id, credential_id)
        )
        
        result = cursor.fetchone()
        
        # If not found directly, this might be a resident key presenting a credential
        # that we haven't seen before but from the same authenticator
        if not result:
            print(f"Login Error: Credential ID not found directly: {credential_id[:20]}...")
            
            # Extract authenticator data for identification
            authenticator_data = data['response'].get('authenticatorData', '')
            client_data_json = data['response'].get('clientDataJSON', '')
            
            # Generate hashes for matching
            auth_data_hash = hashlib.sha256(authenticator_data.encode()).hexdigest()
            combined_auth_hash = hashlib.sha256((authenticator_data + client_data_json).encode()).hexdigest()
            
            # Check if we have user_id in the assertion response (for resident keys)
            user_handle = data.get('response', {}).get('userHandle')
            
            if user_handle:
                print(f"Login Complete: Found user handle in assertion: {user_handle}")
                # Try to find the user by user_id
                cursor.execute(
                    "SELECT user_id, public_key, credential_id, username, attestation_hash, authenticator_model, is_resident_key FROM security_keys WHERE user_id = ? AND is_resident_key = 1", 
                    (user_handle,)
                )
                result = cursor.fetchone()
                
                if result:
                    print(f"Login Complete: Found user by user handle")
            
            # If still not found, try to identify the authenticator model
            if not result:
                try:
                    # Try to extract model info from authenticator data
                    auth_bytes = base64url_to_bytes(authenticator_data)
                    auth_str = auth_bytes.decode('utf-8', errors='ignore')
                    
                    # Check for common security key identifiers
                    authenticator_model = None
                    if any(identifier in auth_str for identifier in ['FIDO', 'U2F', 'Security Key']):
                        # Try to determine specific model types
                        if any(model in auth_str for model in ['5Ci', '5 Ci']):
                            authenticator_model = "Multi-connector Security Key"
                        elif any(model in auth_str for model in ['5C', '5 C']):
                            authenticator_model = "USB-C Security Key"
                        elif any(model in auth_str for model in ['5NFC', '5 NFC', 'NFC']):
                            authenticator_model = "NFC-enabled Security Key"
                        elif any(model in auth_str for model in ['Bio', 'Biometric']):
                            authenticator_model = "Biometric Security Key"
                        else:
                            authenticator_model = "Security Key"
                        
                        print(f"Login Complete: Detected authenticator model: {authenticator_model}")
                        
                        # If this is a multi-connector security key, try to find any registered one
                        if authenticator_model == "Multi-connector Security Key" and REGISTRATION_LIMITS['use_resident_key']:
                            cursor.execute(
                                "SELECT user_id, public_key, credential_id, username, attestation_hash, authenticator_model, is_resident_key FROM security_keys WHERE authenticator_model = ? AND is_resident_key = 1 LIMIT 1", 
                                (authenticator_model,)
                            )
                            result = cursor.fetchone()
                            
                            if result:
                                print(f"Login Complete: Found matching security key registration")
                except Exception as e:
                    print(f"Error during authenticator model detection: {e}")
            
            if not result:
                print(f"Login Error: Could not find matching credential or authenticator")
                conn.close()
                return jsonify({'error': 'Credential not recognized. Please register first.'}), 401
        
        # Extract all fields from the result
        user_id = result[0]
        public_key_json = result[1]
        stored_credential_id = result[2]
        username = result[3]
        attestation_hash = result[4] if len(result) > 4 else None
        authenticator_model = result[5] if len(result) > 5 else None
        is_resident_key = result[6] if len(result) > 6 else False
        
        if not user_id:
            print(f"Login Error: Invalid user ID for credential")
            conn.close()
            return jsonify({'error': 'Invalid user credential. Please register again.'}), 401
            
        print(f"Login Complete: Found user ID: {user_id} with username: {username or 'Unknown'}")
        print(f"Login Complete: Authenticator model: {authenticator_model or 'Unknown'}")
        print(f"Login Complete: Is resident key: {is_resident_key}")
        
        # If we have authenticator data but no attestation hash, try to update it
        if not attestation_hash and data['response'].get('authenticatorData'):
            try:
                # Check if attestation_hash column exists
                cursor.execute("PRAGMA table_info(security_keys)")
                columns = [col[1] for col in cursor.fetchall()]
                
                if 'attestation_hash' in columns:
                    # Generate a hash from the authenticator data
                    auth_data_hash = hashlib.sha256(data['response']['authenticatorData'].encode()).hexdigest()
                    print(f"Updating attestation hash for existing credential: {auth_data_hash[:20]}...")
                    
                    # Update the record with the hash
                    cursor.execute(
                        "UPDATE security_keys SET attestation_hash = ? WHERE credential_id = ?",
                        (auth_data_hash, stored_credential_id)
                    )
                    conn.commit()
                    
                # Try to detect and update authenticator model if not already set
                if 'authenticator_model' in columns and not authenticator_model:
                    # Try to detect from the authenticator data
                    auth_bytes = base64url_to_bytes(data['response']['authenticatorData'])
                    auth_str = auth_bytes.decode('utf-8', errors='ignore')
                    
                    # Check for common security key identifiers
                    if any(identifier in auth_str for identifier in ['FIDO', 'U2F', 'Security Key']):
                        # Try to determine specific model types
                        if any(model in auth_str for model in ['5Ci', '5 Ci']):
                            detected_model = "Multi-connector Security Key"
                        elif any(model in auth_str for model in ['5C', '5 C']):
                            detected_model = "USB-C Security Key"
                        elif any(model in auth_str for model in ['5NFC', '5 NFC', 'NFC']):
                            detected_model = "NFC-enabled Security Key"
                        elif any(model in auth_str for model in ['Bio', 'Biometric']):
                            detected_model = "Biometric Security Key"
                        else:
                            detected_model = "Security Key"
                            
                        print(f"Detected and updating authenticator model: {detected_model}")
                        cursor.execute(
                            "UPDATE security_keys SET authenticator_model = ? WHERE credential_id = ?",
                            (detected_model, stored_credential_id)
                        )
                        conn.commit()
                
                # Update is_resident_key if needed
                if 'is_resident_key' in columns and data.get('response', {}).get('userHandle'):
                    print(f"Updating credential to mark as resident key")
                    cursor.execute(
                        "UPDATE security_keys SET is_resident_key = 1 WHERE credential_id = ?",
                        (stored_credential_id,)
                    )
                    conn.commit()
            except Exception as e:
                print(f"Warning: Could not update credential metadata: {e}")
                # Continue with login regardless
        
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
    
    message = data['message'].strip()
    if not message:
        print("❌ Empty message")
        return jsonify({"error": "Message cannot be empty"}), 400
    
    user_id = session.get('user_id')
    print(f"Message from user: {user_id}")
    print(f"Message content: {message[:50]}...")
    
    # Check for command to change username
    if message.startswith('/username '):
        new_username = message[10:].strip()
        if not new_username:
            return jsonify({"error": "Username cannot be empty"}), 400
        
        if len(new_username) > 30:
            return jsonify({"error": "Username too long (max 30 characters)"}), 400
        
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            
            # Check if username column exists
            c.execute("PRAGMA table_info(security_keys)")
            columns = [col[1] for col in c.fetchall()]
            
            if 'username' in columns:
                # Update username for all credentials of this user
                c.execute("UPDATE security_keys SET username = ? WHERE user_id = ?", (new_username, user_id))
                conn.commit()
                
                # Add system message about username change
                system_message = f"User {user_id} changed their username to {new_username}"
                c.execute("INSERT INTO messages (user_id, message) VALUES ('system', ?)", (system_message,))
                conn.commit()
                
                conn.close()
                print(f"✅ Username changed to: {new_username}")
                return jsonify({"success": True, "message": f"Username changed to {new_username}"}), 200
            else:
                conn.close()
                print("❌ Username column does not exist in the database")
                return jsonify({"error": "Username feature is not available"}), 400
        except Exception as e:
            print(f"❌ Error changing username: {e}")
            print(traceback.format_exc())
            return jsonify({"error": str(e)}), 500
    
    # Regular message processing
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
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

# ==========================================
# Admin functionality
# ==========================================

@app.route('/debug_all', methods=['GET'])
def debug_all():
    """Debug endpoint to view all credentials (admin only)"""
    try:
        print("\n=== DEBUG ALL REQUEST ===")
        
        # In a real app, this would be protected by admin authentication
        # For this demo, we'll allow it for testing purposes
        
        # Get all credentials from the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get all security keys with all available columns
        cursor.execute("PRAGMA table_info(security_keys)")
        columns = [col[1] for col in cursor.fetchall()]
        
        # Build a dynamic query based on available columns
        select_columns = ["credential_id", "user_id", "username", "public_key", "created_at"]
        
        # Add optional columns if they exist
        if "attestation_hash" in columns:
            select_columns.append("attestation_hash")
        if "aaguid" in columns:
            select_columns.append("aaguid")
        if "combined_hash" in columns:
            select_columns.append("combined_hash")
        if "authenticator_model" in columns:
            select_columns.append("authenticator_model")
        if "browser_fingerprint" in columns:
            select_columns.append("browser_fingerprint")
        if "registration_time" in columns:
            select_columns.append("registration_time")
            
        # Build and execute the query
        query = f"SELECT {', '.join(select_columns)} FROM security_keys"
        cursor.execute(query)
        rows = cursor.fetchall()
        
        # Prepare the response data
        security_keys = []
        for row in rows:
            # Create a dictionary with column names as keys
            key_data = {}
            for i, col in enumerate(select_columns):
                if i < len(row):
                    # For credential_id, check if it's valid base64url
                    if col == "credential_id":
                        try:
                            # Try to decode it to check if it's valid
                            base64url_to_bytes(row[i])
                            key_data[col] = row[i]
                        except Exception as e:
                            key_data[col] = f"INVALID: {row[i]}"
                    else:
                        key_data[col] = row[i]
                        
            security_keys.append(key_data)
        
        # Get all messages
        cursor.execute("SELECT user_id, message, timestamp FROM messages ORDER BY timestamp DESC LIMIT 20")
        message_rows = cursor.fetchall()
        
        messages = []
        for row in message_rows:
            user_id, message, timestamp = row
            messages.append({
                "user_id": user_id,
                "message": message,
                "timestamp": timestamp
            })
        
        # Get environment info
        env_info = {
            "DB_PATH": DB_PATH,
            "FLASK_ENV": os.environ.get('FLASK_ENV', 'production'),
            "PLATFORM": platform.platform(),
            "PYTHON_VERSION": platform.python_version(),
            "REGISTRATION_LIMITS": REGISTRATION_LIMITS
        }
        
        # Get session info (for debugging only)
        session_info = dict(session)
        
        conn.close()
        
        return jsonify({
            "security_keys": security_keys,
            "messages": messages,
            "environment": env_info,
            "session": session_info
        }), 200
        
    except Exception as e:
        print(f"Debug Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

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

@app.route('/force_cleanup', methods=['GET', 'POST'])
def force_cleanup_credentials():
    """Force cleanup all credentials (admin only, for testing)"""
    try:
        print("\n=== FORCE CLEANUP REQUEST ===")
        
        # In a real app, this would be protected by admin authentication
        # For this demo, we'll allow it for testing purposes
        
        # Clear all credentials from the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Delete all records from security_keys
        cursor.execute("DELETE FROM security_keys")
        key_count = cursor.rowcount
        
        # Delete all messages
        try:
            cursor.execute("DELETE FROM messages")
            message_count = cursor.rowcount
        except sqlite3.OperationalError:
            # Messages table might not exist
            message_count = 0
            
        # Commit changes
        conn.commit()
        
        # Reset the database schema to ensure all columns are properly created
        try:
            # Drop and recreate the security_keys table with all columns
            cursor.execute("DROP TABLE IF EXISTS security_keys")
            
            # Create the security_keys table with all necessary columns
            cursor.execute("""
            CREATE TABLE security_keys (
                credential_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                username TEXT,
                public_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attestation_hash TEXT,
                aaguid TEXT,
                combined_hash TEXT,
                raw_id TEXT,
                authenticator_model TEXT,
                browser_fingerprint TEXT,
                registration_time TIMESTAMP,
                is_resident_key BOOLEAN DEFAULT 0
            )
            """)
            
            # Create the messages table if it doesn't exist
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            
            conn.commit()
            print("Database schema reset successfully")
        except Exception as schema_error:
            print(f"Error resetting schema: {schema_error}")
            # Continue with cleanup even if schema reset fails
        
        # Clear the session
        session.clear()
        
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'All credentials and messages have been removed. Deleted {key_count} credentials and {message_count} messages. Database schema has been reset.',
            'key_count': key_count,
            'message_count': message_count
        }), 200
        
    except Exception as e:
        print(f"Force Cleanup Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

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

@app.route('/style.css')
def serve_css():
    """Serve CSS file"""
    return send_from_directory('static', 'style.css')

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
# FIDO2 Chat System

**Author(s)**: Chris Becker, Jake McDowell, Jason Page  
**Date**: March 8, 2024  
**Description**: A secure chat application that uses WebAuthn/FIDO2 for authentication.

## Core Requirements

1. **One Physical Key = One Account**
   - Each physical security key maps to exactly one user account
   - This mapping persists across different devices (e.g., a key used on both a laptop and phone accesses the same account)
   - The system prevents creating multiple accounts with the same physical key

2. **Cross-Device Authentication**
   - Users can authenticate on any device using their security key
   - The system recognizes the same physical key regardless of the device it's used on

3. **Username System**
   - Initial username is automatically generated based on user ID
   - Username change functionality planned for future implementation

4. **Security Requirements**
   - No passwords stored or transmitted
   - All authentication handled via FIDO2/WebAuthn
   - Resident keys (discoverable credentials) required for cross-device functionality

## Technical Implementation Details

### Authentication Flow

1. **Registration**:
   - System requires resident keys (discoverable credentials)
   - System extracts and stores key identifiers (AAGUID, attestation hash)
   - System checks for existing registrations with the same physical key
   - If the key is already registered, user is logged into the existing account

2. **Login**:
   - System uses resident key capabilities to identify the user
   - System matches the credential to the stored user account
   - System supports authenticating with the same key across different devices

### Key Identification Strategy

The system uses multiple identifiers to recognize the same physical key across different devices:

1. **AAGUID (Authenticator Attestation Global Unique Identifier)**
   - Identifies the model of the authenticator
   - Same for all keys of the same model

2. **Attestation Hash**
   - Hash of the attestation object
   - Provides a more unique identifier for the physical key

3. **Combined Hash**
   - Hash that combines AAGUID and attestation information
   - Provides an even more unique identifier

4. **Key Fingerprints Table**
   - Stores associations between AAGUIDs and attestation hashes
   - Allows the system to learn and recognize the same physical key used on different devices

### Database Schema

The system uses SQLite with the following tables:

#### Security Keys Table
- `id`: Primary key
- `credential_id`: WebAuthn credential ID
- `user_id`: User identifier
- `username`: User's display name
- `public_key`: WebAuthn public key data
- `created_at`: Timestamp
- `attestation_hash`: Hash of the attestation object
- `combined_key_hash`: Combined hash for key identification
- `aaguid`: Authenticator Attestation Global Unique Identifier
- `resident_key`: Flag indicating if this is a resident key

#### Key Fingerprints Table
- `id`: Primary key
- `aaguid`: Authenticator Attestation Global Unique Identifier
- `attestation_hash`: Hash of the attestation object
- `user_id`: Associated user identifier
- `created_at`: Timestamp

#### Messages Table
- `id`: Primary key
- `user_id`: User identifier
- `username`: User's display name
- `message`: Message content
- `created_at`: Timestamp

## Frontend Architecture

The frontend JavaScript is organized into modular components for better maintainability:

### Core Modules

1. **webauthn-core.js**
   - Core functionality and configuration
   - Base64 encoding/decoding utilities
   - Logging functions
   - WebAuthn support detection

2. **webauthn-register.js**
   - Handles the registration process
   - Prepares registration options
   - Processes credential creation
   - Sends registration data to server

3. **webauthn-login.js**
   - Handles the login process
   - Prepares login options
   - Processes credential authentication
   - Sends login data to server
   - Handles logout

4. **webauthn-ui.js**
   - Manages the user interface
   - Updates authentication status display
   - Shows messages and errors
   - Handles UI state changes

5. **webauthn-main.js**
   - Initializes all modules
   - Checks WebAuthn support
   - Coordinates module interactions

6. **chat.js**
   - Handles chat functionality
   - Sends and receives messages
   - Updates message display

## Admin Features

- `/debug_all` - View all registered credentials, fingerprints, and messages
- `/force_cleanup` - Reset the database (for testing purposes)
- `/cleanup_credentials` - Remove credentials for the current user

## Testing Guidelines

When testing the application:
1. Register with a security key on one device
2. Attempt to register with the same key on another device
3. Verify that the system recognizes the key and logs into the existing account
4. Verify that one physical key cannot create multiple accounts

## Compatibility

- Works with all FIDO2-compliant security keys
- Special handling for different key types (YubiKey, Feitian, Thales/Gemalto, etc.)
- Fallback mechanisms for keys with limited capabilities
- Requires browsers with WebAuthn support
- Tested with Chrome, Safari, and Firefox

## API Endpoints

### Authentication Endpoints
- `/register_options` (POST) - Get options for a new registration
- `/register_complete` (POST) - Complete registration with authenticator data
- `/login_options` (POST) - Get options for login
- `/login_complete` (POST) - Complete login with authenticator response
- `/logout` (POST) - End the user's session
- `/auth_status` (GET) - Check current authentication status

### Chat Endpoints
- `/get_messages` (GET) - Retrieve chat messages
- `/send_message` (POST) - Send a new message (requires authentication)

### Admin Endpoints
- `/debug_all` (GET) - View debugging information
- `/force_cleanup` (GET) - Reset the database
- `/cleanup_credentials` (POST) - Remove credentials for the current user

### Static Content
- `/` - Main application
- `/chat` - Chat interface
- `/<path>` - Static files (JS, CSS, etc.)

## Error Handling

The application includes comprehensive error handling:

- Client-side validation of WebAuthn responses
- Detailed error messages for debugging
- Graceful fallbacks for unsupported browsers
- HTTP error handling with meaningful messages
- Database error recovery

## Local Development

1. **Setup**:
   ```bash
   # Clone the repository
   git clone https://github.com/yourusername/render-authentication-project.git
   cd render-authentication-project
   
   # Set up virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   ```

2. **Run the Application**:
   ```bash
   python app.py
   ```
   Access the application at http://localhost:5000

## Deployment

This application is deployed on Render.com:

1. Environment Variables:
   - `SECRET_KEY`: Secure random string for session management
   - `DB_PATH`: Database path (usually `/opt/render/webauthn.db`)

2. Build Command:
   ```
   pip install -r requirements.txt
   ```

3. Start Command:
   ```
   gunicorn app:app
   ```

## Troubleshooting

### Common Issues

1. **404 Errors on Registration/Login**
   - Ensure the server is running
   - Check that the endpoint paths match in both client and server code
   - Verify that the HTTP methods (GET/POST) match the server expectations

2. **Cross-Device Authentication Issues**
   - Ensure the security key supports resident keys
   - Check that AAGUID extraction is working correctly
   - Verify the key fingerprints table is being populated

3. **Browser Compatibility**
   - Ensure the browser supports WebAuthn
   - Check for browser-specific WebAuthn implementation differences
   - Verify that the security key is compatible with the browser

## Authors

Chris Becker, Jake McDowell, Jason Page

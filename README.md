# FIDO2 Chat System

A secure chat application that uses WebAuthn/FIDO2 for authentication.

## Core Requirements

1. **One Physical Key = One Account**
   - Each physical security key must map to exactly one user account
   - This mapping must persist across different devices (e.g., a key used on both a laptop and phone should access the same account)
   - The system must prevent creating multiple accounts with the same physical key

2. **Cross-Device Authentication**
   - Users must be able to authenticate on any device using their security key
   - The system should recognize the same physical key regardless of the device it's used on

3. **Username Management**
   - Users can set and change their username via chat commands
   - Initial username is automatically generated based on user ID

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

### Database Schema

The system stores the following information for each security key:
- Credential ID
- User ID
- Username
- Public key data
- Attestation hash
- Combined hash
- AAGUID (Authenticator Attestation Global Unique Identifier)
- Resident key flag

## Development Notes

- The system is designed to work with all FIDO2-compliant security keys
- Special handling is implemented to ensure one physical key maps to one account
- The system uses resident keys (discoverable credentials) to enable cross-device functionality

## Admin Features

- `/debug_all` - View all registered credentials
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
- Requires browsers with WebAuthn support
- Tested with Chrome, Safari, and Firefox

## Features

- **Passwordless Authentication**: Users authenticate using FIDO2/WebAuthn compliant devices (security keys, TouchID, Windows Hello, etc.)
- **Secure Chat**: Only authenticated users can send messages
- **Username Customization**: Users can set and change their display names with /username

## Technology Stack

- **Backend**: Flask (Python)
- **Frontend**: JavaScript, HTML, CSS, Render 
- **Authentication**: FIDO2/WebAuthn
- **Database**: SQLite

## Authentication Flow

### Registration Process

1. **Registration Initiation**:
   - User clicks "Register" button
   - Browser makes request to `/register_options`
   - Server generates a random challenge and user ID
   - Server returns registration options

2. **Authenticator Interaction**:
   - Browser prompts user to interact with authenticator
   - Authenticator creates a public/private key pair
   - Public key and credential ID are sent to the server

3. **Registration Completion**:
   - Server receives credential data at `/register_complete`
   - Credential ID, public key, and initial username are stored in the database
   - User is now registered

### Login Process

1. **Login Initiation**:
   - User clicks "Login" button
   - Browser requests login options from `/login_options`
   - Server generates a challenge and provides a list of the user's registered credentials

2. **Authentication**:
   - Browser prompts user to interact with authenticator
   - Authenticator uses private key to sign the challenge
   - Signature and credential ID are sent to the server

3. **Login Completion**:
   - Server verifies the signature at `/login_complete` using the stored public key
   - On success, the server sets authenticated session
   - User is now logged in and can access the chat

## Chat Features

- View messages without authentication
- Send messages only when authenticated
- Change username with the command: `/username [new name]`
- System messages for events (username changes, etc.)

## API Endpoints

### Authentication Endpoints
- `/register_options` - Get options for a new registration
- `/register_complete` - Complete registration with authenticator data
- `/login_options` - Get options for login
- `/login_complete` - Complete login with authenticator response
- `/logout` - End the user's session
- `/auth_status` - Check current authentication status

### Chat Endpoints
- `/get_messages` - Retrieve chat messages
- `/send_message` - Send a new message (requires authentication)

### Admin Endpoints
- `/debug_all` - View debugging information about registered credentials
- `/cleanup_credentials` - Remove all registered credentials

### Static Content
- `/` or `/chat` - Main application
- Various static asset endpoints

## Security Features

- CSRF Protection with session cookies
- Rate limiting on endpoints
- Secure cookies for authentication
- Input validation
- Error handling with appropriate responses

## Local Development

1. **Setup**:
   ```bash
   # Clone the repository
   git clone [repository URL]
   cd [repository directory]
   
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

## Testing

The project includes a comprehensive test suite:

```bash
# Run tests
./run_tests.sh
```

The tests cover:
- Authentication flow
- Chat functionality
- Error handling
- Admin functionality

## Deployment

This application is ready to deploy on Render.com:

1. Create a new Web Service on Render
2. Link your GitHub repository
3. Use the following settings:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`
   - Environment Variables: 
     - `SECRET_KEY`: a secure random string
     - `DB_PATH`: database path (usually `/opt/render/webauthn.db`)


## Authors

Chris Becker, Jake McDowell, Jason Page

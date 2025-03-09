# FIDO2 Chat System

A secure chat application using WebAuthn/FIDO2 for authentication with both passkeys and physical security keys.

## Features

- **FIDO2/WebAuthn Authentication**
  - Multi-authenticator support:
    - Platform authenticators (Face ID, Touch ID, Windows Hello)
    - Cross-platform security keys (YubiKey, etc.)
    - QR code-based passkey transfer
  - One device = one account model:
    - Each Mac gets its own account
    - Each iPhone gets its own account
    - Each security key gets its own account
  - Seamless cross-device experience with QR codes
  - Resident key requirement for better user experience

- **Fun Username System**
  - Random username assignment
  - Easy username cycling with "🎲 New Random Username" button
  - Instant username updates in chat
  - "(You)" indicator for own messages

- **Real-Time Chat**
  - Public chat room visible to all visitors
  - Message sending restricted to authenticated users
  - Real-time message updates (5-second polling)
  - Clean and intuitive interface

## Technical Implementation

### Frontend Architecture
Single JavaScript module (`webauthn.js`) containing:
- Core WebAuthn functionality
- Chat interface management
- Username handling
- UI updates and event handling
- Built-in debugging capabilities

### Authentication Flow
1. **Registration**: Users register with either:
   - Platform authenticator (Face ID, Touch ID, Windows Hello)
   - Physical security key
   - QR code passkey transfer
2. **Login**: Users authenticate using their registered authenticator
3. **Session Management**: Secure session handling with server-side validation

### Database Schema
- `security_keys`: Stores credentials and usernames
- `messages`: Stores chat messages with user associations

## API Endpoints

### Authentication
- `POST /register_options` - Get registration options
- `POST /register_complete` - Complete registration
- `POST /login_options` - Get login options
- `POST /login_complete` - Complete login
- `GET /auth_status` - Check authentication status
- `POST /logout` - Log out user

### Chat & Username
- `GET /get_messages` - Retrieve chat messages
- `POST /send_message` - Send a new message
- `POST /cycle_username` - Get a new random username

## Local Development

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the server: `python app.py`
4. Access at `http://localhost:5000`

## Deployment

Currently deployed on Render.com at `render-authentication-project.onrender.com`

## Security Features

- **Flexible Authentication Options**
  - Platform authenticators (passkeys) for convenience
  - Physical security keys for enhanced security
  - QR code passkey transfer between devices
  - One authenticator = one account model

- **Secure Implementation**
  - Resident key requirement
  - Secure session management
  - Cross-device key recognition
  - Rate limiting on endpoints

## Troubleshooting

### Common Issues
- **Device Recognition**: Each device gets its own unique account - this is by design!
- **QR Code Transfer**: Use the browser's built-in QR code feature to transfer passkeys between devices
- **Username Updates**: Refresh the page if username changes don't appear
- **Message Display**: Messages auto-refresh every 5 seconds
- **Multiple Accounts**: It's normal to have different accounts on different devices - that's how the system is designed

## Authors
- Chris Becker
- Jake McDowell
- Jason Page

## Last Updated
March 8, 2024

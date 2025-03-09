# FIDO2 Chat System

A secure chat application using WebAuthn/FIDO2 for authentication with physical security keys.

## Features

- **FIDO2/WebAuthn Authentication**
  - Cross-platform security key support (YubiKey, etc.)
  - One physical key = one account policy
  - Resident key requirement for better user experience
  - Cross-device authentication support
  - Platform authenticators (Face ID, Touch ID, Windows Hello) not supported

- **Fun Username System**
  - Random username assignment from a curated list of characters
  - Easy username cycling with "🎲 New Random Username" button
  - 40+ preset usernames from popular franchises
  - Instant username updates in chat

- **Real-Time Chat**
  - Public chat room visible to all visitors
  - Message sending restricted to authenticated users
  - Real-time message updates (5-second polling)
  - Username display with "(You)" indicator for own messages

## Technical Implementation

### Authentication Flow
1. **Registration**: Users register with a physical security key
2. **Login**: Users can authenticate using their registered key
3. **Cross-Device**: Same key works across different devices
4. **Key Recognition**: System identifies unique physical keys using AAGUID and attestation data

### Database Schema
- `security_keys`: Stores credentials, usernames, and key identifiers
- `messages`: Stores chat messages with user associations
- `key_fingerprints`: Tracks key identifiers for cross-device recognition

### Frontend Architecture
- Modular JavaScript with separate components for:
  - Core WebAuthn functionality (`webauthn-core.js`)
  - Chat interface
  - Username management
  - Real-time updates

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

- Physical security keys only (no platform authenticators)
  - Enforces use of external authenticators like YubiKeys
  - Prevents use of Face ID, Touch ID, Windows Hello
  - Ensures true cross-device authentication
- Resident key requirement for better security
- One physical key = one account enforcement
- Cross-device key recognition
- Secure session management
- Rate limiting on message endpoints

## Troubleshooting

### Common Issues
- 404 errors: Check if you're using the correct endpoint URLs
- Cross-device authentication: Ensure using the same physical key
- Username not updating: Try refreshing the page
- Platform authenticator error: The system requires a physical security key (like YubiKey) and does not support built-in authenticators like Face ID or Touch ID

## Authors
- Chris Becker
- Jake McDowell
- Jason Page

## Last Updated
March 8, 2024

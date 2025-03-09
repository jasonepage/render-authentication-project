# FIDO2 Chat System

A secure real-time chat application using FIDO2 WebAuthn authentication with physical security keys.

## Features

- **Physical Security Key Authentication**: Secure login using FIDO2-compatible security keys 
- **Fun Username System**: Random character names assigned to users with easy cycling
- **Real-Time Chat**: Public chat room visible to all visitors, with message sending restricted to authenticated users
- **Image Sharing**: Support for sharing images in chat using special commands

### Image Sharing

Share images in the chat using any of these methods:
1. `@` prefix: `@https://example.com/image.gif`
2. `/image` command: `/image https://example.com/image.png`

Supported image formats:
- GIF (.gif)
- PNG (.png)
- JPEG (.jpg, .jpeg)

Images are validated before sending and displayed inline in the chat.

## Technical Implementation

### Authentication Flow
1. User registers/logs in with a physical security key
2. Server validates the security key and creates a session
3. User can then send messages and images in the chat

### Database Schema
- `security_keys`: Stores registered security keys and user information
- `messages`: Stores chat messages including text and image URLs

### API Endpoints

Authentication:
- `/register_options`: Get registration options for new security key
- `/register_complete`: Complete security key registration
- `/login_options`: Get login options for existing security key
- `/login_complete`: Complete security key login
- `/auth_status`: Check current authentication status
- `/logout`: End current session

Chat:
- `/send_message`: Send a message (text or image)
- `/get_messages`: Retrieve chat messages
- `/cycle_username`: Get a new random username

## Local Development

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the application: `python app.py`
4. Visit `http://localhost:5000`

## Deployment

Currently deployed on Render.com with automatic deployments from the main branch.

## Security Features

- Session-based authentication
- Image URL validation and sanitization
- XSS prevention through content escaping
- CSRF protection via secure session handling

## Troubleshooting

Common issues:
- Image not displaying: Verify the URL ends with .gif, .png, .jpg, or .jpeg
- Image fails to send: Check if the URL is accessible and the format is supported

## Authors
- Chris Becker
- Jake McDowell
- Jason Page

Last updated: March 9, 2024

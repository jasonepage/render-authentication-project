# Protest Chat 🔐

A secure, privacy-focused chat application designed for activists and protesters. Uses physical security keys (FIDO2/WebAuthn) for authentication and supports up to 25 registered users.

## Features

- 🔑 **Physical Security Keys Only** - YubiKey, Titan, etc. (no phone/tablet authenticators)
- 💬 **Dual Chat Channels** - Public (visible to all) and Private (authenticated only)
- 🌙 **Dark Mode UI** - Twitter-inspired interface for readability
- 🔒 **Maximum Security** - WebAuthn authentication, HTTPS-only sessions
- 👥 **Limited Capacity** - Capped at 25 users for small, trusted groups
- 🚀 **Easy Deployment** - Works on Render, Heroku, or self-hosted

## Quick Start

### Prerequisites
- Python 3.8+
- Physical security key (YubiKey, Titan, etc.)
- Modern browser with WebAuthn support

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/render-authentication-project.git
   cd render-authentication-project
   ```

2. **Run configuration helper**
   ```bash
   python configure.py
   ```
   This will guide you through setting up your deployment.

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Test locally**
   ```bash
   export DEPLOYMENT_URL="http://localhost:5000"
   python app.py
   ```
   Visit `http://localhost:5000` and test with your security key.

### Deployment

#### Quick Deploy to Render.com
1. Fork this repository
2. Create new Web Service on Render
3. Set environment variables:
   - `SECRET_KEY`: Your secure secret key (from configure.py)
   - `DEPLOYMENT_URL`: Your Render URL
   - `DB_PATH`: `/opt/render/webauthn.db`
4. Deploy!

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for detailed instructions.

## Configuration

### Essential Settings

All configuration is done via environment variables or by editing these files:

**Backend (app.py)**
- Uses environment variables for deployment (no code changes needed!)
- `DEPLOYMENT_URL`: Your domain
- `SECRET_KEY`: Session encryption key
- `DB_PATH`: Database file location

**Frontend (JavaScript)**
- `static/publicchat.js` - Update `SERVER_URL` to your domain
- `static/privatechat.js` - Update `SERVER_URL` to your domain
- `static/webauthn.js` - Auto-detects domain (usually no changes needed)

### Customization

**Change max users:**
```python
# Set environment variable
MAX_USERS=50  # Default is 25
```

**Change colors:**
Edit CSS variables in `static/style.css`:
```css
:root {
    --accent-blue: #1da1f2;  /* Change primary color */
    --bg-primary: #15202b;   /* Change background */
    /* ... more variables ... */
}
```

**Change branding:**
- Edit page titles in `templates/index.html` and `templates/info.html`

## Architecture

### File Structure
```
protest-chat/
├── app.py                  # Flask backend (main application)
├── configure.py            # Configuration helper script
├── requirements.txt        # Python dependencies
├── DEPLOYMENT_GUIDE.md     # Detailed deployment instructions
├── static/
│   ├── webauthn.js        # WebAuthn authentication handler
│   ├── publicchat.js      # Public chat interface
│   ├── privatechat.js     # Private chat interface
│   └── style.css          # Dark mode UI styling
└── templates/
    ├── index.html         # Main chat page
    └── info.html          # Information/help page
```

### Technology Stack
- **Backend**: Python 3.8+, Flask
- **Authentication**: WebAuthn/FIDO2 (physical security keys)
- **Database**: SQLite (local file)
- **Frontend**: Vanilla JavaScript, CSS
- **Hosting**: Render.com (or Heroku, self-hosted)

### Security Features
- Physical security key requirement (cross-platform attachment)
- HTTPS-only session cookies
- CSRF protection (SameSite=Strict)
- Rate limiting on API endpoints
- No password storage (passwordless authentication)
- Secure session management

## Usage

### For Users

1. **First Visit** - Register your security key
   - Click "Register Key"
   - Insert your physical security key when prompted
   - Touch the key to confirm

2. **Public Chat** - Available to everyone
   - View messages without logging in
   - Must authenticate to send messages

3. **Private Chat** - Authenticated users only
   - Only visible after logging in with security key
   - Secure channel for sensitive coordination

4. **Returning** - Login with your key
   - Click "Login"
   - Insert the same security key
   - Touch to authenticate

### For Administrators

The system is designed to be self-managing:
- First 25 people to register get access
- After that, registration closes automatically
- No admin panel needed (simplified from earlier versions)

To reset the system:
```bash
# Connect to database
sqlite3 /path/to/webauthn.db

# Check current users
SELECT COUNT(*) FROM security_keys;

# Remove all users (use with caution!)
DELETE FROM security_keys;
DELETE FROM messages;
DELETE FROM private_messages;
```

## Development

### Code Structure

The codebase is organized into modular components:

**Backend Modules (app.py)**
- Configuration section (environment variables)
- Database functions (init_db, get_db_connection)
- WebAuthn endpoints (register, login, logout)
- Chat endpoints (public/private messages)
- Utility functions (rate limiting, helpers)

**Frontend Modules**
- `webauthn.js` - Authentication logic
- `publicchat.js` - Public chat handler
- `privatechat.js` - Private chat handler
- `style.css` - UI styling

### Adding Features

All files are heavily commented for easy modification.

### Contributing

1. Fork the repository
2. Create a feature branch
3. Add comments to your code
4. Test with a physical security key
5. Submit a pull request

## Troubleshooting

### Common Issues

**"Registration closed" error**
- Check current user count in database
- Increase `MAX_USERS` environment variable if needed

**Security key not detected**
- Ensure HTTPS is enabled (required for WebAuthn)
- Try a different browser (Chrome, Firefox, Edge recommended)
- Check USB connection

**"Origin mismatch" error**
- Update `DEPLOYMENT_URL` environment variable to match your actual domain
- Update `SERVER_URL` in publicchat.js and privatechat.js

**Messages not loading**
- Check browser console for errors
- Verify database path is writable
- Check server logs for backend errors

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for more troubleshooting tips.

## License

Free to use, modify, and deploy for activist and protest coordination.

## Credits

**Authors**: Chris Becker, Jake McDowell, Jason Page  
**Date**: March 8, 2024 - February 12, 2026  
**Purpose**: Secure communication for activists and protesters

## Support

For questions or issues:
1. Check [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
2. Review browser console / server logs
3. Verify configuration matches deployment
4. Test with a different security key

---

**Stay safe, stay secure, stay connected.** ✊

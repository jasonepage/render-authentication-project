# Protest Chat - Deployment Guide

## Overview
Protest Chat is a secure communication platform designed for activists and protesters. It uses physical security keys (like YubiKey) for authentication and supports up to 25 registered users with public and private chat channels.

## Prerequisites
- Python 3.8 or higher
- Physical security key (YubiKey, Titan, etc.)
- A hosting platform (Render, Heroku, AWS, etc.)
- Modern web browser with WebAuthn support

## Quick Start

### 1. Configuration
Edit `app.py` and update these critical values:

```python
# Line 31: Set your domain URL
DEPLOYMENT_URL = "https://your-domain.com"  # Change this!

# Line 33: Set a secure secret key
# Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY = 'your-secret-key-here'  # Change this!

# Line 51: Database path (depends on your hosting platform)
DB_PATH = '/opt/render/webauthn.db'  # Update for your environment
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Locally (Testing)
```bash
# Set environment variable for local testing
export DEPLOYMENT_URL="http://localhost:5000"

# Run the app
python app.py
```

Visit `http://localhost:5000` to test.

### 4. Deploy to Production

#### Option A: Render.com (Recommended)
1. Push code to GitHub repository
2. Create new Web Service on Render
3. Set environment variables:
   - `SECRET_KEY`: Your generated secret key
   - `DB_PATH`: `/opt/render/webauthn.db`
4. Deploy!

#### Option B: Heroku
1. Create new Heroku app: `heroku create your-app-name`
2. Set config vars:
   ```bash
   heroku config:set SECRET_KEY="your-secret-key"
   heroku config:set DB_PATH="/app/webauthn.db"
   ```
3. Deploy: `git push heroku main`

#### Option C: Self-Hosted
1. Set up a Linux server with Python
2. Install dependencies: `pip install -r requirements.txt`
3. Configure environment variables
4. Use a production WSGI server:
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```
5. Set up nginx as reverse proxy with SSL certificate

## Configuration Reference

### Core Settings (app.py)

| Variable | Location | Description | Example |
|----------|----------|-------------|---------|
| `DEPLOYMENT_URL` | Line 31 | Your website URL | `https://protest-chat.com` |
| `SECRET_KEY` | Line 33 | Flask session encryption key | Generate with Python secrets |
| `MAX_USERS` | Line 36 | Maximum registered users | `25` (default) |
| `DB_PATH` | Line 51 | SQLite database file path | `/opt/render/webauthn.db` |
| `RP_NAME` | Line 39 | Name shown during auth | `"Protest Chat"` |

### Database Structure

The app creates these tables automatically:

1. **security_keys**: Stores registered security keys
   - credential_id, user_id, public_key, aaguid, created_at, username, etc.

2. **messages**: Public chat (visible to all)
   - user_id, message, timestamp

3. **private_messages**: Private chat (authenticated only)
   - user_id, message, timestamp

### Frontend Configuration (static/webauthn.js)

Update the endpoint base URL if deploying to a custom domain:

```javascript
// Line 9-15: Update for your deployment
getEndpointPath: function(endpoint) {
    // For custom domains, you may need to adjust this
    const basePath = window.location.origin;
    return `${basePath}/${endpoint}`;
}
```

## Security Considerations

### Physical Keys Only
The app is configured to ONLY accept physical security keys (no phones/tablets):
```python
# In app.py - register_options endpoint
"authenticatorSelection": {
    "authenticatorAttachment": "cross-platform",  # Physical keys only
    "requireResidentKey": True,
    "userVerification": "discouraged"
}
```

### 25 User Limit
Registration is capped at 25 users to keep the system small and manageable:
```python
# In app.py - can_register() function
def can_register():
    total_users = get_total_users()
    if total_users < 25:  # Adjust MAX_USERS constant to change this
        return True, None
    return False, "Registration closed - Maximum 25 users reached"
```

To change the limit, update the `MAX_USERS` constant in app.py.

### Session Security
Sessions are configured with secure defaults:
```python
app.config['SESSION_COOKIE_SECURE'] = True     # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True   # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # CSRF protection
```

## Customization

### Change Max Users
Edit `MAX_USERS` in app.py (line 36):
```python
MAX_USERS = 50  # Change from 25 to 50
```

### Change Branding
1. Update `RP_NAME` in app.py (line 39)
2. Update page titles in `templates/index.html` and `templates/info.html`
3. Customize colors in `static/style.css` (CSS variables at top)

### Add Features
The modular structure makes it easy to extend:
- **New endpoints**: Add to app.py (see existing patterns)
- **New UI features**: Add to templates/index.html
- **New chat handlers**: Follow pattern in static/publicchat.js and static/privatechat.js

## Troubleshooting

### "Origin mismatch" errors
Update `DEPLOYMENT_URL` in app.py to match your actual domain.

### Security key not detected
- Ensure HTTPS is enabled (required for WebAuthn)
- Check browser WebAuthn support (Chrome, Firefox, Edge, Safari 14+)
- Try a different USB port or security key

### Database errors
- Check `DB_PATH` is correct for your environment
- Ensure the directory has write permissions
- For Render: Use `/opt/render/webauthn.db`
- For Heroku: Use `/app/webauthn.db`

### Registration closed unexpectedly
Check current user count:
```bash
# Connect to your database
sqlite3 /path/to/webauthn.db "SELECT COUNT(*) FROM security_keys"
```

## File Structure
```
protest-chat/
├── app.py                  # Main Flask application (CONFIGURE THIS)
├── requirements.txt        # Python dependencies
├── Procfile               # Render/Heroku deployment config
├── render.yaml            # Render deployment config
├── static/
│   ├── webauthn.js        # WebAuthn authentication handler
│   ├── publicchat.js      # Public chat interface
│   ├── privatechat.js     # Private chat interface
│   └── style.css          # Dark mode UI styling
└── templates/
    ├── index.html         # Main chat page
    └── info.html          # Information/help page
```

## Support

For issues or questions:
1. Check the browser console for error messages
2. Review server logs for backend errors
3. Verify configuration values match your deployment
4. Test with a different security key

## License
This is free software. Use, modify, and deploy as needed for your protest/activist work.

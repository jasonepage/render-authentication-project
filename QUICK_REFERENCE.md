# Quick Reference Guide - Protest Chat

## For Deployers: Configuration Checklist

### Step 1: Backend Configuration (Environment Variables)
Set these on your hosting platform:

```bash
DEPLOYMENT_URL=https://your-domain.com
SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
DB_PATH=/opt/render/webauthn.db  # or appropriate path for your host
MAX_USERS=25  # optional, defaults to 25
```

### Step 2: Frontend Configuration (JavaScript Files)
Update these two files:

**static/publicchat.js** - Line 15:
```javascript
SERVER_URL: 'https://your-domain.com',  // Change this!
```

**static/privatechat.js** - Line 15:
```javascript
SERVER_URL: 'https://your-domain.com',  // Change this!
```

### Step 3: Deploy!
No other changes needed. The code is modular and ready to go.

---

## File Purpose Quick Reference

### Backend
- **app.py** - Main Flask application with all endpoints
  - WebAuthn registration/login (lines 200-600)
  - Chat endpoints (lines 600-800)
  - Database functions (lines 80-150)
  - Configuration via environment variables

### Frontend JavaScript
- **webauthn.js** - Security key authentication
  - Auto-detects domain
  - Handles registration and login
  - Dispatches auth events
  
- **publicchat.js** - Public chat interface
  - **REQUIRES**: Update SERVER_URL (line 15)
  - All users can view
  - Authenticated users can send
  
- **privatechat.js** - Private chat interface
  - **REQUIRES**: Update SERVER_URL (line 15)
  - Authenticated users only
  - Auto-hides when not logged in

### Frontend CSS
- **style.css** - Dark mode UI styling
  - Customize colors: Edit :root variables (lines 30-60)
  - Twitter-inspired design
  - Responsive layout

### HTML Templates
- **index.html** - Main chat page
  - Dual chat layout (public + private)
  - Auth controls
  
- **info.html** - Help/information page
  - User instructions
  - Security key info

### Documentation
- **README.md** - Main documentation
- **DEPLOYMENT_GUIDE.md** - Detailed deployment instructions
- **configure.py** - Interactive configuration helper

---

## Common Customizations

### Change User Limit
```bash
# Environment variable
MAX_USERS=50
```

### Change Colors
Edit `static/style.css`:
```css
:root {
    --accent-blue: #1da1f2;    /* Buttons, links */
    --bg-primary: #15202b;     /* Background */
    --text-primary: #ffffff;   /* Text color */
}
```

### Change Polling Interval
Edit `static/publicchat.js` and `static/privatechat.js`:
```javascript
POLLING_INTERVAL: 5000,  // 5 seconds instead of 3
```

### Change Branding
- Edit page titles in `templates/index.html` (line 5)
- Edit page titles in `templates/info.html` (line 5)

---

## Deployment Platform Specific Settings

### Render.com
```bash
DEPLOYMENT_URL=https://your-app.onrender.com
DB_PATH=/opt/render/webauthn.db
```

### Heroku
```bash
DEPLOYMENT_URL=https://your-app.herokuapp.com
DB_PATH=/app/webauthn.db
```

### Self-Hosted Linux
```bash
DEPLOYMENT_URL=https://yourdomain.com
DB_PATH=/var/lib/protestchat/webauthn.db
```

### Local Development
```bash
DEPLOYMENT_URL=http://localhost:5000
DB_PATH=./webauthn.db
```

---

## Database Tables

### security_keys
Stores registered security keys
- credential_id (unique key identifier)
- user_id (user identifier)
- public_key (cryptographic public key)
- username (display name)
- created_at (registration time)

### messages
Public chat messages
- user_id (who sent it)
- message (text content)
- timestamp (when sent)

### private_messages
Private chat messages (same structure as messages)
- user_id
- message
- timestamp

---

## Security Checklist

✅ Physical security keys only (no phone/tablet auth)  
✅ HTTPS required for WebAuthn  
✅ Session cookies: Secure, HttpOnly, SameSite=Strict  
✅ Rate limiting on all endpoints  
✅ No password storage  
✅ User limit enforced (25 default)  
✅ Input validation on all user data  
✅ CSRF protection via session tokens  

---

## Support Resources

1. **README.md** - Overview and quick start
2. **DEPLOYMENT_GUIDE.md** - Detailed deployment instructions
3. **configure.py** - Interactive configuration helper
4. Browser console - Frontend errors
5. Server logs - Backend errors

---

## Emergency Reset

If you need to reset the system:

```bash
# Backup first!
cp /path/to/webauthn.db /path/to/webauthn.db.backup

# Connect to database
sqlite3 /path/to/webauthn.db

# Check current state
SELECT COUNT(*) FROM security_keys;
SELECT COUNT(*) FROM messages;
SELECT COUNT(*) FROM private_messages;

# Reset everything (CAREFUL!)
DELETE FROM security_keys;
DELETE FROM messages;
DELETE FROM private_messages;

# Exit
.exit
```

---

## Quick Test Checklist

After deployment:

1. ✅ Visit your URL - page loads
2. ✅ Click "Register Key" - browser prompts for security key
3. ✅ Touch security key - registration succeeds
4. ✅ Public chat visible - can send messages
5. ✅ Private chat visible - can send messages
6. ✅ Logout works - private chat hides
7. ✅ Login works - can authenticate again
8. ✅ 25th user can register
9. ✅ 26th user sees "Registration closed"

---

**Last Updated**: February 12, 2026  
**Version**: 2.0 (Modular, commented, deployment-ready)

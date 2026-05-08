# Auth Chat

A passwordless real-time chat application built on FIDO2 / WebAuthn. Authentication is hardware-bound: only physical security keys (YubiKey, Titan, etc.) are accepted — no platform or phone authenticators. Backed by Flask, SQLite, and a small zero-dependency frontend.

## Features

- **Hardware-bound authentication** — FIDO2 / WebAuthn with cross-platform attachment only
- **Public + private channels** — open read-only feed, gated send, and a private channel for verified members
- **Live location map** — opt-in real-time location sharing for authenticated users (Leaflet)
- **Anonymous identities** — generated handles, no PII collected
- **Per-endpoint rate limiting** and hardened session cookies (`Secure`, `HttpOnly`, `SameSite=Strict`)
- **Single-binary deploy** — Flask + SQLite, no external services required

## Tech Stack

- **Backend:** Python 3.8+, Flask, SQLite
- **Auth:** WebAuthn / FIDO2 (cross-platform attachment)
- **Frontend:** Vanilla JavaScript, CSS (no build step)
- **Map:** Leaflet
- **Deploy:** Render.com / Heroku / self-hosted (Procfile + render.yaml included)

## Quick Start

### Prerequisites
- Python 3.8+
- A physical security key (YubiKey, Titan, etc.)
- A WebAuthn-capable browser (Chrome, Firefox, Edge, Safari 14+)

### Local development

```bash
git clone https://github.com/yourusername/render-authentication-project.git
cd render-authentication-project
pip install -r requirements.txt

export DEPLOYMENT_URL="http://localhost:5000"
python app.py
```

Then open `http://localhost:5000`.

### Configuration helper

```bash
python configure.py
```

Walks through generating a secret key and producing a `.env` for your target host.

## Deploy to Render

1. Push to GitHub and create a new Web Service on Render.
2. Set environment variables:
   - `SECRET_KEY` — generate with `python -c "import secrets; print(secrets.token_hex(32))"`
   - `DEPLOYMENT_URL` — your Render URL
   - `DB_PATH` — `/opt/render/webauthn.db`
3. Deploy.

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for Heroku and self-hosted instructions.

## Configuration

All configuration is environment-variable driven:

| Variable | Default | Description |
|----------|---------|-------------|
| `DEPLOYMENT_URL` | — | Public URL of the deployment (required for WebAuthn origin check) |
| `SECRET_KEY` | — | Flask session encryption key |
| `DB_PATH` | `./webauthn.db` | SQLite database path |
| `MAX_USERS` | `25` | Maximum registered users |

### Theming

CSS variables live at the top of `static/style.css`:

```css
:root {
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --accent: #10b981;
    --accent-hover: #34d399;
    --text-primary: #f1f5f9;
    /* ... */
}
```

## Architecture

```
.
├── app.py                 # Flask entrypoint, blueprint registration
├── routes/
│   ├── auth.py            # WebAuthn register / login / logout
│   ├── chat.py            # Public + private message endpoints
│   ├── map.py             # Location sharing endpoints
│   ├── admin.py           # Registration toggle, debug
│   └── pages.py           # Template routes
├── webauthn_utils.py      # FIDO2 challenge / verification helpers
├── db_utils.py            # SQLite schema + connection
├── static/
│   ├── webauthn.js        # WebAuthn client
│   ├── publicchat.js      # Public chat polling + render
│   ├── privatechat.js     # Private chat polling + render
│   ├── map.js             # Leaflet integration
│   └── style.css          # Slate + emerald theme
└── templates/
    ├── index.html         # Chat
    ├── map.html           # Live map
    ├── admin.html         # Admin controls
    └── info.html          # About / docs
```

### Database

Three tables, created on first run:

- `security_keys` — credential ID, user ID, public key, AAGUID, handle
- `messages` — public chat
- `private_messages` — gated chat

### Security

- WebAuthn cross-platform attachment only (rejects platform/phone authenticators)
- HTTPS-only session cookies, `SameSite=Strict`
- Per-endpoint rate limiting
- No password storage — credentials are public-key only
- Output sanitization on user-supplied content (incl. image URLs)

## Usage

### First user
1. Visit the deployment.
2. Click **Register New Key**, insert your security key, touch to confirm.
3. The first registered user becomes the admin.

### Returning users
1. Click **Login with Security Key**.
2. Insert the same key and touch to authenticate.

### Reset

```bash
sqlite3 /path/to/webauthn.db
sqlite> DELETE FROM security_keys;
sqlite> DELETE FROM messages;
sqlite> DELETE FROM private_messages;
```

## Troubleshooting

- **"Registration closed"** — increase `MAX_USERS` or remove unused entries from `security_keys`.
- **Security key not detected** — WebAuthn requires HTTPS and a supported browser.
- **"Origin mismatch"** — make sure `DEPLOYMENT_URL` matches the actual served origin.
- **Messages not loading** — check the browser console and server logs; verify the DB path is writable.

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for more.

## License

Free to use, modify, and deploy.

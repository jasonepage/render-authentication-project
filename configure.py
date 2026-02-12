#!/usr/bin/env python3
"""
Protest Chat Configuration Helper
Helps you set up the necessary configuration for deploying Protest Chat
"""

import secrets
import sys
import os

def generate_secret_key():
    """Generate a secure random secret key"""
    return secrets.token_hex(32)

def main():
    print("=" * 70)
    print("  PROTEST CHAT - Configuration Setup")
    print("=" * 70)
    print()
    
    # Get deployment URL
    print("Step 1: Deployment URL")
    print("-" * 70)
    print("Enter your deployment URL (e.g., https://yourdomain.com)")
    print("For local testing, use: http://localhost:5000")
    deployment_url = input("URL: ").strip()
    
    if not deployment_url:
        print("ERROR: Deployment URL is required!")
        sys.exit(1)
    
    print()
    
    # Generate secret key
    print("Step 2: Secret Key")
    print("-" * 70)
    print("Generating a secure secret key...")
    secret_key = generate_secret_key()
    print(f"Generated: {secret_key}")
    print()
    
    # Database path
    print("Step 3: Database Path")
    print("-" * 70)
    print("Choose your hosting platform:")
    print("  1. Render.com")
    print("  2. Heroku")
    print("  3. Self-hosted Linux")
    print("  4. Local development")
    platform = input("Choice (1-4): ").strip()
    
    db_paths = {
        '1': '/opt/render/webauthn.db',
        '2': '/app/webauthn.db',
        '3': '/var/lib/protestchat/webauthn.db',
        '4': './webauthn.db'
    }
    
    db_path = db_paths.get(platform, './webauthn.db')
    print(f"Database path: {db_path}")
    print()
    
    # Max users
    print("Step 4: Maximum Users")
    print("-" * 70)
    print("Enter maximum number of users (default: 25)")
    max_users_input = input("Max users: ").strip()
    max_users = max_users_input if max_users_input else '25'
    print()
    
    # Summary
    print("=" * 70)
    print("  CONFIGURATION SUMMARY")
    print("=" * 70)
    print(f"Deployment URL:  {deployment_url}")
    print(f"Secret Key:      {secret_key[:16]}... (generated)")
    print(f"Database Path:   {db_path}")
    print(f"Max Users:       {max_users}")
    print()
    
    # Instructions
    print("=" * 70)
    print("  NEXT STEPS")
    print("=" * 70)
    print()
    print("1. UPDATE app.py:")
    print(f"   - No changes needed! Configuration is now in environment variables.")
    print()
    print("2. UPDATE static/publicchat.js:")
    print(f"   - Change SERVER_URL to: '{deployment_url}'")
    print()
    print("3. UPDATE static/privatechat.js:")
    print(f"   - Change SERVER_URL to: '{deployment_url}'")
    print()
    print("4. SET ENVIRONMENT VARIABLES:")
    print()
    print("   For Render.com / Heroku (Web UI):")
    print(f"     DEPLOYMENT_URL = {deployment_url}")
    print(f"     SECRET_KEY = {secret_key}")
    print(f"     DB_PATH = {db_path}")
    print()
    print("   For command line:")
    print(f"     export DEPLOYMENT_URL='{deployment_url}'")
    print(f"     export SECRET_KEY='{secret_key}'")
    print(f"     export DB_PATH='{db_path}'")
    print()
    print("5. DEPLOY:")
    print("   - Push to your Git repository")
    print("   - Deploy on your chosen platform")
    print("   - Test with a security key!")
    print()
    
    # Save to file
    save = input("Save configuration to .env file? (y/n): ").strip().lower()
    if save == 'y':
        with open('.env', 'w') as f:
            f.write(f"# Protest Chat Configuration\n")
            f.write(f"# Generated on {__import__('datetime').datetime.now().isoformat()}\n\n")
            f.write(f"DEPLOYMENT_URL={deployment_url}\n")
            f.write(f"SECRET_KEY={secret_key}\n")
            f.write(f"DB_PATH={db_path}\n")
            f.write(f"MAX_USERS={max_users}\n")
        
        print()
        print("✓ Configuration saved to .env file")
        print()
        print("SECURITY WARNING: Keep .env file secret! Add it to .gitignore!")
        print()
        
        # Create/update .gitignore
        gitignore_content = ".env\n*.db\n__pycache__/\n*.pyc\n"
        if os.path.exists('.gitignore'):
            with open('.gitignore', 'r') as f:
                existing = f.read()
            if '.env' not in existing:
                with open('.gitignore', 'a') as f:
                    f.write('\n# Environment variables\n.env\n')
                print("✓ Added .env to .gitignore")
        else:
            with open('.gitignore', 'w') as f:
                f.write(gitignore_content)
            print("✓ Created .gitignore with .env excluded")
    
    print()
    print("=" * 70)
    print("  Configuration complete! Read DEPLOYMENT_GUIDE.md for more details.")
    print("=" * 70)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nConfiguration cancelled.")
        sys.exit(0)

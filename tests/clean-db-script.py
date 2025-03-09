#!/usr/bin/env python3
"""
Database Cleanup and Inspection Tool for FIDO2 Chat System
Use this to inspect or reset the database during testing.
"""

import sqlite3
import os
import json
import argparse
import base64
import sys

# Default DB path matches the one in app.py
DEFAULT_DB_PATH = '/opt/render/webauthn.db'

def encode_base64url(data):
    """Encode bytes as URL-safe base64 without padding"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def decode_base64url(text):
    """Decode URL-safe base64 to bytes"""
    padding = b'=' * (4 - (len(text) % 4))
    return base64.urlsafe_b64decode(text.encode('ascii') + padding)

def inspect_db(db_path):
    """Print database contents and structure"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        print(f"\n=== Database at {db_path} ===")
        print(f"Found {len(tables)} tables:")
        
        for table in tables:
            table_name = table[0]
            print(f"\n=== Table: {table_name} ===")
            
            # Get table schema
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            
            print("Schema:")
            for col in columns:
                print(f"  {col[1]} ({col[2]}){' PRIMARY KEY' if col[5] else ''}")
            
            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cursor.fetchone()[0]
            print(f"Total rows: {count}")
            
            # Show data
            if count > 0:
                cursor.execute(f"SELECT * FROM {table_name} LIMIT 10")
                rows = cursor.fetchall()
                
                print("\nData sample (up to 10 rows):")
                for row in rows:
                    formatted_row = []
                    for i, val in enumerate(row):
                        col_name = columns[i][1]
                        if col_name == 'credential_id':
                            formatted_row.append(f"{col_name}: {val[:20]}..." if val and len(val) > 20 else f"{col_name}: {val}")
                        elif col_name == 'public_key' and val:
                            try:
                                pk_data = json.loads(val)
                                formatted_row.append(f"{col_name}: {json.dumps(pk_data, indent=2)[:100]}...")
                            except:
                                formatted_row.append(f"{col_name}: {val[:20]}...")
                        else:
                            formatted_row.append(f"{col_name}: {val}")
                    print(f"  {', '.join(formatted_row)}")
        
        # Special debug for security keys
        if any(t[0] == 'security_keys' for t in tables):
            print("\n=== Security Key Analysis ===")
            cursor.execute("""
                SELECT user_id, COUNT(*) as key_count, 
                       GROUP_CONCAT(aaguid) as aaguids,
                       GROUP_CONCAT(substring(combined_key_hash, 1, 10)) as key_hashes
                FROM security_keys
                GROUP BY user_id
            """)
            user_stats = cursor.fetchall()
            
            for stats in user_stats:
                print(f"User: {stats[0]}")
                print(f"  Registered keys: {stats[1]}")
                print(f"  AAGUIDs: {stats[2]}")
                print(f"  Key hashes: {stats[3]}")
                print("")
        
        conn.close()
        
    except Exception as e:
        print(f"Error inspecting database: {e}")
        return False
    
    return True

def clean_db(db_path, confirm=False):
    """Remove all data from the database tables"""
    if not confirm:
        confirm = input(f"Are you sure you want to clean the database at {db_path}? This will delete all data. (y/N): ")
        if confirm.lower() not in ('y', 'yes'):
            print("Operation cancelled.")
            return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        for table in tables:
            table_name = table[0]
            print(f"Deleting all data from {table_name}...")
            cursor.execute(f"DELETE FROM {table_name}")
        
        conn.commit()
        conn.close()
        
        print("Database cleaned successfully.")
        
    except Exception as e:
        print(f"Error cleaning database: {e}")
        return False
    
    return True

def check_key_uniqueness(db_path):
    """Check if multiple user accounts have the same physical key"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("\n=== Physical Key Uniqueness Check ===")
        
        # Check AAGUIDs
        cursor.execute("""
            SELECT aaguid, COUNT(DISTINCT user_id) as user_count
            FROM security_keys
            WHERE aaguid IS NOT NULL
            GROUP BY aaguid
            HAVING COUNT(DISTINCT user_id) > 1
        """)
        
        duplicates_by_aaguid = cursor.fetchall()
        if duplicates_by_aaguid:
            print("WARNING: Found multiple users sharing the same physical key (by AAGUID):")
            for row in duplicates_by_aaguid:
                print(f"  AAGUID: {row[0]}, Used by {row[1]} different users")
                
                # Get the specific users
                cursor.execute("""
                    SELECT user_id, credential_id
                    FROM security_keys
                    WHERE aaguid = ?
                """, (row[0],))
                
                users = cursor.fetchall()
                for user in users:
                    print(f"    User: {user[0]}, Credential: {user[1][:20]}...")
        else:
            print("✅ No duplicates found by AAGUID")
            
        # Check combined hash
        cursor.execute("""
            SELECT combined_key_hash, COUNT(DISTINCT user_id) as user_count
            FROM security_keys
            WHERE combined_key_hash IS NOT NULL
            GROUP BY combined_key_hash
            HAVING COUNT(DISTINCT user_id) > 1
        """)
        
        duplicates_by_hash = cursor.fetchall()
        if duplicates_by_hash:
            print("\nWARNING: Found multiple users sharing the same physical key (by combined hash):")
            for row in duplicates_by_hash:
                print(f"  Hash: {row[0][:20]}..., Used by {row[1]} different users")
                
                # Get the specific users
                cursor.execute("""
                    SELECT user_id, credential_id
                    FROM security_keys
                    WHERE combined_key_hash = ?
                """, (row[0],))
                
                users = cursor.fetchall()
                for user in users:
                    print(f"    User: {user[0]}, Credential: {user[1][:20]}...")
        else:
            print("✅ No duplicates found by combined hash")
        
        conn.close()
        
    except Exception as e:
        print(f"Error checking key uniqueness: {e}")
        return False
    
    return True

def main():
    parser = argparse.ArgumentParser(description='FIDO2 Chat System Database Tool')
    parser.add_argument('--db-path', type=str, default=DEFAULT_DB_PATH,
                        help=f'Path to the SQLite database (default: {DEFAULT_DB_PATH})')
    parser.add_argument('--inspect', action='store_true',
                        help='Inspect database contents')
    parser.add_argument('--clean', action='store_true',
                        help='Clean database (delete all data)')
    parser.add_argument('--check-keys', action='store_true',
                        help='Check for multiple users with the same physical key')
    parser.add_argument('--yes', '-y', action='store_true',
                        help='Automatically confirm destructive operations')
    
    args = parser.parse_args()
    
    # Validate that the database exists
    if not os.path.exists(args.db_path) and args.db_path != ':memory:':
        print(f"Error: Database file not found at {args.db_path}")
        return 1
    
    # Perform requested operations
    if args.inspect:
        inspect_db(args.db_path)
    
    if args.check_keys:
        check_key_uniqueness(args.db_path)
    
    if args.clean:
        clean_db(args.db_path, args.yes)
    
    # If no operation specified, show help
    if not (args.inspect or args.clean or args.check_keys):
        parser.print_help()
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
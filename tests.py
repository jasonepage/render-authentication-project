"""
FIDO2 WebAuthn Authentication System Tests
========================================

This module contains unit tests for the FIDO2 WebAuthn Authentication System.
Tests cover core functionality including health checks, debug information,
and basic chat functionality.

Author: Jason Page
Created: March 2024
Version: 1.0

Test Coverage:
- System health check
- Debug dashboard functionality
- Chat message functionality
"""

import unittest
import json
import os
from app import app
import tempfile
import sqlite3

class WebAuthnTestCase(unittest.TestCase):
    """
    Test case class for FIDO2 WebAuthn Authentication System.
    
    This class tests core functionality of the authentication and chat system.
    Each test uses a temporary SQLite database to ensure isolation.
    """

    def setUp(self):
        """
        Set up test environment before each test.
        
        Creates:
        - Test Flask client
        - Temporary SQLite database
        - Required database tables
        """
        app.config['TESTING'] = True
        self.client = app.test_client()
        
        # Create temporary database
        self.db_fd, self.db_path = tempfile.mkstemp()
        app.config['DATABASE_PATH'] = self.db_path
        
        # Initialize database
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS security_keys (credential_id TEXT PRIMARY KEY, public_key TEXT)')
            c.execute('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, user_id TEXT, message TEXT, timestamp DATETIME)')
            conn.commit()

    def tearDown(self):
        """
        Clean up after each test.
        
        Removes:
        - Temporary database file
        - Database file descriptor
        """
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_health_check(self):
        """
        Test the health check endpoint.
        
        Verifies:
        - Endpoint returns 200 status code
        - Response indicates healthy status
        """
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'healthy')

    def test_debug_info(self):
        """
        Test the debug information endpoint.
        
        Verifies:
        - Endpoint returns 200 status code
        - Response contains required debug information fields:
          * status
          * registered_keys
          * total_messages
        """
        response = self.client.get('/debug')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertIn('registered_keys', data)
        self.assertIn('total_messages', data)

    def test_chat_functionality(self):
        """
        Test basic chat functionality.
        
        Steps:
        1. Simulate user login
        2. Send a test message
        3. Retrieve messages
        
        Verifies:
        - Message sending succeeds
        - Message retrieval works
        - Response contains messages array
        """
        # Login simulation
        with self.client.session_transaction() as sess:
            sess['authenticated'] = True
            sess['user_id'] = 'test_user'

        # Send a message
        response = self.client.post('/send_message',
                                  data=json.dumps({'message': 'test message'}),
                                  content_type='application/json')
        self.assertEqual(response.status_code, 200)

        # Get messages
        response = self.client.get('/get_messages')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('messages', data)

if __name__ == '__main__':
    unittest.main() 
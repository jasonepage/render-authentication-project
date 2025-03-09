import unittest
import json
import os
import base64
import sqlite3
import tempfile
import requests
import time
from unittest.mock import patch, MagicMock

# Import the app for direct testing
try:
    from app import app, base64url_to_bytes, bytes_to_base64url, normalize_credential_id, generate_challenge
    DIRECT_IMPORT = True
except ImportError:
    # If running in isolation, we won't be able to import directly
    DIRECT_IMPORT = False

# Constants
LOCAL_URL = "http://127.0.0.1:5000"
DEPLOYED_URL = "https://render-authentication-project.onrender.com"

# Determine which URL to use
BASE_URL = os.environ.get("TEST_URL", LOCAL_URL)

class FidoUtilTests(unittest.TestCase):
    """Unit tests for utility functions"""
    
    @unittest.skipIf(not DIRECT_IMPORT, "App not directly importable")
    def test_base64url_conversions(self):
        """Test base64url encoding and decoding"""
        # Test strings of different lengths
        test_data = [
            os.urandom(10),
            os.urandom(20),
            os.urandom(32),
            os.urandom(64)
        ]
        
        for data in test_data:
            # Convert bytes to base64url and back
            base64url = bytes_to_base64url(data)
            decoded = base64url_to_bytes(base64url)
            
            # Check conversion is lossless
            self.assertEqual(data, decoded, "Base64URL conversion should be lossless")
            
            # Check base64url format (no +, /, or = characters)
            self.assertNotIn('+', base64url, "base64url should not contain '+'")
            self.assertNotIn('/', base64url, "base64url should not contain '/'")
            self.assertNotIn('=', base64url, "base64url should not contain '='")
    
    @unittest.skipIf(not DIRECT_IMPORT, "App not directly importable")
    def test_normalize_credential_id(self):
        """Test credential ID normalization"""
        # Test various formats of the same credential ID
        standard_format = "abc+/def+/ghi="
        urlsafe_format = "abc-_def-_ghi"
        
        # Check normalization
        normalized1 = normalize_credential_id(standard_format)
        normalized2 = normalize_credential_id(urlsafe_format)
        
        # Both should normalize to the same value
        self.assertEqual(normalized1, normalized2, "Different formats should normalize to the same value")
        
        # Check format of normalized ID
        self.assertNotIn('+', normalized1, "Normalized ID should not contain '+'")
        self.assertNotIn('/', normalized1, "Normalized ID should not contain '/'")
        self.assertNotIn('=', normalized1, "Normalized ID should not contain '='")
    
    @unittest.skipIf(not DIRECT_IMPORT, "App not directly importable")
    def test_generate_challenge(self):
        """Test challenge generation"""
        # Generate multiple challenges
        challenges = [generate_challenge() for _ in range(5)]
        
        # Check that challenges are unique
        self.assertEqual(len(challenges), len(set(challenges)), "Challenges should be unique")
        
        # Check challenge format
        for challenge in challenges:
            # Should be a string
            self.assertIsInstance(challenge, str, "Challenge should be a string")
            
            # Should be URL-safe base64
            self.assertNotIn('+', challenge, "Challenge should not contain '+'")
            self.assertNotIn('/', challenge, "Challenge should not contain '/'")
            self.assertNotIn('=', challenge, "Challenge should not contain '='")

class ApiTests(unittest.TestCase):
    """Tests for the API endpoints"""
    
    def setUp(self):
        """Set up for tests"""
        if DIRECT_IMPORT:
            # Use Flask test client
            self.app = app.test_client()
            self.app_context = app.app_context()
            self.app_context.push()
        
        # Create a session for requests
        self.session = requests.Session()
    
    def tearDown(self):
        """Clean up after tests"""
        if DIRECT_IMPORT and hasattr(self, 'app_context'):
            self.app_context.pop()
    
    def test_health_check(self):
        """Test the health check endpoint"""
        if DIRECT_IMPORT:
            response = self.app.get('/')
            data = json.loads(response.data)
            status_code = response.status_code
        else:
            response = self.session.get(f"{BASE_URL}/")
            data = response.json()
            status_code = response.status_code
        
        self.assertEqual(status_code, 200, "Health check should return 200")
        self.assertEqual(data['status'], "healthy", "Health check should return healthy status")
        self.assertEqual(data['service'], "FIDO2 Authentication System", "Health check should identify the service")
    
    def test_auth_status_unauthenticated(self):
        """Test auth status when not authenticated"""
        if DIRECT_IMPORT:
            response = self.app.get('/auth_status')
            data = json.loads(response.data)
        else:
            response = self.session.get(f"{BASE_URL}/auth_status")
            data = response.json()
        
        self.assertFalse(data['authenticated'], "Should not be authenticated")
        self.assertIsNone(data.get('userId'), "User ID should be None when not authenticated")
    
    def test_get_messages(self):
        """Test getting messages"""
        if DIRECT_IMPORT:
            response = self.app.get('/get_messages')
            status_code = response.status_code
            try:
                data = json.loads(response.data)
            except:
                data = []
        else:
            response = self.session.get(f"{BASE_URL}/get_messages")
            status_code = response.status_code
            try:
                data = response.json()
            except:
                data = []
        
        self.assertEqual(status_code, 200, "Getting messages should return 200")
        # Messages could be empty or contain data, we just check it's a list
        self.assertIsInstance(data, list, "Message response should be a list")
    
    def test_debug_all(self):
        """Test the debug endpoint"""
        if DIRECT_IMPORT:
            response = self.app.get('/debug_all')
            data = json.loads(response.data)
        else:
            response = self.session.get(f"{BASE_URL}/debug_all")
            data = response.json()
        
        # Check that we get the right structure
        self.assertIn('timestamp', data, "Debug data should include timestamp")
        self.assertIn('session', data, "Debug data should include session")
        self.assertIn('security_keys', data, "Debug data should include security_keys")
        self.assertIn('environment', data, "Debug data should include environment")

class IntegrationTest(unittest.TestCase):
    """Integration tests for simulating browser interactions"""
    
    def test_full_flow_simulation(self):
        """
        Simulate the full authentication flow
        
        Note: This test doesn't actually create WebAuthn credentials
        as that requires browser interaction, but it tests that the
        endpoints behave correctly with mocked data.
        """
        # Skip in cloud environment
        if BASE_URL != LOCAL_URL:
            self.skipTest("Skipping integration test in cloud environment")
        
        # Only run with direct import
        if not DIRECT_IMPORT:
            self.skipTest("App not directly importable")
        
        with patch('app.navigator.credentials.create') as mock_create, \
             patch('app.navigator.credentials.get') as mock_get:
            
            # Mock credential creation
            mock_credential = MagicMock()
            mock_credential.rawId = b'test_credential_id'
            mock_credential.response.clientDataJSON = b'{"type":"webauthn.create","challenge":"test_challenge"}'
            mock_credential.response.attestationObject = b'test_attestation'
            mock_create.return_value = mock_credential
            
            # Mock credential retrieval
            mock_get.return_value = mock_credential
            
            # Test registration flow
            reg_options_resp = self.app.post('/register_options')
            self.assertEqual(reg_options_resp.status_code, 200, "Registration options should return 200")
            
            # Complete registration with mocked data
            reg_complete_resp = self.app.post('/register_complete', json={
                'id': 'test_credential_id',
                'rawId': 'test_credential_id',
                'type': 'public-key',
                'response': {
                    'clientDataJSON': base64.b64encode(b'{"type":"webauthn.create","challenge":"test_challenge"}').decode('ascii'),
                    'attestationObject': base64.b64encode(b'test_attestation').decode('ascii')
                }
            })
            self.assertEqual(reg_complete_resp.status_code, 200, "Registration complete should return 200")
            
            # Test login flow
            login_options_resp = self.app.post('/login_options')
            self.assertEqual(login_options_resp.status_code, 200, "Login options should return 200")
            
            # Complete login with mocked data
            login_complete_resp = self.app.post('/login_complete', json={
                'id': 'test_credential_id',
                'rawId': 'test_credential_id',
                'type': 'public-key',
                'response': {
                    'clientDataJSON': base64.b64encode(b'{"type":"webauthn.get","challenge":"test_challenge"}').decode('ascii'),
                    'signature': base64.b64encode(b'test_signature').decode('ascii'),
                    'authenticatorData': base64.b64encode(b'test_auth_data').decode('ascii')
                }
            })
            self.assertEqual(login_complete_resp.status_code, 200, "Login complete should return 200")
            
            # Test authenticated endpoints
            auth_status_resp = self.app.get('/auth_status')
            auth_status = json.loads(auth_status_resp.data)
            self.assertTrue(auth_status['authenticated'], "Should be authenticated")
            
            # Test sending a message
            send_message_resp = self.app.post('/send_message', json={'message': 'Test message'})
            self.assertEqual(send_message_resp.status_code, 200, "Send message should return 200")
            
            # Test logout
            logout_resp = self.app.post('/logout')
            self.assertEqual(logout_resp.status_code, 200, "Logout should return 200")
            
            # Verify we're logged out
            auth_status_resp = self.app.get('/auth_status')
            auth_status = json.loads(auth_status_resp.data)
            self.assertFalse(auth_status['authenticated'], "Should be logged out")

class PerformanceTest(unittest.TestCase):
    """Performance tests for the application"""
    
    def setUp(self):
        """Set up the session"""
        self.session = requests.Session()
    
    def test_response_times(self):
        """Test response times for key endpoints"""
        # Skip in CI environment
        if os.environ.get("CI"):
            self.skipTest("Skipping performance test in CI")
        
        endpoints = ['/', '/auth_status', '/get_messages']
        
        results = {}
        for endpoint in endpoints:
            start_time = time.time()
            response = self.session.get(f"{BASE_URL}{endpoint}")
            end_time = time.time()
            
            # Record response time
            response_time = end_time - start_time
            results[endpoint] = {
                'status_code': response.status_code,
                'response_time': response_time
            }
            
            # Basic assertion - should respond in under 2 seconds
            self.assertLess(response_time, 2.0, f"Endpoint {endpoint} should respond in under 2 seconds")
        
        print("\nPerformance Test Results:")
        for endpoint, data in results.items():
            print(f"{endpoint}: {data['response_time']:.3f}s ({data['status_code']})")

def run_local_tests():
    """Run tests in local development environment"""
    unittest.main()

def run_cloud_tests():
    """Run tests against deployed environment"""
    # Set the base URL to the deployed URL
    global BASE_URL
    BASE_URL = DEPLOYED_URL
    
    # Create and run a test suite with only API tests
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ApiTests))
    runner = unittest.TextTestRunner()
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    # Determine whether to run local or cloud tests
    if os.environ.get('RUN_CLOUD_TESTS'):
        success = run_cloud_tests()
        exit(0 if success else 1)
    else:
        run_local_tests() 
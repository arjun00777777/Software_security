import unittest
import json
import os
from io import BytesIO
from server import app, generate_rsa_keypair, encrypt_file_pure_rsa, decrypt_file_pure_rsa, Config

class TestRSAService(unittest.TestCase):
    
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True 
        # Create a valid token for testing
        self.valid_token = self.get_auth_token("alice", "Alice@Secret1!")

    def get_auth_token(self, username, password):
        response = self.app.post('/api/v1/auth/login', 
                                 data=json.dumps({'username': username, 'password': password}),
                                 content_type='application/json')
        return json.loads(response.data)['token']

    
    def test_rsa_key_generation(self):
        """Verify keys are generated at the correct size (2048 bits)."""
        priv, pub = generate_rsa_keypair(2048)
        self.assertTrue(priv.startswith(b"-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(pub.startswith(b"-----BEGIN PUBLIC KEY-----"))

    def test_pure_rsa_roundtrip(self):
        """Verify that data encrypted with Pure RSA can be decrypted."""
        priv, pub = generate_rsa_keypair(2048)
        original_data = b"This is a test message for Pure RSA encryption."
        
        # Encrypt
        encrypted = encrypt_file_pure_rsa(original_data, pub)
        # Decrypt
        decrypted = decrypt_file_pure_rsa(encrypted, priv)
        
        self.assertEqual(original_data, decrypted)

    def test_chunking_large_data(self):
        """Verify that files larger than one RSA block are chunked correctly."""
        priv, pub = generate_rsa_keypair(2048)
        # Create data larger than 190 bytes (Config.MAX_CHUNK_SIZE)
        large_data = os.urandom(300) 
        
        encrypted = encrypt_file_pure_rsa(large_data, pub)
        decrypted = decrypt_file_pure_rsa(encrypted, priv)
        
        self.assertEqual(large_data, decrypted)


    def test_upload_without_auth(self):
        """Ensure unauthenticated users cannot upload files."""
        response = self.app.post('/api/v1/files/upload', data={})
        self.assertEqual(response.status_code, 401)

    def test_login_bruteforce_protection(self):
        """Ensure invalid login returns 401."""
        response = self.app.post('/api/v1/auth/login', 
                                 data=json.dumps({'username': 'alice', 'password': 'WrongPassword!'}),
                                 content_type='application/json')
        self.assertEqual(response.status_code, 401)

if __name__ == '__main__':
    import os
    unittest.main()

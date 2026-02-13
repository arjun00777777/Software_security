import os
import unittest
import json
from io import BytesIO

# --- CONFIGURATION: MUST BE SET BEFORE IMPORTING SERVER ---
os.environ["JWT_SECRET"] = "testing_secret_key_1234567890_min_32_chars"

from server import app, generate_rsa_keypair, encrypt_file_pure_rsa, decrypt_file_pure_rsa

class TestSecureRSAService(unittest.TestCase):
    
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True 
        # Get tokens for all roles
        self.admin_token = self.get_auth_token("admin", "Admin@Secret!")
        self.alice_token = self.get_auth_token("alice", "Alice@Secret1!")
        self.bob_token   = self.get_auth_token("bob", "Bob@Secret2!")     

    def get_auth_token(self, username, password):
        response = self.app.post('/api/v1/auth/login', 
                                 data=json.dumps({'username': username, 'password': password}),
                                 content_type='application/json')
        return json.loads(response.data)['token']

    def test_rsa_math_roundtrip(self):
        """Verify the pure RSA chunking logic works without the API."""
        priv, pub = generate_rsa_keypair(2048)
        original_data = b"Start" + os.urandom(300) + b"End" 
        
        encrypted = encrypt_file_pure_rsa(original_data, pub)
        decrypted = decrypt_file_pure_rsa(encrypted, priv)
        
        self.assertEqual(original_data, decrypted)

    def test_decrypt_tampered_fails(self):
        """Ensure bit-flipping causes a clean error, not a crash."""
        priv, pub = generate_rsa_keypair(2048)
        enc = encrypt_file_pure_rsa(b"Secret", pub)
        
        mutable_enc = bytearray(enc)
        mutable_enc[50] ^= 0xFF
        
        with self.assertRaises(RuntimeError) as ctx:
            decrypt_file_pure_rsa(bytes(mutable_enc), priv)
        self.assertIn("Decryption failed", str(ctx.exception))

    def test_admin_full_lifecycle(self):
        """Admin has both roles, so they should be able to Upload -> Encrypt -> Decrypt."""
        # 1. Upload
        res = self.app.post('/api/v1/files/upload', 
                            headers={'Authorization': f'Bearer {self.admin_token}'},
                            data={'file': (BytesIO(b"Super Secret Admin Data"), 'admin.txt')})
        self.assertEqual(res.status_code, 200)
        file_id = res.json['file_id']

        # 2. Encrypt
        res = self.app.post(f'/api/v1/files/{file_id}/encrypt', 
                            headers={'Authorization': f'Bearer {self.admin_token}'})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json['state'], 'encrypted')

        # 3. Decrypt
        res = self.app.post(f'/api/v1/files/{file_id}/decrypt', 
                            headers={'Authorization': f'Bearer {self.admin_token}'})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data, b"Super Secret Admin Data")

    def test_rbac_segregation(self):
        """Verify Separation of Duties: Bob can Encrypt but NOT Decrypt."""
        # Bob Uploads
        res = self.app.post('/api/v1/files/upload', 
                            headers={'Authorization': f'Bearer {self.bob_token}'},
                            data={'file': (BytesIO(b"Bob Data"), 'bob.txt')})
        file_id = res.json['file_id']

        # Bob Encrypts -> OK
        res = self.app.post(f'/api/v1/files/{file_id}/encrypt', 
                            headers={'Authorization': f'Bearer {self.bob_token}'})
        self.assertEqual(res.status_code, 200)

        # Bob Decrypts -> FORBIDDEN
        res = self.app.post(f'/api/v1/files/{file_id}/decrypt', 
                            headers={'Authorization': f'Bearer {self.bob_token}'})
        self.assertEqual(res.status_code, 403) 

    def test_alice_cannot_encrypt(self):
        """Verify Alice (Decrypt User) cannot Encrypt."""
        # Alice Uploads
        res = self.app.post('/api/v1/files/upload', 
                            headers={'Authorization': f'Bearer {self.alice_token}'},
                            data={'file': (BytesIO(b"Alice Data"), 'alice.txt')})
        file_id = res.json['file_id']
        
        # Alice Encrypts -> FORBIDDEN
        res = self.app.post(f'/api/v1/files/{file_id}/encrypt', 
                            headers={'Authorization': f'Bearer {self.alice_token}'})
        self.assertEqual(res.status_code, 403) 

    def test_idor_protection(self):
        """Verify Admin cannot see Bob's files (IDOR prevention)."""
        # Bob Uploads
        res = self.app.post('/api/v1/files/upload', 
                            headers={'Authorization': f'Bearer {self.bob_token}'},
                            data={'file': (BytesIO(b"Bob Private"), 'bob.txt')})
        bobs_file_id = res.json['file_id']
        
        # Admin tries to Decrypt -> FORBIDDEN (Admin is not the owner)
        res = self.app.post(f'/api/v1/files/{bobs_file_id}/decrypt', 
                            headers={'Authorization': f'Bearer {self.admin_token}'})
        self.assertEqual(res.status_code, 403) 

if __name__ == '__main__':
    unittest.main()

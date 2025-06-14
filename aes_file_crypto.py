from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AESFileCrypto:
    def __init__(self, password: str, salt: bytes = None):
        """
        Initialize the crypto system with a password and optional salt.
        If salt is not provided, a random one will be generated.
        """
        self.password = password.encode()
        self.salt = salt if salt else os.urandom(16)
        
        # Derive key from password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        self.cipher = Fernet(key)
    
    def encrypt_file(self, input_file_path: str, output_file_path: str = None):
        """
        Encrypt a file using AES-256.
        If output path is not specified, adds '.enc' extension to input file.
        """
        if not output_file_path:
            output_file_path = input_file_path + '.enc'
        
        try:
            with open(input_file_path, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = self.cipher.encrypt(file_data)
            
            # Save salt along with encrypted data
            with open(output_file_path, 'wb') as f:
                f.write(self.salt + encrypted_data)
            
            logger.info(f"File encrypted successfully: {output_file_path}")
            return True
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            return False
    
    def decrypt_file(self, input_file_path: str, output_file_path: str = None):
        """
        Decrypt a file encrypted with this system.
        If output path is not specified, removes '.enc' extension if present.
        """
        if not output_file_path:
            if input_file_path.endswith('.enc'):
                output_file_path = input_file_path[:-4]
            else:
                output_file_path = input_file_path + '.dec'
        
        try:
            with open(input_file_path, 'rb') as f:
                # First 16 bytes are the salt
                salt = f.read(16)
                # Rest is encrypted data
                encrypted_data = f.read()
            
            # Reinitialize cipher with the salt from the file
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.password))
            cipher = Fernet(key)
            
            decrypted_data = cipher.decrypt(encrypted_data)
            
            with open(output_file_path, 'wb') as f:
                f.write(decrypted_data)
            
            logger.info(f"File decrypted successfully: {output_file_path}")
            return True
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            return False
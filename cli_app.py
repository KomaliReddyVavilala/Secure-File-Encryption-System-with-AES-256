import argparse
from aes_file_crypto import AESFileCrypto
import getpass
import os  # NEW IMPORT
import sys  # NEW IMPORT

def main():
    parser = argparse.ArgumentParser(description="AES-256 File Encryption/Decryption Tool")
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Action to perform")
    parser.add_argument('input_file', help="Input file path")
    parser.add_argument('-o', '--output', help="Output file path (optional)")
    args = parser.parse_args()
    
    # Convert to absolute path and check existence
    input_path = os.path.abspath(args.input_file)  # NEW: Handle relative paths
    if not os.path.exists(input_path):  # NEW: Check file exists
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        return 1  # NEW: Return error code
    
    # Securely get password without echoing
    password = getpass.getpass("Enter password: ")
    confirm_password = getpass.getpass("Confirm password: ")
    
    if password != confirm_password:
        print("Error: Passwords do not match!", file=sys.stderr)
        return 1
    
    crypto = AESFileCrypto(password)
    
    # Handle output path (NEW: improved path handling)
    output_path = args.output
    if not output_path:
        if args.action == 'encrypt':
            output_path = input_path + '.enc'
        else:
            if input_path.endswith('.enc'):
                output_path = input_path[:-4]
            else:
                output_path = input_path + '.dec'
    
    try:
        if args.action == 'encrypt':
            success = crypto.encrypt_file(input_path, output_path)
        else:
            success = crypto.decrypt_file(input_path, output_path)
        
        if not success:
            return 1  # NEW: Return error code if operation failed
            
    except Exception as e:  # NEW: Catch and display any errors
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1
    
    return 0  # NEW: Success

if __name__ == "__main__":
    sys.exit(main())  # NEW: Proper exit code handling
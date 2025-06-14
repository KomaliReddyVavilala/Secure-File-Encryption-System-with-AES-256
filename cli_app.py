import argparse
from aes_file_crypto import AESFileCrypto
import getpass
import os 
import sys 

def main():
    parser = argparse.ArgumentParser(description="AES-256 File Encryption/Decryption Tool")
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Action to perform")
    parser.add_argument('input_file', help="Input file path")
    parser.add_argument('-o', '--output', help="Output file path (optional)")
    args = parser.parse_args()

    input_path = os.path.abspath(args.input_file) 
    if not os.path.exists(input_path):  
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        return 1 
    
   
    password = getpass.getpass("Enter password: ")
    confirm_password = getpass.getpass("Confirm password: ")
    
    if password != confirm_password:
        print("Error: Passwords do not match!", file=sys.stderr)
        return 1
    
    crypto = AESFileCrypto(password)
    
   
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
            return 1 
            
    except Exception as e:  
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1
    
    return 0  # NEW: Success

if __name__ == "__main__":
    sys.exit(main())  

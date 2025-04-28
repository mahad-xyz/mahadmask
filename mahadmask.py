#!/usr/bin/env python3
"""
mahadmask.py - A command-line tool for secure file operations using hybrid encryption and digital signatures.

This tool implements:
- Symmetric encryption (AES) for file content
- Asymmetric encryption (RSA) for key protection
- Digital signatures for authentication
"""

import os
import sys
import base64
import argparse
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


class SecureFileTool:
    """Handles secure file operations using hybrid encryption and digital signatures."""

    def __init__(self):
        self.aes_key_size = 32  # 256 bits
        self.iv_size = 16  # 128 bits for AES
        self.salt_size = 16
        self.rsa_key_size = 2048

    def generate_key_pair(
        self,
        private_key_path: str,
        public_key_path: str,
        password: Optional[str] = None,
    ) -> None:
        """Generate RSA key pair and save to files."""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size,
        )

        # Get public key
        public_key = private_key.public_key()

        # Serialize private key with optional password protection
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(
                password.encode()
            )
        else:
            encryption_algorithm = serialization.NoEncryption()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )

        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Write keys to files
        with open(private_key_path, "wb") as f:
            f.write(private_pem)
        with open(public_key_path, "wb") as f:
            f.write(public_pem)

        print(f"Key pair generated successfully!")
        print(f"Private key saved to: {private_key_path}")
        print(f"Public key saved to: {public_key_path}")

    def load_private_key(
        self, private_key_path: str, password: Optional[str] = None
    ) -> rsa.RSAPrivateKey:
        """Load RSA private key from file."""
        with open(private_key_path, "rb") as key_file:
            private_key_data = key_file.read()

        if password:
            return serialization.load_pem_private_key(
                private_key_data, password=password.encode()
            )
        else:
            return serialization.load_pem_private_key(private_key_data, password=None)

    def load_public_key(self, public_key_path: str) -> rsa.RSAPublicKey:
        """Load RSA public key from file."""
        with open(public_key_path, "rb") as key_file:
            public_key_data = key_file.read()
        return serialization.load_pem_public_key(public_key_data)

    def generate_aes_key(self) -> bytes:
        """Generate a random AES key."""
        return os.urandom(self.aes_key_size)

    def encrypt_file(
        self,
        input_file: str,
        output_file: str,
        recipient_public_key_path: str,
        sender_private_key_path: str = None,
        sender_key_password: str = None,
    ) -> None:
        """
        Encrypt a file using hybrid encryption and optionally sign it.

        Args:
            input_file: Path to the file to encrypt
            output_file: Path to save the encrypted file
            recipient_public_key_path: Path to recipient's public key for encrypting the AES key
            sender_private_key_path: Optional path to sender's private key for signing
            sender_key_password: Optional password for the sender's private key
        """
        # Load recipient's public key
        recipient_public_key = self.load_public_key(recipient_public_key_path)

        # Read the input file
        with open(input_file, "rb") as f:
            plaintext = f.read()

        # Generate random AES key and IV
        aes_key = self.generate_aes_key()
        iv = os.urandom(self.iv_size)

        # Encrypt the file content with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Add PKCS7 padding
        padding_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + bytes([padding_length]) * padding_length

        # Encrypt
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Encrypt the AES key with the recipient's public key
        encrypted_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Optional: Sign the encrypted content if a sender private key is provided
        signature = None
        if sender_private_key_path:
            sender_private_key = self.load_private_key(
                sender_private_key_path, sender_key_password
            )
            # Sign the combination of ciphertext and IV to ensure integrity of both
            signature = sender_private_key.sign(
                iv + ciphertext,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

        # Write encrypted file
        with open(output_file, "wb") as f:
            # Format:
            # [encrypted_key_length (4 bytes)][encrypted_key][iv][signature_length (4 bytes)][signature (if any)][ciphertext]
            f.write(len(encrypted_key).to_bytes(4, byteorder="big"))
            f.write(encrypted_key)
            f.write(iv)

            if signature:
                f.write(len(signature).to_bytes(4, byteorder="big"))
                f.write(signature)
            else:
                # No signature (0 length)
                f.write((0).to_bytes(4, byteorder="big"))

            f.write(ciphertext)

        print(f"File encrypted successfully!")
        print(f"Encrypted file saved to: {output_file}")
        if signature:
            print("File was digitally signed.")

    def decrypt_file(
        self,
        input_file: str,
        output_file: str,
        recipient_private_key_path: str,
        recipient_key_password: str = None,
        sender_public_key_path: str = None,
    ) -> None:
        """
        Decrypt a file using hybrid encryption and optionally verify its signature.

        Args:
            input_file: Path to the encrypted file
            output_file: Path to save the decrypted file
            recipient_private_key_path: Path to recipient's private key
            recipient_key_password: Optional password for the recipient's private key
            sender_public_key_path: Optional path to sender's public key for signature verification
        """
        # Load recipient's private key
        recipient_private_key = self.load_private_key(
            recipient_private_key_path, recipient_key_password
        )

        # Read the encrypted file
        with open(input_file, "rb") as f:
            # Read encrypted key length
            key_length = int.from_bytes(f.read(4), byteorder="big")

            # Read encrypted key
            encrypted_key = f.read(key_length)

            # Read IV
            iv = f.read(self.iv_size)

            # Read signature length
            sig_length = int.from_bytes(f.read(4), byteorder="big")

            # Read signature if present
            signature = None
            if sig_length > 0:
                signature = f.read(sig_length)

            # Read ciphertext (rest of the file)
            ciphertext = f.read()

        # Decrypt the AES key
        try:
            aes_key = recipient_private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            print(
                f"Error decrypting the AES key. Make sure you have the correct private key: {e}"
            )
            return

        # Verify signature if provided and sender's public key is available
        if signature and sender_public_key_path:
            try:
                sender_public_key = self.load_public_key(sender_public_key_path)
                sender_public_key.verify(
                    signature,
                    iv + ciphertext,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                print("Digital signature verified successfully!")
            except Exception as e:
                print(f"Warning: Signature verification failed! {e}")
                response = input("Continue with decryption anyway? (y/n): ")
                if response.lower() != "y":
                    return

        # Decrypt the file content
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]

        # Write decrypted file
        with open(output_file, "wb") as f:
            f.write(plaintext)

        print(f"File decrypted successfully!")
        print(f"Decrypted file saved to: {output_file}")

    def sign_file(
        self,
        input_file: str,
        output_signature: str,
        private_key_path: str,
        key_password: str = None,
    ) -> None:
        """Sign a file without encrypting it."""
        # Load the private key
        private_key = self.load_private_key(private_key_path, key_password)

        # Read the input file
        with open(input_file, "rb") as f:
            file_data = f.read()

        # Create signature
        signature = private_key.sign(
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # Write the signature to a file
        with open(output_signature, "wb") as f:
            f.write(signature)

        print(f"File signed successfully!")
        print(f"Signature saved to: {output_signature}")

    def verify_signature(
        self, input_file: str, signature_file: str, public_key_path: str
    ) -> bool:
        """Verify a file's signature."""
        # Load the public key
        public_key = self.load_public_key(public_key_path)

        # Read the input file and signature
        with open(input_file, "rb") as f:
            file_data = f.read()

        with open(signature_file, "rb") as f:
            signature = f.read()

        # Verify signature
        try:
            public_key.verify(
                signature,
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            print("Signature is valid! The file is authentic.")
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False


def main():
    """Parse arguments and execute commands."""
    parser = argparse.ArgumentParser(
        description="A Python command-line tool that securely encrypts and "
        "decrypts files using hybrid encryption (AES + RSA) and verifies file "
        "authenticity with digital signatures.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Generate a key pair
  mahadmask.py genkeys --private private.pem --public public.pem
  
  Encrypt a file
  mahadmask.py encrypt --file document.txt --output document.enc --recipient-key public.pem
  
  Encrypt and sign a file
  mahadmask.py encrypt --file document.txt --output document.enc --recipient-key public.pem --sign --private-key private.pem
  
  Decrypt a file
  mahadmask.py decrypt --file document.enc --output document.decrypted --private-key private.pem
  
  Decrypt and verify a file
  mahadmask.py decrypt --file document.enc --output document.decrypted --private-key private.pem --verify --sender-key sender_public.pem
  
  Sign a file without encryption
  mahadmask.py sign --file document.txt --output document.sig --private-key private.pem
  
  Verify a signature
  mahadmask.py verify --file document.txt --signature document.sig --public-key public.pem
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Generate keys command
    genkeys_parser = subparsers.add_parser("genkeys", help="Generate RSA key pair")
    genkeys_parser.add_argument(
        "--private", required=True, help="Private key output file"
    )
    genkeys_parser.add_argument(
        "--public", required=True, help="Public key output file"
    )
    genkeys_parser.add_argument(
        "--password", help="Password to protect the private key (optional)"
    )

    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("--file", required=True, help="File to encrypt")
    encrypt_parser.add_argument("--output", required=True, help="Output encrypted file")
    encrypt_parser.add_argument(
        "--recipient-key", required=True, help="Recipient's public key"
    )
    encrypt_parser.add_argument("--sign", action="store_true", help="Sign the file")
    encrypt_parser.add_argument(
        "--private-key", help="Sender's private key (required for signing)"
    )
    encrypt_parser.add_argument(
        "--key-password", help="Password for the private key (if protected)"
    )

    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("--file", required=True, help="File to decrypt")
    decrypt_parser.add_argument("--output", required=True, help="Output decrypted file")
    decrypt_parser.add_argument(
        "--private-key", required=True, help="Recipient's private key"
    )
    decrypt_parser.add_argument(
        "--key-password", help="Password for the private key (if protected)"
    )
    decrypt_parser.add_argument(
        "--verify", action="store_true", help="Verify the file signature"
    )
    decrypt_parser.add_argument(
        "--sender-key", help="Sender's public key (required for verification)"
    )

    # Sign command
    sign_parser = subparsers.add_parser("sign", help="Sign a file without encrypting")
    sign_parser.add_argument("--file", required=True, help="File to sign")
    sign_parser.add_argument("--output", required=True, help="Output signature file")
    sign_parser.add_argument(
        "--private-key", required=True, help="Signer's private key"
    )
    sign_parser.add_argument(
        "--key-password", help="Password for the private key (if protected)"
    )

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a file signature")
    verify_parser.add_argument("--file", required=True, help="File to verify")
    verify_parser.add_argument("--signature", required=True, help="Signature file")
    verify_parser.add_argument(
        "--public-key", required=True, help="Signer's public key"
    )

    args = parser.parse_args()

    # Create the tool
    tool = SecureFileTool()

    # Execute the requested command
    if args.command == "genkeys":
        tool.generate_key_pair(args.private, args.public, args.password)

    elif args.command == "encrypt":
        if args.sign and not args.private_key:
            parser.error("--private-key is required when using --sign")

        tool.encrypt_file(
            args.file,
            args.output,
            args.recipient_key,
            args.private_key if args.sign else None,
            args.key_password,
        )

    elif args.command == "decrypt":
        if args.verify and not args.sender_key:
            parser.error("--sender-key is required when using --verify")

        tool.decrypt_file(
            args.file,
            args.output,
            args.private_key,
            args.key_password,
            args.sender_key if args.verify else None,
        )

    elif args.command == "sign":
        tool.sign_file(args.file, args.output, args.private_key, args.key_password)

    elif args.command == "verify":
        tool.verify_signature(args.file, args.signature, args.public_key)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

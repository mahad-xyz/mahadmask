# MahadMask Secure FIle tool

A command-line tool for secure file operations using hybrid encryption and digital signatures.

## Features

- **Hybrid Encryption**: Uses AES for file content encryption and RSA for key protection
- **Digital Signatures**: Provides file authentication and integrity verification
- **Command-line Interface**: Easy-to-use CLI for all operations
- **Key Management**: Tools to generate and manage RSA key pairs

## Requirements

- Python 3.7+
- cryptography library

## Installation

1. Clone this repository or download the script
2. Install dependencies:

```bash
pip install cryptography
```

3. Make the script executable (Unix/Linux):

```bash
chmod +x mahadmask.py
```

## Usage

### Generate RSA Key Pair

```bash
./mahadmask.py genkeys --private private.pem --public public.pem
```

To protect the private key with a password:

```bash
./mahadmask.py genkeys --private private.pem --public public.pem --password your_secure_password
```

### Encrypt a File

Basic encryption (without signature):

```bash
./mahadmask.py encrypt --file document.txt --output document.enc --recipient-key recipient_public.pem
```

Encrypt and sign a file:

```bash
./mahadmask.py encrypt --file document.txt --output document.enc --recipient-key recipient_public.pem --sign --private-key sender_private.pem
```

If your private key is password-protected:

```bash
./mahadmask.py encrypt --file document.txt --output document.enc --recipient-key recipient_public.pem --sign --private-key sender_private.pem --key-password your_password
```

### Decrypt a File

Basic decryption (without signature verification):

```bash
./mahadmask.py decrypt --file document.enc --output document.decrypted --private-key recipient_private.pem
```

Decrypt and verify signature:

```bash
./mahadmask.py decrypt --file document.enc --output document.decrypted --private-key recipient_private.pem --verify --sender-key sender_public.pem
```

With a password-protected private key:

```bash
./mahadmask.py decrypt --file document.enc --output document.decrypted --private-key recipient_private.pem --key-password your_password
```

### Sign a File (Without Encryption)

```bash
./mahadmask.py sign --file document.txt --output document.sig --private-key sender_private.pem
```

### Verify a Signature

```bash
./mahadmask.py verify --file document.txt --signature document.sig --public-key sender_public.pem
```

## How It Works

### Encryption

1. A random AES-256 key is generated
2. The file is encrypted using AES in CBC mode with the random key
3. The AES key is encrypted using the recipient's RSA public key
4. If signing is enabled, a digital signature is created using the sender's RSA private key
5. All components are packaged into the output file

### Decryption

1. The encrypted AES key is extracted and decrypted using the recipient's RSA private key
2. If signature verification is enabled, the signature is verified using the sender's RSA public key
3. The file content is decrypted using the AES key

## Security Considerations

- Keep private keys secure and consider password protection
- Use sufficiently strong passwords for key protection
- The tool uses industry-standard encryption algorithms and practices
- RSA keys are 2048 bits by default
- AES-256 is used for symmetric encryption

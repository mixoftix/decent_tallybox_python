# @title

"""
Decent TallyBox (Wallet) Provisioning Script
Version: 2.932 (MVP)
Updated: 2026-06-19

This script provisions a Tallybox wallet (https://wallet.mixoftix.net) for secure management of
tokens on a DAG network. It both generates and recovers a private-public key pair of ecc secp256r1,
derives a wallet address, and stores the wallet data in an XML file with AES-256-CBC encrypted
private keys. Features include RFC 6979-compliant ECDSA signatures, key pair verification, and
Base58-encoded wallet addresses.

Licensed under the GNU General Public License v3 (GPL-3), this software is open-source, ensuring
freedom to use, modify, and distribute. Derivative works must also be open-source under GPL-3,
and source code must be provided with distributions.

MixofTix Was Here!
by shahiN Noursalehi
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import xml.etree.ElementTree as ET
import os
import random
import string
import re
import ecdsa
import getpass


# Step 1: Generate a private-public key pair
def generate_key_pair():
    """
    Generate a private-public key pair using the secp256r1 curve.
    Returns: (private_key, (x, y)) where (x, y) are the public key coordinates as bytes.
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    x = public_key_bytes[1:33]  # First 32 bytes after 0x04 prefix
    y = public_key_bytes[33:]   # Last 32 bytes

    return private_key, (x, y)

def derive_public_key_from_private(private_key_hex):
    """
    Derive the public key from a given private key (hex string) using secp256r1.
    Args:
        private_key_hex (str): Hex string of the private key.
    Returns: (x, y, private_key) where x, y are coordinates as bytes, private_key is the object.
    """
    private_key_int = int(private_key_hex, 16)
    private_key = ec.derive_private_key(
        private_key_int,
        ec.SECP256R1(),
        default_backend()
    )
    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    x = public_key_bytes[1:33]
    y = public_key_bytes[33:]

    return x, y, private_key

# Step 2: Compress and Encode the Public Key
def compress_public_key(x, y):
    """
    Compress the public key as per the tutorial.
    Args:
        x (bytes): X-coordinate of the public key (32 bytes).
        y (bytes): Y-coordinate of the public key (32 bytes).
    Returns: (compressed_key, suffix) where compressed_key is a string and suffix is '1' or '2'.
    """
    y_int = int.from_bytes(y, byteorder='big')
    parity = y_int % 2
    suffix = '1' if parity == 1 else '2'
    x_hex = x.hex()
    compressed_key = f"{x_hex}*{suffix}"
    return compressed_key, suffix

def base58_encode(bytes_data):
    """
    Encode a byte array in Base58 as per the tutorial's pseudo-code.
    Args:
        bytes_data (bytes): The byte array to encode.
    Returns: Base58-encoded string.
    """
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = int.from_bytes(bytes_data, byteorder='big')
    result = ''

    while value > 0:
        remainder = value % 58
        result = alphabet[remainder] + result
        value //= 58

    for byte in bytes_data:
        if byte == 0:
            result = '1' + result
        else:
            break

    return result

def compress_and_encode_public_key(x, y):
    """
    Compress the public key and encode it in Base58.
    Args:
        x (bytes): X-coordinate of the public key.
        y (bytes): Y-coordinate of the public key.
    Returns: (compressed_key, base58_address) where base58_address is the final encoded address.
    """
    compressed_key, suffix = compress_public_key(x, y)
    base58_x = base58_encode(x)
    base58_address = f"{base58_x}*{suffix}"
    return compressed_key, base58_address

# Step 3: Derive the TallyBox Wallet Address
def derive_tallybox_wallet_address(base58_public_key):
    """
    Derive the TallyBox wallet address from the Base58-encoded public key.
    Args:
        base58_public_key (str): The Base58-encoded public key.
    Returns: (final_address, intermediate_steps) where final_address is the wallet address.
    """
    base58_bytes = base58_public_key.encode('utf-8')
    sha256_hash = hashlib.sha256(base58_bytes).hexdigest()
    raw_wallet_string = sha256_hash
    raw_wallet_bytes = bytes.fromhex(raw_wallet_string)
    base58_raw_wallet = base58_encode(raw_wallet_bytes)
    base58_raw_wallet_bytes = base58_raw_wallet.encode('utf-8')
    md5_hash = hashlib.md5(base58_raw_wallet_bytes).hexdigest()
    checksum = 'boxB' + md5_hash[:11]
    final_address = checksum + base58_raw_wallet

    intermediate_steps = {
        'sha256_hash': sha256_hash,
        'raw_wallet_string': raw_wallet_string,
        'raw_wallet_bytes_hex': raw_wallet_bytes.hex(),
        'base58_raw_wallet': base58_raw_wallet,
        'md5_hash': md5_hash,
        'checksum': checksum
    }

    return final_address, intermediate_steps

# Step 4: Verify the Key Pair Integrity with RFC 6979
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

def mod_sqrt(a, p):
    """
    Compute the modular square root of a modulo p (Tonelli-Shanks algorithm).
    Args:
        a (int): The number to find the square root of.
        p (int): The prime modulus (p ≡ 3 mod 4 for secp256r1).
    Returns: One of the square roots (the other is -result mod p).
    """
    if pow(a, (p - 1) // 2, p) != 1:
        raise ValueError("No square root exists")

    exponent = (p + 1) // 4
    result = pow(a, exponent, p)
    return result

def decompress_public_key(compressed_key):
    """
    Decompress the public key by computing Y from X and the suffix.
    Args:
        compressed_key (str): The compressed key in the form 'x_hex*suffix'.
    Returns: (x, y) coordinates as integers.
    """
    x_hex, suffix = compressed_key.split('*')
    x = int(x_hex, 16)

    x3 = (x * x * x) % P
    ax = (A * x) % P
    y2 = (x3 + ax + B) % P

    y = mod_sqrt(y2, P)
    y_neg = (-y) % P

    if suffix == '1':
        y_final = y if y % 2 == 1 else y_neg
    else:
        y_final = y if y % 2 == 0 else y_neg

    return x, y_final

def sign_digest(digest, private_key_hex):
    """
    Sign a SHA-256 digest using RFC 6979-compliant ECDSA with secp256r1.
    Args:
        digest (bytes): The SHA-256 digest to sign (32 bytes).
        private_key_hex (str): The private key as a 64-character hex string.
    Returns: Base64-encoded DER signature.
    """
    # Convert private key hex to bytes
    private_key_bytes = bytes.fromhex(private_key_hex)

    # Create an ecdsa SigningKey for secp256r1
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.NIST256p)

    # Sign the digest with RFC 6979 deterministic k
    signature = sk.sign_digest(
        digest,
        sigencode=ecdsa.util.sigencode_der_canonize  # Canonical DER encoding
    )

    # Encode signature in Base64
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    return signature_b64

def verify_digest(digest, signature_b64, compressed_key):
    """
    Verify a SHA-256 digest signature using RFC 6979-compliant ECDSA with secp256r1.
    Args:
        digest (bytes): The SHA-256 digest that was signed (32 bytes).
        signature_b64 (str): Base64-encoded DER signature.
        compressed_key (str): The compressed public key (x_hex*suffix).
    Returns: True if the signature is valid, False otherwise.
    """
    try:
        # Decompress the public key to get x, y coordinates
        x_int, y_int = decompress_public_key(compressed_key)
        x_bytes = x_int.to_bytes(32, byteorder='big')
        y_bytes = y_int.to_bytes(32, byteorder='big')

        # Create an ecdsa VerifyingKey
        public_key_bytes = b'\x04' + x_bytes + y_bytes
        vk = ecdsa.VerifyingKey.from_string(
            public_key_bytes,
            curve=ecdsa.NIST256p
        )

        # Decode the Base64 signature
        signature = base64.b64decode(signature_b64)

        # Verify the signature
        return vk.verify_digest(
            signature,
            digest,
            sigdecode=ecdsa.util.sigdecode_der
        )
    except Exception:
        return False

def verify_key_pair_integrity(private_key, compressed_key):
    """
    Verify the key pair integrity by signing and verifying a test message using RFC 6979.
    Args:
        private_key: The private key object (from cryptography).
        compressed_key (str): The compressed public key from Step 2 (x_hex*suffix).
    Returns: (is_valid, signature_base64, decompressed_key) for verification.
    """
    # Test message to sign
    message = "TallyBox, a tool for curious minds..".encode('utf-8')
    digest = hashlib.sha256(message).digest()

    # Get private key as hex
    private_key_bytes = private_key.private_numbers().private_value.to_bytes(32, byteorder='big')
    private_key_hex = private_key_bytes.hex()

    # Sign the digest using RFC 6979
    signature_b64 = sign_digest(digest, private_key_hex)

    # Verify the signature
    is_valid = verify_digest(digest, signature_b64, compressed_key)

    # Decompress the public key for reporting
    x_int, y_int = decompress_public_key(compressed_key)
    x_bytes = x_int.to_bytes(32, byteorder='big')
    y_bytes = y_int.to_bytes(32, byteorder='big')
    decompressed_key = f"{x_bytes.hex()}*{y_bytes.hex()}"

    return is_valid, signature_b64, decompressed_key

# Step 5: Upgraded AES Functions
def aes256_cbc_encrypt_js_compatible(data: str, secret: str, show_logs: bool = False) -> str:
    """
    Encrypt data using AES-256-CBC to match Java's AES_Encrypt_by_secret_with_custom_padding.
    Args:
        data (str): The data to encrypt (string, UTF-8 encoded).
        secret (str): Secret key (at least 64 characters, hex string).
        show_logs (bool): Whether to print debug logs.
    Returns: Base64-encoded ciphertext (no IV prepended, may include newlines).
    """
    if len(secret) < 64:
        raise ValueError("Secret key must be at least 64 characters")
    if not re.match(r'^[0-9a-fA-F]{64,}$', secret):
        raise ValueError("Secret key must be a hex string")

    aes_password = secret[:32].encode('ascii')  # Match Java's password.toCharArray() (UTF-8 equivalent)
    aes_iv = secret[32:48].encode('ascii')     # Match Java's aes_iv.getBytes("ASCII")
    aes_salt = secret[48:64].encode('ascii')   # Match Java's salt.getBytes() (UTF-8 equivalent)

    key = hashlib.pbkdf2_hmac('sha256', aes_password, aes_salt, 3, 32)

    if show_logs:
        print(f"Encrypt - Secret: {secret}")
        print(f"Encrypt - Key (hex): {key.hex()}")
        print(f"Encrypt - IV (hex): {aes_iv.hex()}")

    left_padding_size = random.randint(0, 99)
    left_padding = ''.join(random.choice(string.ascii_letters) for _ in range(left_padding_size))
    right_padding_size = random.randint(0, 99)
    right_padding = ''.join(random.choice(string.ascii_letters) for _ in range(right_padding_size))
    padded_data = f"{left_padding}|{data}|{right_padding}".encode('utf-8')

    padding_length = 16 - (len(padded_data) % 16)
    padded_data += bytes([padding_length] * padding_length)

    cipher = Cipher(algorithms.AES(key), modes.CBC(aes_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Match Java's Base64.DEFAULT (may include newlines for long strings)
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    return ciphertext_b64

def aes256_cbc_decrypt_js_compatible(encrypted_base64: str, secret: str, show_logs: bool = False) -> str:
    """
    Decrypt Base64-encoded AES-256-CBC data to match Java's AES_Decrypt_by_secret_with_custom_padding.
    Args:
        encrypted_base64 (str): Base64-encoded ciphertext (no IV prepended, may include newlines).
        secret (str): Secret key (at least 64 characters, hex string).
        show_logs (bool): Whether to print debug logs.
    Returns: Decrypted data as string.
    """
    if len(secret) < 64:
        raise ValueError("Secret key must be at least 64 characters")
    if not re.match(r'^[0-9a-fA-F]{64,}$', secret):
        raise ValueError("Secret key must be a hex string")

    try:
        # Handle Java's Base64.DEFAULT (strip newlines if present)
        ciphertext = base64.b64decode(encrypted_base64.replace('\n', ''))
        if show_logs:
            print(f"Decrypt - Ciphertext length: {len(ciphertext)}")
    except Exception as e:
        raise ValueError(f"Invalid Base64 ciphertext: {e}")

    aes_password = secret[:32].encode('ascii')  # Match Java's password.toCharArray() (UTF-8 equivalent)
    aes_iv = secret[32:48].encode('ascii')     # Match Java's aes_iv.getBytes("ASCII")
    aes_salt = secret[48:64].encode('ascii')   # Match Java's salt.getBytes() (UTF-8 equivalent)

    key = hashlib.pbkdf2_hmac('sha256', aes_password, aes_salt, 3, 32)

    if show_logs:
        print(f"Decrypt - Secret: {secret}")
        print(f"Decrypt - Key (hex): {key.hex()}")
        print(f"Decrypt - IV (hex): {aes_iv.hex()}")

    cipher = Cipher(algorithms.AES(key), modes.CBC(aes_iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

    try:
        padding_length = padded_data[-1]
        if padding_length > 16 or padding_length == 0:
            raise ValueError("Invalid PKCS#7 padding")
        padded_data = padded_data[:-padding_length]
    except IndexError:
        raise ValueError("Invalid padding length")

    if show_logs:
        print(f"Decrypt - Padded data (hex): {padded_data.hex()}")

    try:
        padded_text = padded_data.decode('utf-8')
        if show_logs:
            print(f"Decrypt - Padded text: {padded_text}")
        parts = padded_text.split('|')
        if len(parts) != 3:
            raise ValueError("Invalid padding format in decrypted text")
        plaintext = parts[1]
    except UnicodeDecodeError:
        if show_logs:
            print("Decrypt - Warning: Decrypted data is not UTF-8, attempting byte split")
        parts = padded_data.split(b'|')
        if len(parts) != 3:
            raise ValueError("Invalid padding format in decrypted bytes")
        try:
            plaintext = parts[1].decode('ascii')
            if show_logs:
                print(f"Decrypt - Extracted plaintext: {plaintext}")
        except UnicodeDecodeError:
            raise ValueError("Decrypted plaintext is not a valid ASCII string")

    if not re.match(r'^[0-9a-fA-F]{64}$', plaintext):
        raise ValueError(f"Decrypted private key is not a 64-character hex string: {plaintext}")

    return plaintext

# Step 6: Provision the TallyBox Wallet
def indent(elem, level=0):
    """
    Helper function to pretty-print XML with indentation.
    Args:
        elem: The XML element to indent.
        level: The current indentation level.
    """
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for child in elem:
            indent(child, level + 1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i

def provision_tallybox_wallet(private_key, wallet_address, base58_public_key, wallet_name, password, show_logs: bool = False):
    """
    Provision the TallyBox wallet by securely storing its data.
    Args:
        private_key: The private key object (from cryptography).
        wallet_address (str): The TallyBox wallet address from Step 3.
        base58_public_key (str): The Base58-encoded public key from Step 2.
        wallet_name (str): The wallet name provided by the user.
        password (str): The local password provided by the user.
        show_logs (bool): Whether to print AES debug logs.
    Returns: (encrypted_private_key_b64, xml_str, verification_result, private_key_bytes, secret) for verification.
    """
    # 1. Form the key string using the provided wallet name and password
    key_string = f"{wallet_name}~{password}~{wallet_address}"

    # 2. Compute the SHA-256 hash of the key string to generate the secret
    secret = hashlib.sha256(key_string.encode()).hexdigest()

    # 3. Encrypt the private key as a hex string
    private_key_bytes = private_key.private_numbers().private_value.to_bytes(32, byteorder='big')
    private_key_hex = private_key_bytes.hex()
    encrypted_private_key_b64 = aes256_cbc_encrypt_js_compatible(private_key_hex, secret, show_logs=show_logs)

    # 4. Decrypt to verify correctness
    decrypted_private_key_hex = aes256_cbc_decrypt_js_compatible(encrypted_private_key_b64, secret, show_logs=show_logs)
    verification_result = (decrypted_private_key_hex == private_key_hex)

    # 5. Create the XML file content
    root = ET.Element("tallybox_wallet")

    ET.SubElement(root, "wallet_name").text = wallet_name
    ET.SubElement(root, "wallet_address").text = wallet_address
    ET.SubElement(root, "public_key_b58_compressed").text = base58_public_key
    ET.SubElement(root, "private_key_aes_b64").text = encrypted_private_key_b64
    ET.SubElement(root, "tech_info").text = "https://mailarchive.ietf.org/arch/msg/ideas/VEzD4RXKlCFIUftYIrrEdMFgoW0/"

    # Pretty print the XML
    indent(root)
    xml_str = "\n"
    xml_str += ET.tostring(root, encoding='unicode', method='xml')

    # 6. Write the XML to a file named .xml
    xml_filename = f"{wallet_name}.xml"
    with open(xml_filename, "w", encoding="utf-8") as f:
        f.write(xml_str)

    return encrypted_private_key_b64, xml_str, verification_result, private_key_bytes, secret

def main():
    # Step 1: Prompt user to select an option
    print("Select an option:")
    print("A) Generate Wallet")
    print("B) Recover Wallet")
    option = input("Enter your choice (A or B): ").strip().upper()

    # Validate the option
    while option not in ['A', 'B']:
        print("Invalid choice. Please select A or B.")
        option = input("Enter your choice (A or B): ").strip().upper()

    # Step 2: Get wallet name, password (hidden), and debug log preference
    wallet_name = input("Enter wallet name: ").strip()
    
    while True:
        password = getpass.getpass("Enter local password: ")
        if not password:
            print("Password cannot be empty. Please try again.")
            continue
            
        password_confirm = getpass.getpass("Confirm local password: ")
        
        if password == password_confirm:
            break
        else:
            print("Passwords do not match. Please try again.")
    
    debug_choice = input("Show AES debug logs? (y/N): ").strip().lower()
    show_logs = debug_choice in ['y', 'yes']

    # Step 3: Generate or recover the private-public key pair based on the option
    if option == 'A':
        # Generate a new private-public key pair
        print("Generating a new wallet...")
        private_key, (x, y) = generate_key_pair()
    else:
        # Recover wallet using an existing private key
        print("Recovering wallet from private key...")
        private_key_hex = input("Enter your existing private key (in hex format, 64 characters): ").strip()
        # Basic validation for the private key (should be 64 hex characters)
        while len(private_key_hex) != 64 or not all(c in '0123456789abcdefABCDEF' for c in private_key_hex):
            print("Invalid private key. It must be a 64-character hexadecimal string.")
            private_key_hex = input("Enter your existing private key (in hex format, 64 characters): ").strip()
        x, y, private_key = derive_public_key_from_private(private_key_hex)

    # Step 4: Compress and encode the public key
    compressed_key, base58_public_key = compress_and_encode_public_key(x, y)

    # Step 5: Derive the TallyBox wallet address
    final_address, steps = derive_tallybox_wallet_address(base58_public_key)

    # Print Step 5 results
    print("\nStep 5: TallyBox Wallet Address Derivation")
    if show_logs:
        print(f"Base58 Public Key: {base58_public_key}")
        print(f"SHA-256 Hash: {steps['sha256_hash']}")
        print(f"Raw Wallet Bytes (hex): {steps['raw_wallet_bytes_hex']}")
        print(f"Base58 Raw Wallet: {steps['base58_raw_wallet']}")
        print(f"MD5 Hash: {steps['md5_hash']}")
        print(f"Checksum: {steps['checksum']}")
    print(f"Final Wallet Address: {final_address}")

    # Step 6: Verify the key pair integrity with RFC 6979
    is_valid, signature_base64, decompressed_key = verify_key_pair_integrity(private_key, compressed_key)

    # Step 7: Provision the TallyBox wallet
    encrypted_private_key_b64, xml_str, verification_result, private_key_bytes, secret = provision_tallybox_wallet(
        private_key, final_address, base58_public_key, wallet_name, password, show_logs=show_logs
    )

    # Step 8: Print the results for Step 7
    print("\nStep 7 Results:")
    if show_logs:
        print("Key String (pre-SHA-256):", f"{wallet_name}~{password}~{final_address}")
        print("Local Key (SHA-256):", secret)
        print("Original Private Key (hex):", private_key_bytes.hex())
        print("Encrypted Private Key (Base64):", encrypted_private_key_b64)
        decrypted_private_key = aes256_cbc_decrypt_js_compatible(encrypted_private_key_b64, secret, show_logs=show_logs)
        print("Decrypted Private Key (hex):", decrypted_private_key)
    print("Verification Result:", "Verified" if verification_result else "Not Verified")
    print("\nXML Content:")
    print(xml_str)
    print(f"\nXML data has been saved to {wallet_name}.xml")
    print("\n** Private Key (write it down somewhere safe):\n  ", private_key_bytes.hex().upper())

    print("\nGoodbye!")
    input("")

if __name__ == "__main__":
    main()

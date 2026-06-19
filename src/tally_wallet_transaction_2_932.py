# @title

"""
Decent TallyBox (Wallet) Transaction Script
Version: 2.932 (MVP)
Updated: 2026-06-19

This script enables a Tallybox wallet (https://wallet.mixoftix.net) for secure management of
tokens on a DAG network. This implementation provides AES-256-CBC encryption
for private keys, RFC 6979-compliant ECDSA signatures, and offline transaction signing.

Licensed under the GNU General Public License v3 (GPL-3), this software is open-source, ensuring
freedom to use, modify, and distribute. Derivative works must also be open-source under GPL-3,
and source code must be provided with distributions.

MixofTix Was Here!
by shahiN Noursalehi
"""

import xml.etree.ElementTree as ET
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import requests
from urllib.parse import quote
import time
import re
from getpass import getpass
import random
import string
from ecdsa import SigningKey, NIST256p
from ecdsa.util import sigencode_der_canonize
from datetime import datetime

# Predefined graph domains and their corresponding URLs
GRAPH_DOMAINS = [
    "gpp_mars.mixoftix.net",
    "gpp_venus.mixoftix.net",
    "gpp_pluto.mixoftix.net"
]
GRAPH_URLS = [
    "192.168.88.111:701",
    "192.168.88.111:711",
    "192.168.88.111:721"
]
# Tokens supported by each graph
GRAPH_TOKENS = [
    "USD,TLH,IRR",           # Mars
    "2ZR",                   # Venus
    "2ZR,IRR"                # Pluto
]

# Base58 encoding function
def base58_encode(bytes_data):
    """
    Encode a byte array in Base58 as per the first script's implementation.
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


def load_wallet(file_path, password, protocol="http", graph="tallybox.mixoftix.net", show_logs: bool = False):
    """Step 1: Load wallet XML, decrypt private key, and reconstruct key pair."""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        wallet_name = root.find("wallet_name").text
        public_key_b58 = root.find("public_key_b58_compressed").text
        private_key_aes_b64 = root.find("private_key_aes_b64").text
        wallet_address = root.find("wallet_address").text

        if not all([wallet_name, public_key_b58, private_key_aes_b64, wallet_address]):
            raise ValueError("Invalid XML format")

        key_components = f"{wallet_name}~{password}~{wallet_address}"
        secret = hashlib.sha256(key_components.encode()).hexdigest()
        if show_logs:
            print(f"Load Wallet - Key components: {key_components}")
            print(f"Load Wallet - Secret: {secret}")

        private_key_hex = aes256_cbc_decrypt_js_compatible(private_key_aes_b64, secret, show_logs)
        if show_logs:
            print(f"Load Wallet - Decrypted private key (hex): {private_key_hex}")

        try:
            private_key_int = int(private_key_hex, 16)
            SECP256R1_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
            if not (1 <= private_key_int < SECP256R1_ORDER):
                raise ValueError(f"Private key out of range for secp256r1: {private_key_hex}")
        except ValueError:
            raise ValueError(f"Decrypted private key is not a valid hex string: {private_key_hex}")

        key_pair = ec.derive_private_key(
            private_key_int,
            ec.SECP256R1(),
            default_backend()
        )

        public_key = key_pair.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        x_bytes = public_key_bytes[1:33]
        y_bytes = public_key_bytes[33:]
        y_int = int.from_bytes(y_bytes, byteorder='big')
        y_parity = y_int % 2
        suffix = '1' if y_parity == 1 else '2'
        compressed_key = f"{x_bytes.hex()}*{suffix}"

        return {
            "key_pair": key_pair,
            "compressed_key": compressed_key,
            "public_key_b58": public_key_b58,
            "wallet_address": wallet_address,
            "wallet_name": wallet_name,
            "protocol": protocol,
            "graph": graph,  # Kept for compatibility, but we'll override graph_from/graph_to
            "graph_domains": GRAPH_DOMAINS,
            "graph_urls": GRAPH_URLS
        }
    except Exception as e:
        raise ValueError(f"Decryption failed or invalid file: {str(e)}")


def main_menu_loop(wallet_state):
    """Improved main menu with navigation loop"""
    while True:
        print("\n" + "="*55)
        print("          TALLYBOX WALLET MAIN MENU")
        print("="*55)
        print("[1] View History & Balances")
        print("[2] Sign Transaction")
        print("[3] Pass KYC")
        print("[4] Quit / Exit")
        print("="*55)

        action = input("\nEnter your choice (1-4): ").strip()

        if action == "1":
            fetch_balances(wallet_state)
        elif action == "2":
            transaction_flow(wallet_state)
        elif action == "3":
            kyc_result = pass_kyc(wallet_state)
            if kyc_result and isinstance(kyc_result, dict):
                print(f"\n{kyc_result.get('kyc_result', 'KYC process completed.')}")
        elif action == "4":
            print("\nWallet session ended.")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")


def pass_kyc(wallet_state):
    """
    Updated KYC function with consistent navigation and better UX.
    """
    print("\n" + "="*60)
    print("                    KYC PROCESS")
    print("="*60)

    # Graph selection with Back option
    print("Select target graph domain for KYC:\n")
    for i, domain in enumerate(wallet_state["graph_domains"], 1):
        print(f"[{i}] {domain}")
    print(f"[{len(wallet_state['graph_domains']) + 1}] Back to Main Menu")
    print("="*60)

    try:
        choice = input(f"\nEnter choice (1-{len(wallet_state['graph_domains'])+1}): ").strip()
        if not choice.isdigit():
            print("Invalid input.")
            return {"kyc_result": "KYC cancelled."}

        graph_idx = int(choice) - 1

        if graph_idx == len(wallet_state["graph_domains"]):
            print("\nKYC process cancelled - returned to main menu.")
            return {"kyc_result": "KYC cancelled."}

        if graph_idx < 0 or graph_idx >= len(wallet_state["graph_domains"]):
            print("Invalid graph selection.")
            return {"kyc_result": "Invalid selection."}

        target_graph = wallet_state["graph_domains"][graph_idx]
        graph_url = wallet_state["graph_urls"][graph_idx]

    except Exception:
        print("Invalid input.")
        return {"kyc_result": "KYC cancelled."}

    # === KYC Request ===
    print(f"\n--- KYC Request on {target_graph} ---")
    national_id = input("Enter National ID: ").strip()
    mobile_number = input("Enter Mobile Number: ").strip()

    if not national_id or not mobile_number:
        print("National ID and Mobile Number are required.")
        return {"kyc_result": "Missing required information."}

    url = f"{wallet_state['protocol']}://{graph_url}/dmz.asmx/kyc_generate"
    post_data = {
        "app_name": "tallybox",
        "app_version": "2.0",
        "national_id": national_id,
        "mobile_number": mobile_number
    }

    try:
        response = requests.post(url, data=post_data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        response.raise_for_status()
        kyc_msg = response.text.strip()

        if kyc_msg.startswith("error~") or kyc_msg.startswith("info~"):
            return {"kyc_result": f"KYC request failed: {kyc_msg}"}
    except Exception as e:
        return {"kyc_result": f"KYC request failed: {str(e)}"}

    # === KYC Signing ===
    print(f"\nKYC Message received: {kyc_msg}")
    kyc_pin = getpass("Enter KYC PIN: ").strip()

    if not kyc_pin:
        print("PIN is required.")
        return {"kyc_result": "KYC cancelled - no PIN entered."}

    wallet_address = wallet_state["wallet_address"]
    kyc_order = f"{national_id}~{wallet_address}~{kyc_pin}"

    try:
        kyc_hash = hashlib.sha256(kyc_order.encode()).digest()
        private_key = wallet_state["key_pair"].private_numbers().private_value
        private_key_bytes = private_key.to_bytes(32, byteorder='big')

        sk = SigningKey.from_string(private_key_bytes, curve=NIST256p)
        signature_der = sk.sign_digest(kyc_hash, sigencode=sigencode_der_canonize)
        sig_base64 = base64.b64encode(signature_der).decode()

    except Exception as e:
        return {"kyc_result": f"Failed to sign KYC: {str(e)}"}

    # Broadcast KYC
    url = f"{wallet_state['protocol']}://{graph_url}/dmz.asmx/kyc_accept"
    post_data = {
        "app_name": "tallybox",
        "app_version": "2.0",
        "national_id": national_id,
        "wallet_2_kyc": wallet_address,
        "wallet_pubkey": wallet_state["public_key_b58"],
        "sign_4_kyc": sig_base64
    }

    try:
        response = requests.post(url, data=post_data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        response.raise_for_status()
        result = response.text.strip()

        if result.startswith("error~"):
            return {"kyc_result": f"xx KYC failed: {result}"}
        else:
            return {"kyc_result": f"== KYC completed successfully: {result}"}

    except Exception as e:
        return {"kyc_result": f"KYC signing failed: {str(e)}"}


def get_graph_menu():
    """Return formatted list showing graph + supported tokens"""
    menu = []
    for i, (domain, tokens) in enumerate(zip(GRAPH_DOMAINS, GRAPH_TOKENS), 1):
        menu.append(f"[{i}] {domain}  [ {tokens} ]")
    return menu


def fetch_balances(wallet_state):
    """
    Improved version with better navigation:
    - Back to Graph Selection
    - Back to Main Menu
    - Cleaner flow and user experience
    """
    while True:  # Graph selection loop
        print("\n" + "="*60)
        print("                  VIEW BALANCES & HISTORY")
        print("="*60)
        print("Select target graph domain:\n")
        
        for line in get_graph_menu():
            print(line)
        
        print(f"[{len(GRAPH_DOMAINS) + 1}] Back to Main Menu")
        print("="*60)

        try:
            choice = input(f"\nEnter choice (1-{len(GRAPH_DOMAINS)+1}): ").strip()
            if not choice.isdigit():
                print("Please enter a valid number.")
                continue
                
            graph_idx = int(choice) - 1
            
            if graph_idx == len(GRAPH_DOMAINS):
                return  # Back to Main Menu
            
            if graph_idx < 0 or graph_idx >= len(GRAPH_DOMAINS):
                print("Invalid graph selection.")
                continue
                
        except ValueError:
            print("Invalid input. Please enter a number.")
            continue

        target_graph = GRAPH_DOMAINS[graph_idx]
        allowed_tokens = get_tokens(graph_idx)

        if not allowed_tokens:
            print(f"\nNo tokens supported on {target_graph}.")
            input("\nPress Enter to continue...")
            continue

        # Fetch balances
        url = f"{wallet_state['protocol']}://{GRAPH_URLS[graph_idx]}/dmz.asmx/ledger_history"
        post_data = (
            f"app_name=tallybox&app_version=2.0&in_graph={quote(target_graph)}"
            f"&wallet_address={quote(wallet_state['wallet_address'])}"
        )

        try:
            response = requests.post(url, data=post_data, headers={"Content-Type": "application/x-www-form-urlencoded"})
            response.raise_for_status()
            parts = response.text.split("~")
            
            # Initialize balances
            balances = {token: "0.00000000" for token in allowed_tokens}

            for i in range(6, len(parts) - 1, 2):
                token = parts[i]
                amount = parts[i + 1]
                if token in allowed_tokens and amount:
                    try:
                        balances[token] = f"{float(amount):.8f}"
                    except:
                        pass

            # Token selection loop
            while True:
                print(f"\n=== Latest Balances on {target_graph} ===")
                token_list = list(balances.keys())
                
                for i, token in enumerate(token_list, 1):
                    print(f"[{i}] {token:>3}   Balance: {balances[token]}")

                print(f"[{len(token_list)+1}] Back to Graph Selection")
                print(f"[{len(token_list)+2}] Back to Main Menu")
                print("="*50)

                choice_str = input("\nSelect token for detailed history: ").strip()
                
                if not choice_str.isdigit():
                    print("Please enter a number.")
                    continue
                    
                choice = int(choice_str) - 1

                if choice == len(token_list):
                    break  # Back to Graph Selection
                elif choice == len(token_list) + 1:
                    return  # Back to Main Menu
                elif 0 <= choice < len(token_list):
                    selected_token = token_list[choice]
                    fetch_ledger_history_detail(wallet_state, graph_idx, selected_token)
                    # After viewing detail, continue to token selection
                else:
                    print("Invalid choice. Try again.")

        except Exception as e:
            print(f"Failed to fetch balances: {str(e)}")
            input("\nPress Enter to continue...")
            continue

def parse_history_detail(raw_csv: str):
    """Correctly parse ledger_history_detail response with header + multiple records"""
    if not raw_csv or raw_csv.startswith("error~"):
        return []

    transactions = []
    
    # Split header from transactions
    # Header ends with the first record starting after the third '^'
    parts = raw_csv.split('#')
    
    for record in parts:
        record = record.strip()
        if not record:
            continue
            
        fields = record.split('^')
        
        # Skip header (first part usually has graph^wallet^balance)
        if len(fields) >= 3 and fields[0].startswith("gpp_"):
            continue  # This is the header line
            
        # Transaction record: tnx_type^tnx_id^currency_amount^left_amount^hash
        if len(fields) >= 5:
            transactions.append({
                "tnx_type": fields[0],
                "tnx_id": fields[1],
                "currency_amount": fields[2],
                "left_amount": fields[3],
                "hash_of_book": fields[4]
            })
    
    return transactions


def get_tnx_type_name(tnx_type: str) -> str:
    """Convert numeric tnx_type to human readable name"""
    try:
        t_type = int(tnx_type)
        if t_type == 0:
            return "(Fee)    "
        elif t_type == 1:
            return "(Send)   "
        else:  # 2 and above
            return "(Receive)"
    except:
        return "Unknown"


def fetch_ledger_history_detail(wallet_state, graph_idx: int, currency: str):
    """Fetch and display detailed transaction history with meaningful type names"""
    target_graph = GRAPH_DOMAINS[graph_idx]
    graph_url = GRAPH_URLS[graph_idx]

    print(f"\nFetching latest transactions for {currency} on {target_graph}...\n")

    url = f"{wallet_state['protocol']}://{graph_url}/dmz.asmx/ledger_history_detail"

    post_data = (
        f"app_name=tallybox&app_version=2.0"
        f"&in_graph={quote(target_graph)}"
        f"&wallet_address={quote(wallet_state['wallet_address'])}"
        f"&currency_name={quote(currency)}"
    )

    try:
        response = requests.post(url, data=post_data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        response.raise_for_status()
        raw_data = response.text.strip()

        if not raw_data:
            print("No data returned from server.")
            return []

        transactions = parse_history_detail(raw_data)

        if not transactions:
            print("No transactions found for this token.")
            return []

        # Extract current balance from header
        header = raw_data.split('#')[0]
        header_fields = header.split('^')
        current_balance = header_fields[2] if len(header_fields) > 2 else "N/A"

        print(f"=== Latest Transactions for {currency} on {target_graph} ===")
        print(f"Wallet         : {wallet_state['wallet_address']}")
        print(f"Current Balance: {current_balance}\n")

        for i, tnx in enumerate(transactions[:15], 1):   # Top 15 records
            try:
                amount = float(tnx['currency_amount'])
                left = float(tnx['left_amount'])
            except:
                amount = 0.0
                left = 0.0

            type_name = get_tnx_type_name(tnx['tnx_type'])

            print(f"{i:2d}. Type: {tnx['tnx_type']:>2} {type_name:<13} | Tnx-ID: {tnx['tnx_id']} ")
            print(f"    Amount: {amount:>14.8f} | Left: {left:>14.8f} ")
            print(f"    Hash : {tnx['hash_of_book'][:64]}\n")

        return transactions

    except Exception as e:
        print(f"Failed to fetch detailed history: {str(e)}")
        return []


def validate_wallet_address(address):
    """
    Validate a Tallybox wallet address, matching C# logic.
    Args:
        address (str): Wallet address in the format box.
    Returns:
        bool: True if valid, False otherwise.
    """
    # Null/empty and length check
    if not address or len(address) < 40:
        return False

    # Prefix check
    if not address.startswith("box"):
        return False

    # Algorithm check
    curve_char = address[3]
    if curve_char not in ["A", "B", "C"]:
        return False

    # Checksum check
    checksum_md5 = address[4:15]  # 11 characters
    base58_part = address[15:]
    computed_md5 = hashlib.md5(base58_part.encode()).hexdigest()[:11]

    return checksum_md5 == computed_md5


# Determine allowed tokens
def get_tokens(graph_idx: int) -> set[str]:
    """Safely extract non-empty tokens for a graph."""
    token_str = GRAPH_TOKENS[graph_idx].strip()
    if not token_str:
        return set()
    # Split, strip whitespace, and filter out empty strings
    tokens = {t.strip() for t in token_str.split(',') if t.strip()}
    return tokens


def transaction_flow(wallet_state):
    """
    Final improved transaction flow with meaningful offline review + 
    option to broadcast after review.
    """
    while True:
        print("\n" + "="*65)
        print("                 SIGN NEW TRANSACTION")
        print("="*65)

        result = prepare_transaction(wallet_state)
        
        if result == "BACK":
            return

        broadcast_data, graph_from_idx, filename = result

        print(f"\n== Transaction successfully signed!")
        print(f"== Transaction saved to: {filename}\n")

        # Show options
        print("[1] Broadcast Transaction Now")
        print("[2] Review Transaction File")
        print("[3] Sign Another Transaction")
        print("[4] Back to Main Menu")
        print("="*65)

        choice = input("\nEnter choice (1-4): ").strip()

        if choice == "1":
            print("\nBroadcasting immediately...")
            _perform_broadcast(wallet_state, broadcast_data, graph_from_idx)

        elif choice == "2":
            # ====================== REVIEW OFFLINE FILE ======================
            print(f"\n== Reviewing offline transaction file: {filename}")
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    content = f.read().strip()

                fields = content.split("~")
                labels = [
                    "App", "Parcel", "", "Graph From", "", "Graph To",
                    "", "From Wallet", "", "To Wallet", "", "Token",
                    "", "Amount", "", "Order ID", "", "Timestamp",
                    "", "Signature", "", "Public Key"
                ]

                print("-" * 85)
                for i, (label, value) in enumerate(zip(labels, fields)):
                    if not label.strip():
                        continue
                    if label == "Signature":
                        # print(f"{label:>12} : {value[:50]}... (truncated)")
                        print(f"{label:>12} : {value[:50]}")
                        print(f"{' ':>12}   {value[50:]}")
                    else:
                        print(f"{label:>12} : {value}")
                print("-" * 85)

            except Exception as e:
                print(f"Could not read file: {e}")

            # ====================== POST-REVIEW DECISION ======================
            print("\nWould you like to broadcast this transaction now?")
            post_review = input("Enter (y)es or (n)o: ").strip().lower()

            if post_review == 'y' or post_review == 'yes':
                _perform_broadcast(wallet_state, broadcast_data, graph_from_idx)
            else:
                print("== Transaction remains saved offline.")

        elif choice == "3":
            continue  # Sign another transaction

        elif choice == "4":
            return    # Back to Main Menu

        else:
            print("Invalid choice. Please try again.")
            continue

        input("\nPress Enter to continue...")


def _perform_broadcast(wallet_state, broadcast_data, graph_from_idx):
    """Internal helper to avoid code duplication"""
    try:
        # Quote the signature for network
        parts = broadcast_data.split("~")
        parts[19] = quote(parts[19])          # the_sign field
        broadcast_quoted = "~".join(parts)

        result = broadcast_transaction(wallet_state, broadcast_quoted, graph_from_idx)
        print(f"\n{result}")
    except Exception as e:
        print(f"\nxx Broadcast failed: {e}")


def prepare_transaction(wallet_state):
    """
    Updated with proper Back navigation + correct data handling for both 
    offline save and broadcast.
    """
    try:
        # ====================== GRAPH FROM ======================
        print("\nSelect graph_from domain:")
        for line in get_graph_menu():
            print(line)
        print(f"[{len(GRAPH_DOMAINS)+1}] Back to Main Menu")

        idx = int(input(f"Enter choice (1-{len(GRAPH_DOMAINS)+1}): ")) - 1
        if idx == len(GRAPH_DOMAINS):
            return "BACK"
        if idx < 0 or idx >= len(GRAPH_DOMAINS):
            raise ValueError("Invalid selection")
        graph_from = GRAPH_DOMAINS[idx]
        graph_from_idx = idx

        # ====================== GRAPH TO ======================
        print("\nSelect graph_to domain:")
        for line in get_graph_menu():
            print(line)
        print(f"[{len(GRAPH_DOMAINS)+1}] Back to Main Menu")

        idx = int(input(f"Enter choice (1-{len(GRAPH_DOMAINS)+1}): ")) - 1
        if idx == len(GRAPH_DOMAINS):
            return "BACK"
        if idx < 0 or idx >= len(GRAPH_DOMAINS):
            raise ValueError("Invalid selection")
        graph_to = GRAPH_DOMAINS[idx]

        # ====================== TOKEN & DETAILS ======================
        tokens_from = get_tokens(graph_from_idx)
        tokens_to = get_tokens(idx)  # current idx is graph_to

        if graph_from_idx == idx:  # internal
            allowed_tokens = sorted(tokens_from)
        else:
            allowed_tokens = sorted(tokens_from.intersection(tokens_to))

        if not allowed_tokens:
            raise ValueError("No common tokens available between selected graphs.")

        # print(f"\nAllowed tokens: {', '.join(allowed_tokens)}")

        target_address = input("\nEnter target wallet address: ").strip()
        token = input(f"Select token ({', '.join(allowed_tokens)}): ").strip().upper()
        amount = input("Enter amount: ").strip()
        order_id = input("Enter optional Order ID (or press Enter): ").strip()
        utc_unix = int(time.time())

        if token not in allowed_tokens:
            raise ValueError(f"Token '{token}' not allowed.")
        if not validate_wallet_address(target_address):
            raise ValueError("Invalid target wallet address.")

        try:
            amount_float = float(amount)
            if amount_float <= 0:
                raise ValueError
        except:
            raise ValueError("Invalid amount.")

        # ====================== SIGN TRANSACTION ======================
        transaction_data = (
            f"{graph_from}~{graph_to}~"
            f"{wallet_state['wallet_address']}~{target_address}~"
            f"{token}~{amount_float:.8f}~{order_id}~{utc_unix}"
        )
        msg_hash = hashlib.sha256(transaction_data.encode()).digest()

        private_key = wallet_state["key_pair"].private_numbers().private_value
        private_key_bytes = private_key.to_bytes(32, byteorder='big')

        sk = SigningKey.from_string(private_key_bytes, curve=NIST256p)
        signature_der = sk.sign_digest(msg_hash, sigencode=sigencode_der_canonize)
        sig_base64 = base64.b64encode(signature_der).decode()

        # ====================== BUILD BROADCAST DATA ======================
        broadcast_data = "~".join([
            "tallybox", "parcel_of_transaction",
            "graph_from", graph_from,
            "graph_to", graph_to,
            "wallet_from", wallet_state['wallet_address'],
            "wallet_to", target_address,
            "order_currency", token,
            "order_amount", f"{amount_float:.8f}",
            "order_id", order_id,
            "order_utc_unix", str(utc_unix),
            "the_sign", sig_base64,                    # unquoted for file
            "publicKey_xy_compressed", wallet_state['public_key_b58']
        ])

        # ====================== SAVE OFFLINE FILE ======================
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filename = f"offline_{token}_{timestamp}.txt"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(broadcast_data)

        # print(f"== Transaction saved to: {filename}")

        return broadcast_data, graph_from_idx, filename   # Return filename too

    except Exception as e:
        print(f"\nxx Transaction preparation failed: \n{e}")
        input("\nPress Enter to continue...")
        return "BACK"


def broadcast_transaction(wallet_state, broadcast_data, graph_from_idx):
    """Broadcast with better error reporting"""
    graph_url = wallet_state["graph_urls"][graph_from_idx]
    url = f"{wallet_state['protocol']}://{graph_url}/dmz.asmx/order_accept"
    
    post_data = f"app_name=tallybox&app_version=2.0&order_csv={broadcast_data}"

    try:
        response = requests.post(url, data=post_data, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=30)
        response.raise_for_status()
        
        if response.text.startswith("pending~200~"):
            return f"== Successfully depended to GPP! {response.text}"
        else:
            return f"Server Response: {response.text}"
            
    except requests.exceptions.HTTPError as e:
        return f"xx Server Error ({response.status_code}): {response.text if 'response' in locals() else str(e)}"
    except Exception as e:
        return f"xx Broadcast failed: {str(e)}"


def main():
    """Main function with improved navigation"""
    print("=== Tallybox Wallet Transaction Script ===\n")
    
    try:
        file_path = input("Enter wallet XML file name (without .xml): ").strip()
        if not file_path.endswith(".xml"):
            file_path += ".xml"

        password = getpass("Enter wallet password: ")

        # Log visibility choice
        print("\nDo you want to see detailed logs during wallet loading?")
        print("[1] Yes")
        print("[2] No")
        log_choice = input("Enter choice (1 or 2): ").strip()

        show_logs = log_choice == "1"

        # Load wallet
        wallet_state = load_wallet(file_path, password, show_logs=show_logs)

        print("\n== Wallet loaded successfully ==")
        print(f"Wallet: {wallet_state['wallet_name']} \nAddress: {wallet_state['wallet_address']}")

        # Start improved main menu
        main_menu_loop(wallet_state)

    except Exception as e:
        print(f"\nxx Error: {str(e)} xx")
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user.")
    finally:
        print("Goodbye!")


if __name__ == "__main__":
    main()

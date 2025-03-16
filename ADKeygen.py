#!/usr/bin/env python3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from binascii import unhexlify
import argparse
import hashlib  # Added for NTLM hash


# Constants
AES256_CONSTANT = bytes([
    0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,
    0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,
    0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4
])
AES128_CONSTANT = AES256_CONSTANT[:16]
IV = bytes([0x00]*16)
ITERATION = 4096  # Active Directory default


def do_aes_256(aes_256_pbkdf2):
    cipher = Cipher(algorithms.AES(aes_256_pbkdf2), modes.CBC(IV))
    encryptor = cipher.encryptor()
    key_1 = encryptor.update(AES256_CONSTANT) + encryptor.finalize()
    
    cipher = Cipher(algorithms.AES(aes_256_pbkdf2), modes.CBC(IV))
    encryptor = cipher.encryptor()
    key_2 = encryptor.update(key_1) + encryptor.finalize()
    
    aes_256_raw = key_1[:16] + key_2[:16]
    return aes_256_raw.hex().upper()


def do_aes_128(aes_128_pbkdf2):
    cipher = Cipher(algorithms.AES(aes_128_pbkdf2), modes.CBC(IV))
    encryptor = cipher.encryptor()
    aes_128_raw = encryptor.update(AES128_CONSTANT) + encryptor.finalize()
    return aes_128_raw.hex().upper()


def do_ntlm(password_str):
    """Generate NTLM hash from password string using hashlib"""
    return hashlib.new('md4', password_str.encode('utf-16-le')).hexdigest().upper()


def main():
    parser = argparse.ArgumentParser(
        description='Generate AES128/256 Kerberos keys and NTLM hash for an AD account',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-domain', type=str, help='EXAMPLE.COM', required=True)
    parser.add_argument('-user', type=str, 
                       help='sAMAccountName - case sensitive for AD user accounts', required=True)
    parser.add_argument('-pass', type=str, dest='password',
                       help='Valid cleartext or hex account password', required=True)
    parser.add_argument('-host', action='store_true',
                       help='Target is a computer account', required=False)

    args = parser.parse_args()

    domain = args.domain.upper()
    if args.host:
        host = args.user.replace('$', '')  # Ensure $ is not present in hostname
        salt = f'{domain}host{host.lower()}.{domain.lower()}'
    else:
        salt = f'{domain}{args.user}'

    print(f'[*] Salt: {salt}')    
    
    # Password handling
    try:
        hex_bytes = unhexlify(args.password)
        password_str = hex_bytes.decode('utf-16-le', 'replace')
        password_bytes = password_str.encode('utf-8', 'replace')
    except:
        password_str = args.password
        password_bytes = args.password.encode('utf-8')

    salt_bytes = salt.encode('utf-8')

    # Derive PBKDF2 keys
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,
        salt=salt_bytes,
        iterations=ITERATION,
    )
    aes_256_pbkdf2 = kdf.derive(password_bytes)
    aes_128_pbkdf2 = aes_256_pbkdf2[:16]

    # Generate all keys
    aes_256_key = do_aes_256(aes_256_pbkdf2)
    aes_128_key = do_aes_128(aes_128_pbkdf2)
    ntlm_hash = do_ntlm(password_str)
    
    # Print results
    print(f'\n[+] AES256 Key: {aes_256_key}')
    print(f'[+] AES128 Key: {aes_128_key}')
    print(f'[+] NTLM Hash:  {ntlm_hash}')


if __name__ == '__main__':
    main()

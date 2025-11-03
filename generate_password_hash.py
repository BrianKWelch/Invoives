#!/usr/bin/env python3
"""
Helper script to generate password hashes for Streamlit secrets
Usage: python generate_password_hash.py <password>
"""
import hashlib
import sys

def hash_password(password: str) -> str:
    """Hash a password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate_password_hash.py <password>")
        sys.exit(1)
    
    password = sys.argv[1]
    hashed = hash_password(password)
    print(f"Password hash: {hashed}")
    print("\nAdd this to your Streamlit secrets (.streamlit/secrets.toml):")
    print("\n[users]")
    print(f'admin = "{hashed}"  # or your username')


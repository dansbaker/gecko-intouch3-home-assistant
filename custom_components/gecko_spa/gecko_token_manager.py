#!/usr/bin/env python3
"""
Extract Gecko authentication tokens from Charles Proxy or manual input
"""

import json
import base64
from datetime import datetime

def extract_tokens_from_charles_log(file_path: str):
    """Extract tokens from Charles Proxy export (if you have one)"""
    try:
        with open(file_path, 'r') as f:
            data = f.read()
        
        # Look for common token patterns in Charles logs
        if 'access_token' in data:
            print("Found potential tokens in Charles log...")
            # This would need to be customized based on actual Charles export format
            
    except Exception as e:
        print(f"Could not read Charles log: {e}")

def manual_token_input():
    """Manually input tokens"""
    print("🔑 Manual Token Input")
    print("="*30)
    print("Please provide your Gecko authentication tokens.")
    print("You can get these from:")
    print("1. Charles Proxy captures of the mobile app")
    print("2. Browser developer tools during web login")
    print("3. Previous successful authentication\n")
    
    access_token = input("Access Token: ").strip()
    refresh_token = input("Refresh Token: ").strip()
    
    if not access_token or not refresh_token:
        print("❌ Both access token and refresh token are required")
        return None, None
    
    # Try to decode and validate access token
    try:
        # JWT tokens have 3 parts separated by dots
        payload = access_token.split('.')[1]
        # Add padding if needed
        payload += '=' * (4 - len(payload) % 4)
        decoded = base64.b64decode(payload)
        token_data = json.loads(decoded)
        
        print(f"\n✅ Token Analysis:")
        print(f"   Issuer: {token_data.get('iss', 'Unknown')}")
        print(f"   Subject: {token_data.get('sub', 'Unknown')}")
        print(f"   Audience: {token_data.get('aud', 'Unknown')}")
        
        if 'exp' in token_data:
            exp_time = datetime.fromtimestamp(token_data['exp'])
            print(f"   Expires: {exp_time}")
            if exp_time < datetime.now():
                print("   ⚠️  Token appears to be expired")
        
    except Exception as e:
        print(f"⚠️  Could not decode token (may still be valid): {e}")
    
    return access_token, refresh_token

def save_tokens_to_file(access_token: str, refresh_token: str, filename: str = "gecko_tokens.json"):
    """Save tokens to a file for later use"""
    tokens = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "saved_at": datetime.now().isoformat()
    }
    
    with open(filename, 'w') as f:
        json.dump(tokens, f, indent=2)
    
    print(f"💾 Tokens saved to {filename}")

def load_tokens_from_file(filename: str = "gecko_tokens.json"):
    """Load tokens from a file"""
    try:
        with open(filename, 'r') as f:
            tokens = json.load(f)
        
        return tokens.get('access_token'), tokens.get('refresh_token')
        
    except FileNotFoundError:
        print(f"Token file {filename} not found")
        return None, None
    except Exception as e:
        print(f"Error loading tokens: {e}")
        return None, None

def main():
    print("🦎 Gecko Token Manager")
    print("="*25)
    print()
    
    # Try to load existing tokens first
    access_token, refresh_token = load_tokens_from_file()
    
    if access_token and refresh_token:
        print("✅ Found saved tokens")
        use_saved = input("Use saved tokens? (y/n): ").strip().lower()
        if use_saved == 'y':
            print("Using saved tokens")
            return access_token, refresh_token
    
    # Get tokens manually
    access_token, refresh_token = manual_token_input()
    
    if access_token and refresh_token:
        save_tokens = input("\nSave tokens for future use? (y/n): ").strip().lower()
        if save_tokens == 'y':
            save_tokens_to_file(access_token, refresh_token)
        
        print(f"\n🎯 Ready to use tokens with GeckoHotTubController!")
        print(f"Usage example:")
        print(f"  controller = GeckoHotTubController(")
        print(f"      access_token='{access_token[:20]}...',")
        print(f"      refresh_token='{refresh_token[:20]}...'")
        print(f"  )")
        
        return access_token, refresh_token
    
    return None, None

if __name__ == "__main__":
    main()

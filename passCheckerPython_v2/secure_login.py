"""Secure Login System with Password Strength Validation and OTP (MFA)

Objectives Implemented:
1. Password strength validation using regular expressions.
2. Generation and verification of a one-time password (OTP) for second-factor authentication.
3. Demonstrates the principle of Multi-Factor Authentication (MFA):
   - Factor 1: Something you KNOW (username + password)
   - Factor 2: Something you HAVE (a transient OTP delivered via an out-of-band channel; here we simulate by printing it)

Usage (interactive):
    python secure_login.py

Optional flags:
    --demo      Run a non-interactive demonstration flow.

Security Notes:
- Passwords are stored only as salted PBKDF2-HMAC hashes (never in plaintext).
- OTP codes are 6-digit numeric values, cryptographically generated, expiring after a short window.
- Rate-limiting is applied for password attempts and OTP attempts.

This is an educational example and omits production concerns such as secure secret delivery, audit logs, lockout policies, and anti-enumeration strategies.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import sys
import time
import hashlib
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

# Optional TOTP support
try:
    import pyotp  # type: ignore
except ImportError:  # pragma: no cover - handled gracefully if not installed
    pyotp = None  # type: ignore

# ----------------------------- Password Policy ---------------------------------
PASSWORD_POLICY = {
    "min_length": 8,
    "uppercase": 1,
    "lowercase": 1,
    "digits": 1,
    "special": 1,
    "allowed_specials": r"!@#$%^&*()_+\-={}\[\]:;\"'`~<>,.?/\\|"  # used for explanation only
}

PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{%d,}$" % PASSWORD_POLICY["min_length"]
)

# ----------------------------- User Store (In-Memory) --------------------------
# For persistence across runs, replace with file or database. Here we show a JSON file cache.
USER_STORE_FILE = "users.json"

@dataclass
class UserRecord:
    username: str
    password_hash: str  # format: algo$iterations$salt_hex$hash_hex
    totp_secret: Optional[str] = None  # presence enables TOTP second factor

# ----------------------------- Helper Functions --------------------------------

def load_users() -> Dict[str, UserRecord]:
    """Load users from the JSON user store.

    Returns:
        Dict[str, UserRecord]: Mapping of username -> UserRecord. Empty dict on error/missing file.
    Notes:
        Swallows broad exceptions intentionally for a smooth classroom demo. In production,
        handle JSON errors explicitly and log them.
    """
    if not os.path.exists(USER_STORE_FILE):
        return {}
    try:
        with open(USER_STORE_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        users: Dict[str, UserRecord] = {}
        for u, data in raw.items():
            users[u] = UserRecord(
                username=u,
                password_hash=data.get("password_hash", ""),
                totp_secret=data.get("totp_secret")
            )
        return users
    except Exception:
        return {}

def save_users(users: Dict[str, UserRecord]) -> None:
    """Persist all users to disk in JSON format.

    Args:
        users: Mapping of usernames to UserRecord.
    Security:
        TOTP secrets are stored in plain text here (educational simplification). In real systems,
        encrypt or store secrets in a dedicated secrets manager.
    """
    serializable = {
        u: {"password_hash": rec.password_hash, "totp_secret": rec.totp_secret}
        for u, rec in users.items()
    }
    with open(USER_STORE_FILE, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2)

# ----------------------------- Password Hashing --------------------------------

def hash_password(password: str, *, iterations: int = 130_000) -> str:
    """Return a salted PBKDF2-HMAC-SHA256 hash string.

    Format: ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>``

    Args:
        password: Plaintext password (never stored)
        iterations: PBKDF2 iteration count (tunable work factor)
    Returns:
        Parameterized encoded hash string that includes algorithm, iteration count, salt and hash.
    """
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"

def verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored PBKDF2 hash string.

    Args:
        password: Candidate plaintext password.
        stored: Stored hash produced by ``hash_password``.
    Returns:
        True if the password matches; False otherwise or on parse error.
    """
    try:
        algo, iterations_s, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iterations_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        test = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        # constant-time compare
        return secrets.compare_digest(expected, test)
    except Exception:
        return False

# ----------------------------- Password Validation -----------------------------

def validate_password(password: str) -> Tuple[bool, str]:
    """Validate password strength against policy.

    Args:
        password: Candidate password.
    Returns:
        (ok, message) where ok indicates policy pass and message provides feedback.
    """
    if not PASSWORD_REGEX.match(password):
        reasons = []
        if len(password) < PASSWORD_POLICY["min_length"]:
            reasons.append(f"at least {PASSWORD_POLICY['min_length']} characters")
        if not re.search(r"[A-Z]", password):
            reasons.append("an uppercase letter")
        if not re.search(r"[a-z]", password):
            reasons.append("a lowercase letter")
        if not re.search(r"\d", password):
            reasons.append("a digit")
        if not re.search(r"[^A-Za-z0-9]", password):
            reasons.append("a special character")
        return False, "Password must contain: " + ", ".join(reasons)
    return True, "Strong password."

# ----------------------------- OTP Management ----------------------------------
@dataclass
class OTPRecord:
    code: str
    expires_at: float
    attempts_left: int

OTP_LENGTH = 6
OTP_TTL_SECONDS = 120  # 2 minutes
OTP_MAX_ATTEMPTS = 3

_active_otps: Dict[str, OTPRecord] = {}

def generate_otp(username: str) -> str:
    """Generate and store a single-use numeric OTP for a user.

    Args:
        username: User identifier.
    Returns:
        The generated 6-digit code (returned for simulation; would be sent out-of-band in production).
    Side Effects:
        Creates/overwrites an OTPRecord in the in-memory store with expiry & attempt counter.
    """
    code = ''.join(secrets.choice('0123456789') for _ in range(OTP_LENGTH))
    _active_otps[username] = OTPRecord(code=code, expires_at=time.time() + OTP_TTL_SECONDS, attempts_left=OTP_MAX_ATTEMPTS)
    return code

def verify_otp(username: str, code: str) -> bool:
    """Validate a submitted OTP for a user.

    Args:
        username: User identifier.
        code: Submitted OTP string.
    Returns:
        True if valid (and consumes it). False if invalid, expired, or attempts exceeded.
    """
    rec = _active_otps.get(username)
    if not rec:
        return False
    if time.time() > rec.expires_at:
        del _active_otps[username]
        return False
    if rec.attempts_left <= 0:
        del _active_otps[username]
        return False
    rec.attempts_left -= 1
    if secrets.compare_digest(rec.code, code):
        del _active_otps[username]
        return True
    if rec.attempts_left <= 0:
        del _active_otps[username]
    return False

# ----------------------------- Core Flows --------------------------------------

def register(users: Dict[str, UserRecord]) -> None:
    """Interactive registration flow: prompts for unique username and strong password.

    Persists the new user on success. Re-prompts until requirements met.
    """
    print("=== Registration ===")
    while True:
        username = input("Choose username: ").strip()
        if not username:
            print("Username cannot be empty.")
            continue
        if username in users:
            print("Username already exists.")
            continue
        break
    while True:
        pwd1 = getpass.getpass("Create password: ")
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd1 != pwd2:
            print("Passwords do not match.")
            continue
        ok, msg = validate_password(pwd1)
        print(msg)
        if not ok:
            continue
        break
    users[username] = UserRecord(username=username, password_hash=hash_password(pwd1))
    save_users(users)
    print("User registered successfully.\n")

LOGIN_MAX_ATTEMPTS = 5

def login(users: Dict[str, UserRecord]) -> Optional[str]:
    """Interactive primary-factor authentication (username + password).

    Returns:
        Username on successful password verification; None if attempts exhausted or failure.
    """
    print("=== Login ===")
    attempts = LOGIN_MAX_ATTEMPTS
    while attempts > 0:
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        user = users.get(username)
        if user and verify_password(password, user.password_hash):
            print("Password verified. Proceeding to OTP (second factor)...")
            return username
        attempts -= 1
        print(f"Invalid credentials. Attempts left: {attempts}")
    print("Too many failed attempts.")
    return None

def second_factor(username: str, user: UserRecord) -> bool:
    """Perform second factor verification.

    Selection Logic:
        - If user has a TOTP secret and `pyotp` is available -> prompt for rolling TOTP.
        - Otherwise -> generate & validate a fallback single-use OTP.
    Returns:
        True if second factor succeeds; False otherwise.
    """
    if user.totp_secret and pyotp:
        print("=== TOTP Verification (MFA Second Factor) ===")
        totp = pyotp.TOTP(user.totp_secret)
        for attempt in range(3):
            code = input("Enter current 6-digit TOTP (or 'q' to cancel): ").strip()
            if code.lower() == 'q':
                return False
            if totp.verify(code, valid_window=1):  # allow slight clock skew
                print("TOTP verified. Login successful.\n")
                return True
            else:
                print(f"Invalid TOTP. Attempts left: {2 - attempt}")
        print("Failed TOTP verification.")
        return False
    # Fallback OTP flow
    print("=== OTP Verification (MFA Second Factor) ===")
    otp = generate_otp(username)
    print(f"[Simulation] OTP for {username}: {otp}")
    while True:
        code = input("Enter the 6-digit OTP (or 'q' to cancel): ").strip()
        if code.lower() == 'q':
            return False
        if verify_otp(username, code):
            print("OTP verified. Login successful.\n")
            return True
        else:
            print("Invalid or expired OTP.")
            if username not in _active_otps:
                print("OTP no longer valid. Restart login.")
                return False
            else:
                rec = _active_otps[username]
                print(f"Attempts left for this OTP: {rec.attempts_left}")

# ----------------------------- Demo & CLI --------------------------------------

def interactive_main():
    """Main interactive loop presenting the menu and dispatching user choices."""
    users = load_users()
    menu = {
        '1': ("Register", lambda: register(users)),
        '2': ("Login", lambda: handle_login(users)),
        '3': ("Enroll TOTP (if pyotp installed)", lambda: enroll_totp(users)),
        '4': ("Quit", lambda: sys.exit(0))
    }
    while True:
        print("\nSecure Login System")
        for k, (label, _) in menu.items():
            print(f" {k}. {label}")
        choice = input("Select option: ").strip()
        action = menu.get(choice)
        if action:
            action[1]()
        else:
            print("Invalid choice.")

def handle_login(users: Dict[str, UserRecord]):
    """Wrapper to execute login followed by second factor and final welcome message."""
    username = login(users)
    if not username:
        return
    user = users.get(username)
    if not user:
        return
    if second_factor(username, user):
        print(f"Welcome, {username}! You are now authenticated with MFA.")

def enroll_totp(users: Dict[str, UserRecord]):
    """Enroll a user in TOTP MFA by generating and storing a new secret.

    Prompts for username, ensures existence & non-duplication, then prints provisioning URI
    which can be entered or converted to a QR code. Requires `pyotp`.
    """
    if not pyotp:
        print("pyotp not installed. Install with 'pip install pyotp' to use TOTP.")
        return
    username = input("Username to enroll TOTP: ").strip()
    user = users.get(username)
    if not user:
        print("User not found.")
        return
    if user.totp_secret:
        print("User already has TOTP enrolled.")
        return
    secret = pyotp.random_base32()
    user.totp_secret = secret
    save_users(users)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="SecureLoginDemo")
    print("TOTP enrollment successful.")
    print(f"Secret (store securely): {secret}")
    print("Add to your authenticator app using this URI or its QR code:")
    print(uri)
    print("Next login will request your TOTP code instead of a one-time printed OTP.")

# ----------------------------- Self Test / Demo --------------------------------

def demo_flow():
    """Run a scripted non-interactive demonstration of password + OTP success path."""
    print("Running demo flow...")
    users = {}
    pwd = "StrongP@ssw0rd!"
    users['alice'] = UserRecord(username='alice', password_hash=hash_password(pwd))
    assert verify_password(pwd, users['alice'].password_hash)
    username = 'alice'
    otp_code = generate_otp(username)
    assert verify_otp(username, otp_code) is True
    print("Demo completed: Password + OTP verified.")

# ----------------------------- Entry Point -------------------------------------

def parse_args(argv=None):
    """Parse command-line arguments.

    Args:
        argv: Optional custom argument list (defaults to sys.argv when None)
    Returns:
        argparse.Namespace with parsed flags.
    """
    p = argparse.ArgumentParser(description="Secure Login System with Password Strength and OTP.")
    p.add_argument('--demo', action='store_true', help='Run a scripted demo flow and exit.')
    return p.parse_args(argv)


def main():
    """Program entry point: decides between demo and interactive modes."""
    args = parse_args()
    if args.demo:
        demo_flow()
        return
    interactive_main()

if __name__ == '__main__':
    main()

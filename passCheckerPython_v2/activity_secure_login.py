"""Activity Version: Enhanced Secure Login System

Implements extended features for the assignment:
- Additional user profile fields: full_name, email (validated)
- Security question + hashed answer (case-insensitive)
- Password reset (account recovery) via security question
- Password history enforcement (no reuse of recent N)
- Centralized config for security tunables
- Account lockout after repeated failures (generic error messages)
- Audit logging (JSON lines)
- TOTP second factor (if pyotp installed) or fallback OTP
- Generic responses to reduce enumeration risk

NOTE: Educational example; not production ready.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass, asdict, field
from typing import Dict, Optional, Tuple, Any, List

# Optional TOTP support
try:
    import pyotp  # type: ignore
except ImportError:  # pragma: no cover
    pyotp = None  # type: ignore

# ---------------------------------- Config -------------------------------------
CONFIG = {
    "password_min_length": 8,
    "pbkdf2_iterations": 130_000,
    "otp_length": 6,
    "otp_ttl_seconds": 120,
    "otp_max_attempts": 3,
    "login_max_attempts": 5,
    "lockout_threshold": 5,          # failed password attempts before lockout
    "lockout_seconds": 120,          # lockout duration
    "password_history_depth": 3,     # number of previous hashes disallowed (plus current)
    "max_username_len": 32,
    "max_email_len": 254,
    "max_full_name_len": 80,
    "max_custom_question_len": 120,
}

# --------------------------------- Constants -----------------------------------
USER_STORE_FILE = "users_activity.json"
AUDIT_LOG_FILE = "auth_audit.log"
GENERIC_AUTH_FAIL = "Authentication failed."
GENERIC_RECOVERY_FAIL = "Recovery failed."
PASSWORD_POLICY = {
    "min_length": CONFIG["password_min_length"],
    "uppercase": 1,
    "lowercase": 1,
    "digits": 1,
    "special": 1,
}
PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{%d,}$" % PASSWORD_POLICY["min_length"]
)
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
TOKEN_NAME_REGEX = re.compile(r"^[A-Za-z](?:[A-Za-z'-]*[A-Za-z])?\.?$")

SECURITY_QUESTIONS = [
    "What is your favorite book?",
    "What city were you born in?",
    "What was the name of your first pet?",
    "Custom..."  # sentinel for user-provided
]

# --------------------------------- Dataclasses ---------------------------------
@dataclass
class UserRecord:
    username: str
    password_hash: str
    full_name: str
    email: str
    totp_secret: Optional[str] = None
    security_question: Optional[str] = None
    security_answer_hash: Optional[str] = None  # pbkdf2 hashed normalized answer
    password_history: List[str] = field(default_factory=list)  # previous password hashes
    failed_attempts: int = 0
    lock_until: Optional[float] = None

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)

# OTP record for fallback
@dataclass
class OTPRecord:
    code: str
    expires_at: float
    attempts_left: int

_active_otps: Dict[str, OTPRecord] = {}

# --------------------------------- Utilities -----------------------------------

def record_audit_event(event: str, username: str = "unknown", **details: Any) -> None:
    payload = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        "username": username,
        "ip": "127.0.0.1",  # placeholder for demo
        "details": details or None,
    }
    try:
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass  # non-fatal

def sanitize(s: str, *, max_len: int) -> str:
    s = s.strip()
    if len(s) > max_len:
        s = s[:max_len]
    # remove control characters
    s = ''.join(ch for ch in s if ch.isprintable())
    return s

def validate_full_name(name: str) -> bool:
    """Validate a full name.

    Rules (educational, simplified):
    - At least two tokens separated by whitespace.
    - Each token may be a word of letters (optionally containing ' or -) OR an initial (single letter with optional period).
    - Trailing period allowed only at end of token (for initials like "T.").
    Accepts: "Jane A. Doe", "Mary-Anne O'Neil", "John Q Public".
    """
    parts = [p for p in name.split() if p]
    if len(parts) < 2:
        return False
    return all(TOKEN_NAME_REGEX.match(p) for p in parts)

def validate_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

# --------------------------------- Persistence ---------------------------------

def load_users() -> Dict[str, UserRecord]:
    if not os.path.exists(USER_STORE_FILE):
        return {}
    try:
        with open(USER_STORE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        users: Dict[str, UserRecord] = {}
        for u, rec in data.items():
            users[u] = UserRecord(**rec)
        return users
    except Exception:
        return {}

def save_users(users: Dict[str, UserRecord]) -> None:
    serializable = {u: user.to_json() for u, user in users.items()}
    new_content = json.dumps(serializable, indent=2, ensure_ascii=False, sort_keys=True)
    try:
        if os.path.exists(USER_STORE_FILE):
            with open(USER_STORE_FILE, "r", encoding="utf-8") as f:
                current = f.read()
            if current == new_content:
                return
    except Exception:
        # If reading fails, proceed to write a fresh file
        pass
    tmp = f"{USER_STORE_FILE}.tmp-{secrets.token_hex(6)}"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(new_content)
    os.replace(tmp, USER_STORE_FILE)

# --------------------------------- Hashing -------------------------------------

def hash_pbkdf2(value: str, *, iterations: int | None = None) -> str:
    iterations = iterations or CONFIG["pbkdf2_iterations"]
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", value.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"

def verify_pbkdf2(value: str, stored: str) -> bool:
    try:
        algo, iterations_s, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iterations_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        test = hashlib.pbkdf2_hmac("sha256", value.encode(), salt, iterations)
        return secrets.compare_digest(expected, test)
    except Exception:
        return False

# Password-specific wrappers
hash_password = hash_pbkdf2
verify_password = verify_pbkdf2

def hash_security_answer(answer: str) -> str:
    # Normalize to lower-case trimmed to make answer comparison case-insensitive
    normalized = answer.strip().lower()
    return hash_pbkdf2(normalized)

def verify_security_answer(answer: str, stored_hash: str) -> bool:
    return verify_pbkdf2(answer.strip().lower(), stored_hash)

# --------------------------------- Password Policy -----------------------------

def validate_password(password: str) -> Tuple[bool, str]:
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

# --------------------------------- OTP / TOTP ----------------------------------

def generate_otp(username: str) -> str:
    length = CONFIG["otp_length"]
    code = str(secrets.randbelow(10 ** length)).zfill(length)
    _active_otps[username] = OTPRecord(
        code=code,
        expires_at=time.time() + CONFIG["otp_ttl_seconds"],
        attempts_left=CONFIG["otp_max_attempts"]
    )
    return code

def verify_otp(username: str, code: str) -> bool:
    rec = _active_otps.get(username)
    if not rec:
        return False
    if time.time() > rec.expires_at or rec.attempts_left <= 0:
        _active_otps.pop(username, None)
        return False
    rec.attempts_left -= 1
    if secrets.compare_digest(rec.code, code):
        _active_otps.pop(username, None)
        return True
    if rec.attempts_left <= 0:
        _active_otps.pop(username, None)
    return False

# --------------------------------- Account Helpers -----------------------------

def is_account_locked(user: UserRecord) -> bool:
    if user.lock_until and time.time() < user.lock_until:
        return True
    if user.lock_until and time.time() >= user.lock_until:
        # auto unlock
        user.lock_until = None
        user.failed_attempts = 0
    return False

def register_failed_attempt(user: UserRecord) -> None:
    user.failed_attempts += 1
    if user.failed_attempts >= CONFIG["lockout_threshold"]:
        user.lock_until = time.time() + CONFIG["lockout_seconds"]
        record_audit_event("lockout", user.username, until=user.lock_until)

# --------------------------------- Password History ----------------------------

def enforce_password_history(user: UserRecord, new_plain: str) -> bool:
    """Return True if the plaintext password has NOT been used recently.

    Compares the candidate plaintext against the current hash and prior
    password history entries using constant-time verification so that
    reusing the exact same password (even with a new salt producing a
    different hash) is still rejected.
    """
    depth = CONFIG["password_history_depth"]
    if depth <= 0:
        return True
    candidates = [user.password_hash] + user.password_history[: depth - 1]
    for h in candidates:
        if h and verify_password(new_plain, h):
            return False
    return True

def update_password_history(user: UserRecord, new_hash: str) -> None:
    # insert current into history before replacing
    if user.password_hash:
        user.password_history.insert(0, user.password_hash)
    user.password_history = user.password_history[: CONFIG["password_history_depth"] - 1]
    user.password_hash = new_hash

# --------------------------------- Registration --------------------------------

def register(users: Dict[str, UserRecord]) -> None:
    print("=== Registration ===")
    while True:
        username = sanitize(input("Choose username: "), max_len=CONFIG["max_username_len"]).lower()
        if not username:
            print("Username cannot be empty.")
            continue
        if username in users:
            print("Username already exists.")
            continue
        break
    while True:
        full_name = sanitize(input("Full name: "), max_len=CONFIG["max_full_name_len"])
        if not validate_full_name(full_name):
            print("Invalid full name (need at least two words, alphabetic).")
            continue
        break
    while True:
        email = sanitize(input("Email: "), max_len=CONFIG["max_email_len"]).lower()
        if not validate_email(email):
            print("Invalid email format.")
            continue
        if any(u.email == email for u in users.values()):
            print("Email already in use.")
            continue
        break
    # Password selection
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
        password_hash = hash_password(pwd1)
        break
    # Security question
    print("Security questions:")
    for idx, q in enumerate(SECURITY_QUESTIONS, start=1):
        print(f" {idx}. {q}")
    chosen: str
    while True:
        choice = input("Select question number: ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(SECURITY_QUESTIONS)):
            print("Invalid selection.")
            continue
        q_idx = int(choice) - 1
        if SECURITY_QUESTIONS[q_idx] == "Custom...":
            custom = sanitize(input("Enter custom question: "), max_len=CONFIG["max_custom_question_len"])
            if len(custom) < 10:
                print("Custom question too short.")
                continue
            chosen = custom
        else:
            chosen = SECURITY_QUESTIONS[q_idx]
        break
    while True:
        ans1 = getpass.getpass("Security answer: ")
        ans2 = getpass.getpass("Confirm security answer: ")
        if ans1 != ans2:
            print("Answers do not match.")
            continue
        if len(ans1.strip()) < 3:
            print("Answer too short.")
            continue
        answer_hash = hash_security_answer(ans1)
        break
    user = UserRecord(
        username=username,
        password_hash=password_hash,
        full_name=full_name,
        email=email,
        security_question=chosen,
        security_answer_hash=answer_hash,
    )
    users[username] = user
    save_users(users)
    record_audit_event("register", username)
    print("User registered successfully.\n")

# --------------------------------- Login --------------------------------------

def login(users: Dict[str, UserRecord]) -> Optional[str]:
    print("=== Login ===")
    attempts_left = CONFIG["login_max_attempts"]
    while attempts_left > 0:
        username = sanitize(input("Username: "), max_len=CONFIG["max_username_len"]).lower()
        password = getpass.getpass("Password: ")
        user = users.get(username)
        # Check lockout (and persist auto-unlock side effects once)
        dirty = False
        if user:
            pre_lock = user.lock_until
            locked = is_account_locked(user)
            if pre_lock and user.lock_until is None:
                dirty = True
            if locked:
                print(GENERIC_AUTH_FAIL)
                record_audit_event("login_fail", username, reason="locked")
                attempts_left -= 1
                if dirty:
                    save_users(users)
                continue
        if user and verify_password(password, user.password_hash):
            user.failed_attempts = 0
            user.lock_until = None
            save_users(users)
            print("Password verified. Proceeding to second factor...")
            record_audit_event("login_primary_ok", username)
            return username
        # failed path
        if user:
            # register failed attempt may set lock_until; persist after call
            register_failed_attempt(user)
            dirty = True
        record_audit_event("login_fail", username, reason="bad_credentials")
        attempts_left -= 1
        print(GENERIC_AUTH_FAIL)
        if dirty:
            save_users(users)
    print("Too many failures.")
    return None

# --------------------------------- Second Factor -------------------------------

def second_factor(user: UserRecord) -> bool:
    if user.totp_secret and pyotp:
        print("=== TOTP Verification ===")
        totp = pyotp.TOTP(user.totp_secret)
        for attempt in range(3):
            code = input("Enter TOTP (or q to cancel): ").strip()
            if code.lower() == 'q':
                record_audit_event("login_fail", user.username, reason="totp_cancel")
                return False
            if totp.verify(code, valid_window=1):
                record_audit_event("login_success", user.username, method="totp")
                print("Login successful.\n")
                return True
            else:
                print(GENERIC_AUTH_FAIL)
        record_audit_event("login_fail", user.username, reason="totp_exhaust")
        return False
    # Fallback OTP
    print("=== OTP Verification ===")
    otp = generate_otp(user.username)
    print(f"[Simulation] OTP (for demo only): {otp}")
    while True:
        code = input("Enter OTP (or q to cancel): ").strip()
        if code.lower() == 'q':
            record_audit_event("login_fail", user.username, reason="otp_cancel")
            return False
        if verify_otp(user.username, code):
            record_audit_event("login_success", user.username, method="fallback_otp")
            print("Login successful.\n")
            return True
        else:
            print(GENERIC_AUTH_FAIL)
            if user.username not in _active_otps:
                record_audit_event("login_fail", user.username, reason="otp_expired")
                return False
            rec = _active_otps[user.username]
            if rec.attempts_left <= 0:
                record_audit_event("login_fail", user.username, reason="otp_attempts")
                return False

# --------------------------------- TOTP Enrollment -----------------------------

def enroll_totp(users: Dict[str, UserRecord]) -> None:
    if not pyotp:
        print("TOTP library not installed (pip install pyotp).")
        return
    username = sanitize(input("Username to enroll TOTP: "), max_len=CONFIG["max_username_len"]).lower()
    user = users.get(username)
    if not user:
        print(GENERIC_AUTH_FAIL)
        return
    if user.totp_secret:
        print("Already enrolled.")
        return
    secret = pyotp.random_base32()
    user.totp_secret = secret
    save_users(users)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="ActivitySecureLogin")
    record_audit_event("totp_enroll", username)
    print("TOTP enrollment complete. Add this to your authenticator app:")
    print(f"Secret: {secret}")
    print(uri)

# --------------------------------- Password Reset -----------------------------

def password_reset_flow(users: Dict[str, UserRecord]) -> None:
    print("=== Password Recovery ===")
    username = sanitize(input("Username: "), max_len=CONFIG["max_username_len"]).lower()
    user = users.get(username)
    # Always show generic message timings to reduce enumeration
    if not user or not user.security_question:
        time.sleep(1)  # artificial delay
        print(GENERIC_RECOVERY_FAIL)
        record_audit_event("reset_start", username, status="user_not_found")
        return
    print(f"Security Question: {user.security_question}")
    answer = getpass.getpass("Answer: ")
    if not user.security_answer_hash or not verify_security_answer(answer, user.security_answer_hash):
        time.sleep(1)
        print(GENERIC_RECOVERY_FAIL)
        record_audit_event("reset_fail", username, reason="answer")
        return
    # New password
    while True:
        new1 = getpass.getpass("New password: ")
        new2 = getpass.getpass("Confirm new password: ")
        if new1 != new2:
            print("Mismatch.")
            continue
        ok, msg = validate_password(new1)
        print(msg)
        if not ok:
            continue
        if not enforce_password_history(user, new1):
            print("Cannot reuse recent password.")
            continue
        new_hash = hash_password(new1)
        update_password_history(user, new_hash)
        # reset failure counters
        user.failed_attempts = 0
        user.lock_until = None
        save_users(users)
        record_audit_event("reset_success", username)
        print("Password reset successful.")
        break

# --------------------------------- Main Menu ----------------------------------

def handle_login(users: Dict[str, UserRecord]) -> None:
    username = login(users)
    if not username:
        return
    user = users.get(username)
    if not user:
        return
    if second_factor(user):
        print(f"Welcome, {user.full_name}!")


def interactive_main():
    users = load_users()
    menu = {
        '1': ("Register", lambda: register(users)),
        '2': ("Login", lambda: handle_login(users)),
        '3': ("Enroll TOTP", lambda: enroll_totp(users)),
        '4': ("Forgot Password", lambda: password_reset_flow(users)),
        '5': ("Quit", lambda: sys.exit(0)),
    }
    while True:
        print("\nActivity Secure Login System")
        for k, (label, _) in menu.items():
            print(f" {k}. {label}")
        choice = input("Select option: ").strip()
        action = menu.get(choice)
        if action:
            action[1]()
        else:
            print("Invalid choice.")

# --------------------------------- Demo Flow ----------------------------------

def demo_flow():
    print("Running demo...")
    users: Dict[str, UserRecord] = {}
    # Minimal demo user
    user = UserRecord(
        username="demo",
        password_hash=hash_password("StrongP@ssw0rd!"),
        full_name="Demo User",
        email="demo@example.com",
        security_question="What is your favorite book?",
        security_answer_hash=hash_security_answer("Dune"),
    )
    users[user.username] = user
    # OTP path
    otp_code = generate_otp(user.username)
    assert verify_otp(user.username, otp_code)
    print("Demo complete: OTP generated & verified.")

# --------------------------------- CLI ----------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Activity Enhanced Secure Login System")
    p.add_argument("--demo", action="store_true", help="Run a scripted demo and exit")
    return p.parse_args(argv)


def main():
    args = parse_args()
    if args.demo:
        demo_flow()
        return
    interactive_main()

if __name__ == "__main__":
    main()

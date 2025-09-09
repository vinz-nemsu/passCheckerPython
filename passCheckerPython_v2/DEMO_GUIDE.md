# Demo Guide: Activity Secure Login System

This guide provides a structured 8–12 minute live presentation flow demonstrating key security features in `activity_secure_login.py`.

## Objectives to Demonstrate
1. Baseline registration and login (password + second factor).
2. Account lockout after repeated failed password attempts.
3. Password reset using a security question.
4. Password history enforcement (reject reuse of recent passwords).
5. Viewing the audit log to illustrate recorded security events.

---
## 1. Baseline Registration & Login (2–3 min)
Purpose: Show strong password requirements, security question capture, and MFA step.

Steps:
1. Choose menu option `1` (Register).
2. Enter a username (e.g., `student1`).
3. Provide a full name with possible middle initial: `Juan dela Cruz` (demonstrates updated validation acceptance).
4. Enter a valid email (e.g., `student1@example.com`).
5. Intentionally fail password once (e.g., `weakpass`) to trigger policy feedback.
6. Enter a strong password (e.g., `Str0ng!Pass123`).
7. Select a predefined security question and supply an answer (e.g., `Dune`).
8. Back at menu, pick `2` (Login):
   - Enter username + password.
   - If TOTP enrolled later, skip for now. Otherwise fallback OTP printed; enter code.
9. Show success message and note generic messages for failures.

Talking Points:
- Immediate password strength feedback.
- Hash storage (no plaintext) – optionally open `users_activity.json` in a separate editor tab.

---
## 2. Account Lockout (2–3 min)
Purpose: Demonstrate throttling of brute-force password attempts.

Setup: Use existing user (e.g., `student1`).

Steps:
1. Choose `2` (Login).
2. Enter correct username with an incorrect password repeatedly (≥ lockout threshold, default 5).
3. After exceeding attempts: observe generic failure messages each time.
4. Attempt one more login with the correct password—still blocked if within lockout window.
5. (Optional) Show `users_activity.json` snippet for `failed_attempts` / `lock_until` fields.

Talking Points:
- Generic error prevents username enumeration difference.
- Lockout window limits rapid guessing but can enable DoS if too aggressive.

---
## 3. Password Reset via Security Question (2–3 min)
Purpose: Show recovery flow relying on hashed security answer.

Steps:
1. Choose `4` (Forgot Password).
2. Enter existing username (e.g., `student1`).
3. Observe security question prompt.
4. Enter wrong answer first (demonstrate generic `Recovery failed`).
5. Run flow again, enter correct answer.
6. Provide a new strong password (e.g., `NewStr0ng!Pass456`).
7. Login with the new password to confirm reset succeeded.

Talking Points:
- Answers hashed (not stored raw); case-insensitive by normalization.
- Recovery still a weak link if questions are guessable—encourage better factors in production.

---
## 4. Password History Enforcement (1–2 min)
Purpose: Show rejection of recently used passwords.

Steps:
1. Initiate password reset again (option `4`).
2. Supply correct answer.
3. Attempt to reuse previous password (`Str0ng!Pass123`) – expect "Cannot reuse recent password." message.
4. Choose a different valid password (e.g., `YetAn0ther!Pass789`).
5. Login with the latest password to confirm success.

Talking Points:
- History depth defined by `CONFIG["password_history_depth"]`.
- Limitation: does not detect trivial variants (e.g., incrementing a number).

---
## 5. Display Audit Log Tail (1 min)
Purpose: Show recorded security events for accountability.

Command:
```powershell
Get-Content .\auth_audit.log -Tail 12
```

Explain typical entries:
- `register` – new user registration.
- `login_primary_ok` – password verified (pre-MFA).
- `login_success` – full MFA success (totp or fallback_otp method).
- `login_fail` – failed attempts (with reasons like `bad_credentials`, `locked`).
- `lockout` – account lock event.
- `reset_success` – password reset complete.
- `totp_enroll` – TOTP enrollment performed.

Talking Points:
- JSON lines facilitate simple ingestion into SIEM or log processing.
- No sensitive data (no passwords, OTP codes, or raw answers).

---
## Suggested Timing
| Segment | Time |
|---------|------|
| Baseline login | 3 min |
| Lockout | 2–3 min |
| Password reset | 3 min |
| History enforcement | 2 min |
| Log review | 1 min |
| Buffer/Q&A | 1–2 min |

---
## Troubleshooting Tips
| Issue | Resolution |
|-------|------------|
| Lockout persists | Wait lockout window or manually set `lock_until` to null in JSON. |
| TOTP codes rejected | Check system time sync; ensure pyotp installed. |
| OTP expired | Re-login to generate new code. |
| Reusing password passes | Confirm `password_history_depth` > 1 and code saved. |
| Unicode in names rejected | Validator restricts to letters, apostrophes, hyphens; adjust regex if needed. |

---
## Optional Add-ons to Mention
- Add QR code for TOTP (library: `qrcode`).
- Replace security questions with email token flow.
- Add Argon2id hashing.
- Implement exponential backoff instead of fixed lockout.

---
## Key Takeaways Slide (Sample Text)
"Layered defenses—strong passwords, salted iterative hashing, MFA, lockout, recovery controls, and audit logging—collectively reduce compromise risk, while still leaving improvement room around secret storage, delivery channels, and usability."

---
## Cleanup After Demo
```powershell
Remove-Item .\users_activity.json -ErrorAction SilentlyContinue
Remove-Item .\auth_audit.log -ErrorAction SilentlyContinue
```

---
End of Instructor Demo Guide.

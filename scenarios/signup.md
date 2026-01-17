# Signup Flow - Complete Scenarios

## Phase 1: Input Validation (Before DB Check)

1. Validate email format (RFC 5322)
2. Check password strength:
   - Minimum 12 characters
   - Contains uppercase, lowercase, number, special char
3. Validate username:
   - 3-30 characters
   - Alphanumeric + underscore/dash only
   - Not reserved words (admin, root, system, etc.)
4. Sanitize all inputs to prevent XSS/injection

## Phase 2: Rate Limiting

5. Check IP-based rate limit (5 attempts per hour)
   - If exceeded: return 429 with retry-after header
6. Check email-based rate limit (3 attempts per 24h)
   - Prevents spam to same email

## Phase 3: Username Availability

7. Check if username already taken
   - If taken: immediate error "Username unavailable"
   - Don't reveal if it exists for security

## Phase 4: Email Existence Check

8. Check if email exists in:
   - Main users table (verified accounts)
   - Pending signups table (unverified)

### Scenario A: Email Already Verified (In Users Table)

9. Display: "Check your email inbox" (same as new signup)
10. Send email with subject: "Account Access Attempt"
    - Message: "Someone tried to create an account with this email. If this was you, you already have an account. [Login here](login_url) or [Reset password](reset_url). If this wasn't you, ignore this email."
11. Log attempt with IP for security monitoring

### Scenario B: Email in Pending Signups (Unverified)

12. Check if previous token expired:
    - **If expired (>30 min):**
      - Delete old pending signup
      - Create new pending signup with new token
      - Send new verification email
    - **If still valid (<30 min):**
      - Display: "Check your email inbox"
      - Option 1: Resend same token (update sent_at timestamp)
      - Option 2: Generate new token, invalidate old one
13. Include "Didn't receive email?" link on confirmation page

### Scenario C: Email Does Not Exist (New Signup)

14. Hash password using Argon2id
15. Generate cryptographically secure token (32 bytes, URL-safe)
16. Create PendingSignup record:
    - username
    - email
    - password_hash
    - verification_token
    - created_at
    - expires_at (now + 30 minutes)
17. Display: "Check your email inbox to verify your account"
18. Send verification email:
    - Subject: "Verify your account"
    - Message: "Click to verify your signup: [Verify](verify_url). Link expires in 30 minutes. Don't share this link. Didn't request this? Ignore this email."

## Phase 5: Verification Click

19. User clicks verification link: `GET /verify?token={token}`

### Scenario D: Valid Token

20. Look up token in pending_signups table
21. Verify token hasn't expired
22. Move data to users table:
    - Copy username, email, password_hash
    - Set email_verified = true
    - Set created_at = now()
23. Delete from pending_signups table
24. Optional: Auto-login user (create session)
25. Redirect to: /login (or /dashboard if auto-login)
26. Display success message: "Account verified! You can now login"

### Scenario E: Expired Token

27. Display: "Verification link expired"
28. Show "Resend verification email" button
29. On resend click:
    - Check if pending signup still exists
    - If exists: generate new token, extend expiry
    - If deleted: user must restart signup

### Scenario F: Invalid/Malformed Token

30. Display: "Invalid verification link"
31. Suggest: "Try signing up again"
32. Log suspicious activity (potential attack)

### Scenario G: Token Already Used

33. Check if email already in users table (verified)
34. Display: "This account is already verified"
35. Redirect to login page

## Phase 6: Cleanup & Maintenance

36. Background job runs every 15 minutes:
    - Delete expired pending signups (>30 minutes old)
    - Delete old verification tokens
37. Maintain signup_attempts table for rate limiting
    - Clean up entries older than 24 hours

## Phase 7: Security Logging

38. Log all signup attempts with:
    - IP address
    - User agent
    - Timestamp
    - Success/failure reason
39. Monitor for patterns:
    - Multiple failed attempts from same IP
    - Same email attempted from different IPs
    - Suspicious timing patterns

## Additional Edge Cases

40. **User has multiple browser tabs open:**
    - Only first verification click succeeds
    - Others show "already verified"
41. **Email delivery failures:**
    - Queue for retry (3 attempts, exponential backoff)
    - Log failures for monitoring
42. **Database connection issues during verification:**
    - Show friendly error
    - Suggest retry
    - Don't delete pending signup yet
43. **User changes mind before verifying:**
    - Pending signup auto-deletes after 30 min
    - They can re-signup with same email

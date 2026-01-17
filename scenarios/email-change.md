### Email Change Flow

**Prerequisites**

- User must be authenticated with valid access token
- New email must be different from current email
- New email must not already exist in the system
- User can only have one pending email change at a time

### Step-by-Step Process

**Phase 1: Request Email Change**

1. User submits request with access token and new email
2. Server validates access token and extracts user identity
3. Server checks if new email format is valid
4. Server checks if new email already exists in database
5. Server checks if user has pending email change (if yes, reject or overwrite)
6. Server generates verification token and stores in Redis with user_id + new_email
7. Server sends verification email to **new email address**
8. Server sends notification email to **old email address** with "cancel change" link
9. Server returns success response

**Phase 2: Verify New Email**

10. User clicks verification link in new email inbox
11. Server validates token exists in Redis and hasn't expired
12. Server retrieves user_id and new_email from Redis
13. Server updates user's email in database
14. Server deletes verification token from Redis
15. Server invalidates current access token (forces re-login)
16. Server returns success response

**Phase 3: Cancel Change (Optional)**

17. User clicks "This wasn't me" link in old email
18. Server validates cancellation token
19. Server deletes pending email change from Redis
20. Server sends confirmation to old email that change was cancelled

### Conditions \& Edge Cases

**Rate Limiting**

- Maximum 3 email change requests per hour per user

**Token Expiry**

- Verification token expires after 15 minutes
- Cancellation token expires after 15 minutes

**Concurrent Changes**

- If new request arrives while one is pending, overwrite previous request

**Token Reuse Prevention**

- Token deleted after successful verification
- Token deleted after cancellation

**Email Already Taken**

- Return generic "Unable to change email" message (don't reveal if email exists)

**Same Email**

- Reject if new email matches current email

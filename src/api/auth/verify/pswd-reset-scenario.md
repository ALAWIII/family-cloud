# Password Reset Flow

## 1. User requests password reset

- **Action:** `POST /api/auth/password-reset`
- **Body:** `{ "email": "user@example.com" }`
- **Server checks:** `email exists?`
  - **If false:**
    - Return `200 OK`
    - Message: `"If account exists, check your email"`
  - **If true:**
    - Return `200 OK` (same message)
    - Send email to user containing **URL + token**

---

## 2. User clicks the email link

- **Frontend:** Extracts `token` from URL
- **Action:** `POST /api/auth/consume`
- **Body:** `{ "token": "<token>" }`
- **Server checks:** `token.expired()?`
  - **If true:**
    - Return `400 Bad Request`
    - Message: `"Token expired, request a new password reset"`
  - **If false:**
    - Return `200 OK`
    - Frontend shows **"Enter new password"** page/form

---

## 3. User sets new password

- **Action:** `POST /api/auth/password-reset/confirm`
- **Body:** `{ "token": "<token>", "new_password": "<new_password>" }`
- **Server checks:** `token.expired()?`
  - **If false:**
    - Update password
    - Consume/delete token
    - Return `200 OK`
  - **If true:**
    - Return `400 Bad Request`
    - Message: `"Token expired, request a new password reset"`

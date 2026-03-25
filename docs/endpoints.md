
## Auth endpoints

| Method | Path | Auth | Request (where \& type) | Success (status \& body) | Key errors (status → meaning) | Notes |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| POST | `/api/auth/signup` | Public | Body JSON `SignupRequest { username: String, email: String, password: SecretString }` | `200 OK`, empty/implicit body | `400` BadRequest (validation), `500` Internal (infra) | Returns 200 even if email already exists; real check is silent to avoid enumeration. |
| GET | `/api/auth/signup` | Public | Query `TokenPayload { token: SecretString }` | `201 Created`, empty body | `401` Unauthorized (bad/expired token), `500` Internal | Verifies email, creates user, root folder, bucket; token is deleted from Redis on success. |
| POST | `/api/auth/login` | Public | Body JSON `Credentials { email: String, password: SecretString }` | `200 OK` `LoginResponse { access_token: String, refresh_token: String, user: UserProfile }` | `401` Unauthorized (wrong email/password), `503` ServiceUnavailable (DB/Redis) | Returns both JWT access token and opaque refresh token stored in Redis. |
| POST | `/api/auth/logout` | Public\* | Refresh token in cookie **or** body JSON `TokenPayload { token: SecretString }` | `204 No Content` | `401` Unauthorized (missing/invalid refresh), `503` ServiceUnavailable (Redis) | Stateless w.r.t. JWT; just revokes refresh token in Redis. |
| POST | `/api/auth/refresh` | Public\* | Refresh token in cookie **or** body JSON `TokenPayload { token: SecretString }` | `200 OK` `TokenPayload { token: SecretString }` (new access JWT) | `401` Unauthorized (bad/expired/unknown refresh), `503` ServiceUnavailable (Redis/crypto) | Does not rotate refresh; just issues new short‑lived access JWT. |
| POST | `/api/auth/password-reset` | Public | Body JSON `EmailInput { email: String }` | `200 OK`, empty/implicit | `400` BadRequest (malformed email), `503` ServiceUnavailable (email/DB/Redis) | Always returns 200; if account exists, sends reset email with short‑lived token. |
| GET | `/api/auth/password-reset` | Public | Query `TokenPayload { token: SecretString }` | `200 OK` HTML form, or `400/401` on invalid token | `400` BadRequest (malformed), `401` Unauthorized (missing/expired token) | Only checks token and renders password reset form. |
| POST | `/api/auth/password-reset/confirm` | Public | Form `PasswordResetForm { token: String, new_password: String, confirm_password: String }` | `200 OK`, empty/implicit | `400` BadRequest (passwords mismatch), `401` Unauthorized (invalid/expired token), `503` Internal (DB) | Updates password and deletes token from Redis; one‑time use. |
| POST | `/api/auth/change-email` | JWT (user) | Header `Authorization: Bearer <access_jwt>`, body JSON `EmailInput { email: String }` | `202 Accepted`, empty/implicit | `400` BadRequest (invalid email), `409` Conflict (email taken), `503` ServiceUnavailable (DB/Redis/email) | Sends cancel link to old email and verify link to new email; change is deferred. |
| GET | `/api/auth/change-email/verify` | Public | Query `TokenPayload { token: SecretString }` | `200 OK`, empty/implicit | `401` Unauthorized (bad/expired token), `404` NotFound (user missing), `409` Conflict (DB duplicate) | Confirms email change and removes token from Redis. |
| GET | `/api/auth/change-email/cancel` | Public | Query `TokenPayload { token: SecretString }` | `200 OK`, empty/implicit | `400` BadRequest (invalid/used token) | Only deletes the change‑email token; no account changes. |


## Object endpoints (JWT protected)

| Method | Path | Auth | Request (where \& type) | Success (status \& body) | Key errors (status → meaning) | Notes |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| GET | `/api/objects` | JWT (user) | Header `Authorization: Bearer <access_jwt>` | `200 OK` `Vec<FolderChild>` | `503` ServiceUnavailable (DB) | Returns all active file/folder ids for the user (flat list for sync). |
| POST | `/api/objects` | JWT (user) | Query `UploadQuery { parent_id: Uuid }`; headers: `Object-Type: "file"|"folder"`, `Object-Name: String`, for files also `Content-Length: i64`, optional `Content-Type`, checksum; body = raw stream | Folder: `201 Created` `FolderRecord`; File: `201 Created` `FileRecord` | `400` BadRequest (headers/name/checksum), `409` Conflict (name exists), `413` ObjectTooLarge, `422` ChecksumMismatch, `503` Internal | Creates folder or uploads file via multipart saga; enforces quota and checksum. |
| DELETE | `/api/objects` | JWT (user) | Body JSON `Vec<DeleteRequest { f_id: Uuid, kind: ObjectKind }>` | `200 OK` `usize` (number of delete jobs queued) | `400` BadRequest (empty list), `409` Conflict (delete blocked), `503` ServiceUnavailable (DB/worker) | Marks DB objects deleted and enqueues background RustFS deletes. |
| GET | `/api/objects/{id}` | JWT (user) | Path `{ id: Uuid }`, Query `ObjectKindQuery { kind: ObjectKind }` | `200 OK` `FileRecord` or `FolderRecord` | `404` NotFound (not owned/deleted), `503` ServiceUnavailable (DB) | Only returns active or copying objects for the owner. |
| PATCH | `/api/objects/{id}` | JWT (user) | Path `{ id: Uuid }`, body JSON `UpdateMetadata { metadata: serde_json::Value }` | `200 OK` `UpdateMetadata` | `404` NotFound (file missing/wrong owner), `503` ServiceUnavailable (DB) | Updates JSONB metadata for files only; folders have no metadata field. |
| GET | `/api/objects/children/{id}` | JWT (user) | Path `{ id: Uuid }` (folder id) | `200 OK` `Vec<FolderChild>` | `503` ServiceUnavailable (DB) | Lists direct (non‑recursive) children of a folder. |
| POST | `/api/objects/move` | JWT (user) | Body JSON `MoveRequest { source_id: Uuid, destination_id: Uuid, object_kind: ObjectKind }` | `200 OK` `MoveResponse { f_id: Uuid }` | `404` NotFound (source/destination), `409` Conflict (name conflict / cyclic move), `503` ServiceUnavailable (DB) | SQL guards against moving into own descendant; conflict used for name/cycle issues. |
| POST | `/api/objects/copy` | JWT (user) | Body JSON `CopyRequest { dest_folder_id: Uuid, f_list: Vec<{ f_id: Uuid, kind: ObjectKind }> }` | `200 OK` `usize` (copy jobs queued) | `400` BadRequest (empty list), `404` NotFound (some ids), `503` ServiceUnavailable (DB/worker) | DB stage marks records “copying”; RustFS copy done by workers. |
| POST | `/api/objects/shares` | JWT (user) | Body JSON `SharedObjectReq { f_id: Uuid, object_kind: ObjectKind, ttl: i64 }` | `200 OK` `SharedTokenResponse { token: String }` | `400` BadRequest (ttl <= 0), `404` NotFound (object), `503` ServiceUnavailable (DB/Redis) | Reuses existing share token per object if present, extending TTL via Lua script. |
| GET | `/api/objects/{id}/download` | JWT (user) | Path `{ id: Uuid }`, Query `ObjectKindQuery { kind: ObjectKind }` | `200 OK` `TokenPayload { token: String }` (download token) | `404` NotFound (not owned/deleted), `429` TooManyDownloads (limit reached), `503` ServiceUnavailable (DB/Redis) | Issues short‑lived download token bound to user and IP; used by `/api/objects/stream`. |

## Streaming \& share endpoints

| Method | Path | Auth | Request (where \& type) | Success (status \& body) | Key errors (status → meaning) | Notes |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| GET | `/api/shares/{token}` | Share token | Path `{ token: Uuid }`, Query `AccessQuery { id: Option<Uuid>, kind: Option<ObjectKind> }` | `200 OK` `FileShared` or `FolderShared` JSON | `403` Forbidden (invalid/expired token or out‑of‑scope child), `503` ServiceUnavailable (Redis/DB) | For folders, can also access descendants if within shared subtree (validated in DB). |
| GET | `/api/objects/stream` | Download token | Query `StreamQuery { token: Uuid, download: Option<bool> }`; headers optional `Range: bytes=...` | `200 OK` or `206 Partial Content`, streaming file or ZIP body | `400` BadRequest (invalid Range), `401` Unauthorized (bad/expired token/IP change), `429` TooManyDownloads, `503` ServiceUnavailable | Authenticated streaming via `/download` token; enforces per‑user concurrent stream limit in Redis. |
| GET | `/api/objects/stream/share` | Share token + IP | Query `StreamShareQuery { token: Uuid, target_id: Option<Uuid>, is_folder: Option<bool>, download: Option<bool> }`; headers optional `Range: bytes=...` | `200/206`, streaming shared file or ZIP | `400` BadRequest (child/file mismatch), `401` Unauthorized (bad share token), `403` Forbidden (out‑of‑scope), `429` TooManyDownloads, `503` ServiceUnavailable | Anonymous/unauth streaming for shares; per‑IP concurrent limit tracked in Redis. |

## User \& storage endpoints (JWT protected)

| Method | Path | Auth | Request (where \& type) | Success (status \& body) | Key errors (status → meaning) | Notes |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| GET | `/api/users/me` | JWT (user) | Header `Authorization: Bearer <access_jwt>` | `200 OK` `UserProfile` | `404` NotFound (user deleted), `503` ServiceUnavailable | Basic profile for settings / UI. |
| PATCH | `/api/users/me` | JWT (user) | Body JSON `UpdateUserNameOps { user_name: String }` | `200 OK` `UpdateUserNameOps` (updated) | `400` BadRequest (name too long), `503` ServiceUnavailable | Simple username update only. |
| DELETE | `/api/users/me` | JWT (user) | JWT, refresh token in cookie or body `TokenPayload { token: SecretString }` | `200/204` (account deleted, jobs queued) | `401` Unauthorized (refresh invalid), `503` ServiceUnavailable | Schedules delete of all files + possibly bucket. |
| GET | `/api/storage/usage` | JWT (user) | JWT | `200 OK` `UserStorageInfo` | `503` ServiceUnavailable | Returns quota and used bytes for the user. |


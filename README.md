# PSNA secure password recovery

Independent implementation for PSNA Feedback. **The original PSNA-feedback repository has not been changed.**

## Features
- Student and Admin email recovery; no login JWT required.
- Gmail SMTP with TLS and server-side App Password.
- Six-digit OTP from Node crypto; keyed HMAC-SHA256 at rest.
- Five-minute OTP expiry, five failed attempts, sixty-second resend cooldown.
- PostgreSQL row locking to prevent concurrent OTP reuse.
- Verified OTP exchanges for 256-bit random, single-use reset proof (5 minutes).
- bcrypt cost 12; password change and old-JWT invalidation are atomic.
- Generic email response to reduce account enumeration.

## Files
- `src/recovery.js`: Express router and PostgreSQL schema setup.
- `src/sessionVersion.js`: JWT session-version checks.
- `src/ForgotPassword.jsx`: React recovery form for student/admin.
- `.env.example`: SMTP and OTP hashing secret placeholders.
- `test/sessionVersion.test.js`: basic session-version tests.

## Integration (NOT YET DONE)
1. Make this new repository private; GitHub currently reports it as public.
2. Add `nodemailer` to the original application's dependencies. Keep `SMTP_USER`, `SMTP_APP_PASSWORD`, `SMTP_FROM`, `RECOVERY_HMAC_KEY` in its server-side `.env`, never GitHub or `VITE_*`.
3. After the original database initializes, run `await setupRecoverySchema(pool)` from `src/recovery.js`.
4. Register `app.use('/api/auth', createRecoveryRouter({pool}))` in the Express app. Endpoints are `/api/auth/forgot-password`, `/api/auth/verify-otp`, and `/api/auth/reset-password`; no JWT or feedback-open middleware on these.
5. All JWT issuers (student login, signup, Google login, admin login) must read `session_version` from DB and include `sessionVersion` in JWT claims. All protected middleware must call `checkSessionVersion(pool,claims)` after verifying signature. Older JWTs lacking a version will be rejected.
6. The existing student change-password API must increment `session_version` too.
7. Render `<ForgotPassword role="student" onBack={...}/>` and `<ForgotPassword role="admin" onBack={...}/>` from their respective login screens.

## Required tests before deployment
- `npm install && npm test && npm run check`.
- Real PostgreSQL/Gmail: registered/unregistered email, valid/invalid/expired OTP, attempt limit, cooldown, SMTP outage.
- Concurrency: two simultaneous OTP verifies and two simultaneous resets; only one should succeed.
- Old JWT rejected after reset for both roles; new JWT accepted. Test every login method.
- Review HTTPS, CORS allowlist, shared rate-limit storage (current limiter is per process), audit logs, deployment secrets, and operational recovery.

**Status:** Source code added to this separate repository. It has not been integrated into PSNA-feedback or validated against a live database or Gmail. It is not yet production-certified.

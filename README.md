# totallins-auth

Totallins shared authentication service.

## What This Does

- Shared login for `totallins-hub` and `totallins-card`
- Session cookie issuance and validation
- Initial account activation flow
- Operations center UI at `/admin/`
- Shared `/api/auth/*` endpoints for Netlify deployments

## Endpoints

- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `POST /api/auth/activate`
- `GET /api/admin/dashboard`
- `POST /api/admin/employee-import`
- `POST /api/admin/employee-reset-password`
- `POST /api/admin/employee-active`
- `POST /api/admin/employee-update`
- `POST /api/admin/employee-delete`
- `GET /api/health`

## Required Netlify Environment Variables

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `SESSION_COOKIE_NAME`
  - Example: `totallins_auth_session`
- `SESSION_COOKIE_DOMAIN`
  - Leave empty for temporary `*.netlify.app`
  - Use `.babymusic.co.kr` after custom domain setup
- `SESSION_TTL_DAYS`
  - Example: `7`
- `AUTH_ALLOWED_ORIGINS`
  - Comma-separated list
  - Example: `https://hub.babymusic.co.kr,https://card.babymusic.co.kr`

## Supabase Tables Used

- `employees`
- `auth_sessions`

This service assumes the existing schema already contains:

- `activation_status`
- `must_change_password`
- `temp_password_hash`
- `activated_at`

## Deploy

1. Upload these files to the `totallins-auth` repository.
2. Connect the repo to Netlify.
3. Add the environment variables above.
4. Deploy.
5. Check `GET /api/health`.

## Current Domains

- `https://auth.babymusic.co.kr`
- `https://hub.babymusic.co.kr`
- `https://card.babymusic.co.kr`

Current production settings:

- `SESSION_COOKIE_DOMAIN=.babymusic.co.kr`
- `AUTH_ALLOWED_ORIGINS=https://hub.babymusic.co.kr,https://card.babymusic.co.kr`

# totallins-auth

Totallins shared authentication service.

## What This Does

- Shared login for `totallins-hub` and `totallins-card`
- Session cookie issuance and validation
- Initial account activation flow
- Shared `/api/auth/*` endpoints for Netlify deployments

## Endpoints

- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `POST /api/auth/activate`
- `GET /api/health`

## Required Netlify Environment Variables

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `SESSION_COOKIE_NAME`
  - Example: `totallins_auth_session`
- `SESSION_COOKIE_DOMAIN`
  - Leave empty for temporary `*.netlify.app`
  - Use `.totallins.com` after custom domain setup
- `SESSION_TTL_DAYS`
  - Example: `7`
- `AUTH_ALLOWED_ORIGINS`
  - Comma-separated list
  - Example: `https://hub-totallins.netlify.app,https://card-totallins.netlify.app`

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

## Temporary Deployment Strategy

Before buying a custom domain, use:

- `https://auth-totallins.netlify.app`

Later, after you buy `totallins.com`, move to:

- `https://auth.totallins.com`

At that point, set:

- `SESSION_COOKIE_DOMAIN=.totallins.com`
- `AUTH_ALLOWED_ORIGINS=https://hub.totallins.com,https://card.totallins.com`

const {
  ok,
  fail,
  getOrigin,
  handleOptions,
  parseCookies,
  sha256,
  updateRow,
  getClearCookieHeader,
  getEnv,
} = require('./_lib/utils');

function getCookieName() {
  return String(getEnv('SESSION_COOKIE_NAME', 'totallins_auth_session')).trim() || 'totallins_auth_session';
}

exports.handler = async (event) => {
  const origin = getOrigin(event.headers);

  if (event.httpMethod === 'OPTIONS') {
    return handleOptions(event);
  }

  if (event.httpMethod !== 'POST') {
    return fail(405, 'METHOD_NOT_ALLOWED', 'POST only.', origin);
  }

  try {
    const cookieHeader = event.headers.cookie || event.headers.Cookie || '';
    const cookies = parseCookies(cookieHeader);
    const rawToken = cookies[getCookieName()];

    if (rawToken) {
      const tokenHash = sha256(rawToken);
      try {
        await updateRow('auth_sessions', 'session_token_hash', tokenHash, {
          revoked_at: new Date().toISOString(),
        });
      } catch (error) {
      }
    }

    return ok(
      { loggedOut: true },
      {
        'Set-Cookie': getClearCookieHeader(),
      },
      origin
    );
  } catch (error) {
    return fail(500, 'LOGOUT_FAILED', 'Logout failed.', origin);
  }
};

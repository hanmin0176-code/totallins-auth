const { ok, fail, getOrigin, handleOptions, getEnv } = require('./_lib/utils');

exports.handler = async (event) => {
  const origin = getOrigin(event.headers);

  if (event.httpMethod === 'OPTIONS') {
    return handleOptions(event);
  }

  if (event.httpMethod !== 'GET') {
    return fail(405, 'METHOD_NOT_ALLOWED', 'GET only.', origin);
  }

  const hasSupabaseUrl = Boolean(getEnv('SUPABASE_URL'));
  const hasServiceRoleKey = Boolean(getEnv('SUPABASE_SERVICE_ROLE_KEY'));

  return ok(
    {
      service: 'totallins-auth',
      status: 'ok',
      environment: {
        hasSupabaseUrl,
        hasServiceRoleKey,
      },
      timestamp: new Date().toISOString(),
    },
    {},
    origin
  );
};

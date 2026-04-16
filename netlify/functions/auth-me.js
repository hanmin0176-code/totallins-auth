const { ok, fail, getOrigin, handleOptions, requireAuth } = require('./_lib/utils');

exports.handler = async (event) => {
  const origin = getOrigin(event.headers);

  if (event.httpMethod === 'OPTIONS') {
    return handleOptions(event);
  }

  if (event.httpMethod !== 'GET') {
    return fail(405, 'METHOD_NOT_ALLOWED', 'GET only.', origin);
  }

  try {
    const auth = await requireAuth(event);
    if (!auth.authenticated) {
      return ok({ authenticated: false }, {}, origin);
    }

    return ok(
      {
        authenticated: true,
        employee: {
          id: auth.employee.id,
          employeeNo: auth.employee.employee_no,
          name: auth.employee.name,
          roleCode: auth.employee.role_code,
        },
      },
      {},
      origin
    );
  } catch (error) {
    return fail(500, 'AUTH_ME_FAILED', 'Could not check auth state.', origin);
  }
};

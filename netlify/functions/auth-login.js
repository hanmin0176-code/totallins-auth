const {
  ok,
  fail,
  getEnv,
  getOrigin,
  handleOptions,
  parseJsonBody,
  getEmployeeByEmployeeNo,
  verifyPassword,
  createSessionToken,
  sha256,
  insertRow,
  updateRow,
  getCookieHeader,
} = require('./_lib/utils');

function normalizeIpAddress(raw) {
  if (!raw) return null;
  const first = String(raw).split(',')[0].trim().replace(/^::ffff:/i, '');
  if (!first) return null;
  const ipv4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const ipv6Loose = /^[0-9a-f:]+$/i;
  if (ipv4.test(first)) return first;
  if (first.includes(':') && ipv6Loose.test(first)) return first;
  return null;
}

function assertRequiredEnv() {
  const required = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY'];
  const missing = required.filter((name) => !getEnv(name));
  if (missing.length) {
    const error = new Error(`MISSING_ENV:${missing.join(',')}`);
    error.code = 'MISSING_ENV';
    throw error;
  }
}

async function insertSessionWithFallback(payload) {
  try {
    return await insertRow('auth_sessions', payload);
  } catch (error) {
    return insertRow('auth_sessions', {
      ...payload,
      ip_address: null,
    });
  }
}

exports.handler = async (event) => {
  const origin = getOrigin(event.headers);

  if (event.httpMethod === 'OPTIONS') {
    return handleOptions(event);
  }

  if (event.httpMethod !== 'POST') {
    return fail(405, 'METHOD_NOT_ALLOWED', 'POST only.', origin);
  }

  const body = parseJsonBody(event);
  if (!body) {
    return fail(400, 'INVALID_JSON', 'Invalid request body.', origin);
  }

  const employeeNo = String(body.employeeNo || '').trim();
  const password = String(body.password || '');

  if (!employeeNo || !password) {
    return fail(400, 'INVALID_INPUT', 'Employee number and password are required.', origin);
  }

  try {
    assertRequiredEnv();

    const employee = await getEmployeeByEmployeeNo(employeeNo);
    if (!employee) {
      return fail(401, 'INVALID_CREDENTIALS', 'Invalid employee number or password.', origin);
    }

    if (!employee.is_active || String(employee.activation_status || '').toLowerCase() === 'inactive') {
      return fail(403, 'ACCOUNT_DISABLED', 'This account is disabled.', origin);
    }

    const activationStatus = String(employee.activation_status || 'active').toLowerCase();
    const pendingPasswordHash = employee.temp_password_hash || employee.password_hash;

    if (activationStatus === 'pending' || employee.must_change_password) {
      const pendingValid = verifyPassword(password, pendingPasswordHash);
      if (!pendingValid) {
        return fail(401, 'INVALID_CREDENTIALS', 'Invalid employee number or password.', origin);
      }

      return fail(
        403,
        'PASSWORD_CHANGE_REQUIRED',
        'Password change is required before continuing.',
        origin,
        {
          employeeNo: employee.employee_no,
          name: employee.name,
        }
      );
    }

    const valid = verifyPassword(password, employee.password_hash);
    if (!valid) {
      return fail(401, 'INVALID_CREDENTIALS', 'Invalid employee number or password.', origin);
    }

    const rawToken = createSessionToken();
    const sessionTokenHash = sha256(rawToken);
    const ttlDays = Number(getEnv('SESSION_TTL_DAYS', '7')) || 7;
    const maxAgeSeconds = ttlDays * 24 * 60 * 60;
    const expiresAt = new Date(Date.now() + maxAgeSeconds * 1000).toISOString();
    const nowIso = new Date().toISOString();

    const forwardedFor = event.headers['x-forwarded-for'] || event.headers['X-Forwarded-For'] || '';
    const userAgent = event.headers['user-agent'] || event.headers['User-Agent'] || null;
    const ipAddress = normalizeIpAddress(forwardedFor);

    await insertSessionWithFallback({
      employee_id: employee.id,
      session_token_hash: sessionTokenHash,
      expires_at: expiresAt,
      ip_address: ipAddress,
      user_agent: userAgent,
      last_seen_at: nowIso,
    });

    await updateRow('employees', 'id', employee.id, {
      last_login_at: nowIso,
    });

    return ok(
      {
        employee: {
          id: employee.id,
          employeeNo: employee.employee_no,
          name: employee.name,
          roleCode: employee.role_code,
        },
      },
      {
        'Set-Cookie': getCookieHeader(rawToken, maxAgeSeconds),
      },
      origin
    );
  } catch (error) {
    if (error?.code === 'MISSING_ENV') {
      return fail(500, 'MISSING_ENV', 'Required Netlify environment variables are missing.', origin);
    }

    return fail(500, 'LOGIN_FAILED', 'Login failed.', origin);
  }
};

const {
  ok,
  fail,
  getOrigin,
  handleOptions,
  parseJsonBody,
  getEmployeeByEmployeeNo,
  verifyPassword,
  hashPassword,
  createSessionToken,
  sha256,
  insertRow,
  updateRow,
  getCookieHeader,
  getEnv,
  normalizeName,
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
  const name = String(body.name || '').trim();
  const tempPassword = String(body.tempPassword || '');
  const newPassword = String(body.newPassword || '');
  const confirmPassword = String(body.confirmPassword || '');

  if (!employeeNo || !name || !tempPassword || !newPassword || !confirmPassword) {
    return fail(400, 'INVALID_INPUT', 'Required fields are missing.', origin);
  }

  if (newPassword !== confirmPassword) {
    return fail(400, 'PASSWORD_MISMATCH', 'Password confirmation does not match.', origin);
  }

  if (newPassword.length < 8) {
    return fail(400, 'PASSWORD_TOO_SHORT', 'Password must be at least 8 characters.', origin);
  }

  try {
    const employee = await getEmployeeByEmployeeNo(employeeNo);
    if (!employee) {
      return fail(404, 'EMPLOYEE_NOT_FOUND', 'Employee not found.', origin);
    }

    if (!employee.is_active || String(employee.activation_status || '').toLowerCase() === 'inactive') {
      return fail(403, 'ACCOUNT_DISABLED', 'This account is disabled.', origin);
    }

    const activationStatus = String(employee.activation_status || 'active').toLowerCase();
    if (activationStatus === 'active' && !employee.must_change_password) {
      return fail(400, 'ACCOUNT_ALREADY_ACTIVE', 'This account is already active.', origin);
    }

    if (normalizeName(employee.name) !== normalizeName(name)) {
      return fail(400, 'NAME_MISMATCH', 'Name does not match the registered record.', origin);
    }

    const tempHash = employee.temp_password_hash || employee.password_hash;
    const validTemp = verifyPassword(tempPassword, tempHash);
    if (!validTemp) {
      return fail(401, 'INVALID_TEMP_PASSWORD', 'Temporary password is invalid.', origin);
    }

    const nowIso = new Date().toISOString();
    const newPasswordHash = hashPassword(newPassword);

    await updateRow('employees', 'id', employee.id, {
      password_hash: newPasswordHash,
      temp_password_hash: null,
      must_change_password: false,
      activation_status: 'active',
      activated_at: nowIso,
      updated_at: nowIso,
      last_login_at: nowIso,
    });

    const rawToken = createSessionToken();
    const sessionTokenHash = sha256(rawToken);
    const ttlDays = Number(getEnv('SESSION_TTL_DAYS', '7')) || 7;
    const maxAgeSeconds = ttlDays * 24 * 60 * 60;
    const expiresAt = new Date(Date.now() + maxAgeSeconds * 1000).toISOString();

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
    return fail(500, 'AUTH_ACTIVATE_FAILED', 'Account activation failed.', origin);
  }
};

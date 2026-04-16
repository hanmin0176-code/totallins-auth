const crypto = require('crypto');

const DEFAULT_COOKIE_NAME = 'totallins_auth_session';

function getEnv(name, fallback = '') {
  return process.env[name] || fallback;
}

function getCookieName() {
  return String(getEnv('SESSION_COOKIE_NAME', DEFAULT_COOKIE_NAME)).trim() || DEFAULT_COOKIE_NAME;
}

function getAllowedOrigins() {
  return String(getEnv('AUTH_ALLOWED_ORIGINS', ''))
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}

function getOrigin(headers) {
  if (!headers || typeof headers !== 'object') return '';
  return headers.origin || headers.Origin || '';
}

function buildCorsHeaders(origin) {
  const allowedOrigins = getAllowedOrigins();
  if (!origin) {
    return {
      Vary: 'Origin',
    };
  }

  if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      Vary: 'Origin',
    };
  }

  return {
    Vary: 'Origin',
  };
}

function json(statusCode, payload, headers = {}, origin = '') {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...buildCorsHeaders(origin),
      ...headers,
    },
    body: JSON.stringify(payload),
  };
}

function ok(data, headers = {}, origin = '') {
  return json(200, { ok: true, data }, headers, origin);
}

function fail(statusCode, code, message, origin = '') {
  return json(statusCode, { ok: false, error: { code, message } }, {}, origin);
}

function handleOptions(event) {
  const origin = getOrigin(event.headers);
  return {
    statusCode: 204,
    headers: {
      ...buildCorsHeaders(origin),
      'Cache-Control': 'no-store',
    },
    body: '',
  };
}

function parseJsonBody(event) {
  try {
    return event.body ? JSON.parse(event.body) : {};
  } catch (error) {
    return null;
  }
}

function parseCookies(header = '') {
  return String(header)
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((acc, item) => {
      const idx = item.indexOf('=');
      if (idx === -1) return acc;
      const key = item.slice(0, idx).trim();
      const value = item.slice(idx + 1).trim();
      acc[key] = decodeURIComponent(value);
      return acc;
    }, {});
}

function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function createSessionToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function getCookieHeader(token, maxAgeSeconds) {
  const cookieName = getCookieName();
  const domain = String(getEnv('SESSION_COOKIE_DOMAIN', '')).trim();
  const domainPart = domain ? `; Domain=${domain}` : '';
  return `${cookieName}=${encodeURIComponent(token)}; Path=/${domainPart}; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

function getClearCookieHeader() {
  const cookieName = getCookieName();
  const domain = String(getEnv('SESSION_COOKIE_DOMAIN', '')).trim();
  const domainPart = domain ? `; Domain=${domain}` : '';
  return `${cookieName}=; Path=/${domainPart}; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function timingSafeEqualString(a, b) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(12).toString('base64url');
  const derived = crypto.scryptSync(String(password || ''), salt, 64).toString('base64url');
  return `scrypt$${salt}$${derived}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== 'string') return false;
  const parts = storedHash.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const salt = parts[1];
  const expected = parts[2];
  const actual = crypto.scryptSync(String(password || ''), salt, 64).toString('base64url');
  return timingSafeEqualString(actual, expected);
}

function buildSupabaseServiceHeaders(extra = {}) {
  const serviceKey = getEnv('SUPABASE_SERVICE_ROLE_KEY');
  return {
    apikey: serviceKey,
    Authorization: `Bearer ${serviceKey}`,
    ...extra,
  };
}

function buildSupabaseHeaders(extra = {}) {
  return buildSupabaseServiceHeaders({
    'Content-Type': 'application/json',
    ...extra,
  });
}

async function supabaseRequest(path, options = {}) {
  const baseUrl = getEnv('SUPABASE_URL');
  const url = new URL(`/rest/v1/${path}`, baseUrl);

  if (options.searchParams) {
    for (const [key, value] of Object.entries(options.searchParams)) {
      url.searchParams.set(key, value);
    }
  }

  const response = await fetch(url, {
    method: options.method || 'GET',
    headers: buildSupabaseHeaders(options.headers || {}),
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (error) {
      data = text;
    }
  }

  if (!response.ok) {
    const error = new Error('SUPABASE_REQUEST_FAILED');
    error.status = response.status;
    error.payload = data;
    throw error;
  }

  return data;
}

async function getEmployeeByEmployeeNo(employeeNo) {
  const rows = await supabaseRequest('employees', {
    searchParams: {
      employee_no: `eq.${employeeNo}`,
      select: '*',
      limit: '1',
    },
  });
  return Array.isArray(rows) && rows[0] ? rows[0] : null;
}

async function getEmployeeById(id) {
  const rows = await supabaseRequest('employees', {
    searchParams: {
      id: `eq.${id}`,
      select: 'id,employee_no,name,team_name,role_code,is_active,activation_status,must_change_password,activated_at',
      limit: '1',
    },
  });
  return Array.isArray(rows) && rows[0] ? rows[0] : null;
}

async function getSessionByToken(rawToken) {
  if (!rawToken) return null;
  const tokenHash = sha256(rawToken);
  const nowIso = new Date().toISOString();
  const rows = await supabaseRequest('auth_sessions', {
    searchParams: {
      session_token_hash: `eq.${tokenHash}`,
      revoked_at: 'is.null',
      expires_at: `gt.${nowIso}`,
      select: '*',
      limit: '1',
    },
  });
  return Array.isArray(rows) && rows[0] ? rows[0] : null;
}

async function updateRow(table, matchField, matchValue, patch) {
  return supabaseRequest(table, {
    method: 'PATCH',
    headers: { Prefer: 'return=representation' },
    searchParams: {
      [matchField]: `eq.${matchValue}`,
      select: '*',
    },
    body: patch,
  });
}

async function insertRow(table, payload) {
  return supabaseRequest(table, {
    method: 'POST',
    headers: { Prefer: 'return=representation' },
    body: payload,
  });
}

function normalizeName(value) {
  return String(value || '').replace(/\s+/g, '').trim().toLowerCase();
}

function getHeaderValue(headers, name) {
  if (!headers || typeof headers !== 'object') return '';
  const target = String(name || '').toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (String(key).toLowerCase() === target) {
      return Array.isArray(value) ? String(value[0] || '') : String(value || '');
    }
  }
  return '';
}

async function requireAuth(event) {
  const cookieName = getCookieName();
  const cookieHeader = event.headers.cookie || event.headers.Cookie || '';
  const cookies = parseCookies(cookieHeader);
  const rawToken = cookies[cookieName];
  if (!rawToken) return { authenticated: false };

  const session = await getSessionByToken(rawToken);
  if (!session) return { authenticated: false };

  const employee = await getEmployeeById(session.employee_id);
  if (!employee || !employee.is_active || String(employee.activation_status || 'active') !== 'active') {
    return { authenticated: false };
  }

  await updateRow('auth_sessions', 'id', session.id, {
    last_seen_at: new Date().toISOString(),
  });

  return {
    authenticated: true,
    employee,
    session,
    rawToken,
  };
}

module.exports = {
  ok,
  fail,
  getEnv,
  getOrigin,
  handleOptions,
  parseJsonBody,
  parseCookies,
  sha256,
  createSessionToken,
  getCookieHeader,
  getClearCookieHeader,
  hashPassword,
  verifyPassword,
  supabaseRequest,
  getEmployeeByEmployeeNo,
  getEmployeeById,
  getSessionByToken,
  updateRow,
  insertRow,
  normalizeName,
  getHeaderValue,
  requireAuth,
};

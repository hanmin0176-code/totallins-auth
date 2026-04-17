const crypto = require('crypto');

const DEFAULT_COOKIE_NAME = 'totallins_auth_session';
const DEFAULT_CARD_PUBLIC_BASE_URL = 'https://card.babymusic.co.kr';

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
  if (!origin) return { Vary: 'Origin' };

  if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      Vary: 'Origin',
    };
  }

  return { Vary: 'Origin' };
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

async function insertRow(table, payload) {
  return supabaseRequest(table, {
    method: 'POST',
    headers: { Prefer: 'return=representation' },
    body: payload,
  });
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

async function listRows(table, searchParams = {}, select = '*') {
  return supabaseRequest(table, {
    searchParams: {
      select,
      ...searchParams,
    },
  });
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
      select: 'id,employee_no,name,team_name,role_code,is_active,activation_status,must_change_password,activated_at,last_login_at,created_at',
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

function limitString(value, maxLength) {
  return String(value == null ? '' : value).slice(0, maxLength);
}

function getRequestPathFromEvent(event) {
  if (!event) return '';
  if (event.path) return String(event.path);
  if (event.rawUrl) {
    try {
      return new URL(event.rawUrl).pathname;
    } catch (error) {
      return String(event.rawUrl);
    }
  }
  return '';
}

async function logEvent(payload) {
  try {
    const level = ['debug', 'info', 'warn', 'error'].includes(payload?.level) ? payload.level : 'info';
    const source = ['server', 'client'].includes(payload?.source) ? payload.source : 'server';
    const metadata = payload?.metadata && typeof payload.metadata === 'object' ? payload.metadata : {};

    await insertRow('app_event_logs', {
      level,
      source,
      event_key: limitString(payload?.eventKey || 'app_event', 120),
      message: limitString(payload?.message || '', 1000) || null,
      request_path: limitString(payload?.requestPath || '', 255) || null,
      method: limitString(payload?.method || '', 32) || null,
      employee_id: payload?.employeeId || null,
      card_id: payload?.cardId || null,
      slug: limitString(payload?.slug || '', 64) || null,
      metadata,
    });
  } catch (error) {
    console.error('[logEvent] failed', {
      status: error?.status,
      message: error?.message,
      payload: error?.payload,
    });
  }
}

async function logServerEvent(event, payload = {}) {
  return logEvent({
    source: 'server',
    requestPath: payload.requestPath || getRequestPathFromEvent(event),
    method: payload.method || (event && event.httpMethod) || null,
    ...payload,
  });
}

function normalizeName(value) {
  return String(value || '').replace(/\s+/g, '').trim().toLowerCase();
}

function normalizeTeamName(value) {
  return String(value || '').replace(/\s+/g, ' ').trim().toLowerCase();
}

function normalizeRoleCode(value, fallback = 'employee') {
  const text = String(value || '').trim().toLowerCase();
  if (!text) return fallback;
  if (['developer', '개발자'].includes(text)) return 'developer';
  if (['admin', '관리자'].includes(text)) return 'admin';
  if (['manager', '매니저'].includes(text)) return 'manager';
  return 'employee';
}

function parseBooleanLike(value, fallback = null) {
  if (value == null || value === '') return fallback;
  const text = String(value).trim().toLowerCase();
  if (['y', 'yes', 'true', '1', '활성', '예'].includes(text)) return true;
  if (['n', 'no', 'false', '0', '비활성', '아니오'].includes(text)) return false;
  return fallback;
}

function generateTempPassword(length = 8) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  let output = '';
  for (let i = 0; i < length; i += 1) {
    const idx = crypto.randomInt(0, chars.length);
    output += chars[idx];
  }
  return output;
}

function isDeveloperRole(roleCode) {
  return String(roleCode || '').toLowerCase() === 'developer';
}

function isAdminRole(roleCode) {
  const value = String(roleCode || '').toLowerCase();
  return value === 'admin' || value === 'developer';
}

function isManagerOrAdminRole(roleCode) {
  const value = String(roleCode || '').toLowerCase();
  return value === 'developer' || value === 'admin' || value === 'manager';
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

async function requireManagerOrAdmin(event) {
  const auth = await requireAuth(event);
  if (!auth.authenticated) return { authenticated: false };
  if (!isManagerOrAdminRole(auth.employee.role_code)) {
    return { authenticated: true, authorized: false, employee: auth.employee, session: auth.session };
  }
  return { authenticated: true, authorized: true, employee: auth.employee, session: auth.session };
}

async function requireAdmin(event) {
  const auth = await requireAuth(event);
  if (!auth.authenticated) return { authenticated: false };
  if (!isAdminRole(auth.employee.role_code)) {
    return { authenticated: true, authorized: false, employee: auth.employee, session: auth.session };
  }
  return { authenticated: true, authorized: true, employee: auth.employee, session: auth.session };
}

async function requireDeveloper(event) {
  const auth = await requireAuth(event);
  if (!auth.authenticated) return { authenticated: false };
  if (!isDeveloperRole(auth.employee.role_code)) {
    return { authenticated: true, authorized: false, employee: auth.employee, session: auth.session };
  }
  return { authenticated: true, authorized: true, employee: auth.employee, session: auth.session };
}

function buildPublicUrlAbsolute(slug) {
  const safeSlug = String(slug || '').trim();
  if (!safeSlug) return '';
  const siteUrl = String(getEnv('CARD_PUBLIC_BASE_URL', DEFAULT_CARD_PUBLIC_BASE_URL)).trim().replace(/\/$/, '');
  return `${siteUrl}/u/${safeSlug}`;
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
  insertRow,
  updateRow,
  listRows,
  getEmployeeByEmployeeNo,
  getEmployeeById,
  getSessionByToken,
  logServerEvent,
  normalizeName,
  normalizeTeamName,
  normalizeRoleCode,
  parseBooleanLike,
  generateTempPassword,
  isDeveloperRole,
  isAdminRole,
  isManagerOrAdminRole,
  requireAuth,
  requireManagerOrAdmin,
  requireAdmin,
  requireDeveloper,
  buildPublicUrlAbsolute,
  getHeaderValue,
};

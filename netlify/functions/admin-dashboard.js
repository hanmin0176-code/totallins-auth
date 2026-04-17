const {
  ok,
  fail,
  listRows,
  requireManagerOrAdmin,
  buildPublicUrlAbsolute,
  logServerEvent,
  normalizeTeamName,
} = require('./_lib/utils');

const DEFAULT_PAGE_SIZE = 10;
const MAX_PAGE_SIZE = 50;

function toInt(value, fallback) {
  const parsed = Number.parseInt(String(value || ''), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function getSortConfig(rawSortBy, rawSortOrder) {
  const allowed = new Set(['employeeNo', 'name', 'teamName', 'roleCode', 'publicStatus', 'accountStatus']);
  const sortBy = allowed.has(rawSortBy) ? rawSortBy : 'employeeNo';
  const sortOrder = String(rawSortOrder || 'asc').toLowerCase() === 'desc' ? 'desc' : 'asc';
  return { sortBy, sortOrder };
}

function roleRank(roleCode) {
  const value = String(roleCode || '').toLowerCase();
  if (value === 'developer') return 0;
  if (value === 'admin') return 1;
  if (value === 'manager') return 2;
  return 3;
}

function accountRank(item) {
  const status = String(item.activationStatus || '').toLowerCase();
  if (status === 'active') return 0;
  if (status === 'pending') return 1;
  if (status === 'inactive') return 2;
  return 3;
}

function publicRank(item) {
  if (item.cardStatus === 'published' && item.slug) return 0;
  if (item.cardStatus === 'draft') return 1;
  if (item.cardStatus === 'archived') return 2;
  return 3;
}

function compareStrings(a, b) {
  return String(a || '').localeCompare(String(b || ''), 'ko', { sensitivity: 'base', numeric: true });
}

function sortEmployees(rows, sortBy, sortOrder) {
  const direction = sortOrder === 'desc' ? -1 : 1;
  return [...rows].sort((left, right) => {
    let value = 0;
    switch (sortBy) {
      case 'name':
        value = compareStrings(left.name, right.name);
        break;
      case 'teamName':
        value = compareStrings(left.teamName, right.teamName);
        if (value === 0) value = compareStrings(left.name, right.name);
        break;
      case 'roleCode':
        value = roleRank(left.roleCode) - roleRank(right.roleCode);
        if (value === 0) value = compareStrings(left.name, right.name);
        break;
      case 'publicStatus':
        value = publicRank(left) - publicRank(right);
        if (value === 0) value = compareStrings(left.name, right.name);
        break;
      case 'accountStatus':
        value = accountRank(left) - accountRank(right);
        if (value === 0) value = compareStrings(left.name, right.name);
        break;
      case 'employeeNo':
      default:
        value = compareStrings(left.employeeNo, right.employeeNo);
        break;
    }
    return value * direction;
  });
}

function normalizeEmployeeRow(row, card) {
  const activationStatus = String(row.activation_status || (row.is_active ? 'active' : 'inactive')).toLowerCase();
  return {
    id: row.id,
    employeeNo: row.employee_no,
    name: row.name,
    teamName: row.team_name || '',
    roleCode: row.role_code,
    isActive: Boolean(row.is_active),
    activationStatus,
    mustChangePassword: Boolean(row.must_change_password),
    activatedAt: row.activated_at || null,
    lastLoginAt: row.last_login_at || null,
    createdAt: row.created_at || null,
    cardStatus: card ? card.status : 'none',
    slug: card && card.slug ? card.slug : '',
    publicUrl: card && card.slug ? buildPublicUrlAbsolute(card.slug) : '',
    cardUpdatedAt: card ? card.updated_at || null : null,
    cardPublishedAt: card ? card.published_at || null : null,
  };
}

function buildSearchText(item) {
  return [item.name, item.employeeNo, item.teamName, item.roleCode, item.slug, item.activationStatus]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

function applyScope(viewer, rows) {
  const viewerRole = String(viewer.role_code || '').toLowerCase();
  if (viewerRole === 'admin' || viewerRole === 'developer') {
    return rows;
  }
  const viewerTeam = normalizeTeamName(viewer.team_name);
  return rows.filter((item) => normalizeTeamName(item.teamName) === viewerTeam);
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') {
    return fail(405, 'METHOD_NOT_ALLOWED', 'GET only.');
  }

  try {
    const auth = await requireManagerOrAdmin(event);
    if (!auth.authenticated) return fail(401, 'UNAUTHORIZED', 'Login required.');
    if (!auth.authorized) return fail(403, 'FORBIDDEN', 'Manager or admin role required.');

    const query = event.queryStringParameters || {};
    const page = toInt(query.page, 1);
    const pageSize = Math.min(toInt(query.pageSize, DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE);
    const keyword = String(query.query || '').trim().toLowerCase();
    const { sortBy, sortOrder } = getSortConfig(query.sortBy, query.sortOrder);

    const [employees, cards, recentLogs] = await Promise.all([
      listRows('employees', { order: 'employee_no.asc', limit: '1000' }, 'id,employee_no,name,team_name,role_code,is_active,activation_status,must_change_password,activated_at,last_login_at,created_at'),
      listRows('cards', { order: 'updated_at.desc', limit: '1000' }, 'id,owner_employee_id,status,slug,updated_at,published_at'),
      listRows('app_event_logs', { level: 'in.(error,warn)', order: 'created_at.desc', limit: '50' }, 'id,level,source,event_key,message,slug,employee_id,created_at,metadata'),
    ]);

    const cardMap = new Map();
    for (const card of Array.isArray(cards) ? cards : []) {
      cardMap.set(card.owner_employee_id, card);
    }

    let employeeRows = (Array.isArray(employees) ? employees : []).map((row) => normalizeEmployeeRow(row, cardMap.get(row.id)));
    employeeRows = applyScope(auth.employee, employeeRows);
    if (keyword) employeeRows = employeeRows.filter((item) => buildSearchText(item).includes(keyword));

    const sortedRows = sortBy === 'employeeNo' && sortOrder === 'asc' ? employeeRows : sortEmployees(employeeRows, sortBy, sortOrder);
    const totalEmployees = sortedRows.length;
    const totalPages = Math.max(1, Math.ceil(totalEmployees / pageSize));
    const currentPage = Math.min(page, totalPages);
    const pagedEmployees = sortedRows.slice((currentPage - 1) * pageSize, (currentPage - 1) * pageSize + pageSize);

    const visibleIds = new Set(employeeRows.map((item) => item.id));
    const scopedLogs = (Array.isArray(recentLogs) ? recentLogs : [])
      .filter((item) => item.employee_id ? visibleIds.has(item.employee_id) : ['admin', 'developer'].includes(String(auth.employee.role_code || '').toLowerCase()))
      .slice(0, 20);

    const summary = {
      totalEmployees,
      activeEmployees: employeeRows.filter((item) => item.isActive).length,
      inactiveEmployees: employeeRows.filter((item) => !item.isActive).length,
      pendingEmployees: employeeRows.filter((item) => item.activationStatus === 'pending').length,
      publishedCards: employeeRows.filter((item) => item.cardStatus === 'published' && item.slug).length,
      developerEmployees: employeeRows.filter((item) => item.roleCode === 'developer').length,
      adminEmployees: employeeRows.filter((item) => item.roleCode === 'admin').length,
      managerEmployees: employeeRows.filter((item) => item.roleCode === 'manager').length,
      recentWarnings: scopedLogs.length,
    };

    Promise.resolve(logServerEvent(event, {
      level: 'info',
      eventKey: 'admin_dashboard_viewed',
      message: 'Viewed account dashboard',
      employeeId: auth.employee.id,
      metadata: { page: currentPage, pageSize, sortBy, sortOrder, query: keyword },
    })).catch(() => null);

    return ok({
      summary,
      employees: pagedEmployees,
      recentLogs: scopedLogs,
      viewer: { id: auth.employee.id, roleCode: auth.employee.role_code, teamName: auth.employee.team_name || '' },
      pagination: { page: currentPage, pageSize, totalEmployees, totalPages, hasPrev: currentPage > 1, hasNext: currentPage < totalPages },
      sort: { sortBy, sortOrder, query: keyword },
    });
  } catch (error) {
    console.error('[admin-dashboard] error', error);
    const auth = await requireManagerOrAdmin(event).catch(() => ({ authenticated: false }));
    await logServerEvent(event, {
      level: 'error',
      eventKey: 'admin_dashboard_failed',
      message: error?.message || 'Failed to load account dashboard',
      employeeId: auth.authenticated ? auth.employee.id : null,
      metadata: { status: error?.status || null },
    });
    return fail(500, 'ADMIN_DASHBOARD_FAILED', 'Failed to load account dashboard.');
  }
};

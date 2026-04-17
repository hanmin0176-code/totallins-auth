const {
  ok,
  fail,
  parseJsonBody,
  requireManagerOrAdmin,
  updateRow,
  supabaseRequest,
  getEmployeeById,
  logServerEvent,
  normalizeTeamName,
  listRows,
} = require('./_lib/utils');

function resolveActivationStatus(target, nextActive) {
  if (!nextActive) return 'inactive';
  if (target.must_change_password || String(target.activation_status || '').toLowerCase() === 'pending' || !target.activated_at) {
    return 'pending';
  }
  return 'active';
}

function canManagerManage(viewer, target) {
  return String(viewer.role_code || '').toLowerCase() === 'manager'
    && String(target.role_code || '').toLowerCase() === 'employee'
    && normalizeTeamName(viewer.team_name) === normalizeTeamName(target.team_name);
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return fail(405, 'METHOD_NOT_ALLOWED', 'POST only.');

  try {
    const auth = await requireManagerOrAdmin(event);
    if (!auth.authenticated) return fail(401, 'UNAUTHORIZED', 'Login required.');
    if (!auth.authorized) return fail(403, 'FORBIDDEN', 'Manager or admin role required.');

    const body = parseJsonBody(event);
    if (!body) return fail(400, 'INVALID_JSON', 'Invalid request body.');

    const employeeId = String(body.employeeId || '').trim();
    const nextActive = Boolean(body.isActive);
    if (!employeeId) return fail(400, 'EMPLOYEE_ID_REQUIRED', 'Employee ID is required.');

    const target = await getEmployeeById(employeeId);
    if (!target) return fail(404, 'EMPLOYEE_NOT_FOUND', 'Employee not found.');

    const viewerRole = String(auth.employee.role_code || '').toLowerCase();
    const isElevated = viewerRole === 'admin' || viewerRole === 'developer';
    const allowed = isElevated || canManagerManage(auth.employee, target);
    if (!allowed) return fail(403, 'FORBIDDEN', 'You do not have permission to update this account.');

    if (employeeId === auth.employee.id && !nextActive) {
      return fail(400, 'CANNOT_DISABLE_SELF', 'You cannot disable your own account.');
    }

    const targetRole = String(target.role_code || '').toLowerCase();
    if (!nextActive && (targetRole === 'admin' || targetRole === 'developer')) {
      const elevatedRows = await listRows('employees', { role_code: 'in.(admin,developer)', is_active: 'eq.true', activation_status: 'neq.inactive', limit: '1000' }, 'id');
      const elevatedCount = Array.isArray(elevatedRows) ? elevatedRows.length : 0;
      if (elevatedCount <= 1) {
        return fail(400, 'LAST_ELEVATED_DISABLE_BLOCKED', 'Cannot disable the last active elevated account.');
      }
    }

    const rows = await updateRow('employees', 'id', employeeId, {
      is_active: nextActive,
      activation_status: resolveActivationStatus(target, nextActive),
      updated_at: new Date().toISOString(),
    });
    const updated = Array.isArray(rows) && rows[0] ? rows[0] : target;

    if (!nextActive) {
      await supabaseRequest('auth_sessions', {
        method: 'PATCH',
        headers: { Prefer: 'return=minimal' },
        searchParams: { employee_id: `eq.${employeeId}`, revoked_at: 'is.null' },
        body: { revoked_at: new Date().toISOString() },
      }).catch(() => null);
    }

    await logServerEvent(event, {
      level: 'warn',
      eventKey: nextActive ? 'admin_employee_enabled' : 'admin_employee_disabled',
      message: nextActive ? 'Enabled employee account' : 'Disabled employee account',
      employeeId: auth.employee.id,
      metadata: { targetEmployeeId: employeeId, targetEmployeeNo: target.employee_no, actorRole: auth.employee.role_code },
    });

    return ok({
      employee: {
        id: updated.id,
        employeeNo: updated.employee_no || target.employee_no,
        name: updated.name || target.name,
        roleCode: updated.role_code || target.role_code,
        teamName: updated.team_name || target.team_name || '',
        isActive: Boolean(updated.is_active),
        activationStatus: updated.activation_status || resolveActivationStatus(target, nextActive),
      },
    });
  } catch (error) {
    console.error('[admin-employee-active] error', error);
    const auth = await requireManagerOrAdmin(event).catch(() => ({ authenticated: false }));
    await logServerEvent(event, {
      level: 'error',
      eventKey: 'admin_employee_active_failed',
      message: error?.message || 'Failed to update employee account state',
      employeeId: auth.authenticated ? auth.employee.id : null,
      metadata: { status: error?.status || null },
    });
    return fail(500, 'ADMIN_EMPLOYEE_ACTIVE_FAILED', 'Failed to update employee account state.');
  }
};

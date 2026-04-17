const {
  ok,
  fail,
  parseJsonBody,
  requireManagerOrAdmin,
  updateRow,
  getEmployeeById,
  logServerEvent,
  normalizeTeamName,
  generateTempPassword,
  hashPassword,
  supabaseRequest,
} = require('./_lib/utils');

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
    const requestedTempPassword = String(body.tempPassword || '').trim();
    if (!employeeId) return fail(400, 'EMPLOYEE_ID_REQUIRED', 'Employee ID is required.');

    const target = await getEmployeeById(employeeId);
    if (!target) return fail(404, 'EMPLOYEE_NOT_FOUND', 'Employee not found.');

    const viewerRole = String(auth.employee.role_code || '').toLowerCase();
    const targetRole = String(target.role_code || '').toLowerCase();
    const isElevated = viewerRole === 'admin' || viewerRole === 'developer';
    const allowed = isElevated || canManagerManage(auth.employee, target);
    if (!allowed) return fail(403, 'FORBIDDEN', 'You do not have permission to reset this account.');
    if (targetRole === 'developer' && viewerRole !== 'developer') {
      return fail(403, 'DEVELOPER_ACCOUNT_PROTECTED', 'Only developer can reset developer account.');
    }

    const tempPassword = requestedTempPassword || generateTempPassword(10);
    if (requestedTempPassword && requestedTempPassword.length < 6) {
      return fail(400, 'TEMP_PASSWORD_TOO_SHORT', 'Temporary password must be at least 6 characters.');
    }

    const nextTempHash = hashPassword(tempPassword);
    await updateRow('employees', 'id', employeeId, {
      password_hash: nextTempHash,
      temp_password_hash: nextTempHash,
      must_change_password: true,
      activation_status: 'pending',
      is_active: true,
      activated_at: null,
      updated_at: new Date().toISOString(),
    });

    await supabaseRequest('auth_sessions', {
      method: 'PATCH',
      headers: { Prefer: 'return=minimal' },
      searchParams: { employee_id: `eq.${employeeId}`, revoked_at: 'is.null' },
      body: { revoked_at: new Date().toISOString() },
    }).catch(() => null);

    await logServerEvent(event, {
      level: 'warn',
      eventKey: 'admin_employee_password_reset',
      message: 'Reset employee password',
      employeeId: auth.employee.id,
      metadata: { targetEmployeeId: employeeId, targetEmployeeNo: target.employee_no, actorRole: auth.employee.role_code },
    });

    return ok({
      employee: { id: target.id, employeeNo: target.employee_no, name: target.name },
      tempPassword,
    });
  } catch (error) {
    console.error('[admin-employee-reset-password] error', error);
    const auth = await requireManagerOrAdmin(event).catch(() => ({ authenticated: false }));
    await logServerEvent(event, {
      level: 'error',
      eventKey: 'admin_employee_password_reset_failed',
      message: error?.message || 'Failed to reset employee password',
      employeeId: auth.authenticated ? auth.employee.id : null,
      metadata: { status: error?.status || null },
    });
    return fail(500, 'ADMIN_EMPLOYEE_PASSWORD_RESET_FAILED', 'Failed to reset employee password.');
  }
};

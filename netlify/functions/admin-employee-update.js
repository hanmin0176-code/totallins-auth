const {
  ok,
  fail,
  parseJsonBody,
  requireAdmin,
  updateRow,
  getEmployeeById,
  logServerEvent,
  normalizeRoleCode,
} = require('./_lib/utils');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return fail(405, 'METHOD_NOT_ALLOWED', 'POST only.');

  try {
    const auth = await requireAdmin(event);
    if (!auth.authenticated) return fail(401, 'UNAUTHORIZED', 'Login required.');
    if (!auth.authorized) return fail(403, 'FORBIDDEN', 'Admin role required.');

    const body = parseJsonBody(event);
    if (!body) return fail(400, 'INVALID_JSON', 'Invalid request body.');

    const employeeId = String(body.employeeId || '').trim();
    const nextRoleCode = normalizeRoleCode(body.roleCode || '', 'employee');
    const nextTeamName = String(body.teamName || '').trim();
    if (!employeeId) return fail(400, 'EMPLOYEE_ID_REQUIRED', 'Employee ID is required.');

    const target = await getEmployeeById(employeeId);
    if (!target) return fail(404, 'EMPLOYEE_NOT_FOUND', 'Employee not found.');

    const actorRole = String(auth.employee.role_code || '').toLowerCase();
    const targetRole = String(target.role_code || '').toLowerCase();
    if (nextRoleCode === 'developer' && !['admin', 'developer'].includes(actorRole)) {
      return fail(403, 'DEVELOPER_ROLE_ASSIGN_FORBIDDEN', 'Only admin or developer can assign developer role.');
    }
    if (employeeId === auth.employee.id) {
      if (actorRole === 'developer' && nextRoleCode !== 'developer') return fail(400, 'CANNOT_CHANGE_SELF_ROLE', 'Developer must keep own role as developer.');
      if (actorRole === 'admin' && !['admin', 'developer'].includes(nextRoleCode)) return fail(400, 'CANNOT_CHANGE_SELF_ROLE', 'Admin must keep own role as admin or developer.');
    }
    if (targetRole === 'developer' && actorRole !== 'developer') {
      return fail(403, 'DEVELOPER_ACCOUNT_PROTECTED', 'Only developer can edit developer account.');
    }

    const rows = await updateRow('employees', 'id', employeeId, {
      role_code: nextRoleCode,
      team_name: nextTeamName || null,
      updated_at: new Date().toISOString(),
    });
    const updated = Array.isArray(rows) && rows[0] ? rows[0] : target;

    await logServerEvent(event, {
      level: 'warn',
      eventKey: 'admin_employee_updated',
      message: 'Updated employee role or team',
      employeeId: auth.employee.id,
      metadata: { targetEmployeeId: employeeId, targetEmployeeNo: target.employee_no, previousRoleCode: target.role_code, nextRoleCode, nextTeamName },
    });

    return ok({
      employee: {
        id: updated.id,
        employeeNo: updated.employee_no || target.employee_no,
        name: updated.name || target.name,
        roleCode: updated.role_code || nextRoleCode,
        teamName: updated.team_name || nextTeamName || '',
      },
    });
  } catch (error) {
    console.error('[admin-employee-update] error', error);
    const auth = await requireAdmin(event).catch(() => ({ authenticated: false }));
    await logServerEvent(event, {
      level: 'error',
      eventKey: 'admin_employee_update_failed',
      message: error?.message || 'Failed to update employee role or team',
      employeeId: auth.authenticated ? auth.employee.id : null,
      metadata: { status: error?.status || null },
    });
    return fail(500, 'ADMIN_EMPLOYEE_UPDATE_FAILED', 'Failed to update employee role or team.');
  }
};

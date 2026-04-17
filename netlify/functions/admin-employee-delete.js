const {
  ok,
  fail,
  parseJsonBody,
  requireAdmin,
  getEmployeeById,
  listRows,
  supabaseRequest,
  logServerEvent,
} = require('./_lib/utils');

async function countActiveElevatedUsers() {
  const rows = await listRows('employees', {
    role_code: 'in.(admin,developer)',
    is_active: 'eq.true',
    activation_status: 'neq.inactive',
    limit: '1000',
  }, 'id');
  return Array.isArray(rows) ? rows.length : 0;
}

function canDeleteTarget(target) {
  return !target.is_active || String(target.activation_status || '').toLowerCase() === 'inactive';
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return fail(405, 'METHOD_NOT_ALLOWED', 'POST only.');

  try {
    const auth = await requireAdmin(event);
    if (!auth.authenticated) return fail(401, 'UNAUTHORIZED', 'Login required.');
    if (!auth.authorized) return fail(403, 'FORBIDDEN', 'Admin role required.');

    const body = parseJsonBody(event);
    if (!body) return fail(400, 'INVALID_JSON', 'Invalid request body.');

    const employeeId = String(body.employeeId || '').trim();
    if (!employeeId) return fail(400, 'EMPLOYEE_ID_REQUIRED', 'Employee ID is required.');
    if (employeeId === auth.employee.id) return fail(400, 'CANNOT_DELETE_SELF', 'You cannot delete your own account.');

    const target = await getEmployeeById(employeeId);
    if (!target) return fail(404, 'EMPLOYEE_NOT_FOUND', 'Employee not found.');
    if (!canDeleteTarget(target)) return fail(400, 'EMPLOYEE_MUST_BE_INACTIVE', 'Employee must be inactive before deletion.');

    const actorRole = String(auth.employee.role_code || '').toLowerCase();
    const targetRole = String(target.role_code || '').toLowerCase();
    if (targetRole === 'developer' && actorRole !== 'developer') {
      return fail(403, 'DEVELOPER_ACCOUNT_PROTECTED', 'Only developer can delete developer account.');
    }
    if ((targetRole === 'admin' || targetRole === 'developer') && (await countActiveElevatedUsers()) <= 1) {
      return fail(400, 'LAST_ELEVATED_DELETE_BLOCKED', 'Cannot delete the last active elevated account.');
    }

    const deletedRows = await supabaseRequest('employees', {
      method: 'DELETE',
      headers: { Prefer: 'return=representation' },
      searchParams: { id: `eq.${employeeId}`, select: 'id,employee_no,name,role_code,team_name' },
    });
    const deleted = Array.isArray(deletedRows) && deletedRows[0] ? deletedRows[0] : target;

    await logServerEvent(event, {
      level: 'warn',
      eventKey: 'admin_employee_deleted',
      message: 'Deleted employee account',
      employeeId: auth.employee.id,
      metadata: { targetEmployeeId: employeeId, targetEmployeeNo: deleted.employee_no || target.employee_no, targetRoleCode: deleted.role_code || target.role_code, targetTeamName: deleted.team_name || target.team_name || '' },
    });

    return ok({
      employee: {
        id: deleted.id || target.id,
        employeeNo: deleted.employee_no || target.employee_no,
        name: deleted.name || target.name,
        roleCode: deleted.role_code || target.role_code,
        teamName: deleted.team_name || target.team_name || '',
      },
    });
  } catch (error) {
    console.error('[admin-employee-delete] error', error);
    const auth = await requireAdmin(event).catch(() => ({ authenticated: false }));
    await logServerEvent(event, {
      level: 'error',
      eventKey: 'admin_employee_delete_failed',
      message: error?.message || 'Failed to delete employee account',
      employeeId: auth.authenticated ? auth.employee.id : null,
      metadata: { status: error?.status || null },
    });
    return fail(500, 'ADMIN_EMPLOYEE_DELETE_FAILED', 'Failed to delete employee account.');
  }
};

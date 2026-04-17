const XLSX = require('xlsx');
const {
  ok,
  fail,
  parseJsonBody,
  requireAdmin,
  getEmployeeByEmployeeNo,
  insertRow,
  updateRow,
  hashPassword,
  normalizeRoleCode,
  parseBooleanLike,
  generateTempPassword,
  logServerEvent,
} = require('./_lib/utils');

function normalizeHeaderKey(value) {
  return String(value || '').trim().toLowerCase().replace(/[\s_\-()]/g, '');
}

function getColumnValue(row, aliases) {
  const keys = Object.keys(row || {});
  const aliasSet = new Set(aliases.map(normalizeHeaderKey));
  for (const key of keys) {
    if (aliasSet.has(normalizeHeaderKey(key))) return row[key];
  }
  return '';
}

function readWorkbookRows(buffer) {
  const workbook = XLSX.read(buffer, { type: 'buffer', raw: false, cellDates: false });
  const firstSheetName = workbook.SheetNames[0];
  if (!firstSheetName) throw new Error('Excel sheet is empty.');
  const rows = XLSX.utils.sheet_to_json(workbook.Sheets[firstSheetName], { defval: '', raw: false });
  if (!Array.isArray(rows) || !rows.length) throw new Error('Uploaded file has no rows.');
  return rows;
}

function buildNormalizedRow(rawRow, index) {
  return {
    rowNumber: index + 2,
    employeeNo: String(getColumnValue(rawRow, ['employee_no', 'employeeNo', '사번'])).trim(),
    name: String(getColumnValue(rawRow, ['name', '이름'])).trim(),
    teamName: String(getColumnValue(rawRow, ['team_name', 'teamName', '팀명', '소속'])).trim(),
    roleCode: normalizeRoleCode(getColumnValue(rawRow, ['role_code', 'roleCode', '권한']), 'employee'),
    tempPassword: String(getColumnValue(rawRow, ['temp_password', 'tempPassword', '임시비밀번호', '초기비밀번호'])).trim(),
    forceReset: parseBooleanLike(getColumnValue(rawRow, ['force_reset', 'forceReset', '강제재설정']), false),
    isActive: parseBooleanLike(getColumnValue(rawRow, ['is_active', 'isActive', '활성여부']), null),
  };
}

function buildImportError(rowNumber, employeeNo, reason) {
  return { rowNumber, employeeNo: employeeNo || '', reason };
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return fail(405, 'METHOD_NOT_ALLOWED', 'POST only.');

  try {
    const auth = await requireAdmin(event);
    if (!auth.authenticated) return fail(401, 'UNAUTHORIZED', 'Login required.');
    if (!auth.authorized) return fail(403, 'FORBIDDEN', 'Admin role required.');

    const body = parseJsonBody(event);
    if (!body) return fail(400, 'INVALID_JSON', 'Invalid request body.');

    const fileBase64 = String(body.fileBase64 || '').trim();
    if (!fileBase64) return fail(400, 'FILE_REQUIRED', 'Excel file data is required.');

    const normalizedRows = readWorkbookRows(Buffer.from(fileBase64, 'base64'))
      .map(buildNormalizedRow)
      .filter((row) => row.employeeNo || row.name || row.teamName);
    if (!normalizedRows.length) return fail(400, 'EMPTY_ROWS', 'No employee rows found in uploaded file.');

    const result = { totalRows: normalizedRows.length, created: 0, updated: 0, pendingPrepared: 0, skipped: 0, errors: [], generatedCredentials: [] };

    for (const row of normalizedRows) {
      if (!row.employeeNo || !row.name) {
        result.errors.push(buildImportError(row.rowNumber, row.employeeNo, 'Employee number and name are required.'));
        continue;
      }

      try {
        const existing = await getEmployeeByEmployeeNo(row.employeeNo);
        const nowIso = new Date().toISOString();
        const nextIsActive = row.isActive == null ? (existing ? Boolean(existing.is_active) : true) : Boolean(row.isActive);

        if (!existing) {
          const nextTempPassword = row.tempPassword || generateTempPassword(8);
          const nextTempHash = hashPassword(nextTempPassword);
          await insertRow('employees', {
            employee_no: row.employeeNo,
            name: row.name,
            team_name: row.teamName || null,
            role_code: row.roleCode,
            is_active: nextIsActive,
            activation_status: nextIsActive ? 'pending' : 'inactive',
            must_change_password: true,
            password_hash: nextTempHash,
            temp_password_hash: nextTempHash,
            activated_at: null,
            updated_at: nowIso,
          });
          result.created += 1;
          if (nextIsActive) {
            result.pendingPrepared += 1;
            result.generatedCredentials.push({ employeeNo: row.employeeNo, name: row.name, tempPassword: nextTempPassword, action: 'created' });
          }
          continue;
        }

        const patch = { name: row.name, team_name: row.teamName || null, role_code: row.roleCode, updated_at: nowIso };
        if (row.isActive != null) {
          patch.is_active = nextIsActive;
          patch.activation_status = nextIsActive
            ? (String(existing.activation_status || 'active').toLowerCase() === 'inactive' ? 'pending' : existing.activation_status || 'active')
            : 'inactive';
        }

        const existingStatus = String(existing.activation_status || 'active').toLowerCase();
        const shouldPreparePending = Boolean(row.forceReset) || existingStatus !== 'active' || !existing.password_hash;
        if (shouldPreparePending) {
          const nextTempPassword = row.tempPassword || generateTempPassword(8);
          const nextTempHash = hashPassword(nextTempPassword);
          patch.password_hash = nextTempHash;
          patch.temp_password_hash = nextTempHash;
          patch.must_change_password = true;
          patch.activation_status = nextIsActive ? 'pending' : 'inactive';
          patch.activated_at = null;
          if (nextIsActive) {
            result.pendingPrepared += 1;
            result.generatedCredentials.push({ employeeNo: row.employeeNo, name: row.name, tempPassword: nextTempPassword, action: row.forceReset ? 'reset-and-reinvite' : 'pending-refresh' });
          }
        }

        await updateRow('employees', 'id', existing.id, patch);
        result.updated += 1;
      } catch (rowError) {
        result.errors.push(buildImportError(row.rowNumber, row.employeeNo, rowError?.message || 'Failed to import row.'));
      }
    }

    result.skipped = result.errors.length;

    await logServerEvent(event, {
      level: 'info',
      eventKey: 'admin_employee_import_success',
      message: 'Imported employee accounts',
      employeeId: auth.employee.id,
      metadata: { totalRows: result.totalRows, created: result.created, updated: result.updated, pendingPrepared: result.pendingPrepared, skipped: result.skipped },
    });

    return ok({ result });
  } catch (error) {
    console.error('[admin-employee-import] error', error);
    const auth = await requireAdmin(event).catch(() => ({ authenticated: false }));
    await logServerEvent(event, {
      level: 'error',
      eventKey: 'admin_employee_import_failed',
      message: error?.message || 'Failed to import employee accounts',
      employeeId: auth.authenticated ? auth.employee.id : null,
      metadata: { status: error?.status || null },
    });
    return fail(500, 'ADMIN_EMPLOYEE_IMPORT_FAILED', error?.message || 'Failed to import employee accounts.');
  }
};

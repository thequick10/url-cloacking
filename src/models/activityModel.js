import { getDbPool } from '../db.js';

function toUtcIsoNow() {
  return new Date().toISOString();
}

export async function logActivity(userId, action, details = {}) {
  const pool = getDbPool();
  const [res] = await pool.query(
    'INSERT INTO activity_logs (user_id, action, details, created_at) VALUES (?,?,?,CURRENT_TIMESTAMP)',
    [userId, action, JSON.stringify(details || {})]
  );
  return res.insertId;
}

export async function listActivitiesForUserOrAll({ userId, all = false, page = 1, pageSize = 100, actionQuery, usernameQuery, roleQuery, fromDate, toDate }) {
  const pool = getDbPool();
  const offset = (page - 1) * pageSize;

  const whereClauses = [];
  const params = [];

  if (!all) {
    whereClauses.push('a.user_id = ?');
    params.push(userId);
  }

  if (actionQuery && String(actionQuery).trim() !== '') {
    whereClauses.push('a.action LIKE ?');
    params.push(`%${actionQuery}%`);
  }

  if (usernameQuery && String(usernameQuery).trim() !== '') {
    whereClauses.push('u.username LIKE ?');
    params.push(`%${usernameQuery}%`);
  }

  if (roleQuery && String(roleQuery).trim() !== '') {
    whereClauses.push('u.role = ?');
    params.push(roleQuery);
  }

  if (fromDate && String(fromDate).trim() !== '') {
    whereClauses.push('DATE(a.created_at) >= ?');
    params.push(fromDate);
  }

  if (toDate && String(toDate).trim() !== '') {
    whereClauses.push('DATE(a.created_at) <= ?');
    params.push(toDate);
  }

  const whereSql = whereClauses.length ? 'WHERE ' + whereClauses.join(' AND ') : '';

  const rowsSql = `
    SELECT a.id, a.user_id, u.username, u.role, a.action, a.details, a.created_at
    FROM activity_logs a
    JOIN users u ON u.id = a.user_id
    ${whereSql}
    ORDER BY a.id DESC
    LIMIT ? OFFSET ?`;

  const totalSql = `
    SELECT COUNT(*) as c
    FROM activity_logs a
    JOIN users u ON u.id = a.user_id
    ${whereSql}`;

  const rowsParams = [...params, pageSize, offset];
  const [rows] = await pool.query(rowsSql, rowsParams);
  const [t] = await pool.query(totalSql, params);
  return { rows, total: t[0].c };
}
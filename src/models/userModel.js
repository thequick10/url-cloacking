import { getDbPool } from '../db.js';

export async function createUser({ name, username, email, passwordHash, role = 'Subscriber' }) {
  const pool = getDbPool();
  const [res] = await pool.query(
    'INSERT INTO users (name, username, email, password_hash, role, approved) VALUES (?,?,?,?,?,0)',
    [name || null, username, email || null, passwordHash, role]
  );
  return res.insertId;
}

export async function findUserByUsernameOrEmail(identifier) {
  const pool = getDbPool();
  const [rows] = await pool.query(
    'SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1',
    [identifier, identifier]
  );
  return rows[0] || null;
}

export async function getUserById(id) {
  const pool = getDbPool();
  const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [id]);
  return rows[0] || null;
}

export async function listUsers({ q, page = 1, pageSize = 50 }) {
  const pool = getDbPool();
  const offset = (page - 1) * pageSize;
  if (q) {
    const like = `%${q}%`;
    const [rows] = await pool.query(
      'SELECT id, name, username, email, role, approved, created_at, updated_at FROM users WHERE name LIKE ? OR username LIKE ? OR email LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?',
      [like, like, like, pageSize, offset]
    );
    return rows;
  }
  const [rows] = await pool.query(
    'SELECT id, name, username, email, role, approved, created_at, updated_at FROM users ORDER BY id DESC LIMIT ? OFFSET ?',
    [pageSize, offset]
  );
  return rows;
}

export async function countUsers({ q }) {
  const pool = getDbPool();
  if (q) {
    const like = `%${q}%`;
    const [rows] = await pool.query(
      'SELECT COUNT(*) as c FROM users WHERE name LIKE ? OR username LIKE ? OR email LIKE ?',
      [like, like, like]
    );
    return rows[0].c;
  }
  const [rows] = await pool.query('SELECT COUNT(*) as c FROM users');
  return rows[0].c;
}

export async function updateUser(id, { name, username, email, role, passwordHash }) {
  const pool = getDbPool();
  const fields = [];
  const params = [];
  if (name !== undefined) { fields.push('name = ?'); params.push(name); }
  if (username !== undefined) { fields.push('username = ?'); params.push(username); }
  if (email !== undefined) { fields.push('email = ?'); params.push(email); }
  if (role !== undefined) { fields.push('role = ?'); params.push(role); }
  if (Object.prototype.hasOwnProperty.call(arguments[1] || {}, 'approved')) { fields.push('approved = ?'); params.push(arguments[1].approved ? 1 : 0); }
  if (passwordHash !== undefined) { fields.push('password_hash = ?'); params.push(passwordHash); }
  if (fields.length === 0) return;
  params.push(id);
  await pool.query(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, params);
}

export async function deleteUserById(id) {
  const pool = getDbPool();
  await pool.query('DELETE FROM users WHERE id = ?', [id]);
}
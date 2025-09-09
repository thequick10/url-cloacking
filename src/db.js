import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
dotenv.config();
let pool;

export function getDbPool() {
  if (!pool) {
    pool = mysql.createPool({
      host: process.env.MYSQL_HOST,
      port: Number(process.env.MYSQL_PORT || 3306),
      user: process.env.MYSQL_USER,
      password: process.env.MYSQL_PASSWORD,
      database: process.env.MYSQL_DB,
      waitForConnections: true,
      connectionLimit: 5,
      timezone: 'Z' // store UTC
    });
  }
  return pool;
}

export async function ensureSchema() {
  const pool = getDbPool();
  // Create tables if not exist
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255),
      username VARCHAR(100) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      role ENUM('Admin','Subscriber','Analytics') NOT NULL DEFAULT 'Subscriber',
      approved TINYINT(1) NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // Add approved column for existing deployments if missing
  try {
    const [cols] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'users' AND COLUMN_NAME = 'approved'`,
      [process.env.MYSQL_DB]
    );
    if (!cols.length) {
      await pool.query(`ALTER TABLE users ADD COLUMN approved TINYINT(1) NOT NULL DEFAULT 0`);
    }
  } catch (e) {
    // ignore if not permitted; startup will continue
  }

  // Ensure all Admin users are approved (for existing deployments)
  try {
    await pool.query(`UPDATE users SET approved = 1 WHERE role = 'Admin' AND approved = 0`);
  } catch (e) {
    // ignore
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS activity_logs (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      action VARCHAR(100) NOT NULL,
      details JSON NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // Ensure at least one admin if env provided
  // const [rows] = await pool.query('SELECT COUNT(*) as c FROM users');
  // if (rows[0].c === 0 && process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD_HASH) {
  //   await pool.query(
  //     'INSERT INTO users (name, username, email, password_hash, role, approved) VALUES (?,?,?,?,?,1)',
  //     [process.env.ADMIN_NAME || 'Admin', process.env.ADMIN_USERNAME, process.env.ADMIN_EMAIL || null, process.env.ADMIN_PASSWORD_HASH, 'Admin']
  //   );
  // }

  // New Code to Ensure at least one admin if env provided
  const [rows] = await pool.query('SELECT COUNT(*) as c FROM users');
  if (rows[0].c === 0 && process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD_HASH) {
    const now = new Date().toISOString().slice(0, 19).replace('T', ' ');

    await pool.query(
      'INSERT INTO users (name, username, email, password_hash, role, approved, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        process.env.ADMIN_NAME || 'Admin',
        process.env.ADMIN_USERNAME,
        process.env.ADMIN_EMAIL || null,
        process.env.ADMIN_PASSWORD_HASH,
        'Admin',
        1,
        now
      ]
    );
  }
}
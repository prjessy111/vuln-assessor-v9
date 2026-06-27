'use strict';
const pool = require('../db/pool');
const { encrypt } = require('../util/crypto');

const SELECT_COLS = `
  server_id, name, hostname, os_type, description,
  ssh_port, ssh_user, ssh_auth_type, ssh_key_path, ssh_password_enc,
  remote_raw_path, use_sudo, last_collected_at,
  created_at, updated_at
`;

const serverDao = {
  async list() {
    const [rows] = await pool.query(
      `SELECT ${SELECT_COLS} FROM servers ORDER BY name`
    );
    return rows;
  },

  async findById(id) {
    const [rows] = await pool.query(
      `SELECT ${SELECT_COLS} FROM servers WHERE server_id = ?`, [id]
    );
    return rows[0] || null;
  },

  async create(data) {
    const passEnc = data.ssh_auth_type === 'password' && data.ssh_password
      ? encrypt(data.ssh_password) : null;
    const [r] = await pool.execute(
      `INSERT INTO servers
        (name, hostname, os_type, description,
         ssh_port, ssh_user, ssh_auth_type, ssh_key_path, ssh_password_enc,
         remote_raw_path, use_sudo)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        data.name, data.hostname, data.os_type, data.description || null,
        data.ssh_port || 22, data.ssh_user || null,
        data.ssh_auth_type || 'key',
        data.ssh_key_path || null, passEnc,
        data.remote_raw_path || '/var/lib/secums/data.db',
        data.use_sudo ? 1 : 0,
      ]
    );
    return r.insertId;
  },

  async update(id, data) {
    // 비밀번호는 새 값이 들어왔을 때만 갱신 (빈 값이면 기존 유지)
    const fields = [
      'name=?', 'hostname=?', 'os_type=?', 'description=?',
      'ssh_port=?', 'ssh_user=?', 'ssh_auth_type=?', 'ssh_key_path=?',
      'remote_raw_path=?', 'use_sudo=?',
    ];
    const vals = [
      data.name, data.hostname, data.os_type, data.description || null,
      data.ssh_port || 22, data.ssh_user || null,
      data.ssh_auth_type || 'key', data.ssh_key_path || null,
      data.remote_raw_path || '/var/lib/secums/data.db',
      data.use_sudo ? 1 : 0,
    ];
    if (data.ssh_password) {
      fields.push('ssh_password_enc=?');
      vals.push(encrypt(data.ssh_password));
    }
    vals.push(id);
    await pool.execute(
      `UPDATE servers SET ${fields.join(', ')} WHERE server_id=?`, vals
    );
  },

  async remove(id) {
    await pool.execute('DELETE FROM servers WHERE server_id=?', [id]);
  },

  async updateLastCollected(id) {
    await pool.execute(
      'UPDATE servers SET last_collected_at=NOW() WHERE server_id=?', [id]
    );
  },

  async latestAssessmentSummary() {
    const [rows] = await pool.query(`
      SELECT s.server_id, s.name, s.hostname, s.os_type, s.last_collected_at,
             a.assessment_id, a.executed_at,
             a.total_count, a.vuln_count, a.safe_count, a.na_count
      FROM servers s
      LEFT JOIN (
        SELECT a1.* FROM assessments a1
        INNER JOIN (
          SELECT server_id, MAX(executed_at) AS mx
          FROM assessments GROUP BY server_id
        ) m ON a1.server_id = m.server_id AND a1.executed_at = m.mx
      ) a ON a.server_id = s.server_id
      ORDER BY s.name
    `);
    return rows;
  },
};

module.exports = serverDao;

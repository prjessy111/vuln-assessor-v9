'use strict';
const pool = require('../db/pool');

const collectionDao = {
  async insertStarted({ server_id, triggered_by }) {
    const [r] = await pool.execute(
      `INSERT INTO collection_history (server_id, status, triggered_by)
       VALUES (?, '진행중', ?)`,
      [server_id, triggered_by || null]
    );
    return r.insertId;
  },

  async finishSuccess(collectionId, { raw_file_path, raw_file_hash, file_size }) {
    await pool.execute(
      `UPDATE collection_history
         SET status='성공', finished_at=NOW(),
             raw_file_path=?, raw_file_hash=?, file_size=?
       WHERE collection_id=?`,
      [raw_file_path, raw_file_hash, file_size, collectionId]
    );
  },

  async finishFailure(collectionId, errorMessage) {
    await pool.execute(
      `UPDATE collection_history
         SET status='실패', finished_at=NOW(), error_message=?
       WHERE collection_id=?`,
      [String(errorMessage || '').slice(0, 1000), collectionId]
    );
  },

  async listByServer(serverId, limit = 50) {
    const [rows] = await pool.query(
      `SELECT * FROM collection_history
       WHERE server_id = ?
       ORDER BY started_at DESC LIMIT ?`,
      [serverId, limit]
    );
    return rows;
  },

  async listRecent(limit = 100) {
    const [rows] = await pool.query(
      `SELECT ch.*, s.name AS server_name, s.hostname
       FROM collection_history ch
       JOIN servers s ON s.server_id = ch.server_id
       ORDER BY started_at DESC LIMIT ?`,
      [limit]
    );
    return rows;
  },
};

module.exports = collectionDao;

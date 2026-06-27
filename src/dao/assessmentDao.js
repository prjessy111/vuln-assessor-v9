'use strict';
const pool = require('../db/pool');

const assessmentDao = {
  /**
   * 진단 세션 + 결과를 하나의 트랜잭션으로 저장.
   */
  async insertSession({ session, results }) {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [r] = await conn.execute(
        `INSERT INTO assessments
          (server_id, raw_file_name, raw_file_hash, ruleset_ver,
           executed_by, total_count, vuln_count, safe_count, na_count, elapsed_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          session.server_id, session.raw_file_name, session.raw_file_hash,
          session.ruleset_ver, session.executed_by || null,
          session.total_count, session.vuln_count, session.safe_count,
          session.na_count, session.elapsed_ms || null,
        ]
      );
      const assessmentId = r.insertId;

      // bulk insert (다중 row VALUES)
      if (results.length) {
        const placeholders = results.map(() => '(?, ?, ?, ?, ?, ?)').join(', ');
        const flat = [];
        for (const it of results) {
          flat.push(assessmentId, it.rule_id, it.status,
                    it.collected_value, it.reason, it.severity);
        }
        await conn.query(
          `INSERT INTO assessment_results
            (assessment_id, rule_id, status, collected_value, reason, severity)
           VALUES ${placeholders}`,
          flat
        );
      }

      await conn.commit();
      return assessmentId;
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  },

  async findById(id) {
    const [rows] = await pool.query(
      `SELECT a.*, s.name AS server_name, s.hostname, s.os_type
       FROM assessments a JOIN servers s ON s.server_id = a.server_id
       WHERE a.assessment_id = ?`, [id]
    );
    return rows[0] || null;
  },

  async listByServer(serverId, limit = 50) {
    const [rows] = await pool.query(
      `SELECT assessment_id, raw_file_name, ruleset_ver, executed_by, executed_at,
              total_count, vuln_count, safe_count, na_count, elapsed_ms
       FROM assessments
       WHERE server_id = ?
       ORDER BY executed_at DESC
       LIMIT ?`,
      [serverId, limit]
    );
    return rows;
  },

  async getResults(assessmentId) {
    const [rows] = await pool.query(
      `SELECT r.rule_id, r.status, r.collected_value, r.reason, r.severity,
              ru.title, ru.category, ru.recommend
       FROM assessment_results r
       JOIN assessments a ON a.assessment_id = r.assessment_id
       LEFT JOIN rules ru
         ON ru.rule_id = r.rule_id AND ru.ruleset_ver = a.ruleset_ver
       WHERE r.assessment_id = ?
       ORDER BY r.severity = '상' DESC, r.status = '취약' DESC, r.rule_id`,
      [assessmentId]
    );
    return rows;
  },

  async compare(idA, idB) {
    // 두 세션의 동일 rule_id 결과 변화
    const [rows] = await pool.query(
      `SELECT
         COALESCE(ra.rule_id, rb.rule_id) AS rule_id,
         ra.status AS status_a, rb.status AS status_b,
         COALESCE(ra.severity, rb.severity) AS severity
       FROM
         (SELECT * FROM assessment_results WHERE assessment_id = ?) ra
         LEFT JOIN
         (SELECT * FROM assessment_results WHERE assessment_id = ?) rb
         ON ra.rule_id = rb.rule_id
       UNION
       SELECT
         COALESCE(ra.rule_id, rb.rule_id),
         ra.status, rb.status,
         COALESCE(ra.severity, rb.severity)
       FROM
         (SELECT * FROM assessment_results WHERE assessment_id = ?) ra
         RIGHT JOIN
         (SELECT * FROM assessment_results WHERE assessment_id = ?) rb
         ON ra.rule_id = rb.rule_id
       ORDER BY rule_id`,
      [idA, idB, idA, idB]
    );
    return rows;
  },
};

module.exports = assessmentDao;

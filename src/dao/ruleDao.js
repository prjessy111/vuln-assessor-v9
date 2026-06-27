'use strict';
const pool = require('../db/pool');

const ruleDao = {
  async listEnabled(rulesetVer) {
    const [rows] = await pool.query(
      `SELECT rule_id, ruleset_ver, title, category, severity,
              os_target, check_key, check_type, check_param,
              recommend, enabled
       FROM rules
       WHERE enabled = 1 AND ruleset_ver = ?
       ORDER BY rule_id`,
      [rulesetVer]
    );
    // check_param JSON 자동 파싱은 pool.typeCast에서 처리됨
    return rows;
  },

  async listAll(rulesetVer) {
    const [rows] = await pool.query(
      `SELECT rule_id, ruleset_ver, title, category, severity,
              os_target, check_key, check_type, check_param,
              recommend, enabled
       FROM rules
       WHERE ruleset_ver = ?
       ORDER BY rule_id`,
      [rulesetVer]
    );
    return rows;
  },

  async listVersions() {
    const [rows] = await pool.query(
      `SELECT DISTINCT ruleset_ver FROM rules ORDER BY ruleset_ver DESC`
    );
    return rows.map(r => r.ruleset_ver);
  },

  async upsertMany(rules, rulesetVer) {
    if (!rules.length) return;
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const sql = `
        INSERT INTO rules
          (rule_id, ruleset_ver, title, category, severity,
           os_target, check_key, check_type, check_param,
           recommend, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), ?, ?)
        ON DUPLICATE KEY UPDATE
          title=VALUES(title), category=VALUES(category),
          severity=VALUES(severity), os_target=VALUES(os_target),
          check_key=VALUES(check_key), check_type=VALUES(check_type),
          check_param=VALUES(check_param), recommend=VALUES(recommend),
          enabled=VALUES(enabled)`;
      for (const r of rules) {
        await conn.execute(sql, [
          r.rule_id, rulesetVer, r.title, r.category, r.severity,
          r.os_target, r.check_key, r.check_type,
          JSON.stringify(r.check_param || {}),
          r.recommend || null, r.enabled === false ? 0 : 1,
        ]);
      }
      await conn.commit();
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  },

  async setEnabled(ruleId, rulesetVer, enabled) {
    await pool.execute(
      `UPDATE rules SET enabled=? WHERE rule_id=? AND ruleset_ver=?`,
      [enabled ? 1 : 0, ruleId, rulesetVer]
    );
  },
};

module.exports = ruleDao;

'use strict';
const path = require('path');

// .env 로딩 (dotenv 미사용; 단순화)
try { require('fs').readFileSync(path.resolve('.env'), 'utf8').split('\n').forEach(l => {
  const m = l.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
  if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
}); } catch (_) { /* .env 없음: 무시 */ }

module.exports = {
  port: parseInt(process.env.PORT || '3000', 10),
  env: process.env.NODE_ENV || 'development',
  db: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER || 'vuln_app',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'vuln_assessor',
    connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT || '10', 10),
    charset: 'utf8mb4',
  },
  paths: {
    rawStorage: path.resolve(process.env.RAW_STORAGE_DIR || './data/raw'),
    uploadTmp: path.resolve(process.env.UPLOAD_TMP_DIR || './data/uploads'),
    rules:     path.resolve(process.env.RULES_DIR || './rules'),
  },
  maxUploadBytes: parseInt(process.env.MAX_UPLOAD_MB || '50', 10) * 1024 * 1024,
};

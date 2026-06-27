'use strict';
const mysql = require('mysql2/promise');
const config = require('../config');

const pool = mysql.createPool({
  host: config.db.host,
  port: config.db.port,
  user: config.db.user,
  password: config.db.password,
  database: config.db.database,
  connectionLimit: config.db.connectionLimit,
  charset: config.db.charset,
  waitForConnections: true,
  // ENUM 값을 문자열로 받기 위해
  typeCast(field, next) {
    if (field.type === 'JSON') {
      const v = field.string();
      return v == null ? null : JSON.parse(v);
    }
    return next();
  },
});

module.exports = pool;

'use strict';
const express = require('express');
const path = require('path');
const config = require('./config');

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/static', express.static(path.join(__dirname, 'public')));

// 공통 locals
app.use((req, res, next) => {
  res.locals.activeMenu = req.path.split('/')[1] || '';
  next();
});

// 라우트 마운트
app.use('/', require('./routes/index'));
app.use('/servers', require('./routes/servers'));
app.use('/assess', require('./routes/assess'));
app.use('/reports', require('./routes/reports'));
app.use('/history', require('./routes/history'));
app.use('/collect', require('./routes/collect'));
app.use('/rules', require('./routes/rules'));

// 에러 핸들러
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).render('error', {
    message: err.message || '서버 오류가 발생했습니다.',
    stack: config.env === 'development' ? err.stack : null,
  });
});

if (require.main === module) {
  app.listen(config.port, () => {
    console.log(`[vuln-assessor] listening on http://localhost:${config.port}`);
  });
}

module.exports = app;

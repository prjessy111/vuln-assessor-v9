'use strict';
const express = require('express');
const serverDao = require('../dao/serverDao');
const assessmentDao = require('../dao/assessmentDao');
const router = express.Router();

router.get('/', async (req, res, next) => {
  try {
    const servers = await serverDao.list();
    const serverId = req.query.server_id ? parseInt(req.query.server_id, 10) : null;
    let assessments = [];
    let selectedServer = null;
    if (serverId) {
      selectedServer = await serverDao.findById(serverId);
      assessments = await assessmentDao.listByServer(serverId);
    }
    res.render('history/list', { servers, selectedServer, assessments });
  } catch (e) { next(e); }
});

router.get('/compare', async (req, res, next) => {
  try {
    const a = parseInt(req.query.a, 10), b = parseInt(req.query.b, 10);
    if (!a || !b) return res.status(400).send('a, b 두 진단 ID가 필요합니다.');
    const sessA = await assessmentDao.findById(a);
    const sessB = await assessmentDao.findById(b);
    const rows = await assessmentDao.compare(a, b);
    // 변화 분류
    const classified = rows.map(r => {
      let change = '유지';
      if (r.status_a === '취약' && r.status_b !== '취약') change = '개선';
      else if (r.status_a !== '취약' && r.status_b === '취약') change = '악화';
      else if (!r.status_a) change = '신규(B)';
      else if (!r.status_b) change = '제거(A)';
      return { ...r, change };
    });
    res.render('history/compare', { sessA, sessB, rows: classified });
  } catch (e) { next(e); }
});

module.exports = router;

'use strict';
const express = require('express');
const serverDao = require('../dao/serverDao');
const collectionDao = require('../dao/collectionDao');
const { collectMany } = require('../services/rawCollectorService');

const router = express.Router();

// 수집 실행 화면
router.get('/', async (req, res, next) => {
  try {
    const servers = await serverDao.list();
    const recent = await collectionDao.listRecent(20);
    // SSH 정보 등록된 서버만 표시
    const collectable = servers.filter(s => s.ssh_user && (s.ssh_key_path || s.ssh_password_enc));
    res.render('collect/index', { servers: collectable, recent });
  } catch (e) { next(e); }
});

// 수집 실행
router.post('/run', async (req, res, next) => {
  try {
    let serverIds = req.body.server_ids;
    if (!serverIds) return res.status(400).send('server_ids 필요');
    if (!Array.isArray(serverIds)) serverIds = [serverIds];
    serverIds = serverIds.map(x => parseInt(x, 10)).filter(Number.isFinite);

    const triggeredBy = `수동:${req.body.executed_by || 'unknown'}`;
    const results = await collectMany(serverIds, triggeredBy);

    res.render('collect/result', { results });
  } catch (e) { next(e); }
});

// 수집 이력 (서버별)
router.get('/history', async (req, res, next) => {
  try {
    const serverId = parseInt(req.query.server_id, 10);
    if (!serverId) {
      const recent = await collectionDao.listRecent(100);
      return res.render('collect/history', { recent, selectedServer: null });
    }
    const selectedServer = await serverDao.findById(serverId);
    const recent = await collectionDao.listByServer(serverId);
    res.render('collect/history', { recent, selectedServer });
  } catch (e) { next(e); }
});

module.exports = router;

'use strict';
const express = require('express');
const serverDao = require('../dao/serverDao');
const { testConnection } = require('../services/connectionTester');
const router = express.Router();

router.get('/', async (req, res, next) => {
  try {
    const servers = await serverDao.list();
    res.render('servers/list', { servers });
  } catch (e) { next(e); }
});

router.get('/new', (req, res) => {
  res.render('servers/edit', { server: null });
});

router.get('/:id/edit', async (req, res, next) => {
  try {
    const server = await serverDao.findById(req.params.id);
    if (!server) return res.status(404).send('서버를 찾을 수 없습니다');
    res.render('servers/edit', { server });
  } catch (e) { next(e); }
});

router.post('/', async (req, res, next) => {
  try {
    const data = req.body;
    if (!data.name || !data.hostname || !data.os_type) {
      return res.status(400).send('필수 항목 누락');
    }
    data.use_sudo = data.use_sudo === 'on' || data.use_sudo === '1';
    await serverDao.create(data);
    res.redirect('/servers');
  } catch (e) { next(e); }
});

router.post('/:id/update', async (req, res, next) => {
  try {
    const data = req.body;
    data.use_sudo = data.use_sudo === 'on' || data.use_sudo === '1';
    await serverDao.update(req.params.id, data);
    res.redirect('/servers');
  } catch (e) { next(e); }
});

router.post('/:id/delete', async (req, res, next) => {
  try {
    await serverDao.remove(req.params.id);
    res.redirect('/servers');
  } catch (e) { next(e); }
});

// 연결 테스트: JSON 응답
router.post('/:id/test-connection', async (req, res, next) => {
  try {
    const server = await serverDao.findById(req.params.id);
    if (!server) return res.status(404).json({ error: '서버 없음' });
    const steps = await testConnection(server);
    const overall = steps.every(s => s.status !== 'fail') ? '성공' : '실패';
    res.json({ overall, steps });
  } catch (e) {
    res.json({ overall: '실패', steps: [{ name: '예외', status: 'fail', message: e.message }] });
  }
});

module.exports = router;

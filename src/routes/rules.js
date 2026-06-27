'use strict';
const express = require('express');
const ruleDao = require('../dao/ruleDao');
const router = express.Router();

router.get('/', async (req, res, next) => {
  try {
    const versions = await ruleDao.listVersions();
    const ver = req.query.v || versions[0] || 'v1.0';
    const rules = await ruleDao.listAll(ver);
    res.render('rules/list', { rules, versions, currentVer: ver });
  } catch (e) { next(e); }
});

router.post('/:rule_id/toggle', async (req, res, next) => {
  try {
    const { ruleset_ver, enabled } = req.body;
    await ruleDao.setEnabled(req.params.rule_id, ruleset_ver, enabled === '1');
    res.redirect(`/rules?v=${encodeURIComponent(ruleset_ver)}`);
  } catch (e) { next(e); }
});

module.exports = router;

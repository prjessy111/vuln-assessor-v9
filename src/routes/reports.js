'use strict';
const express = require('express');
const { buildReportData, exportXlsx } = require('../services/reportService');
const router = express.Router();

router.get('/:id', async (req, res, next) => {
  try {
    const { session, results } = await buildReportData(req.params.id);
    // 카테고리별로 그룹핑
    const grouped = {};
    for (const r of results) {
      (grouped[r.category] ||= []).push(r);
    }
    res.render('reports/view', { session, results, grouped });
  } catch (e) { next(e); }
});

router.get('/:id/xlsx', async (req, res, next) => {
  try {
    await exportXlsx(req.params.id, res);
  } catch (e) { next(e); }
});

module.exports = router;

'use strict';
const express = require('express');
const serverDao = require('../dao/serverDao');
const router = express.Router();

router.get('/', async (req, res, next) => {
  try {
    const summaries = await serverDao.latestAssessmentSummary();
    res.render('dashboard', { summaries });
  } catch (e) { next(e); }
});

module.exports = router;

'use strict';
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const config = require('../config');
const serverDao = require('../dao/serverDao');
const { runAssessment } = require('../services/assessmentService');

const router = express.Router();
fs.mkdirSync(config.paths.uploadTmp, { recursive: true });
fs.mkdirSync(config.paths.rawStorage, { recursive: true });

const upload = multer({
  dest: config.paths.uploadTmp,
  limits: { fileSize: config.maxUploadBytes },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!['.db', '.sqlite', '.sqlite3'].includes(ext)) {
      return cb(new Error('허용되지 않는 확장자입니다.'));
    }
    cb(null, true);
  },
});

router.get('/new', async (req, res, next) => {
  try {
    const servers = await serverDao.list();
    // /data/raw 디렉토리 스캔: 진단 가능한 raw 파일 목록
    let rawFiles = [];
    if (fs.existsSync(config.paths.rawStorage)) {
      rawFiles = fs.readdirSync(config.paths.rawStorage)
        .filter(f => /\.(db|sqlite|sqlite3)$/i.test(f))
        .map(f => {
          const full = path.join(config.paths.rawStorage, f);
          const st = fs.statSync(full);
          return { name: f, path: full, size: st.size, mtime: st.mtime };
        })
        .sort((a, b) => b.mtime - a.mtime);
    }
    res.render('assess/new', {
      servers, rawFiles,
      selectedId: req.query.server_id,
      prefillRaw: req.query.prefill_raw,
    });
  } catch (e) { next(e); }
});

// 1) 파일 업로드 기반 진단
router.post('/run', upload.single('raw_file'), async (req, res, next) => {
  try {
    const { server_id, executed_by, ruleset_ver, raw_file_path } = req.body;
    let uploadedPath, originalName;

    if (req.file) {
      // 업로드 케이스
      uploadedPath = req.file.path;
      originalName = req.file.originalname;
    } else if (raw_file_path) {
      // 디렉토리에서 선택한 기존 raw 파일 케이스
      if (!raw_file_path.startsWith(config.paths.rawStorage)) {
        return res.status(400).send('허용되지 않은 경로');
      }
      if (!fs.existsSync(raw_file_path)) {
        return res.status(400).send('해당 파일이 존재하지 않습니다.');
      }
      // 사본을 uploadTmp로 만들어 assessmentService가 이동 처리하도록
      uploadedPath = path.join(config.paths.uploadTmp, `reuse_${Date.now()}.db`);
      fs.copyFileSync(raw_file_path, uploadedPath);
      originalName = path.basename(raw_file_path);
    } else {
      return res.status(400).send('raw_file 업로드 또는 raw_file_path 선택 필요');
    }

    const result = await runAssessment({
      serverId: parseInt(server_id, 10),
      uploadedPath, originalName,
      rulesetVer: ruleset_ver || 'v1.0',
      executedBy: executed_by,
    });
    res.redirect(`/diagnosis/${result.assessmentId}/ai`);
  } catch (e) {
    if (req.file && fs.existsSync(req.file.path)) {
      try { fs.unlinkSync(req.file.path); } catch (_) {}
    }
    next(e);
  }
});

module.exports = router;

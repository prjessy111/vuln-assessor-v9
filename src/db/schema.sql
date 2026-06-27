-- ============================================================================
-- 취약점 진단 시스템 운영 DB 스키마 v6
--
-- v5 → v6 변경점:
--   - servers 테이블에 asset_no(자산번호), service_name(업무명/용도) 추가
--   - assessment_results 에 운영 추적 컬럼 추가 (신규여부/담당자/조치 등)
--   - 금보원 양식 18개 컬럼 모두 매핑 가능하도록 확장
-- ============================================================================

SET NAMES utf8mb4;

-- ----------------------------------------------------------------------------
-- servers: 진단 대상 + SSH 정보 + 자산 정보
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS servers (
    server_id        INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name             VARCHAR(100) NOT NULL,
    hostname         VARCHAR(255) NOT NULL,
    os_type          ENUM('linux','windows') NOT NULL,
    description      VARCHAR(500),
    -- 자산 정보 (금보원 양식)
    asset_no         VARCHAR(50),                 -- 자산번호 (예: SVR-2025-001)
    service_name     VARCHAR(200),                -- 업무명/용도 (예: 결제 시스템 DB)
    ip_address       VARCHAR(45),                 -- IPv4/IPv6
    department       VARCHAR(100),                -- 운영 부서
    -- SSH
    ssh_port         INT UNSIGNED DEFAULT 22,
    ssh_user         VARCHAR(50),
    ssh_auth_type    ENUM('key','password') DEFAULT 'key',
    ssh_key_path     VARCHAR(500),
    ssh_password_enc VARBINARY(2048),
    remote_raw_path  VARCHAR(500) DEFAULT '/var/lib/secums/data.db',
    use_sudo         TINYINT(1) NOT NULL DEFAULT 1,
    last_collected_at DATETIME,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (server_id),
    UNIQUE KEY uk_servers_hostname (hostname),
    UNIQUE KEY uk_servers_asset (asset_no)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rules (
    rule_id      VARCHAR(20)  NOT NULL,
    ruleset_ver  VARCHAR(20)  NOT NULL,
    title        VARCHAR(200) NOT NULL,
    category     VARCHAR(50)  NOT NULL,
    severity     ENUM('상','중','하') NOT NULL,
    os_target    ENUM('linux','windows','all') NOT NULL,
    check_key    VARCHAR(100) NOT NULL,
    check_type   VARCHAR(30)  NOT NULL,
    check_param  JSON,
    recommend    TEXT,
    -- v6: 추가 메타 (룰 카드용)
    description  TEXT,
    check_method TEXT,
    check_criteria TEXT,
    related_cves JSON,
    enabled      TINYINT(1)   NOT NULL DEFAULT 1,
    PRIMARY KEY (rule_id, ruleset_ver),
    KEY idx_rules_oskey (os_target, check_key),
    KEY idx_rules_enabled (enabled, ruleset_ver)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS assessments (
    assessment_id  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    server_id      INT UNSIGNED NOT NULL,
    raw_file_name  VARCHAR(255) NOT NULL,
    raw_file_hash  CHAR(64)     NOT NULL,
    ruleset_ver    VARCHAR(20)  NOT NULL,
    executed_by    VARCHAR(100),
    executed_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    total_count    INT UNSIGNED NOT NULL,
    vuln_count     INT UNSIGNED NOT NULL,
    safe_count     INT UNSIGNED NOT NULL,
    na_count       INT UNSIGNED NOT NULL,
    elapsed_ms     INT UNSIGNED,
    PRIMARY KEY (assessment_id),
    KEY idx_assess_server_time (server_id, executed_at DESC),
    KEY idx_assess_hash (raw_file_hash),
    CONSTRAINT fk_assess_server FOREIGN KEY (server_id)
        REFERENCES servers(server_id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- assessment_results: 항목별 판정 + 운영 추적 정보 (금보원 양식)
-- v7: 중항목/소항목 계층 지원
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assessment_results (
    result_id       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    assessment_id   BIGINT UNSIGNED NOT NULL,
    rule_id         VARCHAR(20)  NOT NULL,
    -- v7: 중/소항목 구분
    parent_result_id BIGINT UNSIGNED,             -- NULL=중항목, 값=소항목(부모 참조)
    sub_key         VARCHAR(200),                 -- 소항목 식별자 (예: 'jessy1')
    sub_label       VARCHAR(300),                 -- 소항목 표시 라벨
    -- 판정 결과
    status          ENUM('양호','취약','점검불가') NOT NULL,
    collected_value TEXT,
    reason          VARCHAR(500),
    evidence        VARCHAR(500),
    severity        ENUM('상','중','하') NOT NULL,
    eval_method     ENUM('simple','llm','na') NOT NULL DEFAULT 'na',
    -- 금보원 운영 컬럼 (중항목에만 저장, 소항목은 모두 NULL)
    -- 정책: 중항목 fix_status='조치완료' 처리 시 자식 소항목들도 일괄 종료
    is_new          TINYINT(1),                   -- 중항목만 (소항목 NULL)
    management_no   VARCHAR(50),                  -- 중항목만
    assignee        VARCHAR(100),                 -- 중항목만
    delivered_at    DATE,                          -- 중항목만
    fixed_at        DATE,                          -- 중항목만
    fix_status      ENUM('미조치','진행중','조치완료','조치불가','예외') DEFAULT '미조치',
    unfixed_reason  VARCHAR(500),                 -- 중항목만
    remark          VARCHAR(500),                 -- 중항목만
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (result_id),
    KEY idx_result_assess (assessment_id),
    KEY idx_result_rule_status (rule_id, status),
    KEY idx_result_fix_status (fix_status, status),
    KEY idx_result_assignee (assignee),
    KEY idx_result_parent (parent_result_id),
    KEY idx_result_main (assessment_id, parent_result_id, status),
    CONSTRAINT fk_result_assess FOREIGN KEY (assessment_id)
        REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    CONSTRAINT fk_result_parent FOREIGN KEY (parent_result_id)
        REFERENCES assessment_results(result_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS collection_history (
    collection_id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    server_id       INT UNSIGNED NOT NULL,
    started_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at     DATETIME,
    status          ENUM('성공','실패','진행중') NOT NULL DEFAULT '진행중',
    raw_file_path   VARCHAR(500),
    raw_file_hash   CHAR(64),
    file_size       BIGINT UNSIGNED,
    error_message   VARCHAR(1000),
    triggered_by    VARCHAR(100),
    PRIMARY KEY (collection_id),
    KEY idx_coll_server_time (server_id, started_at DESC),
    CONSTRAINT fk_coll_server FOREIGN KEY (server_id)
        REFERENCES servers(server_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- 트리거: 중항목 조치완료/예외 처리 시 자식 소항목 일괄 동기화
-- ============================================================================
DELIMITER $$

DROP TRIGGER IF EXISTS trg_result_cascade_close $$
CREATE TRIGGER trg_result_cascade_close
AFTER UPDATE ON assessment_results
FOR EACH ROW
BEGIN
    -- 중항목(parent_result_id IS NULL)의 fix_status가 종료 상태로 변경되었을 때만
    IF NEW.parent_result_id IS NULL
       AND OLD.fix_status <> NEW.fix_status
       AND NEW.fix_status IN ('조치완료', '예외')
    THEN
        UPDATE assessment_results
        SET fix_status = NEW.fix_status,
            fixed_at   = COALESCE(NEW.fixed_at, CURDATE())
        WHERE parent_result_id = NEW.result_id;
    END IF;
END$$

DELIMITER ;

-- ============================================================================
-- v9: 스케줄링 점검
-- ============================================================================

CREATE TABLE IF NOT EXISTS schedules (
    schedule_id   INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name          VARCHAR(100) NOT NULL,
    description   VARCHAR(500),
    -- 스케줄 정의
    cron_expr     VARCHAR(50)  NOT NULL,            -- '0 2 * * *' (매일 02:00)
    timezone      VARCHAR(50)  NOT NULL DEFAULT 'Asia/Seoul',
    jitter_seconds INT UNSIGNED DEFAULT 0,          -- 시작 시각 ± 랜덤 (피크 회피)
    -- 대상
    server_scope  ENUM('all', 'group', 'list') NOT NULL DEFAULT 'all',
    server_group  VARCHAR(100),                     -- 'production', 'dmz' 등
    server_ids    JSON,                             -- [1,2,3] (server_scope='list' 시)
    -- 룰셋
    ruleset_ver   VARCHAR(20)  NOT NULL,
    -- 운영 옵션
    enabled       TINYINT(1)   NOT NULL DEFAULT 1,
    max_concurrency INT UNSIGNED DEFAULT 5,         -- 동시 진단 서버 수
    timeout_ms    INT UNSIGNED DEFAULT 600000,      -- 단일 진단 최대 10분
    retry_failed  TINYINT(1)   NOT NULL DEFAULT 1,
    -- 알림 설정
    notify_on_vuln    TINYINT(1) NOT NULL DEFAULT 1,
    notify_on_failure TINYINT(1) NOT NULL DEFAULT 1,
    notify_channels   JSON,                          -- [{type:'email', target:'ops@..'}]
    -- 통계
    last_run_at   DATETIME,
    last_status   ENUM('성공','실패','부분실패','실행중'),
    next_run_at   DATETIME,
    -- 메타
    created_by    VARCHAR(100),
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (schedule_id),
    KEY idx_sched_enabled_next (enabled, next_run_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS schedule_runs (
    run_id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    schedule_id    INT UNSIGNED NOT NULL,
    started_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at    DATETIME,
    triggered_by   ENUM('cron','manual','retry') NOT NULL DEFAULT 'cron',
    status         ENUM('실행중','성공','실패','부분실패','중단') NOT NULL DEFAULT '실행중',
    total_servers  INT UNSIGNED DEFAULT 0,
    success_count  INT UNSIGNED DEFAULT 0,
    failed_count   INT UNSIGNED DEFAULT 0,
    elapsed_ms     INT UNSIGNED,
    log_summary    TEXT,
    PRIMARY KEY (run_id),
    KEY idx_run_sched_time (schedule_id, started_at DESC),
    CONSTRAINT fk_run_sched FOREIGN KEY (schedule_id)
        REFERENCES schedules(schedule_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

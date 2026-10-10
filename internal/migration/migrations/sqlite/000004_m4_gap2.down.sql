-- 000004_m4_gap2.down.sql (sqlite)
-- GAP2 回滚：删除 login_audits。

DROP INDEX IF EXISTS IDX_login_audits_createdAt;
DROP INDEX IF EXISTS IDX_login_audits_userGuid;
DROP TABLE IF EXISTS login_audits;

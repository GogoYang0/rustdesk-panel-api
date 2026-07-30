-- 000002_m2_core.down.sql (sqlite)
-- M2 回滚：倒序 DROP 12 表（users.strategyGuid 本方言无 FK 可清理）。

DROP TABLE IF EXISTS console_audits;
DROP TABLE IF EXISTS user_role_assignment_device_groups;
DROP TABLE IF EXISTS user_role_assignments;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS active_connections;
DROP TABLE IF EXISTS sysinfos;
DROP TABLE IF EXISTS peers;
DROP TABLE IF EXISTS user_user_permissions;
DROP TABLE IF EXISTS device_group_user_permissions;
DROP TABLE IF EXISTS device_groups;
DROP TABLE IF EXISTS strategies;

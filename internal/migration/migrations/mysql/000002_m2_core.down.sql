-- 000002_m2_core.down.sql (mysql)
-- M2 回滚：先 DROP users 上补加的 FK，再倒序 DROP 12 表。

ALTER TABLE `users` DROP FOREIGN KEY `FK_users_strategy`;

DROP TABLE IF EXISTS `console_audits`;
DROP TABLE IF EXISTS `user_role_assignment_device_groups`;
DROP TABLE IF EXISTS `user_role_assignments`;
DROP TABLE IF EXISTS `role_permissions`;
DROP TABLE IF EXISTS `roles`;
DROP TABLE IF EXISTS `active_connections`;
DROP TABLE IF EXISTS `sysinfos`;
DROP TABLE IF EXISTS `peers`;
DROP TABLE IF EXISTS `user_user_permissions`;
DROP TABLE IF EXISTS `device_group_user_permissions`;
DROP TABLE IF EXISTS `device_groups`;
DROP TABLE IF EXISTS `strategies`;

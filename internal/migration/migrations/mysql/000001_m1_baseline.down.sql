-- 000001_m1_baseline.down.sql (mysql)
-- 回滚 M1 基线：删除全部 7 表（子表先删，索引随表删除）。

DROP TABLE IF EXISTS `oidc_auth_states`;
DROP TABLE IF EXISTS `oidc_providers`;
DROP TABLE IF EXISTS `passkey_credentials`;
DROP TABLE IF EXISTS `login_sessions`;
DROP TABLE IF EXISTS `user_tokens`;
DROP TABLE IF EXISTS `users`;
DROP TABLE IF EXISTS `user_groups`;

-- 000003_m3_business.down.sql (mysql)
-- 逆序 DROP 12 表（依赖方向：peer_tags → tags/peers、rules → books）。

DROP TABLE IF EXISTS `system_settings`;
DROP TABLE IF EXISTS `nexus_tokens`;
DROP TABLE IF EXISTS `nexus_builds`;
DROP TABLE IF EXISTS `address_book_rules`;
DROP TABLE IF EXISTS `address_book_peer_tags`;
DROP TABLE IF EXISTS `address_book_tags`;
DROP TABLE IF EXISTS `address_book_peers`;
DROP TABLE IF EXISTS `address_books`;
DROP TABLE IF EXISTS `alarm_audits`;
DROP TABLE IF EXISTS `file_audits`;
DROP TABLE IF EXISTS `connection_audits`;
DROP TABLE IF EXISTS `invitations`;

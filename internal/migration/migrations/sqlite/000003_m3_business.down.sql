-- 000003_m3_business.down.sql (sqlite)
-- M3 回滚：倒序 DROP 12 表（本方言无 FK 可清理；级联语义由应用层承担）。

DROP TABLE IF EXISTS system_settings;
DROP TABLE IF EXISTS nexus_tokens;
DROP TABLE IF EXISTS nexus_builds;
DROP TABLE IF EXISTS address_book_rules;
DROP TABLE IF EXISTS address_book_peer_tags;
DROP TABLE IF EXISTS address_book_tags;
DROP TABLE IF EXISTS address_book_peers;
DROP TABLE IF EXISTS address_books;
DROP TABLE IF EXISTS alarm_audits;
DROP TABLE IF EXISTS file_audits;
DROP TABLE IF EXISTS connection_audits;
DROP TABLE IF EXISTS invitations;

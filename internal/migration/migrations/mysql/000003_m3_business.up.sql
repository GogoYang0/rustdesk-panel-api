-- 000003_m3_business.up.sql (mysql)
-- M3 业务域 12 表 DDL（MySQL 8.4 方言）：invitations、connection_audits、
-- file_audits、alarm_audits、address_books、address_book_peers、
-- address_book_tags、address_book_peer_tags、address_book_rules、
-- nexus_builds、nexus_tokens、system_settings。
-- 列名 = DB 契约（camelCase 原样，反引号包裹；沿 M2 惯例与设计
-- §1.1⑦ 实测列集；§3.2 表格的 snake_case 为行文形态，不落库）。
-- FK 策略（设计 §3.2）：MySQL 侧仅对既有强关联补 FK——
-- invitations.userGuid → users SET NULL；ab 全系列与 nexus 系列无 FK
-- （跨表级联由应用层事务保证，共享知识 9/10 同款）。
-- 审计三表时间锚点：connection_audits.requestedAt / file_audits.requestedAt
-- 由上报链赋值；alarm_audits.createdAt 为落库时刻（仪表盘 trends 按日
-- 聚合锚点，设计事实⑥）。

CREATE TABLE `invitations` (
    `guid`          varchar(36)  NOT NULL,
    `token`         varchar(64)  NOT NULL,
    `email`         varchar(255) NOT NULL,
    `name`          varchar(255) NOT NULL,
    `displayName`   varchar(255) DEFAULT NULL,
    `userGroupGuid` varchar(36)  DEFAULT NULL,
    `note`          text,
    `userGuid`      varchar(36)  DEFAULT NULL,
    `expiresAt`     datetime(6)  NOT NULL,
    `usedAt`        datetime(6)  DEFAULT NULL,
    `createdAt`     datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`guid`),
    CONSTRAINT `FK_invitations_user` FOREIGN KEY (`userGuid`) REFERENCES `users` (`guid`) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE UNIQUE INDEX `UK_invitations_token` ON `invitations` (`token`);
CREATE INDEX `IDX_invitations_userGuid` ON `invitations` (`userGuid`);

CREATE TABLE `connection_audits` (
    `id`            int          NOT NULL AUTO_INCREMENT,
    `deviceId`      varchar(255) NOT NULL,
    `deviceUuid`    varchar(36)  DEFAULT NULL,
    `connId`        varchar(64)  DEFAULT NULL,
    `sessionId`     varchar(64)  DEFAULT NULL,
    `ip`            varchar(64)  DEFAULT NULL,
    `action`        varchar(32)  NOT NULL DEFAULT 'new',
    `peerId`        varchar(255) DEFAULT NULL,
    `peerName`      varchar(255) DEFAULT NULL,
    `type`          int          NOT NULL DEFAULT 0,
    `requestedAt`   datetime(6)  NOT NULL,
    `establishedAt` datetime(6)  DEFAULT NULL,
    `closedAt`      datetime(6)  DEFAULT NULL,
    `note`          varchar(256) DEFAULT NULL,
    `nonce`         varchar(36)  DEFAULT NULL,
    `connAuditRef`  varchar(36)  DEFAULT NULL,
    `primaryAuth`   int          NOT NULL DEFAULT 0,
    `twoFactor`     int          NOT NULL DEFAULT 0,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

-- upsert 定位键（设计事实②：按 deviceId+deviceUuid+connId 定位既有行）
CREATE INDEX `IDX_connection_audits_conn_key` ON `connection_audits` (`deviceId`, `deviceUuid`, `connId`);
CREATE INDEX `IDX_connection_audits_requestedAt` ON `connection_audits` (`requestedAt`);

CREATE TABLE `file_audits` (
    `id`          int          NOT NULL AUTO_INCREMENT,
    `deviceId`    varchar(255) NOT NULL,
    `deviceUuid`  varchar(36)  NOT NULL,
    `peerId`      varchar(255) NOT NULL,
    `connId`      varchar(64)  DEFAULT NULL,
    `type`        int          NOT NULL DEFAULT 0,
    `path`        text,
    `isFile`      tinyint      NOT NULL DEFAULT 0,
    `clientIp`    varchar(64)  DEFAULT NULL,
    `clientName`  varchar(255) DEFAULT NULL,
    `fileCount`   int          NOT NULL DEFAULT 0,
    `files`       mediumtext,
    `nonce`       varchar(36)  DEFAULT NULL,
    `requestedAt` datetime(6)  NOT NULL,
    `createdAt`   datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    CONSTRAINT `UK_file_audits_device_nonce` UNIQUE (`deviceId`, `nonce`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX `IDX_file_audits_requestedAt` ON `file_audits` (`requestedAt`);

CREATE TABLE `alarm_audits` (
    `id`           int          NOT NULL AUTO_INCREMENT,
    `deviceId`     varchar(255) NOT NULL,
    `deviceUuid`   varchar(36)  NOT NULL,
    `typ`          int          NOT NULL DEFAULT 0,
    `infoId`       varchar(255) DEFAULT NULL,
    `infoIp`       varchar(64)  DEFAULT NULL,
    `infoName`     varchar(255) DEFAULT NULL,
    `connId`       varchar(64)  DEFAULT NULL,
    `nonce`        varchar(36)  DEFAULT NULL,
    `connAuditRef` varchar(36)  DEFAULT NULL,
    `createdAt`    datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    CONSTRAINT `UK_alarm_audits_device_nonce` UNIQUE (`deviceId`, `nonce`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX `IDX_alarm_audits_typ` ON `alarm_audits` (`typ`);
CREATE INDEX `IDX_alarm_audits_createdAt` ON `alarm_audits` (`createdAt`);

CREATE TABLE `address_books` (
    `guid`       varchar(36)  NOT NULL,
    `owner`      varchar(36)  NOT NULL,
    `isPersonal` tinyint      NOT NULL DEFAULT 0,
    `isShared`   tinyint      NOT NULL DEFAULT 0,
    `name`       varchar(255) NOT NULL,
    `note`       text,
    `info`       text,
    `createdAt`  datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    `updatedAt`  datetime(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`guid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX `IDX_address_books_owner_personal` ON `address_books` (`owner`, `isPersonal`);
CREATE INDEX `IDX_address_books_name` ON `address_books` (`name`);

CREATE TABLE `address_book_peers` (
    `guid`            varchar(36)  NOT NULL,
    `addressBookGuid` varchar(36)  NOT NULL,
    `deviceId`        varchar(255) NOT NULL,
    `hash`            varchar(255) DEFAULT NULL,
    `password`        varchar(255) DEFAULT NULL,
    `alias`           varchar(255) DEFAULT NULL,
    `note`            text,
    `createdAt`       datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    `updatedAt`       datetime(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`guid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX `IDX_address_book_peers_book` ON `address_book_peers` (`addressBookGuid`);

CREATE TABLE `address_book_tags` (
    `guid`            varchar(36) NOT NULL,
    `addressBookGuid` varchar(36) NOT NULL,
    `name`            varchar(255) NOT NULL,
    `color`           int unsigned NOT NULL DEFAULT 0,
    `createdAt`       datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`guid`),
    CONSTRAINT `UK_address_book_tags_book_name` UNIQUE (`addressBookGuid`, `name`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE `address_book_peer_tags` (
    `peerGuid`  varchar(36) NOT NULL,
    `tagGuid`   varchar(36) NOT NULL,
    `createdAt` datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`peerGuid`, `tagGuid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX `IDX_address_book_peer_tags_tag` ON `address_book_peer_tags` (`tagGuid`);

CREATE TABLE `address_book_rules` (
    `guid`            varchar(36) NOT NULL,
    `addressBookGuid` varchar(36) NOT NULL,
    `targetUserId`    varchar(36) DEFAULT NULL,
    `targetGroupId`   varchar(36) DEFAULT NULL,
    `rule`            int         NOT NULL,
    `createdAt`       datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`guid`, `addressBookGuid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX `IDX_address_book_rules_targetUser` ON `address_book_rules` (`targetUserId`);
CREATE INDEX `IDX_address_book_rules_targetGroup` ON `address_book_rules` (`targetGroupId`);

CREATE TABLE `nexus_builds` (
    `uuid`      varchar(36)  NOT NULL,
    `userGuid`  varchar(36)  NOT NULL,
    `os`        varchar(32)  NOT NULL,
    `arch`      varchar(32)  NOT NULL,
    `appName`   varchar(255) DEFAULT NULL,
    `custom`    text,
    `status`    varchar(32)  NOT NULL DEFAULT 'pending',
    `files`     text,
    `message`   text,
    `createdAt` datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`uuid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX `IDX_nexus_builds_user_created` ON `nexus_builds` (`userGuid`, `createdAt`);
CREATE INDEX `IDX_nexus_builds_status` ON `nexus_builds` (`status`);

CREATE TABLE `nexus_tokens` (
    `userGuid`      varchar(36) NOT NULL,
    `nexusToken`    varchar(255) NOT NULL,
    `nexusUsername` varchar(255) DEFAULT NULL,
    `expiresAt`     datetime(6)  NOT NULL,
    `currentUuid`   varchar(36)  DEFAULT NULL,
    `createdAt`     datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    `updatedAt`     datetime(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`userGuid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE `system_settings` (
    `key`         varchar(255) NOT NULL,
    `value`       mediumtext,
    `category`    varchar(64)  NOT NULL DEFAULT '',
    `description` varchar(255) DEFAULT NULL,
    `isSensitive` tinyint      NOT NULL DEFAULT 0,
    `updatedAt`   datetime(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`key`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX `IDX_system_settings_category` ON `system_settings` (`category`);

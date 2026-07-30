-- 000002_m2_core.up.sql (mysql)
-- M2 核心业务域 12 表 DDL（MySQL 8.4 方言）：strategies、device_groups、
-- device_group_user_permissions、user_user_permissions、peers、sysinfos、
-- active_connections、roles、role_permissions、user_role_assignments、
-- user_role_assignment_device_groups、console_audits。
-- 列名 = DB 契约（camelCase 原样，反引号包裹）；唯一例外 sysinfos 的
-- preset_* 为 snake_case 列（共享知识 11，契约本身，禁止规范化）。
-- datetime(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)、
-- tinyint 对齐参考 TypeORM initial-schema（M1 同款惯例）。
-- FK（设计 §3.1 关系标注）：peers.userGuid、sysinfos.uuid 无 FK（与参考一致）。

CREATE TABLE `strategies` (
    `guid`          varchar(36)  NOT NULL,
    `name`          varchar(255) NOT NULL,
    `note`          text,
    `configOptions` text,
    `createdAt`     datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    `updatedAt`     datetime(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`guid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE UNIQUE INDEX `UK_strategies_name` ON `strategies` (`name`);

CREATE TABLE `device_groups` (
    `guid`         varchar(36)  NOT NULL,
    `name`         varchar(255) NOT NULL,
    `note`         text,
    `strategyGuid` varchar(36)  DEFAULT NULL,
    `createdAt`    datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    `updatedAt`    datetime(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`guid`),
    CONSTRAINT `FK_device_groups_strategy` FOREIGN KEY (`strategyGuid`) REFERENCES `strategies` (`guid`) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE UNIQUE INDEX `UK_device_groups_name` ON `device_groups` (`name`);
CREATE INDEX `IDX_device_groups_strategyGuid` ON `device_groups` (`strategyGuid`);

CREATE TABLE `device_group_user_permissions` (
    `deviceGroupGuid` varchar(36) NOT NULL,
    `userGuid`        varchar(36) NOT NULL,
    `createdAt`       datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`deviceGroupGuid`, `userGuid`),
    CONSTRAINT `FK_dgup_device_group` FOREIGN KEY (`deviceGroupGuid`) REFERENCES `device_groups` (`guid`) ON DELETE CASCADE,
    CONSTRAINT `FK_dgup_user` FOREIGN KEY (`userGuid`) REFERENCES `users` (`guid`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE `user_user_permissions` (
    `userGuid`       varchar(36) NOT NULL,
    `targetUserGuid` varchar(36) NOT NULL,
    `createdAt`      datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`userGuid`, `targetUserGuid`),
    CONSTRAINT `FK_uup_user` FOREIGN KEY (`userGuid`) REFERENCES `users` (`guid`) ON DELETE CASCADE,
    CONSTRAINT `FK_uup_target_user` FOREIGN KEY (`targetUserGuid`) REFERENCES `users` (`guid`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE `peers` (
    `uuid`            varchar(36)  NOT NULL,
    `id`              varchar(255) NOT NULL DEFAULT '',
    `userGuid`        varchar(36)  DEFAULT NULL,
    `deviceGroupGuid` varchar(36)  DEFAULT NULL,
    `strategyGuid`    varchar(36)  DEFAULT NULL,
    `note`            text,
    `status`          tinyint      NOT NULL DEFAULT 1,
    `ver`             bigint       NOT NULL DEFAULT 0,
    `modifiedAt`      bigint       NOT NULL DEFAULT 0,
    `lastHeartbeat`   datetime(6)  DEFAULT NULL,
    `createdAt`       datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    `updatedAt`       datetime(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`uuid`),
    CONSTRAINT `FK_peers_device_group` FOREIGN KEY (`deviceGroupGuid`) REFERENCES `device_groups` (`guid`) ON DELETE SET NULL,
    CONSTRAINT `FK_peers_strategy` FOREIGN KEY (`strategyGuid`) REFERENCES `strategies` (`guid`) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX `IDX_peers_id` ON `peers` (`id`);
CREATE INDEX `IDX_peers_userGuid` ON `peers` (`userGuid`);
CREATE INDEX `IDX_peers_deviceGroupGuid` ON `peers` (`deviceGroupGuid`);
CREATE INDEX `IDX_peers_lastHeartbeat` ON `peers` (`lastHeartbeat`);

CREATE TABLE `sysinfos` (
    `uuid`                     varchar(36)  NOT NULL,
    `hostname`                 varchar(255) DEFAULT NULL,
    `username`                 varchar(255) DEFAULT NULL,
    `os`                       varchar(255) DEFAULT NULL,
    `cpu`                      varchar(255) DEFAULT NULL,
    `memory`                   varchar(255) DEFAULT NULL,
    `preset_username`          varchar(255) DEFAULT NULL,
    `preset_strategy_name`     varchar(255) DEFAULT NULL,
    `preset_device_group_name` varchar(255) DEFAULT NULL,
    `createdAt`                datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    `updatedAt`                datetime(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`uuid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE `active_connections` (
    `id`         int         NOT NULL AUTO_INCREMENT,
    `connId`     bigint      NOT NULL,
    `deviceUuid` varchar(36) NOT NULL,
    `createdAt`  datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    CONSTRAINT `FK_active_connections_peer` FOREIGN KEY (`deviceUuid`) REFERENCES `peers` (`uuid`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX `IDX_active_connections_deviceUuid` ON `active_connections` (`deviceUuid`);

CREATE TABLE `roles` (
    `guid`             varchar(36)  NOT NULL,
    `name`             varchar(255) NOT NULL,
    `note`             text,
    `protectedAccount` tinyint      NOT NULL DEFAULT 0,
    `createdAt`        datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    `updatedAt`        datetime(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`guid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE UNIQUE INDEX `UK_roles_name` ON `roles` (`name`);

CREATE TABLE `role_permissions` (
    `roleGuid`       varchar(36)  NOT NULL,
    `permissionCode` varchar(255) NOT NULL,
    PRIMARY KEY (`roleGuid`, `permissionCode`),
    CONSTRAINT `FK_role_permissions_role` FOREIGN KEY (`roleGuid`) REFERENCES `roles` (`guid`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE `user_role_assignments` (
    `guid`      varchar(36)  NOT NULL,
    `userGuid`  varchar(36)  NOT NULL,
    `roleGuid`  varchar(36)  NOT NULL,
    `scopeType` varchar(255) NOT NULL,
    `createdAt` datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    `updatedAt` datetime(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`guid`),
    CONSTRAINT `FK_user_role_assignments_user` FOREIGN KEY (`userGuid`) REFERENCES `users` (`guid`) ON DELETE CASCADE,
    CONSTRAINT `FK_user_role_assignments_role` FOREIGN KEY (`roleGuid`) REFERENCES `roles` (`guid`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE UNIQUE INDEX `UK_user_role_assignments_user_role` ON `user_role_assignments` (`userGuid`, `roleGuid`);
CREATE INDEX `IDX_user_role_assignments_roleGuid` ON `user_role_assignments` (`roleGuid`);

CREATE TABLE `user_role_assignment_device_groups` (
    `assignmentGuid`  varchar(36) NOT NULL,
    `deviceGroupGuid` varchar(36) NOT NULL,
    PRIMARY KEY (`assignmentGuid`, `deviceGroupGuid`),
    CONSTRAINT `FK_uradg_assignment` FOREIGN KEY (`assignmentGuid`) REFERENCES `user_role_assignments` (`guid`) ON DELETE CASCADE,
    -- RESTRICT：删除被角色授权引用的设备组由应用层 400 拦截（device-group.service），
    -- DB 层兜底拒绝（设计 §3.2）。
    CONSTRAINT `FK_uradg_device_group` FOREIGN KEY (`deviceGroupGuid`) REFERENCES `device_groups` (`guid`) ON DELETE RESTRICT
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE `console_audits` (
    `guid`          varchar(36)  NOT NULL,
    `actorUserGuid` varchar(36)  DEFAULT NULL,
    `targetType`    varchar(255) NOT NULL,
    `targetGuid`    varchar(36)  DEFAULT NULL,
    `action`        varchar(255) NOT NULL,
    `result`        varchar(32)  NOT NULL,
    `reason`        text,
    `beforeState`   text,
    `afterState`    text,
    `requestId`     varchar(36)  DEFAULT NULL,
    `createdAt`     datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`guid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX `IDX_console_audits_actor` ON `console_audits` (`actorUserGuid`, `createdAt`);

-- M1 预留列补 FK（共享知识 10）：仅 MySQL 版添加；SQLite 方言不加
-- （不能 ALTER ADD CONSTRAINT，删除策略置空引用由应用层事务保证，
-- 见 strategy.service DeleteWithDetach / 共享知识 9）。
ALTER TABLE `users`
    ADD CONSTRAINT `FK_users_strategy` FOREIGN KEY (`strategyGuid`) REFERENCES `strategies` (`guid`) ON DELETE SET NULL;

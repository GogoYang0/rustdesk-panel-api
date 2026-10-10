-- 000002_m2_core.up.sql (sqlite)
-- M2 核心业务域 12 表 DDL（sqlite 方言）。
-- 列名 = DB 契约（camelCase 原样，禁止规范化）；唯一例外 sysinfos 的
-- preset_* 为 snake_case 列（共享知识 11，契约本身）。
-- MySQL 方言差异：datetime(6) DEFAULT/ON UPDATE、active_connections 用
-- INTEGER AUTOINCREMENT、users.strategyGuid 补 FK_users_strategy
-- （SQLite 不能 ALTER ADD CONSTRAINT，共享知识 10；删除策略置空引用由
-- 应用层事务保证，见 strategy.service DeleteWithDetach / 共享知识 9）。
-- 级联语义说明：glebarez SQLite 驱动默认 foreign_keys=OFF（测试基建显式
-- PRAGMA 开启），跨表级联一律以服务层事务为准，FK 仅为 schema 平价。

CREATE TABLE strategies (
    guid           VARCHAR(36)  NOT NULL PRIMARY KEY,
    name           VARCHAR(255) NOT NULL,
    note           TEXT,
    configOptions  TEXT,
    createdAt      DATETIME,
    updatedAt      DATETIME
);

CREATE UNIQUE INDEX UK_strategies_name ON strategies (name);

CREATE TABLE device_groups (
    guid         VARCHAR(36)  NOT NULL PRIMARY KEY,
    name         VARCHAR(255) NOT NULL,
    note         TEXT,
    strategyGuid VARCHAR(36),
    createdAt    DATETIME,
    updatedAt    DATETIME,
    FOREIGN KEY (strategyGuid) REFERENCES strategies (guid) ON DELETE SET NULL
);

CREATE UNIQUE INDEX UK_device_groups_name ON device_groups (name);
CREATE INDEX IDX_device_groups_strategyGuid ON device_groups (strategyGuid);

CREATE TABLE device_group_user_permissions (
    deviceGroupGuid VARCHAR(36) NOT NULL,
    userGuid        VARCHAR(36) NOT NULL,
    createdAt       DATETIME,
    PRIMARY KEY (deviceGroupGuid, userGuid),
    FOREIGN KEY (deviceGroupGuid) REFERENCES device_groups (guid) ON DELETE CASCADE,
    FOREIGN KEY (userGuid) REFERENCES users (guid) ON DELETE CASCADE
);

CREATE TABLE user_user_permissions (
    userGuid       VARCHAR(36) NOT NULL,
    targetUserGuid VARCHAR(36) NOT NULL,
    createdAt      DATETIME,
    PRIMARY KEY (userGuid, targetUserGuid),
    FOREIGN KEY (userGuid) REFERENCES users (guid) ON DELETE CASCADE,
    FOREIGN KEY (targetUserGuid) REFERENCES users (guid) ON DELETE CASCADE
);

CREATE TABLE peers (
    uuid            VARCHAR(36)  NOT NULL PRIMARY KEY,
    id              VARCHAR(255) NOT NULL DEFAULT '',
    userGuid        VARCHAR(36),
    deviceGroupGuid VARCHAR(36),
    strategyGuid    VARCHAR(36),
    note            TEXT,
    status          TINYINT      NOT NULL DEFAULT 1,
    ver             BIGINT       NOT NULL DEFAULT 0,
    modifiedAt      BIGINT       NOT NULL DEFAULT 0,
    lastHeartbeat   DATETIME,
    createdAt       DATETIME,
    updatedAt       DATETIME,
    FOREIGN KEY (deviceGroupGuid) REFERENCES device_groups (guid) ON DELETE SET NULL,
    FOREIGN KEY (strategyGuid) REFERENCES strategies (guid) ON DELETE SET NULL
);

CREATE INDEX IDX_peers_id ON peers (id);
CREATE INDEX IDX_peers_userGuid ON peers (userGuid);
CREATE INDEX IDX_peers_deviceGroupGuid ON peers (deviceGroupGuid);
CREATE INDEX IDX_peers_lastHeartbeat ON peers (lastHeartbeat);

CREATE TABLE sysinfos (
    uuid                     VARCHAR(36)  NOT NULL PRIMARY KEY,
    hostname                 VARCHAR(255),
    username                 VARCHAR(255),
    os                       VARCHAR(255),
    cpu                      VARCHAR(255),
    memory                   VARCHAR(255),
    preset_username          VARCHAR(255),
    preset_strategy_name     VARCHAR(255),
    preset_device_group_name VARCHAR(255),
    createdAt                DATETIME,
    updatedAt                DATETIME
);

CREATE TABLE active_connections (
    id         INTEGER     NOT NULL PRIMARY KEY AUTOINCREMENT,
    connId     BIGINT      NOT NULL,
    deviceUuid VARCHAR(36) NOT NULL,
    createdAt  DATETIME,
    FOREIGN KEY (deviceUuid) REFERENCES peers (uuid) ON DELETE CASCADE
);

CREATE INDEX IDX_active_connections_deviceUuid ON active_connections (deviceUuid);

CREATE TABLE roles (
    guid             VARCHAR(36)  NOT NULL PRIMARY KEY,
    name             VARCHAR(255) NOT NULL,
    note             TEXT,
    protectedAccount TINYINT      NOT NULL DEFAULT 0,
    createdAt        DATETIME,
    updatedAt        DATETIME
);

CREATE UNIQUE INDEX UK_roles_name ON roles (name);

CREATE TABLE role_permissions (
    roleGuid       VARCHAR(36)  NOT NULL,
    permissionCode VARCHAR(255) NOT NULL,
    PRIMARY KEY (roleGuid, permissionCode),
    FOREIGN KEY (roleGuid) REFERENCES roles (guid) ON DELETE CASCADE
);

CREATE TABLE user_role_assignments (
    guid      VARCHAR(36)  NOT NULL PRIMARY KEY,
    userGuid  VARCHAR(36)  NOT NULL,
    roleGuid  VARCHAR(36)  NOT NULL,
    scopeType VARCHAR(255) NOT NULL,
    createdAt DATETIME,
    updatedAt DATETIME,
    FOREIGN KEY (userGuid) REFERENCES users (guid) ON DELETE CASCADE,
    FOREIGN KEY (roleGuid) REFERENCES roles (guid) ON DELETE CASCADE
);

CREATE UNIQUE INDEX UK_user_role_assignments_user_role ON user_role_assignments (userGuid, roleGuid);
CREATE INDEX IDX_user_role_assignments_roleGuid ON user_role_assignments (roleGuid);

CREATE TABLE user_role_assignment_device_groups (
    assignmentGuid  VARCHAR(36) NOT NULL,
    deviceGroupGuid VARCHAR(36) NOT NULL,
    PRIMARY KEY (assignmentGuid, deviceGroupGuid),
    FOREIGN KEY (assignmentGuid) REFERENCES user_role_assignments (guid) ON DELETE CASCADE,
    FOREIGN KEY (deviceGroupGuid) REFERENCES device_groups (guid) ON DELETE RESTRICT
);

CREATE TABLE console_audits (
    guid          VARCHAR(36)  NOT NULL PRIMARY KEY,
    actorUserGuid VARCHAR(36),
    targetType    VARCHAR(255) NOT NULL,
    targetGuid    VARCHAR(36),
    action        VARCHAR(255) NOT NULL,
    result        VARCHAR(32)  NOT NULL,
    reason        TEXT,
    beforeState   TEXT,
    afterState    TEXT,
    requestId     VARCHAR(36),
    createdAt     DATETIME
);

CREATE INDEX IDX_console_audits_actor ON console_audits (actorUserGuid, createdAt);

-- 000003_m3_business.up.sql (sqlite)
-- M3 业务域 12 表 DDL（sqlite 方言），与 mysql/000003_m3_business 同构：
-- invitations、connection_audits、file_audits、alarm_audits、address_books、
-- address_book_peers、address_book_tags、address_book_peer_tags、
-- address_book_rules、nexus_builds、nexus_tokens、system_settings。
-- 列名 = DB 契约（camelCase 原样，禁止规范化；设计 §1.1⑦ 实测列集；
-- §3.2 表格的 snake_case 为行文形态，不落库）。
-- 方言差异（沿 M2 惯例）：无反引号/ENGINE；id 用 INTEGER AUTOINCREMENT；
-- 时间默认值（DEFAULT CURRENT_TIMESTAMP(6)/ON UPDATE）不落 DDL——
-- 落库时刻一律由应用层赋值。
-- FK 策略（设计 §3.2）：SQLite 侧一律不加（共享知识 9：跨表级联由
-- 应用层事务显式执行；glebarez 驱动默认 foreign_keys=OFF）；MySQL 侧
-- invitations.userGuid → users 的 schema 平价由同一应用层事务保证。
-- 审计三表时间锚点：connection_audits.requestedAt / file_audits.requestedAt
-- 由上报链赋值；alarm_audits.createdAt 为落库时刻（仪表盘 trends 按日
-- 聚合锚点，设计事实⑥）。

CREATE TABLE invitations (
    guid          VARCHAR(36)  NOT NULL PRIMARY KEY,
    token         VARCHAR(64)  NOT NULL,
    email         VARCHAR(255) NOT NULL,
    name          VARCHAR(255) NOT NULL,
    displayName   VARCHAR(255),
    userGroupGuid VARCHAR(36),
    note          TEXT,
    userGuid      VARCHAR(36),
    expiresAt     DATETIME     NOT NULL,
    usedAt        DATETIME,
    createdAt     DATETIME
);

CREATE UNIQUE INDEX UK_invitations_token ON invitations (token);
CREATE INDEX IDX_invitations_userGuid ON invitations (userGuid);

CREATE TABLE connection_audits (
    id            INTEGER      NOT NULL PRIMARY KEY AUTOINCREMENT,
    deviceId      VARCHAR(255) NOT NULL,
    deviceUuid    VARCHAR(36),
    connId        VARCHAR(64),
    sessionId     VARCHAR(64),
    ip            VARCHAR(64),
    action        VARCHAR(32)  NOT NULL DEFAULT 'new',
    peerId        VARCHAR(255),
    peerName      VARCHAR(255),
    type          INTEGER      NOT NULL DEFAULT 0,
    requestedAt   DATETIME     NOT NULL,
    establishedAt DATETIME,
    closedAt      DATETIME,
    note          VARCHAR(256),
    nonce         VARCHAR(36),
    connAuditRef  VARCHAR(36),
    primaryAuth   INTEGER      NOT NULL DEFAULT 0,
    twoFactor     INTEGER      NOT NULL DEFAULT 0
);

-- upsert 定位键（设计事实②：按 deviceId+deviceUuid+connId 定位既有行）
CREATE INDEX IDX_connection_audits_conn_key ON connection_audits (deviceId, deviceUuid, connId);
CREATE INDEX IDX_connection_audits_requestedAt ON connection_audits (requestedAt);

CREATE TABLE file_audits (
    id          INTEGER      NOT NULL PRIMARY KEY AUTOINCREMENT,
    deviceId    VARCHAR(255) NOT NULL,
    deviceUuid  VARCHAR(36)  NOT NULL,
    peerId      VARCHAR(255) NOT NULL,
    connId      VARCHAR(64),
    type        INTEGER      NOT NULL DEFAULT 0,
    path        TEXT,
    isFile      TINYINT      NOT NULL DEFAULT 0,
    clientIp    VARCHAR(64),
    clientName  VARCHAR(255),
    fileCount   INTEGER      NOT NULL DEFAULT 0,
    files       TEXT,
    nonce       VARCHAR(36),
    requestedAt DATETIME     NOT NULL,
    createdAt   DATETIME
);

-- nonce 幂等（设计事实②：UNIQUE(deviceId,nonce) 冲突重查返回既有行；
-- nonce 为 NULL 的行不参与去重——SQLite/MySQL 唯一索引对多 NULL 均放行）
CREATE UNIQUE INDEX UK_file_audits_device_nonce ON file_audits (deviceId, nonce);
CREATE INDEX IDX_file_audits_requestedAt ON file_audits (requestedAt);

CREATE TABLE alarm_audits (
    id           INTEGER      NOT NULL PRIMARY KEY AUTOINCREMENT,
    deviceId     VARCHAR(255) NOT NULL,
    deviceUuid   VARCHAR(36)  NOT NULL,
    typ          INTEGER      NOT NULL DEFAULT 0,
    infoId       VARCHAR(255),
    infoIp       VARCHAR(64),
    infoName     VARCHAR(255),
    connId       VARCHAR(64),
    nonce        VARCHAR(36),
    connAuditRef VARCHAR(36),
    createdAt    DATETIME
);

CREATE UNIQUE INDEX UK_alarm_audits_device_nonce ON alarm_audits (deviceId, nonce);
CREATE INDEX IDX_alarm_audits_typ ON alarm_audits (typ);
CREATE INDEX IDX_alarm_audits_createdAt ON alarm_audits (createdAt);

CREATE TABLE address_books (
    guid       VARCHAR(36)  NOT NULL PRIMARY KEY,
    owner      VARCHAR(36)  NOT NULL,
    isPersonal TINYINT      NOT NULL DEFAULT 0,
    isShared   TINYINT      NOT NULL DEFAULT 0,
    name       VARCHAR(255) NOT NULL,
    note       TEXT,
    info       TEXT,
    createdAt  DATETIME,
    updatedAt  DATETIME
);

CREATE INDEX IDX_address_books_owner_personal ON address_books (owner, isPersonal);
CREATE INDEX IDX_address_books_name ON address_books (name);

CREATE TABLE address_book_peers (
    guid            VARCHAR(36)  NOT NULL PRIMARY KEY,
    addressBookGuid VARCHAR(36)  NOT NULL,
    deviceId        VARCHAR(255) NOT NULL,
    hash            VARCHAR(255),
    password        VARCHAR(255),
    alias           VARCHAR(255),
    note            TEXT,
    createdAt       DATETIME,
    updatedAt       DATETIME
);

-- 应用层级联（设计 §3.2：address_book_guid 索引供级联删除定位）
CREATE INDEX IDX_address_book_peers_book ON address_book_peers (addressBookGuid);

CREATE TABLE address_book_tags (
    guid            VARCHAR(36)  NOT NULL PRIMARY KEY,
    addressBookGuid VARCHAR(36)  NOT NULL,
    name            VARCHAR(255) NOT NULL,
    color           INTEGER      NOT NULL DEFAULT 0,
    createdAt       DATETIME
);

CREATE UNIQUE INDEX UK_address_book_tags_book_name ON address_book_tags (addressBookGuid, name);

CREATE TABLE address_book_peer_tags (
    peerGuid  VARCHAR(36) NOT NULL,
    tagGuid   VARCHAR(36) NOT NULL,
    createdAt DATETIME,
    PRIMARY KEY (peerGuid, tagGuid)
);

CREATE INDEX IDX_address_book_peer_tags_tag ON address_book_peer_tags (tagGuid);

CREATE TABLE address_book_rules (
    guid            VARCHAR(36) NOT NULL,
    addressBookGuid VARCHAR(36) NOT NULL,
    targetUserId    VARCHAR(36),
    targetGroupId   VARCHAR(36),
    rule            INTEGER     NOT NULL,
    createdAt       DATETIME,
    PRIMARY KEY (guid, addressBookGuid)
);

CREATE INDEX IDX_address_book_rules_targetUser ON address_book_rules (targetUserId);
CREATE INDEX IDX_address_book_rules_targetGroup ON address_book_rules (targetGroupId);

CREATE TABLE nexus_builds (
    uuid      VARCHAR(36)  NOT NULL PRIMARY KEY,
    userGuid  VARCHAR(36)  NOT NULL,
    os        VARCHAR(32)  NOT NULL,
    arch      VARCHAR(32)  NOT NULL,
    appName   VARCHAR(255),
    custom    TEXT,
    status    VARCHAR(32)  NOT NULL DEFAULT 'pending',
    files     TEXT,
    message   TEXT,
    createdAt DATETIME
);

CREATE INDEX IDX_nexus_builds_user_created ON nexus_builds (userGuid, createdAt);
CREATE INDEX IDX_nexus_builds_status ON nexus_builds (status);

CREATE TABLE nexus_tokens (
    userGuid      VARCHAR(36)  NOT NULL PRIMARY KEY,
    nexusToken    VARCHAR(255) NOT NULL,
    nexusUsername VARCHAR(255),
    expiresAt     DATETIME     NOT NULL,
    currentUuid   VARCHAR(36),
    createdAt     DATETIME,
    updatedAt     DATETIME
);

CREATE TABLE system_settings (
    key         VARCHAR(255) NOT NULL PRIMARY KEY,
    value       TEXT,
    category    VARCHAR(64)  NOT NULL DEFAULT '',
    description VARCHAR(255),
    isSensitive TINYINT      NOT NULL DEFAULT 0,
    updatedAt   DATETIME
);

CREATE INDEX IDX_system_settings_category ON system_settings (category);

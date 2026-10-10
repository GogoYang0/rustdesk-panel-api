-- 000004_m4_gap2.up.sql (sqlite)
-- GAP2 增量迁移（sqlite 方言），与 mysql/000004_m4_gap2 同构：
-- login_audits 登录事件审计表（设计 §3.4）。
-- 列名 = DB 契约（camelCase 原样，禁止规范化；沿 M2/M3 惯例）。
-- 方言差异（沿 M3 惯例）：无反引号/ENGINE；时间默认值不落 DDL，
-- 落库时刻一律由应用层赋值；SQLite 侧一律不加 FK（跨表级联由
-- 应用层事务显式执行，glebarez 驱动默认 foreign_keys=OFF）。
-- userGuid 可空：登录尝试可能不对应任何既有用户（防枚举锚点）。
-- result 六枚举（共享知识 G3）：success | failed | tfa_required |
-- tfa_failed | mfa_enroll_required | mfa_enroll_completed。
-- method 五枚举：password | tfa_code | email_code | passkey | oidc。

CREATE TABLE login_audits (
    guid       VARCHAR(36)  NOT NULL PRIMARY KEY,
    userGuid   VARCHAR(36),
    username   VARCHAR(255) NOT NULL,
    result     VARCHAR(32)  NOT NULL,
    method     VARCHAR(32)  NOT NULL,
    ip         VARCHAR(64),
    userAgent  VARCHAR(255),
    deviceId   VARCHAR(255),
    deviceUuid VARCHAR(36),
    reason     VARCHAR(255),
    createdAt  DATETIME     NOT NULL
);

CREATE INDEX IDX_login_audits_userGuid ON login_audits (userGuid);
CREATE INDEX IDX_login_audits_createdAt ON login_audits (createdAt);

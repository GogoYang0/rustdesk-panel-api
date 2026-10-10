-- 000004_m4_gap2.up.sql (mysql)
-- GAP2 增量迁移（mysql 方言），与 sqlite/000004_m4_gap2 同构：
-- login_audits 登录事件审计表（设计 §3.4）。
-- 列名 = DB 契约（camelCase 原样，禁止规范化；沿 M2/M3 惯例）。
-- userGuid 可空：登录尝试可能不对应任何既有用户（防枚举锚点）。
-- result 六枚举（共享知识 G3）：success | failed | tfa_required |
-- tfa_failed | mfa_enroll_required | mfa_enroll_completed。
-- method 五枚举：password | tfa_code | email_code | passkey | oidc。
-- 时间默认值不落 DDL，落库时刻由应用层赋值（沿 M3 惯例）。

CREATE TABLE login_audits (
    guid       VARCHAR(36)  NOT NULL PRIMARY KEY,
    userGuid   VARCHAR(36)  NULL,
    username   VARCHAR(255) NOT NULL,
    result     VARCHAR(32)  NOT NULL,
    method     VARCHAR(32)  NOT NULL,
    ip         VARCHAR(64)  NULL,
    userAgent  VARCHAR(255) NULL,
    deviceId   VARCHAR(255) NULL,
    deviceUuid VARCHAR(36)  NULL,
    reason     VARCHAR(255) NULL,
    createdAt  DATETIME(6)  NOT NULL,
    KEY IDX_login_audits_userGuid (userGuid),
    KEY IDX_login_audits_createdAt (createdAt)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

-- 000001_m1_baseline.up.sql (sqlite)
-- M1 迁移基线：7 表 DDL（sqlite 方言）。
-- 列名 = DB 契约（camelCase 原样，禁止规范化）；实体 GORM tag 与本文件逐列一致
-- （repository/migration 断言测试保障）。MySQL 方言差异见 migrations/mysql/：
-- datetime(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)、
-- UQ_users_single_owner 用生成列实现。
--
-- FK（批复事项 #4）：user_tokens.userGuid -> users.guid (CASCADE)；
-- users.userGroupGuid -> user_groups.guid (SET NULL)；users.strategyGuid 的 FK 延后
-- M2 建 strategies 表时补加。
-- 种子：默认用户组与默认管理员由 internal/database/seed.go 幂等写入（Go 侧，
-- 支持.ADMIN_USERNAME/ADMIN_PASSWORD 覆盖）；OIDC provider 种子样例见文件尾部注释。

CREATE TABLE user_groups (
    guid           VARCHAR(36)  NOT NULL PRIMARY KEY,
    name           VARCHAR(255) NOT NULL,
    normalizedName VARCHAR(255) NOT NULL,
    note           TEXT,
    isDefault      TINYINT      NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX UK_user_groups_normalizedName ON user_groups (normalizedName);

CREATE TABLE users (
    guid                  VARCHAR(36)  NOT NULL PRIMARY KEY,
    username              VARCHAR(255) NOT NULL,
    displayName           VARCHAR(255),
    email                 VARCHAR(255),
    password              VARCHAR(255),
    note                  TEXT,
    verifier              TEXT,
    status                TINYINT      NOT NULL DEFAULT 0,
    isAdmin               TINYINT      NOT NULL DEFAULT 0,
    emailVerificationCode VARCHAR(255),
    tfaSecret             VARCHAR(255),
    info                  TEXT,
    thirdAuthType         VARCHAR(255),
    oidcSubject           VARCHAR(255),
    avatar                VARCHAR(255),
    strategyGuid          VARCHAR(36),
    userGroupGuid         VARCHAR(36),
    createdAt             DATETIME,
    updatedAt             DATETIME,
    CONSTRAINT FK_users_userGroup FOREIGN KEY (userGroupGuid) REFERENCES user_groups (guid) ON DELETE SET NULL
);

CREATE UNIQUE INDEX UK_users_username ON users (username);
CREATE UNIQUE INDEX UK_users_email ON users (email);
CREATE UNIQUE INDEX UK_users_oidcSubject ON users (oidcSubject);
-- 仅允许一个管理员（partial unique index，索引名原样保留）。
CREATE UNIQUE INDEX UQ_users_single_owner ON users (isAdmin) WHERE isAdmin = 1;

CREATE TABLE user_tokens (
    guid       VARCHAR(36)  NOT NULL PRIMARY KEY,
    userGuid   VARCHAR(36)  NOT NULL,
    jti        VARCHAR(36)  NOT NULL,
    deviceId   VARCHAR(255),
    deviceUuid VARCHAR(255),
    expiresAt  DATETIME     NOT NULL,
    isRevoked  TINYINT      NOT NULL DEFAULT 0,
    deviceOs   VARCHAR(255),
    deviceType VARCHAR(255),
    deviceName VARCHAR(255),
    createdAt  DATETIME,
    CONSTRAINT FK_user_tokens_user FOREIGN KEY (userGuid) REFERENCES users (guid) ON DELETE CASCADE
);

CREATE UNIQUE INDEX UK_user_tokens_jti ON user_tokens (jti);
CREATE INDEX IDX_user_tokens_userGuid ON user_tokens (userGuid);

CREATE TABLE login_sessions (
    guid      VARCHAR(36)  NOT NULL PRIMARY KEY,
    userGuid  VARCHAR(36)  NOT NULL,
    method    VARCHAR(32)  NOT NULL,
    email     VARCHAR(255),
    code      VARCHAR(255),
    expiresAt DATETIME     NOT NULL,
    used      TINYINT      NOT NULL DEFAULT 0
);

CREATE INDEX IDX_login_sessions_userGuid ON login_sessions (userGuid);

CREATE TABLE passkey_credentials (
    guid                VARCHAR(36)  NOT NULL PRIMARY KEY,
    userGuid            VARCHAR(36)  NOT NULL,
    credentialId        VARCHAR(512) NOT NULL,
    credentialPublicKey TEXT,
    counter             INT          NOT NULL DEFAULT 0,
    transports          VARCHAR(255),
    deviceType          VARCHAR(64),
    backedUp            TINYINT      NOT NULL DEFAULT 0,
    name                VARCHAR(255)
);

CREATE UNIQUE INDEX UK_passkey_credentials_credentialId ON passkey_credentials (credentialId);
CREATE INDEX IDX_passkey_credentials_userGuid ON passkey_credentials (userGuid);

CREATE TABLE oidc_providers (
    guid                  VARCHAR(36)  NOT NULL PRIMARY KEY,
    name                  VARCHAR(255) NOT NULL,
    type                  VARCHAR(64),
    issuer                VARCHAR(255),
    clientId              VARCHAR(255),
    clientSecret          VARCHAR(255),
    scope                 VARCHAR(255),
    authorizationEndpoint VARCHAR(255),
    tokenEndpoint         VARCHAR(255),
    userinfoEndpoint      VARCHAR(255),
    jwksUri               VARCHAR(255),
    icon                  VARCHAR(255),
    enabled               TINYINT      NOT NULL DEFAULT 0,
    priority              INT          NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX UK_oidc_providers_name ON oidc_providers (name);

CREATE TABLE oidc_auth_states (
    guid                VARCHAR(36)  NOT NULL PRIMARY KEY,
    code                VARCHAR(255) NOT NULL,
    op                  VARCHAR(255),
    providerType        VARCHAR(64),
    deviceId            VARCHAR(255),
    deviceUuid          VARCHAR(255),
    deviceInfo          TEXT,
    redirectUri         VARCHAR(255),
    state               VARCHAR(255),
    status              VARCHAR(32),
    userGuid            VARCHAR(36),
    accessToken         TEXT,
    codeVerifier        VARCHAR(255),
    nonce               VARCHAR(255),
    frontendRedirectUrl VARCHAR(255),
    expiresAt           DATETIME     NOT NULL
);

CREATE UNIQUE INDEX UK_oidc_auth_states_code ON oidc_auth_states (code);

-- ---------------------------------------------------------------------------
-- OIDC provider 种子样例（M1 无 provider 管理端点，生产表空为正常态，
-- 批复事项 #6；测试用 internal/testutil 注入假 provider）：
--
-- INSERT INTO oidc_providers (guid, name, type, issuer, clientId, clientSecret,
--     scope, authorizationEndpoint, tokenEndpoint, userinfoEndpoint, jwksUri,
--     icon, enabled, priority)
-- VALUES ('00000000-0000-4000-8000-0000000000aa', 'github', 'oidc',
--     'https://token.actions.githubusercontent.com', 'client-id', 'client-secret',
--     'openid profile email', 'https://github.com/login/oauth/authorize',
--     'https://github.com/login/oauth/access_token',
--     'https://api.github.com/user', '', '', 1, 0);
-- ---------------------------------------------------------------------------

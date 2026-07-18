-- 000001_m1_baseline.up.sql (mysql)
-- M1 迁移基线：7 表 DDL（MySQL 8.4 方言）。
-- 列名 = DB 契约（camelCase 原样，反引号包裹）；datetime(6) DEFAULT
-- CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)、tinyint 对齐参考
-- TypeORM initial-schema。UQ_users_single_owner 用生成列实现（不改表列契约）。

CREATE TABLE `user_groups` (
    `guid`           varchar(36)  NOT NULL,
    `name`           varchar(255) NOT NULL,
    `normalizedName` varchar(255) NOT NULL,
    `note`           text,
    `isDefault`      tinyint      NOT NULL DEFAULT 0,
    PRIMARY KEY (`guid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE UNIQUE INDEX `UK_user_groups_normalizedName` ON `user_groups` (`normalizedName`);

CREATE TABLE `users` (
    `guid`                  varchar(36)  NOT NULL,
    `username`              varchar(255) NOT NULL,
    `displayName`           varchar(255) DEFAULT NULL,
    `email`                 varchar(255) DEFAULT NULL,
    `password`              varchar(255) DEFAULT NULL,
    `note`                  text,
    `verifier`              text,
    `status`                tinyint      NOT NULL DEFAULT 0,
    `isAdmin`               tinyint      NOT NULL DEFAULT 0,
    `emailVerificationCode` varchar(255) DEFAULT NULL,
    `tfaSecret`             varchar(255) DEFAULT NULL,
    `info`                  text,
    `thirdAuthType`         varchar(255) DEFAULT NULL,
    `oidcSubject`           varchar(255) DEFAULT NULL,
    `avatar`                varchar(255) DEFAULT NULL,
    `strategyGuid`          varchar(36)  DEFAULT NULL,
    `userGroupGuid`         varchar(36)  DEFAULT NULL,
    `createdAt`             datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    `updatedAt`             datetime(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`guid`),
    CONSTRAINT `FK_users_userGroup` FOREIGN KEY (`userGroupGuid`) REFERENCES `user_groups` (`guid`) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE UNIQUE INDEX `UK_users_username` ON `users` (`username`);
CREATE UNIQUE INDEX `UK_users_email` ON `users` (`email`);
CREATE UNIQUE INDEX `UK_users_oidcSubject` ON `users` (`oidcSubject`);
-- 仅允许一个管理员：生成列 owner_flag（isAdmin=1 时为 1，否则 NULL），
-- 唯一索引忽略 NULL（不改表列契约，设计 §3.2）。
ALTER TABLE `users`
    ADD COLUMN `owner_flag` TINYINT GENERATED ALWAYS AS (IF (`isAdmin` = 1, 1, NULL)) STORED;
CREATE UNIQUE INDEX `UQ_users_single_owner` ON `users` (`owner_flag`);

CREATE TABLE `user_tokens` (
    `guid`       varchar(36)  NOT NULL,
    `userGuid`   varchar(36)  NOT NULL,
    `jti`        varchar(36)  NOT NULL,
    `deviceId`   varchar(255) DEFAULT NULL,
    `deviceUuid` varchar(255) DEFAULT NULL,
    `expiresAt`  datetime(6)  NOT NULL,
    `isRevoked`  tinyint      NOT NULL DEFAULT 0,
    `deviceOs`   varchar(255) DEFAULT NULL,
    `deviceType` varchar(255) DEFAULT NULL,
    `deviceName` varchar(255) DEFAULT NULL,
    `createdAt`  datetime(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`guid`),
    CONSTRAINT `FK_user_tokens_user` FOREIGN KEY (`userGuid`) REFERENCES `users` (`guid`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE UNIQUE INDEX `UK_user_tokens_jti` ON `user_tokens` (`jti`);
CREATE INDEX `IDX_user_tokens_userGuid` ON `user_tokens` (`userGuid`);

CREATE TABLE `login_sessions` (
    `guid`      varchar(36)  NOT NULL,
    `userGuid`  varchar(36)  NOT NULL,
    `method`    varchar(32)  NOT NULL,
    `email`     varchar(255) DEFAULT NULL,
    `code`      varchar(255) DEFAULT NULL,
    `expiresAt` datetime(6)  NOT NULL,
    `used`      tinyint      NOT NULL DEFAULT 0,
    PRIMARY KEY (`guid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX `IDX_login_sessions_userGuid` ON `login_sessions` (`userGuid`);

CREATE TABLE `passkey_credentials` (
    `guid`                varchar(36)  NOT NULL,
    `userGuid`            varchar(36)  NOT NULL,
    `credentialId`        varchar(512) NOT NULL,
    `credentialPublicKey` text,
    `counter`             int          NOT NULL DEFAULT 0,
    `transports`          varchar(255) DEFAULT NULL,
    `deviceType`          varchar(64)  DEFAULT NULL,
    `backedUp`            tinyint      NOT NULL DEFAULT 0,
    `name`                varchar(255) DEFAULT NULL,
    PRIMARY KEY (`guid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE UNIQUE INDEX `UK_passkey_credentials_credentialId` ON `passkey_credentials` (`credentialId`);
CREATE INDEX `IDX_passkey_credentials_userGuid` ON `passkey_credentials` (`userGuid`);

CREATE TABLE `oidc_providers` (
    `guid`                  varchar(36)  NOT NULL,
    `name`                  varchar(255) NOT NULL,
    `type`                  varchar(64)  DEFAULT NULL,
    `issuer`                varchar(255) DEFAULT NULL,
    `clientId`              varchar(255) DEFAULT NULL,
    `clientSecret`          varchar(255) DEFAULT NULL,
    `scope`                 varchar(255) DEFAULT NULL,
    `authorizationEndpoint` varchar(255) DEFAULT NULL,
    `tokenEndpoint`         varchar(255) DEFAULT NULL,
    `userinfoEndpoint`      varchar(255) DEFAULT NULL,
    `jwksUri`               varchar(255) DEFAULT NULL,
    `icon`                  varchar(255) DEFAULT NULL,
    `enabled`               tinyint      NOT NULL DEFAULT 0,
    `priority`              int          NOT NULL DEFAULT 0,
    PRIMARY KEY (`guid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE UNIQUE INDEX `UK_oidc_providers_name` ON `oidc_providers` (`name`);

CREATE TABLE `oidc_auth_states` (
    `guid`                varchar(36)  NOT NULL,
    `code`                varchar(255) NOT NULL,
    `op`                  varchar(255) DEFAULT NULL,
    `providerType`        varchar(64)  DEFAULT NULL,
    `deviceId`            varchar(255) DEFAULT NULL,
    `deviceUuid`          varchar(255) DEFAULT NULL,
    `deviceInfo`          text,
    `redirectUri`         varchar(255) DEFAULT NULL,
    `state`               varchar(255) DEFAULT NULL,
    `status`              varchar(32)  DEFAULT NULL,
    `userGuid`            varchar(36)  DEFAULT NULL,
    `accessToken`         text,
    `codeVerifier`        varchar(255) DEFAULT NULL,
    `nonce`               varchar(255) DEFAULT NULL,
    `frontendRedirectUrl` varchar(255) DEFAULT NULL,
    `expiresAt`           datetime(6)  NOT NULL,
    PRIMARY KEY (`guid`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE UNIQUE INDEX `UK_oidc_auth_states_code` ON `oidc_auth_states` (`code`);

-- ---------------------------------------------------------------------------
-- 种子样例（默认用户组 + 默认管理员，实际由 internal/database/seed.go 幂等写入；
-- bcrypt('databk') = '$2a$10$viV8L2tlU3GDU3mSGs.EPOSae/W/Q4NE/sUPWaj2BQFHqZK3ve6Cy'）：
--
-- INSERT INTO `user_groups` (`guid`, `name`, `normalizedName`, `note`, `isDefault`)
-- VALUES ('00000000-0000-4000-8000-000000000001', 'Default', 'default', NULL, 1);
-- INSERT INTO `users` (`guid`, `username`, `email`, `password`, `status`, `isAdmin`,
--     `userGroupGuid`, `createdAt`, `updatedAt`)
-- VALUES ('00000000-0000-4000-8000-000000000002', 'databk', 'databk@github.com',
--     '$2a$10$viV8L2tlU3GDU3mSGs.EPOSae/W/Q4NE/sUPWaj2BQFHqZK3ve6Cy', 1, 1,
--     '00000000-0000-4000-8000-000000000001', NOW(6), NOW(6));
--
-- OIDC provider 种子样例（M1 无 provider 管理端点，批复事项 #6）：
-- INSERT INTO `oidc_providers` (`guid`, `name`, `type`, `issuer`, `clientId`,
--     `clientSecret`, `scope`, `authorizationEndpoint`, `tokenEndpoint`,
--     `userinfoEndpoint`, `jwksUri`, `icon`, `enabled`, `priority`)
-- VALUES ('00000000-0000-4000-8000-0000000000aa', 'github', 'oidc',
--     'https://token.actions.githubusercontent.com', 'client-id', 'client-secret',
--     'openid profile email', 'https://github.com/login/oauth/authorize',
--     'https://github.com/login/oauth/access_token',
--     'https://api.github.com/user', '', '', 1, 0);
-- ---------------------------------------------------------------------------

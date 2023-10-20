DROP TABLE IF EXISTS `User`;
DROP TABLE IF EXISTS RefreshToken;

CREATE TABLE `User`
(
    id       VARCHAR(255) PRIMARY KEY,
    password VARCHAR(255) NOT NULL,
    role     VARCHAR(255) NOT NULL
);

CREATE TABLE RefreshToken
(
    id       VARCHAR(255) PRIMARY KEY,
    refreshToken VARCHAR(255) NOT NULL
);
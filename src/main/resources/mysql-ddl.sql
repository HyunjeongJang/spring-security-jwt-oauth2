drop table member;

CREATE TABLE member
(
    member_id  bigint auto_increment primary key,
    email      varchar(256) not null,
    password   varchar(256) not null,
    nickname   varchar(256) not null,
    role       varchar(256) not null,
    enabled_yn varchar(1)   not null
);

drop table oauth2_account;

CREATE TABLE oauth2_account
(
    oauth2_account_id bigint auto_increment primary key,
    provider_name     varchar(128) not null,
    account_id        varchar(255) not null,
    member_id         bigint       not null
);

CREATE INDEX idx_memberid ON oauth2_account (member_id);
CREATE INDEX idx_providername_accountid ON oauth2_account (provider_name, account_id);
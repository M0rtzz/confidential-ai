-- P4 密钥签发、授权规则、密文资产与幂等/重放记录。
-- 库中只保存标识、状态与摘要；数据密钥由中心密钥服务托管，密文对象存放于运行目录。

create table if not exists tee_key (
  key_id varchar(64) not null,
  key_version varchar(32) not null,
  asset_id varchar(64) not null,
  asset_version varchar(32) not null,
  owner_id varchar(128) not null,
  resource_uri varchar(128) not null,
  state varchar(32) not null default 'ACTIVE',
  issued_at varchar(64) not null,
  claim_count integer not null default 0,
  release_count integer not null default 0,
  id integer,
  is_deleted integer not null default 0,
  gmt_create datetime,
  gmt_modified datetime,
  primary key (key_id, key_version)
);
create index if not exists idx_tee_key_asset on tee_key(asset_id, asset_version, is_deleted);
create index if not exists idx_tee_key_owner on tee_key(owner_id, is_deleted);

create table if not exists tee_policy (
  policy_id varchar(64) not null,
  policy_version varchar(32) not null,
  asset_id varchar(64) not null,
  asset_version varchar(32) not null,
  owner_id varchar(128) not null,
  sandbox_id varchar(64) not null,
  columns_json text not null default '[]',
  operators_json text not null default '[]',
  report_kinds_json text not null default '[]',
  expires_at varchar(64) not null,
  state varchar(32) not null default 'ACTIVE',
  id integer,
  is_deleted integer not null default 0,
  gmt_create datetime,
  gmt_modified datetime,
  primary key (policy_id, policy_version)
);
create index if not exists idx_tee_policy_asset on tee_policy(asset_id, asset_version, is_deleted);

create table if not exists tee_asset (
  asset_id varchar(64) not null,
  asset_version varchar(32) not null,
  owner_id varchar(128) not null,
  schema_json text not null default '[]',
  object_id varchar(64) not null,
  policy_id varchar(64) not null,
  policy_version varchar(32) not null,
  key_id varchar(64) not null,
  key_version varchar(32) not null,
  id integer,
  is_deleted integer not null default 0,
  gmt_create datetime,
  gmt_modified datetime,
  primary key (asset_id, asset_version)
);
create index if not exists idx_tee_asset_owner on tee_asset(owner_id, is_deleted);

create table if not exists tee_object (
  object_id varchar(64) primary key,
  kind varchar(32) not null,
  owner_id varchar(128) not null,
  asset_id varchar(64),
  task_id varchar(64),
  result_id varchar(64),
  key_id varchar(64) not null,
  key_version varchar(32) not null,
  ciphertext_sha256 varchar(64) not null,
  size_bytes integer not null default 0,
  contributors_json text not null default '[]',
  export_state varchar(32) not null default 'PENDING_APPROVAL',
  id integer,
  is_deleted integer not null default 0,
  gmt_create datetime,
  gmt_modified datetime
);
-- 结果标识首次申领时原子绑定任务；已绑定其他任务的结果必须被拒绝。
create unique index if not exists idx_tee_object_result on tee_object(result_id);
create index if not exists idx_tee_object_task on tee_object(task_id, is_deleted);

create table if not exists tee_request (
  request_key varchar(160) primary key,
  fingerprint varchar(64) not null,
  response_json text not null default '{}',
  created_at varchar(64) not null,
  owner_id varchar(128) not null,
  id integer,
  is_deleted integer not null default 0,
  gmt_create datetime,
  gmt_modified datetime
);
create index if not exists idx_tee_request_created on tee_request(created_at);

create table if not exists tee_nonce (
  issuer varchar(128) not null,
  nonce varchar(128) not null,
  task_id varchar(64) not null,
  request_id varchar(64) not null,
  expires_at varchar(64) not null,
  id integer,
  is_deleted integer not null default 0,
  gmt_create datetime,
  gmt_modified datetime,
  primary key (issuer, nonce)
);
create index if not exists idx_tee_nonce_expires on tee_nonce(expires_at);

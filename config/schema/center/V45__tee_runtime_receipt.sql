-- P5 已接受的可信运行任务、最小对象授权、结果密钥绑定与已验签回执。
-- 只保存签名元数据和密文对象范围，不保存数据密钥或任何明文。
create table if not exists tee_runtime_task (
  task_id varchar(64) primary key,
  request_id varchar(64) not null,
  caller_id varchar(128) not null,
  workload_cert_sha256 varchar(64) not null,
  object_ids_json text not null default '[]',
  contributors_json text not null default '[]',
  program_object_id varchar(64),
  result_bindings_json text not null default '{}',
  task_jws text not null,
  expires_at varchar(64) not null,
  status varchar(32) not null default 'ACCEPTED',
  receipt_jws text,
  receipt_verified integer not null default 0,
  id integer,
  is_deleted integer not null default 0,
  gmt_create datetime,
  gmt_modified datetime
);
create index if not exists idx_tee_runtime_task_caller
  on tee_runtime_task(caller_id, is_deleted);
create index if not exists idx_tee_runtime_task_expires
  on tee_runtime_task(expires_at, is_deleted);

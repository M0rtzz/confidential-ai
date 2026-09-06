-- Unified ciphertext-only assets, approvals, usage tracking and encrypted results.
create table if not exists ds_confidential_asset (
  asset_id varchar(128) primary key,
  owner_id varchar(128) not null,
  asset_type varchar(32) not null,
  source_type varchar(32) not null,
  name varchar(256) not null,
  description varchar(1024) not null default '',
  latest_version integer not null,
  status varchar(32) not null,
  created_at varchar(64) not null,
  updated_at varchar(64) not null
);
create index if not exists idx_ds_conf_asset_owner on ds_confidential_asset(owner_id, asset_type, updated_at);

create table if not exists ds_confidential_asset_version (
  asset_version_id varchar(128) primary key,
  asset_id varchar(128) not null,
  owner_id varchar(128) not null,
  upload_session_id varchar(128) not null,
  version_number integer not null,
  domain_id varchar(128) not null,
  algorithm varchar(64) not null,
  original_file_name varchar(512) not null,
  original_size bigint not null,
  cipher_size bigint not null,
  storage_node varchar(256) not null,
  manifest_json text not null,
  manifest_hash varchar(64) not null,
  owner_signature text not null,
  status varchar(32) not null,
  source_data_name varchar(256),
  source_model_name varchar(256),
  task_id varchar(128),
  compute_node varchar(256),
  created_at varchar(64) not null,
  unique(asset_id, version_number)
);

create table if not exists ds_confidential_asset_upload (
  upload_session_id varchar(128) primary key,
  owner_id varchar(128) not null,
  asset_type varchar(32) not null,
  source_type varchar(32) not null,
  name varchar(256) not null,
  description varchar(1024) not null default '',
  original_file_name varchar(512) not null,
  original_size bigint not null,
  domain_id varchar(128) not null,
  algorithm varchar(64) not null,
  expected_chunks integer not null,
  received_chunks integer not null,
  status varchar(32) not null,
  created_at varchar(64) not null,
  expires_at varchar(64) not null
);

create table if not exists ds_confidential_asset_chunk (
  upload_session_id varchar(128) not null,
  chunk_index integer not null,
  object_uri text not null,
  cipher_hash varchar(64) not null,
  cipher_size bigint not null,
  created_at varchar(64) not null,
  primary key(upload_session_id, chunk_index)
);

create table if not exists ds_confidential_use_request (
  request_id varchar(128) primary key,
  owner_id varchar(128) not null,
  asset_id varchar(128) not null,
  asset_version_id varchar(128) not null,
  applicant varchar(256) not null,
  compute_node varchar(256) not null,
  task_id varchar(128) not null,
  task_name varchar(256) not null,
  purpose varchar(512) not null,
  status varchar(32) not null,
  valid_until varchar(64) not null,
  approval_comment varchar(1024),
  requested_at varchar(64) not null,
  decided_at varchar(64),
  started_at varchar(64),
  completed_at varchar(64)
);
create index if not exists idx_ds_conf_use_asset on ds_confidential_use_request(owner_id, asset_id, requested_at);

create table if not exists ds_confidential_usage_event (
  event_id varchar(128) primary key,
  owner_id varchar(128) not null,
  request_id varchar(128) not null,
  event_type varchar(64) not null,
  status varchar(32) not null,
  detail_json text not null,
  created_at varchar(64) not null
);

create table if not exists ds_confidential_execution_grant (
  grant_id varchar(128) primary key,
  owner_id varchar(128) not null,
  task_id varchar(128) not null,
  compute_node varchar(256) not null,
  asset_versions_json text not null,
  token_hash varchar(64) not null unique,
  status varchar(32) not null,
  issued_at varchar(64) not null,
  expires_at varchar(64) not null,
  consumed_at varchar(64)
);
create index if not exists idx_ds_conf_grant_task on ds_confidential_execution_grant(owner_id, task_id, compute_node, status);

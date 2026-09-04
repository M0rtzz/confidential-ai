-- Confidential model hosting metadata. Ciphertext only; no raw API key, DEK, prompt, or weights.
create table if not exists ds_confidential_model (
  model_id varchar(128) primary key,
  owner_id varchar(128) not null,
  name varchar(256) not null,
  description varchar(1024) not null default '',
  source_type varchar(32) not null,
  status varchar(32) not null,
  latest_version integer not null,
  created_at varchar(64) not null,
  updated_at varchar(64) not null
);
create index if not exists idx_ds_confidential_model_owner on ds_confidential_model(owner_id, updated_at);

create table if not exists ds_model_credential (
  credential_id varchar(128) primary key,
  owner_id varchar(128) not null,
  key_id varchar(128) not null,
  encrypted_credential_json text not null,
  cipher_hash varchar(64) not null,
  status varchar(32) not null,
  created_at varchar(64) not null,
  revoked_at varchar(64)
);

create table if not exists ds_confidential_model_version (
  version_id varchar(128) primary key,
  model_id varchar(128) not null,
  owner_id varchar(128) not null,
  version_number integer not null,
  source_type varchar(32) not null,
  domain_id varchar(128) not null,
  security_profile varchar(32) not null,
  runtime_security_requirement varchar(32) not null,
  content_encryption_algorithm varchar(64),
  asset_version_id varchar(160),
  manifest_json text,
  manifest_hash varchar(64),
  base_url text,
  upstream_model_id varchar(256),
  credential_id varchar(128),
  runtime_config_json text not null,
  status varchar(32) not null,
  approval_id varchar(64),
  created_at varchar(64) not null,
  unique(model_id, version_number)
);
create index if not exists idx_ds_confidential_model_version_model
  on ds_confidential_model_version(model_id, version_number);

create table if not exists ds_model_deployment (
  deployment_id varchar(128) primary key,
  model_id varchar(128) not null,
  version_id varchar(128) not null,
  owner_id varchar(128) not null,
  deployment_type varchar(32) not null,
  security_profile varchar(32) not null,
  status varchar(32) not null,
  endpoint_path varchar(512) not null,
  authorization_session_id varchar(128),
  error_code varchar(128),
  created_at varchar(64) not null,
  updated_at varchar(64) not null
);
create index if not exists idx_ds_model_deployment_model on ds_model_deployment(model_id, updated_at);

create table if not exists ds_confidential_upload_session (
  upload_session_id varchar(128) primary key,
  owner_id varchar(128) not null,
  model_name varchar(256) not null,
  original_file_name varchar(512) not null,
  original_size bigint not null,
  domain_id varchar(128) not null,
  content_encryption_algorithm varchar(64) not null,
  expected_chunks integer not null,
  received_chunks integer not null,
  status varchar(32) not null,
  created_at varchar(64) not null,
  expires_at varchar(64) not null
);
create table if not exists ds_confidential_upload_chunk (
  upload_session_id varchar(128) not null,
  chunk_index integer not null,
  object_uri text not null,
  cipher_hash varchar(64) not null,
  cipher_size bigint not null,
  created_at varchar(64) not null,
  primary key(upload_session_id, chunk_index)
);

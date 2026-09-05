-- Approval-gated confidential training tasks and OpenAI-compatible data providers.
create table if not exists ds_confidential_training_task (
  task_id varchar(128) primary key,
  owner_id varchar(128) not null,
  task_name varchar(256) not null,
  purpose varchar(512) not null,
  compute_node varchar(256) not null,
  data_asset_id varchar(128) not null,
  data_asset_version_id varchar(128) not null,
  model_asset_id varchar(128) not null,
  model_asset_version_id varchar(128) not null,
  data_request_id varchar(128) not null,
  model_request_id varchar(128) not null,
  epochs integer not null,
  learning_rate varchar(32) not null,
  status varchar(64) not null,
  progress integer not null default 0,
  current_epoch integer not null default 0,
  metrics_json text not null default '{}',
  result_data_asset_id varchar(128),
  result_model_asset_id varchar(128),
  failure_reason varchar(1024),
  created_at varchar(64) not null,
  authorized_at varchar(64),
  started_at varchar(64),
  completed_at varchar(64),
  updated_at varchar(64) not null
);
create index if not exists idx_ds_conf_training_owner
  on ds_confidential_training_task(owner_id, updated_at);

create table if not exists ds_confidential_llm_provider (
  provider_id varchar(128) primary key,
  owner_id varchar(128) not null,
  provider_name varchar(256) not null,
  base_url text not null,
  model_id varchar(256) not null,
  encrypted_credential_json text,
  credential_cipher_hash varchar(64),
  is_default integer not null default 0,
  status varchar(32) not null,
  created_at varchar(64) not null,
  updated_at varchar(64) not null
);
create index if not exists idx_ds_conf_llm_provider_owner
  on ds_confidential_llm_provider(owner_id, updated_at);

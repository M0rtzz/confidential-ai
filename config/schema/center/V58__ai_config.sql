create table if not exists ds_ai_config (
  config_id varchar(128) primary key,
  owner_id varchar(128) not null,
  config_version integer not null,
  format varchar(32) not null,
  base_url text not null,
  model_id varchar(256) not null,
  api_key_ciphertext text,
  api_key_nonce varchar(128),
  status varchar(32) not null,
  is_current integer not null default 1,
  created_by varchar(128) not null,
  created_at varchar(64) not null,
  updated_at varchar(64) not null
);
create unique index if not exists uk_ds_ai_config_owner_version
  on ds_ai_config(owner_id, config_version);
create index if not exists idx_ds_ai_config_current
  on ds_ai_config(owner_id, is_current);

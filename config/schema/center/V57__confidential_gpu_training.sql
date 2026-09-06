-- GPU confidential training, per-input key release and customer key metadata.
alter table ds_confidential_training_task add column node_id varchar(128);
alter table ds_confidential_training_task add column created_by varchar(128);
alter table ds_confidential_training_task add column adapter_id varchar(128);
alter table ds_confidential_training_task add column training_config_json text;
alter table ds_confidential_training_task add column training_config_hash varchar(64);
alter table ds_confidential_training_task add column runtime_image_digest varchar(128);
alter table ds_confidential_training_task add column task_spec_digest varchar(64);
alter table ds_confidential_training_task add column task_spec_json text;
alter table ds_confidential_training_task add column attestation_session_id varchar(128);
alter table ds_confidential_training_task add column attestation_json text;
alter table ds_confidential_training_task add column ciphergpu_job_id varchar(128);
alter table ds_confidential_training_task add column output_recipient_kid varchar(128);
alter table ds_confidential_training_task add column queued_at varchar(64);
alter table ds_confidential_training_task add column cancelled_at varchar(64);
alter table ds_confidential_training_task add column cleanup_status varchar(32);

create table if not exists ds_confidential_training_input (
  task_id varchar(128) not null,
  slot varchar(32) not null,
  asset_id varchar(128) not null,
  asset_version_id varchar(128) not null,
  asset_owner_id varchar(128) not null,
  request_id varchar(128) not null,
  grant_json text,
  sealed_dek_json text,
  key_release_status varchar(32) not null,
  staged_chunks integer not null default 0,
  expected_chunks integer not null default 0,
  created_at varchar(64) not null,
  updated_at varchar(64) not null,
  primary key(task_id, slot)
);
create index if not exists idx_ds_conf_training_input_asset
  on ds_confidential_training_input(asset_owner_id, asset_version_id, key_release_status);

create table if not exists ds_customer_encryption_key (
  kid varchar(128) primary key,
  tenant_id varchar(128) not null,
  subject_id varchar(128) not null,
  public_key text not null,
  algorithm varchar(64) not null,
  key_version integer not null,
  fingerprint varchar(128) not null,
  status varchar(32) not null,
  created_at varchar(64) not null,
  revoked_at varchar(64),
  unique(tenant_id, subject_id, key_version)
);
create index if not exists idx_customer_key_subject
  on ds_customer_encryption_key(tenant_id, subject_id, status);

create table if not exists ds_crypto_signing_identity (
  signing_public_key text primary key,
  kid varchar(128) not null,
  owner_id varchar(128) not null,
  status varchar(32) not null,
  created_at varchar(64) not null,
  revoked_at varchar(64)
);
create index if not exists idx_crypto_signing_identity_owner
  on ds_crypto_signing_identity(owner_id, kid, status);

alter table ds_confidential_asset_version add column producer_type varchar(32);
alter table ds_confidential_asset_version add column producer_node_id varchar(128);
alter table ds_confidential_asset_version add column producer_runtime_image_digest varchar(128);
alter table ds_confidential_asset_version add column producer_signature text;
alter table ds_confidential_asset_version add column producer_receipt_json text;
alter table ds_confidential_asset_version add column owner_signing_public_key text;

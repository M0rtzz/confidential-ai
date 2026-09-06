-- ds-confidential/v1 control-plane metadata. No private key or raw DEK may be stored here.
create table if not exists ds_crypto_identity (
  kid varchar(128) primary key,
  tenant_id varchar(128) not null,
  user_id varchar(128) not null,
  encryption_public_key text not null,
  signing_public_key text not null,
  algorithm varchar(128) not null,
  status varchar(32) not null,
  created_at varchar(64) not null,
  revoked_at varchar(64)
);
create index if not exists idx_ds_crypto_identity_owner on ds_crypto_identity(tenant_id, user_id, status);

create table if not exists ds_crypto_asset_version (
  asset_version_id varchar(160) primary key,
  asset_id varchar(128) not null,
  version_id varchar(64) not null,
  owner_id varchar(128) not null,
  manifest_uri text not null,
  manifest_hash varchar(64) not null,
  owner_signature text not null,
  algorithm varchar(128) not null,
  runtime_security_requirement varchar(32) not null,
  retention_policy varchar(64),
  created_at varchar(64) not null
);

create table if not exists ds_crypto_key_envelope (
  envelope_id varchar(128) primary key,
  asset_version_id varchar(160) not null,
  recipient_kid varchar(128) not null,
  envelope_blob text not null,
  aad_hash varchar(64) not null,
  created_at varchar(64) not null
);
create index if not exists idx_ds_crypto_key_envelope_asset on ds_crypto_key_envelope(asset_version_id, recipient_kid);

create table if not exists ds_crypto_task (
  task_id varchar(128) primary key,
  owner_id varchar(128) not null,
  task_spec_json text not null,
  task_spec_digest varchar(64) not null,
  security_profile varchar(32) not null,
  runtime_security_requirement varchar(32) not null,
  status varchar(32) not null,
  created_at varchar(64) not null,
  expires_at varchar(64) not null
);

create table if not exists ds_tee_attestation_session (
  session_id varchar(128) primary key,
  task_id varchar(128) not null,
  task_spec_digest varchar(64) not null,
  client_nonce_hash varchar(64) not null,
  tee_pubkey_hash varchar(64) not null,
  evidence_hash varchar(64) not null,
  evidence_json text not null,
  evidence_type varchar(64) not null,
  simulated integer not null,
  hardware_model varchar(128) not null,
  security_profile varchar(32) not null,
  verifier_id varchar(128) not null,
  policy_id varchar(128) not null,
  issued_at varchar(64) not null,
  expires_at varchar(64) not null,
  status varchar(32) not null
);
create index if not exists idx_ds_tee_attestation_task on ds_tee_attestation_session(task_id, status);

create table if not exists ds_crypto_grant (
  grant_id varchar(128) primary key,
  task_id varchar(128) not null,
  session_id varchar(128) not null,
  jti varchar(128) not null unique,
  owner_id varchar(128) not null,
  claims_hash varchar(64) not null,
  payload_json text not null,
  security_profile varchar(32) not null,
  expires_at varchar(64) not null,
  consumed_at varchar(64),
  revoked_at varchar(64),
  created_at varchar(64) not null
);

create table if not exists ds_confidential_execution (
  execution_id varchar(128) primary key,
  task_id varchar(128) not null,
  grant_id varchar(128) not null,
  session_id varchar(128) not null,
  security_profile varchar(32) not null,
  image_digest varchar(128) not null,
  sbom_digest varchar(128) not null,
  status varchar(32) not null,
  receipt_json text,
  output_manifest_hash varchar(64),
  output_json text,
  created_at varchar(64) not null,
  completed_at varchar(64)
);
create index if not exists idx_ds_confidential_execution_task on ds_confidential_execution(task_id, created_at);

create table if not exists ds_crypto_audit_event (
  event_id varchar(128) primary key,
  tenant_id varchar(128) not null,
  user_id varchar(128) not null,
  event_type varchar(64) not null,
  subject_id varchar(128) not null,
  security_profile varchar(32) not null,
  simulated integer not null,
  event_json text not null,
  previous_hash varchar(64) not null,
  event_hash varchar(64) not null,
  created_at varchar(64) not null
);
create index if not exists idx_ds_crypto_audit_created on ds_crypto_audit_event(created_at);

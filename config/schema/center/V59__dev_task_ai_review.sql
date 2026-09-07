/* TEE data-development immutable review snapshot and AI scan report. */
create table if not exists ds_dev_task_review (
    task_id                 varchar(64) primary key,
    approval_id             varchar(64) unique,
    snapshot_version        integer not null default 1,
    snapshot_sha256         varchar(64) not null,
    code_sha256             varchar(64) not null,
    snapshot_json           text not null,
    provider_nodes_json     text not null default '[]',
    ai_owner_id             varchar(128) not null,
    ai_config_version       integer not null default 0,
    ai_model_id             varchar(256) not null default '',
    prompt_version          varchar(32) not null,
    ai_status               varchar(32) not null,
    risk_level              varchar(16) not null default '',
    summary                 text not null default '',
    findings_json           text not null default '[]',
    limitations_json        text not null default '[]',
    report_sha256           varchar(64) not null default '',
    review_binding_sha256   varchar(64) not null default '',
    scan_error              varchar(2048) not null default '',
    scan_retry_count        integer not null default 0,
    scanned_at              varchar(32) not null default '',
    created_at              varchar(32) not null,
    updated_at              varchar(32) not null
);
create unique index if not exists idx_dev_task_review_approval
    on ds_dev_task_review(approval_id);
create index if not exists idx_dev_task_review_status
    on ds_dev_task_review(ai_status, updated_at);

/* Persist the bounded tail before CipherGPU removes terminal job state. */
alter table ds_confidential_training_task add column terminal_log_snapshot text;
alter table ds_confidential_training_task add column terminal_log_saved_at varchar(64);
alter table ds_confidential_training_task add column terminal_log_truncated integer not null default 0;
alter table ds_confidential_training_task add column terminal_log_status varchar(32) not null default 'NOT_SAVED';
alter table ds_confidential_training_task add column terminal_log_error varchar(512) not null default '';

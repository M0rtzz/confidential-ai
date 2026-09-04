-- Structured binding between an approved model and its encrypted TEE training output.
create table if not exists ds_model_tee_binding (
    model_id varchar(64) primary key,
    object_id varchar(64) not null,
    result_id varchar(64) not null,
    source_task_id varchar(64) not null,
    key_id varchar(64) not null,
    key_version varchar(32) not null,
    ciphertext_sha256 varchar(64) not null,
    size_bytes bigint not null,
    model_kind varchar(64) not null,
    features_json text not null,
    task_type varchar(32) not null default '',
    sandbox_id varchar(64) not null,
    contributors_json text not null default '[]',
    status varchar(16) not null default 'ACTIVE',
    created_at varchar(64) not null,
    updated_at varchar(64) not null
);
create unique index if not exists idx_model_tee_object on ds_model_tee_binding(object_id);

-- TEE 环境的加密配置。取值只记录申请时的选择，实际可用能力以 /tee-capabilities 为准。
alter table ds_sandbox add column cpu_encryption varchar(32) not null default 'NONE';
alter table ds_sandbox add column gpu_encryption varchar(32) not null default 'NONE';
alter table ds_sandbox add column content_algorithm varchar(64) not null default '';
alter table ds_sandbox add column attestation_requirement varchar(32) not null default 'ALLOW_SIMULATION';

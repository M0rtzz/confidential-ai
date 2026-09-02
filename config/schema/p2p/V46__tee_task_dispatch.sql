-- P6 待下发任务说明。签名任务在创建 Kuscia Job 前保存，重试复用同一 JWS/nonce。
alter table ds_dev_task add column tee_task_jws text not null default '';
alter table ds_dev_task add column tee_request_id varchar(64) not null default '';
alter table ds_dev_task add column tee_nonce varchar(128) not null default '';
alter table ds_dev_task add column tee_runtime_image_digest varchar(128) not null default '';
alter table ds_dev_task add column tee_dispatch_status varchar(32) not null default '';

create unique index if not exists idx_ds_dev_task_tee_request
  on ds_dev_task(tee_request_id) where tee_request_id<>'';
create unique index if not exists idx_ds_dev_task_tee_nonce
  on ds_dev_task(tee_nonce) where tee_nonce<>'';

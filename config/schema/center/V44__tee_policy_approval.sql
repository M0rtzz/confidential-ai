-- 授权规则的审批来源。契约要求 /policies/register 的规则由有效审批生成，
-- 这里记录实际采信的审批单，便于审计追溯规则出处。
alter table tee_policy add column approval_id varchar(64) not null default '';
create index if not exists idx_tee_policy_approval on tee_policy(approval_id);

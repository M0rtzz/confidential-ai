-- 工单业务期限由申请人提出并经贡献机构共同审批，历史空值不视为永久授权。
alter table tee_export_request add column export_until varchar(64);
alter table tee_export_request add column purpose varchar(1000);

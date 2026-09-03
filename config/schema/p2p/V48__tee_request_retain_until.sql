-- 出域信封的幂等记录只在信封有效期内保留，不随通用保留期驻留 24 小时。
alter table tee_request add column retain_until varchar(64);

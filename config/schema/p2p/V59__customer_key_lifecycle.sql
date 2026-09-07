-- 客户密钥（UEK）全生命周期：轮换、回收与销毁的状态列。私钥仍只存在于浏览器。
alter table ds_customer_encryption_key add column superseded_at varchar(64);
alter table ds_customer_encryption_key add column destroyed_at varchar(64);
alter table ds_customer_encryption_key add column rotated_from_kid varchar(128);

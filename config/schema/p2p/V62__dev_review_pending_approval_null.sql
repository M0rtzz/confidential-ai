-- 未生成审批单时使用 NULL，避免多个待审核或失败任务争用空字符串唯一键。
update ds_dev_task_review set approval_id=NULL where approval_id='';

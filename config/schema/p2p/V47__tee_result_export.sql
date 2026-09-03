-- P7 结果出域工单与机构投票。P2P 部署使用机构 ownerId，不复用节点投票表。
create table if not exists tee_export_request (
  export_id varchar(64) primary key,
  result_id varchar(64) not null,
  object_id varchar(64) not null,
  kind varchar(32) not null,
  task_id varchar(64) not null,
  ciphertext_sha256 varchar(64) not null,
  key_id varchar(64) not null,
  key_version varchar(32) not null,
  requester_owner_id varchar(128) not null,
  recipient_cert_sha256 varchar(64) not null,
  request_id varchar(64) not null,
  status varchar(32) not null default 'PENDING_APPROVAL',
  approved_at varchar(64),
  id integer,
  is_deleted integer not null default 0,
  gmt_create datetime,
  gmt_modified datetime
);
create unique index if not exists idx_tee_export_request_id on tee_export_request(request_id);
create index if not exists idx_tee_export_result on tee_export_request(result_id, requester_owner_id, status, is_deleted);
create index if not exists idx_tee_export_object on tee_export_request(object_id, status, is_deleted);

create table if not exists tee_export_vote (
  export_id varchar(64) not null,
  voter_owner_id varchar(128) not null,
  status varchar(32) not null default 'PENDING',
  voter varchar(128) not null default '',
  comment varchar(1024) not null default '',
  voted_at varchar(64) not null default '',
  id integer,
  is_deleted integer not null default 0,
  gmt_create datetime,
  gmt_modified datetime,
  primary key (export_id, voter_owner_id)
);
create index if not exists idx_tee_export_vote_voter on tee_export_vote(voter_owner_id, status, is_deleted);

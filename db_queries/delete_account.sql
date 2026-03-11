with collected_files AS(
    SELECT id FROM files WHERE owner_id=$1 AND status!='deleted'
    ),
delete_account AS (
    DELETE FROM users WHERE id=$1 -- when the user is deleted it also deletes all folders records and respectively all files records
    )
select id FROM collected_files;

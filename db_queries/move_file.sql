/*
$1 = source file id
$2 = owner user id
$3 = destination folder id
*/
with file_exist AS (
    SELECT name FROM files WHERE id=$1 AND owner_id=$2 AND status='active'
    ),
dest_exist AS (
    SELECT EXISTS (SELECT 1 FROM folders WHERE id=$3 AND owner_id=$2 AND status='active') as de
    ),
search_child_conflict AS (
   SELECT
       EXISTS (
           SELECT 1 FROM folders f
           JOIN file_exist fe ON f.name = fe.name
           WHERE f.owner_id=$2 AND f.parent_id=$3 AND f.status='active'
       ) AS folder_conflict
       ,
        EXISTS (
            SELECT 1 FROM files f
            JOIN file_exist fe
            ON fe.name=f.name
            WHERE owner_id=$2 AND parent_id=$3 AND status='active'
            ) AS file_conflict
),
update_parent_id AS (
    UPDATE files SET parent_id=$3
    WHERE id=$1 AND (SELECT de FROM dest_exist) AND NOT (SELECT folder_conflict OR file_conflict FROM search_child_conflict)
    RETURNING id
)
SELECT
    (SELECT name FROM file_exist) IS NULL
        OR NOT (SELECT de FROM dest_exist)       AS not_found,
    (SELECT folder_conflict FROM search_child_conflict)
        OR (SELECT file_conflict FROM search_child_conflict) AS conflict,
    (SELECT id FROM update_parent_id)            AS moved_id;

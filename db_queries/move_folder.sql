/*
$1 = source folder id
$2 = owner user id
$3 = destination folder id
*/
with RECURSIVE descendants AS ( -- asserting that the user not moving the folder to itself or one of its decendent children
    SELECT id FROM folders WHERE id = $1 AND owner_id=$2 AND status='active'
    UNION ALL
    SELECT f.id FROM folders f
    JOIN descendants d ON f.parent_id = d.id
    WHERE f.status = 'active'
),
is_descendant AS (
    SELECT EXISTS (SELECT 1 FROM descendants WHERE id = $3) AS is_descendant
),
folder_exist AS (
    SELECT name FROM folders WHERE id=$1 AND owner_id=$2 AND status='active'
    ),
dest_exist AS (

    SELECT EXISTS (SELECT 1 FROM folders WHERE id=$3 AND owner_id=$2 AND status='active') as de
    ),
search_child_conflict AS (
   SELECT
       EXISTS (
           SELECT 1 FROM folders f
           JOIN folder_exist fe ON f.name = fe.name
           WHERE f.owner_id=$2 AND f.parent_id=$3 AND f.status='active'
       ) AS folder_conflict
       ,
        EXISTS (
            SELECT 1 FROM files f
            JOIN folder_exist fe
            ON fe.name=f.name
            WHERE owner_id=$2 AND parent_id=$3 AND status='active'
            ) AS file_conflict
),
update_parent_id AS (
    UPDATE folders SET parent_id=$3
    WHERE id=$1
        AND (SELECT de FROM dest_exist)
        AND NOT (SELECT folder_conflict OR file_conflict FROM search_child_conflict)
        AND NOT (SELECT is_descendant FROM is_descendant)
    RETURNING id
)
SELECT
    (SELECT name FROM folder_exist) IS NULL
        OR NOT (SELECT de FROM dest_exist)       AS not_found,
    (SELECT folder_conflict FROM search_child_conflict)
        OR (SELECT file_conflict FROM search_child_conflict)
       OR (SELECT is_descendant FROM is_descendant) AS conflict,
    (SELECT id FROM update_parent_id)            AS moved_id;

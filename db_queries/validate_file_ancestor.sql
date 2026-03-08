WITH RECURSIVE
file_exist AS (
    SELECT id,parent_id,name,size,etag,mime_type,last_modified,created_at
    FROM files
    WHERE id = $1 AND status = 'active'
),
valid_ancestor AS (
    -- Anchor: start at the file's direct parent folder
    SELECT f.id, f.parent_id
    FROM folders f
    JOIN file_exist fe ON f.id = fe.parent_id
    WHERE f.owner_id = $2 AND f.status = 'active'

    UNION ALL

    -- Recursive: walk up, stop recursing once we've reached $3
    SELECT f.id, f.parent_id
    FROM folders f
    JOIN valid_ancestor va ON f.id = va.parent_id
    WHERE f.owner_id = $2
      AND f.status = 'active'
      AND va.id != $3          -- don't recurse beyond $3
      AND va.parent_id IS NOT NULL
),
is_valid AS (
    SELECT EXISTS (SELECT 1 FROM file_exist)
        AND EXISTS (SELECT 1 FROM valid_ancestor WHERE id = $3)
    AS valid
)
SELECT * FROM file_exist WHERE
    (SELECT valid FROM is_valid);

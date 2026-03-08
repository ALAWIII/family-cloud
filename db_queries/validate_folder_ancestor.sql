/*
$1 = requested folder id
$2 = owner_id
$3 = the ancestor for which it and all its children are shared
*/

WITH RECURSIVE
folder_exist AS (
    SELECT id,parent_id,name,created_at
    FROM folders
    WHERE id = $1 AND status = 'active'
),
valid_ancestor AS (
    -- Anchor: start at the file's direct parent folder
    SELECT f.id, f.parent_id
    FROM folders f
    JOIN folder_exist fe ON f.id = fe.parent_id
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
    SELECT EXISTS (SELECT 1 FROM folder_exist)  -- ← was file_exist
        AND (
            $1::uuid = $3::uuid  -- edge case: folder IS the root
            OR EXISTS (SELECT 1 FROM valid_ancestor WHERE id = $3)
        )
    AS valid
),
fetch_children AS (
    SELECT id,'file' as kind FROM files where parent_id=$1 AND status='active' AND (select valid FROM is_valid)
    UNION ALL
    SELECT id,'folder' as kind FROM folders where parent_id=$1 AND status='active' AND (select valid FROM is_valid)
)
SELECT
    fe.id,
    fe.parent_id,
    fe.name,
    fe.created_at,
    COALESCE(
        json_agg(json_build_object('id', fc.id, 'kind', fc.kind))
        FILTER (WHERE fc.id IS NOT NULL),
        '[]'
    ) AS children
FROM folder_exist fe
LEFT JOIN fetch_children fc ON true
WHERE (SELECT valid FROM is_valid)
GROUP BY fe.id, fe.parent_id, fe.name, fe.created_at;

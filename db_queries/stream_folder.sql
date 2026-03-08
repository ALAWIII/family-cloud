WITH RECURSIVE folder_tree AS (
    SELECT
        id,
        parent_id,
        name,
        ''::text AS path
    FROM folders
    WHERE id = $1
      AND owner_id = $2
      AND status = 'active'

    UNION ALL

    SELECT
        f.id,
        f.parent_id,
        f.name,
        CASE
            WHEN ft.path = '' THEN f.name
            ELSE ft.path || '/' || f.name
        END
    FROM folders f
    INNER JOIN folder_tree ft ON f.parent_id = ft.id
    WHERE f.owner_id = $2
      AND f.status = 'active'
)
SELECT
    fi.id                                           AS file_id,
    CASE
        WHEN ft.path = '' THEN fi.name
        ELSE ft.path || '/' || fi.name
    END                                             AS zip_path
FROM files fi
INNER JOIN folder_tree ft ON fi.parent_id = ft.id
WHERE fi.owner_id = $2
  AND fi.status = 'active'
ORDER BY zip_path;

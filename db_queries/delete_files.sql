-- For files only (separate simple query) should be called as transaction within rust.

WITH updated_files AS (
    UPDATE files
    SET status = 'deleted', last_modified = NOW()
    WHERE id = ANY($1)
      AND owner_id = $2
      AND status = 'active'
    RETURNING id, parent_id
),
increment_counters AS (
    UPDATE folders
    SET deleting_children_count = deleting_children_count + counts.cnt
    FROM (
        SELECT parent_id, COUNT(*) AS cnt FROM updated_files GROUP BY parent_id
    ) counts
    WHERE folders.id = counts.parent_id
)
SELECT id, parent_id FROM updated_files;

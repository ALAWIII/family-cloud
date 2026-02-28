WITH RECURSIVE folder_tree AS (
    -- Anchor: seeds the tree with the requested folder IDs ($1 is an array).
    -- Only includes folders owned by the user ($2) and currently active,
    -- so deleted or foreign folders are excluded from the start.
    SELECT id FROM folders
    WHERE id = ANY($1)
      AND owner_id = $2
      AND status = 'active'

    UNION ALL

    -- Recursive step: finds children of already-discovered folders.
    -- INNER JOIN is intentional — only folders whose parent is already
    -- in the tree are included. Recursion stops naturally when no more
    -- children are found (e.g. fo2 with no subfolders).
    SELECT f.id FROM folders f
    INNER JOIN folder_tree ft ON f.parent_id = ft.id
    WHERE f.owner_id = $2
      AND f.status = 'active'
),
locked_folders AS (
    -- Locks all folders in the tree with FOR UPDATE to prevent race conditions.
    -- Any concurrent copy/delete job on these folders will block here until
    -- this transaction completes. Also fetches copying_children_count for
    -- the guard check below.
    SELECT id, copying_children_count FROM folders
    WHERE id IN (SELECT id FROM folder_tree)
    FOR UPDATE
),
guard AS (
    -- Safety check: if ANY folder in the tree currently has an in-progress
    -- copy job (copying_children_count > 0), the entire operation is blocked.
    -- Returns a single boolean row used by all subsequent CTEs.
    SELECT EXISTS (
        SELECT 1 FROM locked_folders WHERE copying_children_count > 0
    ) AS blocked
),
updated_files AS (
    -- Marks all active files under the entire folder tree as deleted.
    -- Skipped entirely if guard is blocked.
    -- RETURNING id, parent_id is used both by updated_folders (to count
    -- files per folder) and by the final SELECT (to return job IDs to the app).
    UPDATE files
    SET status = 'deleted', last_modified = NOW()
    WHERE parent_id IN (SELECT id FROM folder_tree)
      AND owner_id = $2
      AND status = 'active'
      AND (SELECT NOT blocked FROM guard)
    RETURNING id, parent_id,size
),
total_size AS (
    SELECT COALESCE(sum(size),0) as ts FROM updated_files us
    ),
decrement_size AS (
    UPDATE users SET storage_used_bytes=GREATEST(storage_used_bytes-(SELECT ts FROM total_size ),0) WHERE id=$2

    ),
-- Marks all folders in the tree as deleted.
-- Soft-delete only — no counters to update since deletion is a single
-- atomic status flip. Files under these folders are already handled by
-- updated_files. Guard ensures this is skipped entirely if any folder
-- has an in-progress copy job (copying_children_count > 0).

updated_folders AS (
    UPDATE folders
    SET
        status = 'deleted',
        deleted_at = NOW()
    WHERE id IN (SELECT id FROM locked_folders)
      AND (SELECT NOT blocked FROM guard)
)
-- Final result interprets three distinct outcomes for the caller:
-- 1. blocked=true  → returns a single NULL row   → app returns 409
-- 2. blocked=false, no files → returns no rows   → app returns Some(vec![])
-- 3. blocked=false, has files → returns file IDs → app dispatches delete jobs
SELECT id, parent_id FROM (
    SELECT id, parent_id
    FROM updated_files

    UNION ALL

    -- Sentinel NULL row injected only when blocked,
    -- allowing the app to distinguish "no jobs" from "operation rejected".
    SELECT NULL::uuid AS id, NULL::uuid AS parent_id
    WHERE (SELECT blocked FROM guard)

) AS result;

/*
| blocked | id     | meaning                              |
| ------- | ------ | ------------------------------------ |
| true    | NULL   | blocked → None     409 error         |
| false   | NULL   | empty folder, no jobs → Some(vec![]) |
| false   | <uuid> | has files → Some(vec![ids])          |
*/

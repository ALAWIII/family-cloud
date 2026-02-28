-- ============================================================
-- STEP 1: Copy the folder tree and record old→new ID mappings
-- ============================================================


WITH RECURSIVE

-- Recursively collect the full subtree of folders to copy.
-- Starts from the root folders passed in $1, then walks down
-- through all their descendants (children, grandchildren, etc.)
-- Only includes folders that are 'active' (not deleted/uploading,..etc).
source_tree AS (
    -- Anchor: the root folders explicitly requested by the app
    SELECT id, parent_id, name FROM folders
    WHERE id = ANY($1) AND status = 'active' AND owner_id=$3

    UNION ALL

    -- Recursive step: for each folder already in source_tree,
    -- find its direct children and add them too
    SELECT f.id, f.parent_id, f.name FROM folders f
    JOIN source_tree st ON f.parent_id = st.id
    WHERE f.status = 'active' AND owner_id=$3
),

-- For every folder in the tree, pre-generate a new UUID.
-- This gives us a stable mapping we can reference multiple times
-- in the same query (e.g., both for inserting and for re-wiring parent_id).
folder_mapping AS (
    SELECT id AS source_id, gen_random_uuid() AS dest_id FROM source_tree
),
-- For every active file inside any of the copied folders,
-- pre-generate a new UUID and resolve its new parent folder ID
-- using the mapping stored in folder_mapping_result.
file_mapping AS (
    SELECT
        f.id AS source_id,           -- original file ID
        gen_random_uuid() AS dest_id, -- new UUID for the copied file
        fm.dest_id AS dest_parent_id, -- new parent folder ID (from Step 1 mapping)
        f.name, f.size, f.mime_type, f.etag, f.checksum, f.last_modified, f.metadata
    FROM files f
    -- Only copy files whose parent folder was part of the copied tree
    JOIN folder_mapping fm ON fm.source_id = f.parent_id
    WHERE f.status = 'active'
),
total_size AS (
    SELECT COALESCE(SUM(size), 0) AS ts FROM file_mapping fm
),
check_space AS(

    SELECT NOT EXISTS (
        SELECT 1 FROM users us WHERE id=$3 AND us.storage_used_bytes+(SELECT ts FROM total_size ) > us.storage_quota_bytes
    ) as has_space

),
increment_user_used_storage AS(
    UPDATE users set storage_used_bytes= storage_used_bytes+(SELECT ts FROM total_size ) WHERE id=$3 AND (SELECT has_space FROM check_space)
),
-- Insert the copied folders into the folders table.
-- Each new folder gets:
--   id         → the new UUID from folder_mapping
--   parent_id  → the new UUID of its copied parent (pfm.dest_id),
--                OR $2 if it's a root folder with no copied parent
--   owner_id   → $3, the user performing the copy
--   name       → same as the original
--   status     → 'active'
inserted_folders AS (
    INSERT INTO folders (id, parent_id, owner_id, name, status)
    SELECT
        fm.dest_id,                      -- new ID for this folder
        COALESCE(pfm.dest_id, $2),       -- new parent: copied parent if exists, else app-provided destination
        $3,                              -- owner of the new folders
        st.name,                         -- keep the same folder name
        'active'
    FROM source_tree st
    -- INNER JOIN: only insert folders that have a generated new ID (all of them do)
    JOIN folder_mapping fm ON fm.source_id = st.id
    -- LEFT JOIN: find the new ID of this folder's parent.
    -- LEFT (not INNER) because root folders' parents are NOT in folder_mapping,
    -- so pfm.dest_id will be NULL for roots → COALESCE falls back to $2.
    LEFT JOIN folder_mapping pfm ON pfm.source_id = st.parent_id
    WHERE (SELECT has_space FROM check_space)
    RETURNING id
),

-- ============================================================
-- STEP 2: Copy files into the new folders, update counters
-- ============================================================


-- Insert all copied files.
-- Status is set to 'copying' (not 'active') because the actual file
-- content/storage may still be in progress — the app will flip it
-- to 'active' once the binary copy completes.
inserted_files AS (
    INSERT INTO files (id, parent_id, owner_id, name, size, mime_type, etag, checksum, last_modified, metadata, status)
    SELECT
        dest_id,         -- new file ID
        dest_parent_id,  -- new parent folder ID
        $3,              -- owner
        name, size, mime_type, etag, checksum, last_modified, metadata,
        'copying'        -- mark as in-progress until storage copy is done
    FROM file_mapping WHERE (SELECT has_space FROM check_space)
    RETURNING id, parent_id  -- return to use in count update and final SELECT
),

-- Increment copying_children_count on each destination folder
-- by the number of files being copied into it.
-- This lets the app track progress: when copying_children_count
-- reaches 0 (decremented as each file finishes), the folder is done.
updated_counts AS (
    UPDATE folders f
    SET copying_children_count = copying_children_count + counts.cnt
    FROM (
        -- Count how many files landed in each folder
        SELECT parent_id, COUNT(*) AS cnt FROM inserted_files GROUP BY parent_id
    ) counts
    WHERE f.id = counts.parent_id AND (SELECT has_space FROM check_space)
)

-- Return the mapping of original file → new file + its new parent folder.
-- The app uses this to know which files to copy in storage and where they live.
SELECT
    fmap.source_id AS source_file_id,        -- original file ID
    ins.id AS new_file_id,                   -- new copied file ID
    ins.parent_id AS new_parent_folder_id   -- new folder it was placed in

FROM inserted_files ins
-- Re-join file_mapping to get the source_id (RETURNING doesn't include it)
JOIN file_mapping fmap ON fmap.dest_id = ins.id
WHERE (SELECT has_space FROM check_space)
;

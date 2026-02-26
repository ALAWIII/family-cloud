-- Step 1: Copy folders, store mapping in temp table
CREATE TEMP TABLE folder_mapping_result AS
WITH RECURSIVE
source_tree AS (
    SELECT id, parent_id, name FROM folders
    WHERE id = ANY($1) AND status = 'active'
    UNION ALL
    SELECT f.id, f.parent_id, f.name FROM folders f
    JOIN source_tree st ON f.parent_id = st.id
    WHERE f.status = 'active'
),
folder_mapping AS MATERIALIZED (
    SELECT id AS source_id, gen_random_uuid() AS dest_id FROM source_tree
),
inserted AS (
    INSERT INTO folders (id, parent_id, owner_id, name, status)
    SELECT fm.dest_id, COALESCE(pfm.dest_id, $2), $3, st.name, 'active'
    FROM source_tree st
    JOIN folder_mapping fm ON fm.source_id = st.id
    LEFT JOIN folder_mapping pfm ON pfm.source_id = st.parent_id
    RETURNING id
)
SELECT source_id, dest_id FROM folder_mapping;

-- Step 2: Copy files + update copying_children_count
WITH file_mapping AS MATERIALIZED (
    SELECT f.id AS source_id, gen_random_uuid() AS dest_id,
           fm.dest_id AS dest_parent_id,
           f.name, f.size, f.mime_type, f.etag, f.checksum, f.last_modified, f.metadata
    FROM files f
    JOIN folder_mapping_result fm ON fm.source_id = f.parent_id
    WHERE f.status = 'active'
),
inserted AS (
    INSERT INTO files (id, parent_id, owner_id, name, size, mime_type, etag, checksum, last_modified, metadata, status)
    SELECT dest_id, dest_parent_id, $3, name, size, mime_type, etag, checksum, last_modified, metadata, 'copying'
    FROM file_mapping
    RETURNING id, parent_id
),
updated_counts AS (
    UPDATE folders f
    SET copying_children_count = copying_children_count + counts.cnt
    FROM (
        SELECT parent_id, COUNT(*) AS cnt FROM inserted GROUP BY parent_id
    ) counts
    WHERE f.id = counts.parent_id
)
SELECT fmap.source_id AS source_file_id, ins.id AS new_file_id, ins.parent_id AS new_parent_folder_id
FROM inserted ins
JOIN file_mapping fmap ON fmap.dest_id = ins.id;

DROP TABLE folder_mapping_result;

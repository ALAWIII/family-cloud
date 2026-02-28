WITH file_mapping AS (
    SELECT f.id AS source_id, gen_random_uuid() AS dest_id,
           f.name, f.size, f.mime_type, f.etag, f.checksum, f.last_modified, f.metadata,
           f.parent_id AS source_parent_id
    FROM files f
    WHERE f.id = ANY($1) AND owner_id=$3 AND f.status = 'active'
),

total_size AS (
        SELECT COALESCE(sum(size),0) ts FROM file_mapping
    ),
check_space AS (
    SELECT NOT EXISTS (SELECT 1 FROM users us WHERE us.id=$3 AND us.storage_used_bytes+(SELECT ts FROM total_size ) > us.storage_quota_bytes ) as has_space
),
increment_user_used_storage AS(
    UPDATE users set storage_used_bytes= storage_used_bytes+(SELECT ts FROM total_size ) WHERE id=$3 AND (SELECT has_space FROM check_space)
),
inserted AS (
    INSERT INTO files (id, parent_id, owner_id, name, size, mime_type, etag, checksum, last_modified, metadata, status)
    SELECT dest_id, $2, $3, name, size, mime_type, etag, checksum, last_modified, metadata, 'copying'
    FROM file_mapping
    WHERE (SELECT has_space FROM check_space)
    RETURNING id, parent_id
),
updated_counts AS (
    UPDATE folders
    SET copying_children_count = copying_children_count + (SELECT COUNT(*) FROM inserted)
    WHERE id = $2 AND (SELECT has_space FROM check_space)
)
SELECT fmap.source_id AS source_file_id, ins.id AS new_file_id, ins.parent_id AS new_parent_folder_id
FROM inserted ins
JOIN file_mapping fmap ON fmap.dest_id = ins.id
WHERE (SELECT has_space FROM check_space);

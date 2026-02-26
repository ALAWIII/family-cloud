WITH file_mapping AS MATERIALIZED (
    SELECT f.id AS source_id, gen_random_uuid() AS dest_id,
           f.name, f.size, f.mime_type, f.etag, f.checksum, f.last_modified, f.metadata,
           f.parent_id AS source_parent_id
    FROM files f
    WHERE f.id = ANY($1) AND f.status = 'active'
),
inserted AS (
    INSERT INTO files (id, parent_id, owner_id, name, size, mime_type, etag, checksum, last_modified, metadata, status)
    SELECT dest_id, $2, $3, name, size, mime_type, etag, checksum, last_modified, metadata, 'copying'
    FROM file_mapping
    RETURNING id, parent_id
),
updated_counts AS (
    UPDATE folders
    SET copying_children_count = copying_children_count + (SELECT COUNT(*) FROM inserted)
    WHERE id = $2
)
SELECT fmap.source_id AS source_file_id, ins.id AS new_file_id, ins.parent_id AS new_parent_folder_id
FROM inserted ins
JOIN file_mapping fmap ON fmap.dest_id = ins.id;

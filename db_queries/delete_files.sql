-- For files only (separate simple query) should be called as transaction within rust.

WITH updated_files AS (
    UPDATE files
    SET status = 'deleted', last_modified = NOW()
    WHERE id = ANY($1)
      AND owner_id = $2
      AND status = 'active'
    RETURNING id, parent_id,size
),

total_size AS (
    SELECT COALESCE(sum(uf.size),0) as ts FROM updated_files uf
    ),
decrement_size AS (
    UPDATE users SET storage_used_bytes= GREATEST(storage_used_bytes-(SELECT ts FROM total_size),0) WHERE id=$2
)
SELECT id, parent_id FROM updated_files;

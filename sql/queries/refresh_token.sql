-- name: RefreshToken :one
INSERT INTO refresh_tokens(token,created_at,updated_at,expires_at, revoked_at,user_id)
VALUES (
    $1,
    NOW(),
    NOW(),
    $2,
    NULL,
    $3 
)
RETURNING *;

-- name: SearchRefreshToken :one
SELECT * FROM refresh_tokens WHERE token = $1;

-- name: RevokeToken :exec
UPDATE refresh_tokens SET updated_at = NOW(),revoked_at = NOW() WHERE token = $1;
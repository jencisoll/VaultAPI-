--CREATE USER
INSERT INTO users (email, password_hash, role)
VALUES  ($1,$2,$3)
RETURNING *;

SELECT * FROM users WHERE  email = $1 AND active = TRUE;

SELECT * FROM users WHERE id = $1 AND active = TRUE;

INSERT INTO refresh_tokens (user_id, token_hash, family,expires_at)
VALUES ($1,$2,$3,$4)
RETURNING *;

SELECT * FROM refresh_tokens
WHERE token_hash =$1 AND revoked = FALSE AND    expires_at > NOW();

UPDATE refresh_tokens
SET revoked = TRUE
WHERE user_id =$1;

DELETE FROM refresh_tokens WHERE  expires_at <NOW();

package infraredis

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/jencisoll/vaultapi/internal/domain"
)

type TokenStore struct {
	rdb *redis.Client
}

func NewTokenStore(rdb *redis.Client) *TokenStore {
	return &TokenStore{rdb: rdb}
}

func (s *TokenStore) SaveRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, family uuid.UUID, expiresAt interface{}) error {
	key := fmt.Sprintf("refresh:%s", tokenHash)
	data := map[string]interface{}{
		"user_id": userID.String(),
		"family":  family.String(),
	}
	
	d, ok := expiresAt.(time.Duration)
	if !ok {
		d = 24 * time.Hour
	}
	
	pipe := s.rdb.Pipeline()
	pipe.HSet(ctx, key, data)
	pipe.Expire(ctx, key, d)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *TokenStore) FindRefreshToken(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	key := fmt.Sprintf("refresh:%s", tokenHash)
	res, err := s.rdb.HGetAll(ctx, key).Result()
	if err != nil || len(res) == 0 {
		return nil, err
	}
	
	userID, _ := uuid.Parse(res["user_id"])
	family, _ := uuid.Parse(res["family"])
	
	return &domain.RefreshToken{
		TokenHash: tokenHash,
		UserID:    userID,
		Family:    family,
	}, nil
}

func (s *TokenStore) RevokeFamily(ctx context.Context, family uuid.UUID) error {
	// Implementar lógica de revocación de familia (e.g. usando SADD para indexar familia)
	return nil
}

func (s *TokenStore) RevokeAllUser(ctx context.Context, userID uuid.UUID) error {
	// Implementar lógica de revocación global
	return nil
}

type TokenBlacklist struct {
	rdb *redis.Client
}

func NewTokenBlacklist(rdb *redis.Client) *TokenBlacklist {
	return &TokenBlacklist{rdb: rdb}
}

func (b *TokenBlacklist) Add(ctx context.Context, jti string, ttl interface{}) error {
	d, ok := ttl.(time.Duration)
	if !ok {
		d = 15 * time.Minute
	}
	return b.rdb.Set(ctx, "blacklist:"+jti, "1", d).Err()
}

func (b *TokenBlacklist) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	err := b.rdb.Get(ctx, "blacklist:"+jti).Err()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("blacklist check: %w", err)
	}
	return true, nil
}


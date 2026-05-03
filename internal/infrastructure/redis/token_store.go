package infraredis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

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

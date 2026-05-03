package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config defines connection pool parameters to prevent resource exhaustion
type Config struct {
	ConnString      string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
}

// DB encapsulates the pgxpool for safe concurrent access
type DB struct {
	Pool *pgxpool.Pool
}

// New initializes a new database pool with health check and strict config
func New(ctx context.Context, cfg Config) (*DB, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.ConnString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}

	poolConfig.MaxConns = cfg.MaxConns
	poolConfig.MinConns = cfg.MinConns
	poolConfig.MaxConnLifetime = cfg.MaxConnLifetime

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Immediate health check to fail fast
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("database connectivity check failed: %w", err)
	}

	return &DB{Pool: pool}, nil
}

// Close gracefully shuts down the pool
func (db *DB) Close() {
	db.Pool.Close()
}

package domain

import (
	"context"

	"github.com/google/uuid"
)

type UserRepository interface {
	Create(ctx context.Context, email, passwordHash string, role Role) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByID(ctx context.Context, id uuid.UUID) (*User, error)
}

type TokenRepository interface {
	// SaveRefreshToken persiste el hash del token con su family.
	SaveRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, family uuid.UUID, expiresAt interface{}) error
	// FindRefreshToken busca un token activo por su hash.
	FindRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	// RevokeFamily revoca todos los tokens de una familia (detección de reuso).
	RevokeFamily(ctx context.Context, family uuid.UUID) error
	// RevokeAllUser revoca todos los tokens del usuario (logout global).
	RevokeAllUser(ctx context.Context, userID uuid.UUID) error
}

type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	Family    uuid.UUID
	ExpiresAt interface{}
	Revoked   bool
}

// Blacklist maneja tokens de acceso revocados (logout antes de expirar).
type Blacklist interface {
	Add(ctx context.Context, jti string, ttl interface{}) error
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
}

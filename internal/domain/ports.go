package domain

import "context"

// UserRepository define el contrato para nuestra persistencia. 
// Mantener esto separado nos permite cambiar de BD si mañana nos hartamos de Postgres.
type UserRepository interface {
	Create(ctx context.Context, user *User) error
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id string) (*User, error)
}

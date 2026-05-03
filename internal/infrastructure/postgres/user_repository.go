package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jencisoll/vaultapi/internal/domain"
)

type UserRepository struct {
	db *DB
}

func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, u *domain.User) error {
	// Intentamos meter el usuario en la BD. Si ya existe el email, Postgres nos va a lanzar un error de violación de restricción única.
	const query = `INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, created_at, updated_at`
	
	err := r.db.Pool.QueryRow(ctx, query, u.Email, u.PasswordHash, u.Role).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // 23505 es el código de "violation of unique constraint"
			return domain.ErrEmailTaken
		}
		return fmt.Errorf("error al insertar usuario: %w", err)
	}
	return nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	// Buscamos por email, una query básica pero crítica. Si esto falla, el login se cae.
	const query = `SELECT id, email, password_hash, role, active, created_at, updated_at FROM users WHERE email = $1`
	
	u := &domain.User{}
	err := r.db.Pool.QueryRow(ctx, query, email).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("error al buscar usuario por email: %w", err)
	}
	return u, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	// A veces necesitamos buscar por ID, validamos que el UUID sea correcto antes de molestar a la BD.
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, domain.ErrUserNotFound // O un error más específico si quieres ser quisquilloso
	}

	const query = `SELECT id, email, password_hash, role, active, created_at, updated_at FROM users WHERE id = $1`
	u := &domain.User{}
	err = r.db.Pool.QueryRow(ctx, query, uid).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("error al buscar usuario por id: %w", err)
	}
	return u, nil
}

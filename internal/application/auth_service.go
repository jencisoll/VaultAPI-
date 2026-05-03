package application

import (
	"context"
	"fmt"

	"github.com/jencisoll/vaultapi/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

// AuthService orquestará todo el desmadre del login y registro.
// No queremos lógica de negocio en los handlers, así que todo esto vive aquí.
type AuthService struct {
	repo domain.UserRepository
}

func NewAuthService(repo domain.UserRepository) *AuthService {
	return &AuthService{repo: repo}
}

func (s *AuthService) Register(ctx context.Context, email, password string, role domain.Role) (*domain.User, error) {
	// Primero lo básico, validamos el mail. Si no pasa, ni nos molestamos en hashear la password.
	u := &domain.User{Email: email, Password: password, Role: role}
	if err := u.ValidateEmail(); err != nil {
		return nil, err
	}

	// Hashear contraseñas es el estándar de seguridad. Si alguien roba la BD, no queremos que vean las pass en texto plano.
	// bcrypt con costo 12 es un buen balance entre seguridad y rendimiento hoy en día.
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error al hashear contraseña: %w", err)
	}

	u.PasswordHash = string(hash)

	// Guardamos en BD. La capa de infraestructura ya gestiona el error de email duplicado.
	if err := s.repo.Create(ctx, u); err != nil {
		return nil, err
	}

	return u, nil
}

func (s *AuthService) Login(ctx context.Context, email, password string) (*domain.User, error) {
	// Buscamos al usuario. Si no existe, devolvemos el error genérico para no dar pistas a posibles atacantes.
	u, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	// Comparamos el hash. Si la contraseña no coincide, tratamos esto como credenciales inválidas.
	err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	return u, nil
}

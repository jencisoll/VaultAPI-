package domain

import (
	"errors"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

var (
	ErrUserNotFound       = errors.New("User not found")
	ErrEmailTaken         = errors.New("Email already registered")
	ErrInvalidCredentials = errors.New("Invalid credentials")
	ErrTokenInvalid       = errors.New("Token invalid or expired")
	ErrTokenRevoked       = errors.New("Token has been revoked")
)
var emailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
type User struct {
	ID       uuid.UUID
	Email    string
	Password string
	PasswordHash string
	Role	Role
	Active bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (u *User) ValidateEmail() error {
	if !emailRe.MatchString(u.Email) {
		return errors.New("Invalid email format")
	}
	return nil
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` //segundos
}

type Claims struct {
	UserID uuid.UUID `json:"sub"`
	Email  string    `json:"email"`
	Role   Role      `json:"role"`
	jwt.RegisteredClaims
}
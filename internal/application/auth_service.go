package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/jencisoll/vaultapi/internal/domain"
)

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 7 * 24 * time.Hour
	bcryptCost      = 12
)

type AuthService struct {
	users     domain.UserRepository
	tokens    domain.TokenRepository
	blacklist domain.Blacklist
	jwtSecret []byte
}

func NewAuthService(
	users domain.UserRepository,
	tokens domain.TokenRepository,
	blacklist domain.Blacklist,
	jwtSecret string,
) *AuthService {
	return &AuthService{
		users:     users,
		tokens:    tokens,
		blacklist: blacklist,
		jwtSecret: []byte(jwtSecret),
	}
}

func (s *AuthService) Register(ctx context.Context, email, password string) (*domain.User, error) {
	u := &domain.User{Email: email}
	if err := u.ValidateEmail(); err != nil {
		return nil, err
	}
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user, err := s.users.Create(ctx, email, string(hash), domain.RoleUser)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *AuthService) Login(ctx context.Context, email, password string) (*domain.TokenPair, error) {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		// Timing attack mitigation: siempre hacemos el hash aunque el usuario no exista.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$dummy"), []byte(password))
		return nil, domain.ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	return s.issueTokenPair(ctx, user, uuid.New())
}

func (s *AuthService) Refresh(ctx context.Context, rawRefreshToken string) (*domain.TokenPair, error) {
	tokenHash := hashToken(rawRefreshToken)

	storedToken, err := s.tokens.FindRefreshToken(ctx, tokenHash)
	if err != nil {
		return nil, domain.ErrTokenInvalid
	}

	if storedToken.Revoked {
		// Reuso detectado — alguien está usando un token ya rotado.
		// Revocamos TODA la familia para proteger al usuario.
		_ = s.tokens.RevokeFamily(ctx, storedToken.Family)
		return nil, domain.ErrTokenRevoked
	}

	// Rotar: revocar la familia anterior y emitir nueva con el mismo family ID.
	if err := s.tokens.RevokeFamily(ctx, storedToken.Family); err != nil {
		return nil, fmt.Errorf("revoke family: %w", err)
	}

	user, err := s.users.FindByID(ctx, storedToken.UserID)
	if err != nil {
		return nil, domain.ErrUserNotFound
	}

	return s.issueTokenPair(ctx, user, storedToken.Family)
}

func (s *AuthService) Logout(ctx context.Context, jti string, userID uuid.UUID) error {
	// Blacklistear el access token actual
	if err := s.blacklist.Add(ctx, jti, accessTokenTTL); err != nil {
		return fmt.Errorf("blacklist token: %w", err)
	}
	// Revocar todos los refresh tokens del usuario
	return s.tokens.RevokeAllUser(ctx, userID)
}

func (s *AuthService) ValidateAccessToken(ctx context.Context, tokenStr string) (*domain.Claims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	}, jwt.WithExpirationRequired())

	if err != nil || !token.Valid {
		return nil, domain.ErrTokenInvalid
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, domain.ErrTokenInvalid
	}

	jti, _ := mapClaims["jti"].(string)
	blacklisted, err := s.blacklist.IsBlacklisted(ctx, jti)
	if err == nil && blacklisted {
		return nil, domain.ErrTokenRevoked
	}

	sub, _ := mapClaims["sub"].(string)
	userID, err := uuid.Parse(sub)
	if err != nil {
		return nil, domain.ErrTokenInvalid
	}

	return &domain.Claims{
		UserID: userID,
		Email:  mapClaims["email"].(string),
		Role:   domain.Role(mapClaims["role"].(string)),
	}, nil
}

func (s *AuthService) issueTokenPair(ctx context.Context, user *domain.User, family uuid.UUID) (*domain.TokenPair, error) {
	jti := uuid.New().String()

	accessToken, err := s.buildAccessToken(user, jti)
	if err != nil {
		return nil, err
	}

	rawRefresh, err := generateOpaqueToken()
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().UTC().Add(refreshTokenTTL)
	if err := s.tokens.SaveRefreshToken(ctx, user.ID, hashToken(rawRefresh), family, expiresAt); err != nil {
		return nil, fmt.Errorf("save refresh token: %w", err)
	}

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		ExpiresIn:    int(accessTokenTTL.Seconds()),
	}, nil
}

func (s *AuthService) buildAccessToken(user *domain.User, jti string) (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"sub":   user.ID.String(),
		"email": user.Email,
		"role":  string(user.Role),
		"jti":   jti,
		"iat":   now.Unix(),
		"exp":   now.Add(accessTokenTTL).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// generateOpaqueToken genera 32 bytes aleatorios — el refresh token real.
// No es un JWT: no contiene claims, no es parseable, es solo un secreto.
func generateOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

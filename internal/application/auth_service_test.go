package application

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jencisoll/vaultapi/internal/domain"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

type MockUserRepository struct{ mock.Mock }

func (m *MockUserRepository) Create(ctx context.Context, email, passwordHash string, role domain.Role) (*domain.User, error) {
	args := m.Called(ctx, email, passwordHash, role)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}
func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(*domain.User), args.Error(1)
}
func (m *MockUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*domain.User), args.Error(1)
}

type MockTokenRepository struct{ mock.Mock }

func (m *MockTokenRepository) SaveRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, family uuid.UUID, expiresAt interface{}) error {
	return m.Called(ctx, userID, tokenHash, family, expiresAt).Error(0)
}
func (m *MockTokenRepository) FindRefreshToken(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	args := m.Called(ctx, tokenHash)
	return args.Get(0).(*domain.RefreshToken), args.Error(1)
}
func (m *MockTokenRepository) RevokeFamily(ctx context.Context, family uuid.UUID) error {
	return m.Called(ctx, family).Error(0)
}
func (m *MockTokenRepository) RevokeAllUser(ctx context.Context, userID uuid.UUID) error {
	return m.Called(ctx, userID).Error(0)
}

type MockBlacklist struct{ mock.Mock }

func (m *MockBlacklist) Add(ctx context.Context, jti string, ttl interface{}) error {
	return m.Called(ctx, jti, ttl).Error(0)
}
func (m *MockBlacklist) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	args := m.Called(ctx, jti)
	return args.Bool(0), args.Error(1)
}

func TestAuthService_Login(t *testing.T) {
	mockUsers := new(MockUserRepository)
	mockTokens := new(MockTokenRepository)
	mockBlacklist := new(MockBlacklist)
	svc := NewAuthService(mockUsers, mockTokens, mockBlacklist, "secret")

	ctx := context.Background()
	email := "test@example.com"
	password := "password123"
	
	// Pre-hash a valid password for the mock user
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	user := &domain.User{ID: uuid.New(), Email: email, PasswordHash: string(hash), Role: domain.RoleUser}

	mockUsers.On("FindByEmail", ctx, email).Return(user, nil)
	mockTokens.On("SaveRefreshToken", ctx, user.ID, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	tokenPair, err := svc.Login(ctx, email, password)

	assert.NoError(t, err)
	assert.NotNil(t, tokenPair)
	mockUsers.AssertExpectations(t)
	mockTokens.AssertExpectations(t)
}

func TestAuthService_Refresh(t *testing.T) {
	mockUsers := new(MockUserRepository)
	mockTokens := new(MockTokenRepository)
	mockBlacklist := new(MockBlacklist)
	svc := NewAuthService(mockUsers, mockTokens, mockBlacklist, "secret")

	ctx := context.Background()
	userID := uuid.New()
	familyID := uuid.New()
	rawToken := "some-random-token"
	hashedToken := hashToken(rawToken)
	
	storedToken := &domain.RefreshToken{
		UserID: userID,
		Family: familyID,
		Revoked: false,
	}

	mockTokens.On("FindRefreshToken", ctx, hashedToken).Return(storedToken, nil)
	mockTokens.On("RevokeFamily", ctx, familyID).Return(nil)
	mockUsers.On("FindByID", ctx, userID).Return(&domain.User{ID: userID, Email: "test@ex.com", Role: domain.RoleUser}, nil)
	mockTokens.On("SaveRefreshToken", ctx, userID, mock.Anything, familyID, mock.Anything).Return(nil)

	tokens, err := svc.Refresh(ctx, rawToken)

	assert.NoError(t, err)
	assert.NotNil(t, tokens)
	mockTokens.AssertExpectations(t)
	mockUsers.AssertExpectations(t)
}

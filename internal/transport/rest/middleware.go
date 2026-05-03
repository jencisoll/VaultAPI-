package rest

import (
	"context"
	"net/http"
	"strings"

	"github.com/jencisoll/vaultapi/internal/application"
	"github.com/jencisoll/vaultapi/internal/domain"
)

type contextKey string

const claimsKey contextKey = "claims"

// Auth extrae y valida el Bearer token. Inyecta los claims en el context.
func Auth(authSvc *application.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}

			tokenStr := strings.TrimPrefix(header, "Bearer ")
			claims, err := authSvc.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole verifica que el usuario tenga el rol necesario.
func RequireRole(role domain.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil || claims.Role != role {
				writeError(w, http.StatusForbidden, "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func ClaimsFromContext(ctx context.Context) *domain.Claims {
	claims, _ := ctx.Value(claimsKey).(*domain.Claims)
	return claims
}

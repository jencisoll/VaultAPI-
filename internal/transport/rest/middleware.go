package rest

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jencisoll/vaultapi/internal/domain"
)

// Este middleware es el portero del edificio. Si no traes un token válido, no pasas ni al lobby.
func AuthMiddleware(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Falta el header de autorización", http.StatusUnauthorized)
				return
			}

			// El header suele venir como "Bearer <token>". Tenemos que limpiar eso para quedarnos solo con el JWT.
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Formato de token inválido", http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]
			claims := &domain.Claims{}

			// Parseamos y validamos el token. Si algo falla aquí, al usuario no le dejamos entrar.
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return secret, nil
			})

			if err != nil || !token.Valid {
				http.Error(w, "Token inválido o expirado", http.StatusUnauthorized)
				return
			}

			// Inyectamos los claims en el contexto. Así, más adelante, los handlers saben quién está haciendo la petición.
			ctx := context.WithValue(r.Context(), "user", claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

package rest

import (
	"encoding/json"
	"net/http"

	"github.com/jencisoll/vaultapi/internal/application"
	"github.com/jencisoll/vaultapi/internal/domain"
)

// Handler agrupa las dependencias. Si necesitamos el servicio de auth, aquí lo tenemos a mano.
type Handler struct {
	authService *application.AuthService
}

func NewHandler(authService *application.AuthService) *Handler {
	return &Handler{authService: authService}
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "JSON mal formado", http.StatusBadRequest)
		return
	}

	// Por ahora el rol es fijo. Ya veremos si el usuario puede elegir o si es siempre 'user'.
	u, err := h.authService.Register(r.Context(), req.Email, req.Password, domain.RoleUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(u)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}

	// Login puro y duro. La lógica pesada está en el service.
	_, err := h.authService.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Login exitoso"}`))
}

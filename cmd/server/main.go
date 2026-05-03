package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/caarlos0/env/v10"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jencisoll/vaultapi/internal/application"
	"github.com/jencisoll/vaultapi/internal/infrastructure/postgres"
	"github.com/jencisoll/vaultapi/internal/transport/rest"
)

type Config struct {
	DatabaseURL     string        `env:"DATABASE_URL,required"`
	MaxConns        int32         `env:"DB_MAX_CONNS" envDefault:"10"`
	MinConns        int32         `env:"DB_MIN_CONNS" envDefault:"2"`
	MaxConnLifetime time.Duration `env:"DB_MAX_CONN_LIFETIME" envDefault:"30m"`
	JWTSecret       string        `env:"JWT_SECRET,required"`
	Port            string        `env:"PORT" envDefault:":8080"`
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		log.Fatal().Err(err).Msg("Unable to parse environment variables")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Infrastructure
	db, err := postgres.New(ctx, postgres.Config{
		ConnString:      cfg.DatabaseURL,
		MaxConns:        cfg.MaxConns,
		MinConns:        cfg.MinConns,
		MaxConnLifetime: cfg.MaxConnLifetime,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize database")
	}
	defer db.Close()

	// Logic
	repo := postgres.NewUserRepository(db)
	service := application.NewAuthService(repo)
	handler := rest.NewHandler(service)

	// Routing
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", handler.Register)
		r.Post("/login", handler.Login)
	})

	// Server setup
	server := &http.Server{
		Addr:    cfg.Port,
		Handler: r,
	}

	go func() {
		log.Info().Msgf("Starting server on %s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server failed")
		}
	}()

	// Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down VaultAPI Service...")
	
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	server.Shutdown(shutdownCtx)
}

.PHONY: up down build sqlc test

up:
	docker compose up --build -d

down:
	docker compose down -v

build:
	CGO_ENABLED=0 go build -o bin/vaultapi ./cmd/server

sqlc:
	sqlc generate

test:
	go test -race -cover ./...

tidy:
	go mod tidy
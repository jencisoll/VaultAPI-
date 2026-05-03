# VaultAPI

VaultAPI es un servicio de autenticación y autorización de alto rendimiento desarrollado en Go, diseñado bajo principios de Arquitectura Hexagonal (Clean Architecture) para garantizar la separación de preocupaciones, mantenibilidad y escalabilidad.

## Propósito
El servicio gestiona de forma segura el ciclo de vida de identidades de usuario, incluyendo registro, autenticación, gestión de sesiones mediante tokens JWT (con soporte para rotación) y control de acceso basado en roles (RBAC).

## Especificaciones Técnicas

### Stack Tecnológico
*   **Lenguaje:** Go 1.24. La elección de Go se fundamenta en su modelo de concurrencia nativo, eficiencia en el uso de memoria y tipado estático, ideal para servicios de microarquitectura de alta demanda.
*   **Persistencia:** PostgreSQL. Seleccionado por su robustez en integridad transaccional (ACID).
*   **Gestión de Consultas:** `sqlc`. Optimiza la capa de persistencia al generar código Go seguro y tipado directamente de sentencias SQL, eliminando la sobrecarga de los ORMs tradicionales.
*   **Driver de Base de Datos:** `pgx/v5`. Utilizado en modo `pgxpool` para ofrecer multiplexación de conexiones eficiente y gestión avanzada de pools.
*   **Enrutamiento:** `go-chi/chi/v5`. Un router ligero y idiomático que minimiza el impacto en el rendimiento global del servicio.
*   **Seguridad:** 
    *   `golang.org/x/crypto/bcrypt` para el hashing de credenciales.
    *   `golang-jwt/jwt/v5` para la gestión de tokens.
*   **Configuración:** `caarlos0/env` para la inyección de dependencias basada en variables de entorno, favoreciendo prácticas de *Twelve-Factor App*.

## Arquitectura
El proyecto sigue un diseño por capas para facilitar la inyectabilidad y el testing:
*   `internal/domain`: Entidades core y contratos de interfaces.
*   `internal/application`: Lógica de negocio (casos de uso).
*   `internal/infrastructure`: Implementaciones de persistencia y adaptadores externos.
*   `internal/transport`: Capa de entrega (REST handlers y middleware).

## Despliegue y Configuración

### Requisitos
*   Go 1.24+
*   PostgreSQL 14+

### Variables de Entorno requeridas
Para el funcionamiento del servicio, se deben definir las siguientes variables:
*   `DATABASE_URL`: URI de conexión a la base de datos (e.g., `postgres://user:pass@localhost:5432/db`)
*   `JWT_SECRET`: Llave secreta para la firma de tokens JWT.
*   `PORT`: Puerto donde escuchará el servicio (default `:8080`).

### Ejecución
```bash
# Instalar dependencias
go mod tidy

# Ejecutar el servicio
go run cmd/server/main.go
```

## Roadmap de Desarrollo
*   [ ] Implementación completa del `TokenStore` utilizando Redis.
*   [ ] Integración de pruebas de integración con testcontainers.
*   [ ] Automatización de despliegue mediante Docker y CI/CD.

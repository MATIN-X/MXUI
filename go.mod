module github.com/MATIN-X/MXUI

go 1.22.0

require (
	github.com/go-chi/chi/v5 v5.0.12
	github.com/go-sql-driver/mysql v1.7.1

	// WebSocket
	github.com/gobwas/ws v1.4.0

	// Authentication & Security
	github.com/golang-jwt/jwt/v5 v5.2.0

	// UUID
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.10.9

	// Database
	github.com/mattn/go-sqlite3 v2.0.3+incompatible

	// Payment Gateways
	github.com/stripe/stripe-go/v76 v76.0.0
	golang.org/x/crypto v0.19.0 // Argon2id

	// Rate Limiting
	golang.org/x/time v0.5.0

	// Configuration
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	golang.org/x/net v0.21.0
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
)

require (
	golang.org/x/oauth2 v0.17.0
	google.golang.org/grpc v1.61.0
)

require (
	cloud.google.com/go/compute v1.23.3 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240205150955-31a09d347014 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)

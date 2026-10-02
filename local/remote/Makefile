.DEFAULT_GOAL := help

.PHONY: certs up down traffic start help

certs: ## Generate a self-signed certificate for localhost in ./certs
	@command -v openssl >/dev/null 2>&1 || { echo >&2 "openssl is required"; exit 1; }
	mkdir -p certs
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
		-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
		-keyout certs/server-key.pem -out certs/server.pem

up: ## Start FrankenPHP and the Ember daemon (run `make certs` first)
	@command -v docker >/dev/null 2>&1 || { echo >&2 "Docker is not installed. Please install it."; exit 1; }
	@test -f certs/server.pem || { echo >&2 "Run 'make certs' first."; exit 1; }
	docker compose build && docker compose up -d
	@echo ""
	@echo "  FrankenPHP (Normal)  : http://localhost:8080"
	@echo "  FrankenPHP (Workers) : http://localhost:8081"
	@echo "  Ember daemon         : https://localhost:9191 (admin API not published)"

down: ## Clean docker compose in the local folder
	@command -v docker >/dev/null 2>&1 || { echo >&2 "Docker is not installed. Please install it."; exit 1; }
	docker compose down --remove-orphans

traffic: ## Generate traffic against the local FrankenPHP (WORKERS=N, DURATION=S)
	@../frankenphp/load.sh

start: ## Run the Ember TUI against the daemon, without access to the admin API
	EMBER_REMOTE_AUTH=demo:demo-password go run ../../cmd/ember --remote https://localhost:9191 --ca-cert certs/server.pem

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

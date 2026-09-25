.DEFAULT_GOAL := help

.PHONY: certs up down traffic start logs help

certs: ## Generate a self-signed certificate and a random token (once)
	@mkdir -p certs
	@test -f certs/tls.crt || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
		-days 30 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
		-keyout certs/tls.key -out certs/tls.crt 2>/dev/null
	@test -f .env || echo "EMBER_REMOTE_TOKEN=$$(openssl rand -hex 32)" > .env
	@echo "  certificate : certs/tls.crt"
	@echo "  token       : .env"

up: certs ## Start FrankenPHP and the Ember daemon (remote API on :9443)
	@command -v docker >/dev/null 2>&1 || { echo >&2 "Docker is not installed. Please install it."; exit 1; }
	docker compose build && docker compose up -d
	@echo ""
	@echo "  FrankenPHP (Normal)  : http://localhost:8080"
	@echo "  FrankenPHP (Workers) : http://localhost:8081"
	@echo "  Ember remote API     : https://localhost:9443 (Caddy admin API not published)"

down: ## Stop the stack
	docker compose down --remove-orphans

traffic: ## Generate traffic against FrankenPHP (WORKERS=N, DURATION=S)
	@../frankenphp/load.sh

# Without a Go toolchain, build ../../ember once and run it with the same flags.
start: ## Run the TUI against the daemon, as a developer outside the infrastructure would
	@set -a && . ./.env && set +a && go run ../../cmd/ember --remote https://localhost:9443 --ca-cert certs/tls.crt

logs: ## Follow the daemon's log (remote session audit trail)
	docker compose logs -f ember

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

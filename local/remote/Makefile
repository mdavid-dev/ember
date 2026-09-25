.DEFAULT_GOAL := help

.PHONY: secrets up down traffic tui help

secrets: ## Generate a self-signed certificate, a token and the identities file in ./secrets
	@command -v openssl >/dev/null 2>&1 || { echo >&2 "openssl is required."; exit 1; }
	@mkdir -p secrets
	@openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
		-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
		-keyout secrets/daemon-key.pem -out secrets/daemon.pem 2>/dev/null
	@printf 'ember_rt_%s' "$$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')" > secrets/token
	@printf '[[token]]\nname = "demo"\nsha256 = "%s"\nscopes = ["snapshot"]\n' \
		"$$(sha256sum < secrets/token | cut -d' ' -f1)" > secrets/auth.toml
	@echo "  Secrets written to local/remote/secrets (token: secrets/token)"

up: secrets ## Start FrankenPHP and an Ember daemon serving the remote API on :19443
	@command -v docker >/dev/null 2>&1 || { echo >&2 "Docker is not installed."; exit 1; }
	docker compose up -d --build
	@echo ""
	@echo "  Site       : http://localhost:18080 (the admin API is not published)"
	@echo "  Remote API : https://localhost:19443"
	@echo "  TUI        : make tui"

down: ## Stop and remove the stack's containers
	docker compose down --remove-orphans

traffic: ## Generate light traffic against the site
	@for i in $$(seq 1 200); do curl -s http://localhost:18080/ > /dev/null & sleep 0.02; done; wait
	@echo "  done"

tui: ## Run the TUI against the remote daemon
	go run ../../cmd/ember --remote https://localhost:19443 --remote-ca secrets/daemon.pem --remote-token-file secrets/token

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

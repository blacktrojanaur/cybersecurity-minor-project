# ─────────────────────────────────────────────────────────────────────────────
# ZTSP Makefile  –  AI-Augmented Zero Trust Security Orchestration Platform
# ─────────────────────────────────────────────────────────────────────────────
# Targets:
#   make up    – Build images and start all 5 stubs (detached)
#   make down  – Stop and remove containers
#   make test  – Run contract tests (no Docker required)
#   make lint  – Lint all Python files with ruff
#   make logs  – Tail logs from all running containers
#   make clean – Remove containers, images and orphans
#   make help  – Show this message

.PHONY: up down test lint logs clean help

up:
	docker compose up --build -d

down:
	docker compose down

test:
	pip install jsonschema pytest --quiet
	pytest tests/ -v

lint:
	pip install ruff --quiet
	ruff check m1_identity/ m2_policy/ m3_response/ m4_posture/ m5_ml/ tests/

logs:
	docker compose logs -f

clean:
	docker compose down --rmi local --volumes --remove-orphans

help:
	@echo ""
	@echo "  ZTSP Phase 1 – Available make targets"
	@echo "  ──────────────────────────────────────"
	@echo "  up     Build images and start all 5 stub services"
	@echo "  down   Stop all stub services"
	@echo "  test   Run contract tests (pytest, no Docker needed)"
	@echo "  lint   Lint Python files with ruff"
	@echo "  logs   Tail logs from running containers"
	@echo "  clean  Remove containers, images and volumes"
	@echo ""

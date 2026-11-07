# ─────────────────────────────────────────────────────────────────────────────
# ZTSP Makefile  –  AI-Augmented Zero Trust Security Orchestration Platform
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: up down test test-all train eval scenarios demo lint logs clean help

up:
	docker compose up --build -d

down:
	docker compose down

train:
	python testbed/generate_telemetry.py --seed 42 --normal 10000 --attacks 100
	python m5_ml/trainer.py --data-dir testbed/data --seed 42

eval:
	python evaluation/evaluate.py --seed 42

scenarios:
	python testbed/scenarios/run_all.py

demo: up
	@echo "Waiting for services to become healthy..."
	@sleep 10
	python testbed/scenarios/run_all.py
	@echo ""
	@echo "======================================================================"
	@echo "  ZTSP Platform Live Demo Ready!"
	@echo "  --------------------------------------------------------------------"
	@echo "  Web Dashboard:        http://localhost:8080"
	@echo "  Protected Resource:   http://localhost:8090"
	@echo "  M1 Identity API:      http://localhost:8001/docs"
	@echo "  M2 Policy PDP/PEP:    http://localhost:8002/docs"
	@echo "  M3 SOAR Response:     http://localhost:8003/docs"
	@echo "  M4 Posture Engine:    http://localhost:8004/docs"
	@echo "  M5 ML Risk Engine:    http://localhost:8005/docs"
	@echo "  Mock SOC Webhook:     http://localhost:8099/alerts"
	@echo "======================================================================"

test:
	pip install jsonschema pytest --quiet
	pytest tests/ -v

test-all: test
	python evaluation/evaluate.py --seed 42

lint:
	pip install ruff --quiet
	ruff check m1_identity/ m2_policy/ m3_response/ m4_posture/ m5_ml/ common/ dashboard/ testbed/ tests/

logs:
	docker compose logs -f

clean:
	docker compose down --rmi local --volumes --remove-orphans

help:
	@echo ""
	@echo "  ZTSP Platform – Available make targets"
	@echo "  ──────────────────────────────────────"
	@echo "  up         Build and start all 8 microservices (detached)"
	@echo "  down       Stop all microservices"
	@echo "  demo       Bring up platform, run attack scenarios, show dashboard"
	@echo "  train      Generate synthetic data & train M5 ML ensemble"
	@echo "  eval       Run comprehensive evaluation and output /results"
	@echo "  scenarios  Run live attack scenarios (S1-S4) vs RBAC baseline"
	@echo "  test       Run schema contract tests (pytest, no Docker needed)"
	@echo "  test-all   Run contract tests and full evaluation pipeline"
	@echo "  lint       Lint Python code with ruff"
	@echo "  logs       Tail container logs"
	@echo "  clean      Remove containers, volumes, and images"
	@echo ""

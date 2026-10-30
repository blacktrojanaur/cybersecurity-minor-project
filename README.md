# AI-Augmented Zero Trust Security Orchestration Platform

> **B.Tech Final Year Research Prototype** | Phase 1 – Research, Requirements & Design

A five-module, microservice-based prototype demonstrating continuous Zero Trust access evaluation
augmented by an ML risk-scoring engine. Access is treated as a continuously re-evaluated decision:

```
Telemetry → ML Risk Score → Policy Decision → Enforcement → Automated Response → Feedback
```

---

## Quick Start

### Prerequisites
- Docker Desktop (Windows/macOS/Linux)
- Python 3.11+ (for `make test` without Docker)
- GNU Make (Windows: install via [Chocolatey](https://chocolatey.org): `choco install make`)

### Start all five service stubs

```bash
docker compose up --build -d
# or
make up
```

| Service | URL | Swagger UI |
|---|---|---|
| M1 Identity & Context | http://localhost:8001 | http://localhost:8001/docs |
| M2 Policy Enforcement | http://localhost:8002 | http://localhost:8002/docs |
| M3 Automated Response | http://localhost:8003 | http://localhost:8003/docs |
| M4 Posture & Vuln | http://localhost:8004 | http://localhost:8004/docs |
| M5 ML Risk Scoring | http://localhost:8005 | http://localhost:8005/docs |

### Run contract tests (no Docker required)

```bash
pip install jsonschema pytest
pytest tests/ -v
# or
make test
```

### Stop everything

```bash
make down
```

---

## Repository Structure

```
minor/
├── README.md                   ← This file
├── Makefile                    ← make up / test / lint / down / clean
├── docker-compose.yml          ← Wires all 5 stubs on zt-net bridge
│
├── contracts/                  ← ★ Frozen interface specification v1.0 ★
│   ├── CHANGELOG.md            ← Version history + change governance rules
│   ├── openapi.yaml            ← Aggregated OpenAPI 3.0 spec (all 5 services)
│   ├── telemetry_event.schema.json   (M1 → M5, M4)
│   ├── risk_score.schema.json        (M5 → M2, M3)
│   ├── posture_score.schema.json     (M4 → M5, M2)
│   ├── policy_decision.schema.json   (M2 → M1, M3)
│   └── response_action.schema.json   (M3 → M1, M2)
│
├── docs/
│   ├── 01-gap-matrix.md        ← Research gaps and contributions
│   ├── 02-requirements.md      ← Functional + NFRs + success metrics
│   ├── 03-threat-model.md      ← Assets, actors, 4 attack scenarios (simulation)
│   ├── 04-architecture.md      ← 3 Mermaid diagrams + NIST 800-207 alignment
│   ├── 05-tech-stack-and-data.md ← Stack justification + datasets
│   └── 06-module-briefs.md     ← Per-module inputs/outputs/DoD/week tasks
│
├── m1_identity/                ← M1 stub (FastAPI, port 8001)
├── m2_policy/                  ← M2 stub (FastAPI, port 8002)
├── m3_response/                ← M3 stub (FastAPI, port 8003)
├── m4_posture/                 ← M4 stub (FastAPI, port 8004)
├── m5_ml/                      ← M5 stub (FastAPI, port 8005)
│   (each module: main.py, Dockerfile, requirements.txt)
│
├── testbed/
│   └── README.md               ← Phase 2 dataset and evaluation plan
│
└── tests/
    ├── conftest.py             ← Pytest fixtures (schema loader)
    ├── requirements.txt        ← pytest + jsonschema
    └── test_contracts.py       ← 40+ contract validation tests
```

---

## Make Targets

| Command | Description |
|---|---|
| `make up` | Build Docker images and start all 5 stubs (detached) |
| `make down` | Stop and remove containers |
| `make test` | Run contract tests (no Docker required) |
| `make lint` | Lint all Python with `ruff` |
| `make logs` | Tail logs from running containers |
| `make clean` | Remove containers, images, volumes |

---

## Contract Governance

All inter-module schemas live in `/contracts/`. **Any change requires team approval**:

1. Open a pull request.
2. Tag all five team members as reviewers.
3. Add an entry to `contracts/CHANGELOG.md`.
4. Update the affected stub(s) and OpenAPI spec in the same PR.

See `contracts/CHANGELOG.md` for version history and rules.

---

## Phase Status

| Phase | Status | Deliverables |
|---|---|---|
| **Phase 1** – Research, Requirements & Design | ✅ Complete | All 8 deliverables (see docs/) |
| **Phase 2** – Module Implementation | 🔲 Upcoming (Weeks 2–4) | Real ML model, real data sources, integration tests |
| **Phase 3** – Evaluation & Report | 🔲 Upcoming (Week 5–6) | Accuracy / FPR / MTTR measurements, paper |

---

## Team

| Module | Owner |
|---|---|
| M1 – Identity & Context Engine | Team member 1 |
| M2 – Policy Enforcement | Team member 2 |
| M3 – Automated Response (SOAR-lite) | Team member 3 |
| M4 – Vulnerability & Posture | Team member 4 |
| M5 – ML Risk-Scoring Engine | Team member 5 |

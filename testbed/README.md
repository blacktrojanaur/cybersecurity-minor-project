# Testbed

**Purpose**: Phase 2 evaluation environment for the ZTSP prototype.

This directory will contain:

## Planned Contents (Phase 2)

```
testbed/
├── README.md               ← This file
├── generate_telemetry.py   ← Synthetic TelemetryEvent generator (normal + attack)
├── inject_events.py        ← HTTP client that POSTs generated events to M1
├── evaluate_model.py       ← Computes precision/recall/F1 on labelled test set
├── evaluation_report.md    ← Results: IF vs autoencoder vs RBAC baseline
└── data/
    ├── train/              ← 80% of generated events (unlabelled for IF training)
    ├── test/               ← 20% of generated events (labelled for evaluation)
    └── external/           ← Downloaded public datasets (DS1 UNSW-NB15, DS3 CERT)
```

## Generation Script Design (to be implemented Week 2)

The `generate_telemetry.py` script will produce NDJSON files where each line is a
`TelemetryEvent` object with an additional `ground_truth_label` field:

```json
{
  "schema_version": "1.0",
  "session_id": "sess-gen-0001",
  "user_id": "alice",
  "device_id": "dev-laptop-alice",
  "timestamp": "2024-06-01T09:15:00+00:00",
  "event_type": "access_request",
  "source_ip": "10.0.0.5",
  "geo": {"country": "IN", "city": "Bengaluru", "lat": 12.97, "lon": 77.59},
  "raw_features": {"bytes_sent": 2048, "session_duration": 420, "distinct_resources": 2},
  "ground_truth_label": "normal"
}
```

The `ground_truth_label` field is **stripped before feeding to M5** and **retained for evaluation**.

## External Datasets

See `docs/05-tech-stack-and-data.md` for dataset descriptions and download instructions.
All external data must be placed in `testbed/data/external/` and is excluded from git
(add to `.gitignore`).

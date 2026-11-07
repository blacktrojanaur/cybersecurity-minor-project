"""
testbed/generate_telemetry.py – Seeded synthetic telemetry generator.

Produces labelled NDJSON TelemetryEvents for:
  - Normal user behaviour (10 users, realistic patterns)
  - S1: Credential misuse (new geo + unknown device)
  - S2: Lateral movement (rapid cross-segment access)
  - S3: Privilege escalation attempts
  - S4: Slow-and-low behavioural spoofing (time-compressed)

Usage:
    python testbed/generate_telemetry.py [--seed 42] [--normal 10000] [--attacks 500]
    python testbed/generate_telemetry.py --scenario s4 --output testbed/data/s4_slow_and_low.ndjson

Outputs:
    testbed/data/train/normal.ndjson          (80% of normal events, no labels)
    testbed/data/test/normal.ndjson           (20% of normal events, with labels)
    testbed/data/test/s1_credential_misuse.ndjson
    testbed/data/test/s2_lateral_movement.ndjson
    testbed/data/test/s3_privilege_escalation.ndjson
    testbed/data/test/s4_slow_and_low.ndjson
    testbed/data/all_labelled.ndjson          (combined, for evaluation)

NOTE on synthetic data limitations (OQ4):
  - All user profiles and device attributes are fabricated; they do not represent
    real individuals or organisations.
  - Behavioural distributions (working hours, geo, resource patterns) are simplified
    Gaussian/uniform draws; real traffic has long-tail and bursty structure.
  - Attack patterns are defined by the researchers; a real attacker may behave
    differently. Model performance on this dataset does NOT guarantee real-world
    generalisation.
  - See docs/08-evaluation.md §Limitations for a full discussion.
"""

from __future__ import annotations

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── User profiles ────────────────────────────────────────────────────────────

USERS = [
    {"user_id": "alice", "role": "developer", "devices": ["dev-alice-laptop", "dev-alice-desktop"],
     "home_geo": ("IN", "Bengaluru", 12.97, 77.59), "work_start": 9, "work_end": 18,
     "normal_resources": ["/code", "/code/repo-a", "/code/repo-b"],
     "normal_ips": ["10.0.1.10", "10.0.1.11"]},
    {"user_id": "bob", "role": "analyst", "devices": ["dev-bob-laptop"],
     "home_geo": ("IN", "Mumbai", 19.08, 72.88), "work_start": 10, "work_end": 19,
     "normal_resources": ["/finance", "/finance/reports"],
     "normal_ips": ["10.0.2.10"]},
    {"user_id": "carol", "role": "hr_manager", "devices": ["dev-carol-laptop", "dev-carol-phone"],
     "home_geo": ("IN", "Delhi", 28.61, 77.20), "work_start": 9, "work_end": 17,
     "normal_resources": ["/hr", "/hr/records", "/hr/payroll"],
     "normal_ips": ["10.0.3.10", "10.0.3.11"]},
    {"user_id": "dave", "role": "sysadmin", "devices": ["dev-dave-workstation", "dev-dave-laptop"],
     "home_geo": ("IN", "Pune", 18.52, 73.85), "work_start": 8, "work_end": 20,
     "normal_resources": ["/admin", "/code", "/finance", "/hr"],
     "normal_ips": ["10.0.4.10", "10.0.4.11"]},
    {"user_id": "eve", "role": "viewer", "devices": ["dev-eve-laptop"],
     "home_geo": ("IN", "Chennai", 13.08, 80.27), "work_start": 10, "work_end": 18,
     "normal_resources": ["/hr/org-chart"],
     "normal_ips": ["10.0.5.10"]},
    {"user_id": "frank", "role": "developer", "devices": ["dev-frank-laptop", "dev-frank-desktop"],
     "home_geo": ("IN", "Hyderabad", 17.38, 78.47), "work_start": 9, "work_end": 18,
     "normal_resources": ["/code", "/code/repo-c"],
     "normal_ips": ["10.0.6.10", "10.0.6.11"]},
    {"user_id": "grace", "role": "finance_lead", "devices": ["dev-grace-laptop"],
     "home_geo": ("IN", "Kolkata", 22.57, 88.36), "work_start": 9, "work_end": 17,
     "normal_resources": ["/finance", "/finance/reports", "/finance/audit"],
     "normal_ips": ["10.0.7.10"]},
    {"user_id": "henry", "role": "viewer", "devices": ["dev-henry-laptop"],
     "home_geo": ("IN", "Ahmedabad", 23.02, 72.57), "work_start": 11, "work_end": 19,
     "normal_resources": ["/hr/org-chart", "/finance/reports"],
     "normal_ips": ["10.0.8.10"]},
    {"user_id": "iris", "role": "developer", "devices": ["dev-iris-laptop"],
     "home_geo": ("IN", "Bengaluru", 12.97, 77.59), "work_start": 10, "work_end": 19,
     "normal_resources": ["/code", "/code/repo-d"],
     "normal_ips": ["10.0.9.10"]},
    {"user_id": "jack", "role": "analyst", "devices": ["dev-jack-laptop", "dev-jack-phone"],
     "home_geo": ("IN", "Mumbai", 19.08, 72.88), "work_start": 9, "work_end": 18,
     "normal_resources": ["/finance", "/finance/reports"],
     "normal_ips": ["10.0.10.10", "10.0.10.11"]},
]

ALL_RESOURCES = ["/code", "/code/repo-a", "/code/repo-b", "/code/repo-c", "/code/repo-d",
                 "/finance", "/finance/reports", "/finance/audit",
                 "/hr", "/hr/records", "/hr/payroll", "/hr/org-chart",
                 "/admin"]

EVENT_TYPES_NORMAL = ["login", "access_request", "file_access", "logout"]

BASE_TS = datetime(2024, 6, 1, 0, 0, 0, tzinfo=timezone.utc)


def _ts(offset_hours: float) -> str:
    return (BASE_TS + timedelta(hours=offset_hours)).isoformat()


def _rand_work_hour(rng: random.Random, user: dict, jitter_hours: float = 0.0) -> int:
    hour = rng.randint(user["work_start"], user["work_end"] - 1)
    return max(0, min(23, hour + int(jitter_hours)))


def _make_event(
    session_id: str, user: dict, rng: random.Random,
    ts: str, event_type: str, device_id: str, source_ip: str,
    geo_country: str, geo_city: str, geo_lat: float, geo_lon: float,
    resource: str | None = None,
    raw_features: dict | None = None,
    label: str = "normal",
) -> dict:
    raw = {
        "bytes_sent": rng.randint(512, 8192),
        "session_duration": rng.randint(60, 3600),
        "distinct_resources": 1,
        "off_hours": 0,
        "new_device": 0,
        "geo_anomaly": 0,
        "lateral_move_velocity": 0.0,
        "privilege_claim_mismatch": 0,
        "temporal_drift_score": 0.0,
        "resource_access_deviation": 0.0,
        "failed_auth_count": 0,
        "resource_path": resource or rng.choice(user["normal_resources"]),
        "user_role": user["role"],
        "claimed_role": user["role"],
    }
    if raw_features:
        raw.update(raw_features)
    evt = {
        "schema_version": "1.0",
        "session_id": session_id,
        "user_id": user["user_id"],
        "device_id": device_id,
        "timestamp": ts,
        "event_type": event_type,
        "source_ip": source_ip,
        "geo": {"country": geo_country, "city": geo_city, "lat": geo_lat, "lon": geo_lon},
        "user_agent": f"Mozilla/5.0 ({user['devices'][0]})",
        "raw_features": raw,
        "ground_truth_label": label,
    }
    return evt


def generate_normal_events(rng: random.Random, count: int) -> list[dict]:
    events: list[dict] = []
    events_per_user = count // len(USERS)
    for user in USERS:
        for i in range(events_per_user):
            session_id = f"sess-{user['user_id']}-{i:05d}"
            hour_offset = i * 0.8 + _rand_work_hour(rng, user)
            ts = _ts(hour_offset)
            device = rng.choice(user["devices"])
            ip = rng.choice(user["normal_ips"])
            country, city, lat, lon = user["home_geo"]
            num_events = rng.randint(2, 6)
            resources_accessed = rng.sample(user["normal_resources"], min(num_events, len(user["normal_resources"])))
            # login
            events.append(_make_event(
                session_id, user, rng, ts, "login", device, ip,
                country, city, lat + rng.gauss(0, 0.01), lon + rng.gauss(0, 0.01),
                raw_features={"distinct_resources": len(resources_accessed)},
                label="normal",
            ))
            for j, res in enumerate(resources_accessed):
                evt_ts = _ts(hour_offset + j * 0.1)
                events.append(_make_event(
                    session_id, user, rng, evt_ts,
                    rng.choice(["access_request", "file_access"]),
                    device, ip, country, city,
                    lat + rng.gauss(0, 0.01), lon + rng.gauss(0, 0.01),
                    resource=res, label="normal",
                ))
            # logout
            events.append(_make_event(
                session_id, user, rng, _ts(hour_offset + num_events * 0.1 + 0.5),
                "logout", device, ip, country, city, lat, lon, label="normal",
            ))
    return events


# ── Attack Scenario Generators ───────────────────────────────────────────────

def generate_s1_credential_misuse(rng: random.Random, count: int = 50) -> list[dict]:
    """S1 – Stolen credentials used from foreign geo + unregistered device."""
    events: list[dict] = []
    victims = rng.sample(USERS, min(count, len(USERS)))
    for i, victim in enumerate(victims * (count // len(USERS) + 1)):
        if i >= count:
            break
        session_id = f"sess-s1-attack-{i:04d}"
        # Attacker in a foreign location
        attack_geo = rng.choice([
            ("RU", "Moscow", 55.75, 37.62),
            ("CN", "Beijing", 39.91, 116.39),
            ("NG", "Lagos", 6.52, 3.38),
            ("BR", "Sao Paulo", -23.55, -46.63),
        ])
        ts_base = i * 2.5
        events.append(_make_event(
            session_id, victim, rng, _ts(ts_base), "login",
            "dev-unknown-attacker", f"203.0.{rng.randint(1, 254)}.{rng.randint(1, 254)}",
            attack_geo[0], attack_geo[1], attack_geo[2], attack_geo[3],
            raw_features={
                "new_device": 1, "geo_anomaly": 1, "failed_auth_count": rng.randint(0, 3),
                "off_hours": rng.choice([0, 1]),
                "resource_path": rng.choice(victim["normal_resources"]),
            },
            label="attack_credential_misuse",
        ))
        # Attempt resource access
        events.append(_make_event(
            session_id, victim, rng, _ts(ts_base + 0.05), "access_request",
            "dev-unknown-attacker", f"203.0.{rng.randint(1, 254)}.{rng.randint(1, 254)}",
            attack_geo[0], attack_geo[1], attack_geo[2], attack_geo[3],
            resource=rng.choice(victim["normal_resources"]),
            raw_features={"new_device": 1, "geo_anomaly": 1},
            label="attack_credential_misuse",
        ))
    return events


def generate_s2_lateral_movement(rng: random.Random, count: int = 50) -> list[dict]:
    """S2 – Compromised device sweeping across segments rapidly."""
    events: list[dict] = []
    for i in range(count):
        attacker_user = rng.choice(USERS)
        session_id = f"sess-s2-attack-{i:04d}"
        ts_base = i * 3.0
        device = "dev-compromised-01"
        ip = f"10.0.{rng.randint(1, 10)}.{rng.randint(1, 254)}"
        country, city, lat, lon = attacker_user["home_geo"]
        # Rapid sweep across all segments
        resources_swept = rng.sample(ALL_RESOURCES, rng.randint(8, 13))
        events.append(_make_event(
            session_id, attacker_user, rng, _ts(ts_base), "login",
            device, ip, country, city, lat, lon,
            raw_features={"distinct_resources": len(resources_swept), "lateral_move_velocity": 0.9},
            label="attack_lateral_movement",
        ))
        for j, res in enumerate(resources_swept):
            events.append(_make_event(
                session_id, attacker_user, rng, _ts(ts_base + j * 0.02),
                "lateral_move_attempt", device, ip, country, city, lat, lon,
                resource=res,
                raw_features={
                    "distinct_resources": len(resources_swept),
                    "lateral_move_velocity": 0.85 + rng.uniform(0, 0.15),
                    "resource_access_deviation": 0.8 + rng.uniform(0, 0.2),
                },
                label="attack_lateral_movement",
            ))
    return events


def generate_s3_privilege_escalation(rng: random.Random, count: int = 50) -> list[dict]:
    """S3 – Viewer/analyst tries to claim admin role."""
    events: list[dict] = []
    low_priv_users = [u for u in USERS if u["role"] in ("viewer", "analyst")]
    for i in range(count):
        victim = rng.choice(low_priv_users)
        session_id = f"sess-s3-attack-{i:04d}"
        ts_base = i * 2.0
        device = rng.choice(victim["devices"])
        ip = rng.choice(victim["normal_ips"])
        country, city, lat, lon = victim["home_geo"]
        # Normal login first
        events.append(_make_event(
            session_id, victim, rng, _ts(ts_base), "login",
            device, ip, country, city, lat, lon, label="normal",
        ))
        # Escalation attempt
        events.append(_make_event(
            session_id, victim, rng, _ts(ts_base + 0.1),
            "privilege_escalation_attempt", device, ip, country, city, lat, lon,
            resource="/admin",
            raw_features={
                "claimed_role": "admin",
                "user_role": victim["role"],
                "privilege_claim_mismatch": 1,
                "resource_path": "/admin",
            },
            label="attack_privilege_escalation",
        ))
    return events


def generate_s4_slow_and_low(rng: random.Random, sessions: int = 20) -> list[dict]:
    """
    S4 – Slow-and-low behavioural spoofing.
    Time-compressed: 1 simulated day = 100 events.
    Attacker gradually shifts access hours and targets new resources.
    """
    events: list[dict] = []
    victim = next(u for u in USERS if u["user_id"] == "alice")
    for day in range(10):
        for e in range(sessions):
            session_id = f"sess-s4-day{day:02d}-{e:04d}"
            # Each day the access time drifts 0.5h earlier → off hours by day 6
            hour_offset = day * 100.0 + e * 2.0
            simulated_hour = victim["work_start"] - day * 0.5 + rng.gauss(0, 0.3)
            off_hours = 1 if simulated_hour < victim["work_start"] or simulated_hour > victim["work_end"] else 0
            # Gradually access more diverse resources
            drift = min(day / 9.0, 1.0)
            if rng.random() < drift:
                resource = rng.choice(ALL_RESOURCES)  # anomalous
                resource_deviation = drift
                label = "attack_slow_and_low" if day >= 5 else "normal"
            else:
                resource = rng.choice(victim["normal_resources"])
                resource_deviation = 0.0
                label = "normal"
            temporal_drift = day / 9.0 * rng.uniform(0.7, 1.0)
            events.append(_make_event(
                session_id, victim, rng, _ts(hour_offset),
                rng.choice(["login", "access_request"]),
                victim["devices"][0], victim["normal_ips"][0],
                *victim["home_geo"],
                resource=resource,
                raw_features={
                    "off_hours": off_hours,
                    "temporal_drift_score": temporal_drift,
                    "resource_access_deviation": resource_deviation,
                    "distinct_resources": 1 + day,
                },
                label=label,
            ))
    return events


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="ZTSP synthetic telemetry generator")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed (default: 42)")
    parser.add_argument("--normal", type=int, default=10_000, help="Normal event count")
    parser.add_argument("--attacks", type=int, default=100, help="Attack events per scenario")
    parser.add_argument("--output-dir", default="testbed/data", help="Output directory")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    out = Path(args.output_dir)
    (out / "train").mkdir(parents=True, exist_ok=True)
    (out / "test").mkdir(parents=True, exist_ok=True)

    print(f"[generate_telemetry] seed={args.seed}  normal={args.normal}  attacks={args.attacks}")

    # Normal events
    normal = generate_normal_events(rng, args.normal)
    rng.shuffle(normal)
    split = int(0.8 * len(normal))
    train_normal = normal[:split]
    test_normal = normal[split:]

    # Strip labels for training data
    train_no_label = [{k: v for k, v in e.items() if k != "ground_truth_label"} for e in train_normal]

    def write_ndjson(path: Path, records: list[dict]) -> None:
        path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
        print(f"  → wrote {len(records):>6d} events  {path}")

    write_ndjson(out / "train" / "normal.ndjson", train_no_label)
    write_ndjson(out / "test" / "normal.ndjson", test_normal)

    # Attack scenarios
    n = args.attacks
    attacks = {
        "s1_credential_misuse":   generate_s1_credential_misuse(rng, n),
        "s2_lateral_movement":    generate_s2_lateral_movement(rng, n),
        "s3_privilege_escalation":generate_s3_privilege_escalation(rng, n),
        "s4_slow_and_low":        generate_s4_slow_and_low(rng),
    }
    for name, evts in attacks.items():
        write_ndjson(out / "test" / f"{name}.ndjson", evts)

    # Combined labelled set
    all_labelled = test_normal + [e for evts in attacks.values() for e in evts]
    rng.shuffle(all_labelled)
    write_ndjson(out / "all_labelled.ndjson", all_labelled)

    # Write metadata
    meta = {
        "seed": args.seed, "normal_total": len(normal),
        "train_count": len(train_normal), "test_normal_count": len(test_normal),
        "attack_counts": {k: len(v) for k, v in attacks.items()},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "limitations": [
            "Synthetic profiles; does not represent real individuals.",
            "Behavioural distributions simplified (Gaussian/uniform).",
            "Attack patterns defined by researchers; real attackers may differ.",
            "No external datasets used (OQ4 decision: self-contained).",
        ],
    }
    (out / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"\n[generate_telemetry] Done. Metadata: {out / 'metadata.json'}")


if __name__ == "__main__":
    main()

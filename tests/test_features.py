"""
Unit tests for M5 feature extraction pipeline.
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from m5_ml.features import extract_features, FEATURE_NAMES, N_FEATURES


def test_feature_vector_dimension():
    event = {
        "timestamp": "2024-06-01T12:00:00Z",
        "event_type": "access_request",
        "raw_features": {
            "bytes_sent": 4096,
            "session_duration": 600,
            "distinct_resources": 3,
            "off_hours": 0,
            "new_device": 0,
            "geo_anomaly": 0,
        },
    }
    posture = {
        "patch_level": 0.9,
        "vuln_count": 1,
        "critical_vuln_count": 0,
        "os_compliant": True,
        "antivirus_active": True,
        "posture_score": 0.85,
    }
    vec = extract_features(event, posture)
    assert len(vec) == N_FEATURES
    assert len(FEATURE_NAMES) == N_FEATURES
    # Verify values are numeric and finite
    import numpy as np
    assert np.all(np.isfinite(vec))

"""Generate clearly labeled synthetic network-event records for safe demonstrations."""
import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "duration_seconds",
    "bytes_sent",
    "bytes_received",
    "failed_connections",
    "unique_destination_ports",
    "connection_rate",
    "packet_size_mean",
]

def _make_features(n, rng, threat):
    if threat:
        duration = rng.gamma(1.5, 4.0, n)
        sent = rng.lognormal(8.5, 1.0, n)
        received = rng.lognormal(5.8, 1.0, n)
        failed = rng.poisson(7, n)
        ports = rng.poisson(9, n)
        rate = rng.gamma(4.0, 3.0, n)
        packet = rng.normal(420, 180, n)
    else:
        duration = rng.gamma(2.5, 25.0, n)
        sent = rng.lognormal(7.0, 0.9, n)
        received = rng.lognormal(7.1, 0.9, n)
        failed = rng.poisson(0.4, n)
        ports = rng.poisson(1.2, n)
        rate = rng.gamma(1.5, 1.5, n)
        packet = rng.normal(850, 220, n)
    return pd.DataFrame({
        "duration_seconds": np.clip(duration, 0, None),
        "bytes_sent": np.clip(sent, 0, None).astype(int),
        "bytes_received": np.clip(received, 0, None).astype(int),
        "failed_connections": np.clip(failed, 0, None).astype(int),
        "unique_destination_ports": np.clip(ports, 0, None).astype(int),
        "connection_rate": np.clip(rate, 0, None),
        "packet_size_mean": np.clip(packet, 40, 1500),
    })

def generate_labeled_dataset(n=2000, seed=42):
    """Create synthetic training records with labels; 0=benign, 1=potential threat."""
    rng = np.random.default_rng(seed)
    n_threat = n // 2
    n_benign = n - n_threat
    benign = _make_features(n_benign, rng, threat=False)
    benign["label"] = 0
    threat = _make_features(n_threat, rng, threat=True)
    threat["label"] = 1
    data = pd.concat([benign, threat], ignore_index=True)
    return data.sample(frac=1, random_state=seed).reset_index(drop=True)

def generate_live_events(n=100, seed=142):
    """Create unlabeled synthetic events for dashboard demonstration."""
    rng = np.random.default_rng(seed)
    # Randomly mix benign-like and threat-like patterns. The true class is not exposed to the model.
    threat_mask = rng.random(n) < 0.3
    pieces = []
    for is_threat in threat_mask:
        pieces.append(_make_features(1, rng, bool(is_threat)))
    events = pd.concat(pieces, ignore_index=True) if pieces else pd.DataFrame(columns=FEATURE_COLUMNS)
    event_types = ["normal browsing", "repeated connection failures", "many destination ports", "high connection rate"]
    events.insert(0, "event_id", [f"SIM-{i:05d}" for i in range(1, len(events) + 1)])
    events.insert(1, "event_type", rng.choice(event_types, size=len(events)))
    return events

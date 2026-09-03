"""
ml_detector.py — Unsupervised anomaly detection using Isolation Forest.

Why unsupervised? We have no labeled "attack" examples — the model learns
what "normal" looks like from the log itself and flags statistical outliers.

How Isolation Forest works (simple version):
  Imagine randomly splitting your data with cuts. Normal points are hard to
  isolate (need many cuts). Outliers are easy to isolate (few cuts needed).
  Points that are easy to isolate get a high anomaly score → flagged.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler   # rescales features to same range
from datetime import datetime

# Features fed to the model for each log type
_AUTH_FEATURES = [
    'total_attempts', 'failed_attempts', 'failure_rate',
    'unique_users', 'attempts_per_minute', 'night_attempts', 'invalid_user_count',
]
_WEB_FEATURES = [
    'total_requests', 'error_rate', 'unique_paths', 'requests_per_minute',
    'post_ratio', 'not_found_count', 'night_requests', 'suspicious_path_count',
]


def _run_isolation_forest(df: pd.DataFrame, feature_cols: list[str],
                           contamination: float = 0.1) -> pd.DataFrame:
    """
    Core ML step. Trains Isolation Forest on the feature columns,
    then adds two new columns to the DataFrame:
      anomaly_score — 0.0 (normal) to 1.0 (very anomalous)
      is_anomaly    — True if Isolation Forest flagged this IP as an outlier

    contamination=0.1 means "assume ~10% of IPs are outliers."
    """
    available = [c for c in feature_cols if c in df.columns]
    if len(available) < 2 or len(df) < 2:
        # Not enough data to run ML; mark everything as normal
        df['anomaly_score'] = 0.0
        df['is_anomaly']    = False
        return df

    X = df[available].fillna(0).values   # fill any missing values with 0

    # StandardScaler centres each feature around 0 with unit variance,
    # so a feature with range 0–1000 doesn't dominate one with range 0–1
    X_scaled = StandardScaler().fit_transform(X)

    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit(X_scaled)

    raw_scores  = model.decision_function(X_scaled)  # lower = more anomalous
    predictions = model.predict(X_scaled)             # -1 = outlier, 1 = normal

    # Normalise to [0, 1] where 1 = most anomalous (inverts the raw score)
    mn, mx = raw_scores.min(), raw_scores.max()
    normalised = 1.0 - (raw_scores - mn) / (mx - mn) if mx != mn else np.zeros(len(raw_scores))

    df = df.copy()
    df['anomaly_score'] = np.round(normalised, 3)
    df['is_anomaly']    = (predictions == -1)
    return df


def detect_anomalies(features_df: pd.DataFrame, log_type: str) -> list[dict]:
    """
    Run ML detection on a feature DataFrame.
    Returns threat dicts (same format as rule_engine) for anomalous IPs.
    """
    if features_df is None or features_df.empty:
        return []

    cols = _AUTH_FEATURES if log_type == 'auth' else _WEB_FEATURES
    df   = _run_isolation_forest(features_df, cols)

    threats = []
    for _, row in df[df['is_anomaly']].iterrows():
        ip    = row.get('ip', 'unknown')
        score = row.get('anomaly_score', 0.0)
        sev   = 'CRITICAL' if score >= 0.85 else 'HIGH' if score >= 0.65 else 'MEDIUM'

        # Build a plain-English evidence string from the most notable numbers
        if log_type == 'auth':
            parts = []
            if row.get('failed_attempts', 0):
                parts.append(f"{int(row['failed_attempts'])} failed logins")
            if row.get('unique_users', 0) > 1:
                parts.append(f"{int(row['unique_users'])} unique usernames")
            if row.get('attempts_per_minute', 0) > 1:
                parts.append(f"{row['attempts_per_minute']:.1f} attempts/min")
        else:
            parts = []
            if row.get('error_rate', 0) > 0.3:
                parts.append(f"{row['error_rate']*100:.0f}% error rate")
            if row.get('suspicious_path_count', 0):
                parts.append(f"{int(row['suspicious_path_count'])} suspicious paths")
            if row.get('not_found_count', 0) > 5:
                parts.append(f"{int(row['not_found_count'])} 404s")

        evidence = '; '.join(parts) if parts else 'Statistical outlier'
        threats.append({
            'threat_type': 'ML Anomaly Detected',
            'severity':    sev,
            'ip':          ip,
            'evidence':    f'Anomaly score {score:.2f} — {evidence}',
            'timestamp':   datetime.now(),
            'count':       1,
            'source':      'ml',
        })
    return threats


def get_ip_scores(features_df: pd.DataFrame, log_type: str) -> pd.DataFrame:
    """
    Return the full DataFrame with anomaly_score for every IP.
    Used by the web dashboard to populate the IP Activity chart.
    """
    if features_df is None or features_df.empty:
        return pd.DataFrame()
    cols = _AUTH_FEATURES if log_type == 'auth' else _WEB_FEATURES
    return _run_isolation_forest(features_df, cols)

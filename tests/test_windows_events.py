"""Windows Security Event Log parsing and detection.

Most entry-level SOC work happens in Windows and Active Directory, so this
path matters more for realism than the SSH one. The fixture covers a small
intrusion sequence: a spray attempt, a lockout, a privilege assignment and an
off-hours account creation, plus one unrelated event ID that must be ignored.
"""

from datetime import datetime, timedelta

import pytest

from analyzer.log_parser import WINDOWS_EVENT_IDS, auto_parse, parse_windows_log
from analyzer.rule_engine import (
    KNOWN_ADMIN_ACCOUNTS,
    detect_account_lockouts,
    detect_brute_force,
    detect_off_hours_account_creation,
    detect_unexpected_privilege_assignment,
    run_all_rules,
)


def _win_events(event, count=1, user='attacker', ip='198.51.100.77',
                hour=3, computer='DC01.corp.local', subject_user='-'):
    base = datetime(2025, 1, 10, hour, 0, 0)
    return [
        {'type': 'windows', 'event': event, 'ip': ip, 'user': user,
         'subject_user': subject_user, 'computer': computer,
         'timestamp': base + timedelta(seconds=i * 5), 'raw': ''}
        for i in range(count)
    ]


class TestWindowsParser:
    def test_parses_known_event_ids(self, fixture_path):
        events = parse_windows_log(fixture_path('windows_security.xml'))
        # Six <Event> elements, one of which (4104) is not a tracked ID
        assert len(events) == 5

    def test_ignores_untracked_event_ids(self, fixture_path):
        events = parse_windows_log(fixture_path('windows_security.xml'))
        assert all(e['event_id'] in WINDOWS_EVENT_IDS for e in events)
        assert 4104 not in {e['event_id'] for e in events}

    def test_maps_event_ids_to_shared_event_names(self, fixture_path):
        """4625 must become 'failed_login' so the SSH rules apply unchanged."""
        events = parse_windows_log(fixture_path('windows_security.xml'))
        by_id = {e['event_id']: e['event'] for e in events}
        assert by_id[4625] == 'failed_login'
        assert by_id[4624] == 'successful_login'
        assert by_id[4672] == 'special_privileges'
        assert by_id[4720] == 'account_created'
        assert by_id[4740] == 'account_lockout'

    def test_extracts_event_data_fields(self, fixture_path):
        events = parse_windows_log(fixture_path('windows_security.xml'))
        logon = [e for e in events if e['event_id'] == 4624][0]
        assert logon['user'] == 'jsmith'
        assert logon['ip'] == '10.0.5.21'
        assert logon['computer'] == 'DC01.corp.local'
        assert logon['logon_type'] == 3
        assert logon['logon_type_name'] == 'Network'

    def test_parses_timestamp_ignoring_nanoseconds(self, fixture_path):
        """Windows writes 9 fractional digits, which datetime cannot take."""
        events = parse_windows_log(fixture_path('windows_security.xml'))
        logon = [e for e in events if e['event_id'] == 4624][0]
        assert logon['timestamp'] == datetime(2025, 1, 10, 9, 14, 22)

    def test_normalises_non_remote_source_addresses(self, fixture_path):
        """4740 carries IpAddress '-'; that is not a remote source."""
        events = parse_windows_log(fixture_path('windows_security.xml'))
        lockout = [e for e in events if e['event_id'] == 4740][0]
        assert lockout['ip'] == 'local'

    def test_malformed_xml_returns_empty_not_raises(self, tmp_path):
        broken = tmp_path / 'broken.xml'
        broken.write_text('<Event><System><EventID>4625</EventID>')
        assert parse_windows_log(str(broken)) == []

    def test_empty_file_returns_empty(self, tmp_path):
        empty = tmp_path / 'empty.xml'
        empty.write_text('')
        assert parse_windows_log(str(empty)) == []

    def test_auto_parse_detects_windows(self, fixture_path):
        events, log_type = auto_parse(fixture_path('windows_security.xml'))
        assert log_type == 'windows'
        assert len(events) == 5


class TestOffHoursAccountCreation:
    def test_fires_at_night(self):
        threats = detect_off_hours_account_creation(
            _win_events('account_created', user='sysadmin_svc', hour=3))
        assert len(threats) == 1
        assert 'sysadmin_svc' in threats[0]['evidence']

    def test_silent_during_business_hours(self):
        assert detect_off_hours_account_creation(
            _win_events('account_created', hour=14)) == []

    def test_fires_in_the_evening(self):
        assert len(detect_off_hours_account_creation(
            _win_events('account_created', hour=21))) == 1

    def test_ignores_other_event_types(self):
        assert detect_off_hours_account_creation(
            _win_events('successful_login', hour=3)) == []


class TestPrivilegeAssignment:
    def test_fires_for_an_account_not_on_the_admin_list(self):
        threats = detect_unexpected_privilege_assignment(
            _win_events('special_privileges', user='svc_backup'))
        assert len(threats) == 1

    def test_silent_for_known_admins(self):
        known = next(iter(KNOWN_ADMIN_ACCOUNTS))
        assert detect_unexpected_privilege_assignment(
            _win_events('special_privileges', user=known)) == []

    def test_silent_for_machine_accounts(self):
        """Computer accounts end in $ and legitimately hold privileges."""
        assert detect_unexpected_privilege_assignment(
            _win_events('special_privileges', user='DC01$')) == []

    def test_one_alert_per_account_not_per_event(self):
        threats = detect_unexpected_privilege_assignment(
            _win_events('special_privileges', user='svc_backup', count=20))
        assert len(threats) == 1


class TestAccountLockouts:
    def test_reports_a_lockout(self):
        threats = detect_account_lockouts(_win_events('account_lockout', user='mwilson'))
        assert len(threats) == 1
        assert threats[0]['severity'] == 'MEDIUM'

    def test_repeated_lockouts_escalate(self):
        threats = detect_account_lockouts(
            _win_events('account_lockout', user='mwilson', count=3))
        assert threats[0]['severity'] == 'HIGH'
        assert threats[0]['count'] == 3


class TestSshRulesApplyToWindows:
    def test_brute_force_rule_works_on_4625(self):
        """The whole point of mapping 4625 to failed_login."""
        events = _win_events('failed_login', count=10)
        assert len(detect_brute_force(events)) == 1

    def test_run_all_rules_dispatches_windows(self):
        events = (_win_events('failed_login', count=10)
                  + _win_events('account_created', user='backdoor', hour=3))
        types = {t['threat_type'] for t in run_all_rules(events, 'windows')}
        assert 'Brute Force Attack' in types
        assert 'Off-Hours Account Creation' in types

    def test_windows_threats_carry_attack_techniques(self):
        events = _win_events('account_created', user='backdoor', hour=3)
        threats = run_all_rules(events, 'windows')
        assert threats[0]['technique'] == 'T1136.001'
        assert threats[0]['tactic'] == 'Persistence'


class TestGeneratedWindowsLog:
    @pytest.fixture
    def generated(self, tmp_path):
        import random
        import generate_sample_logs
        random.seed(42)
        path = tmp_path / 'security.xml'
        generate_sample_logs.gen_windows_log(str(path))
        return str(path)

    def test_detects_the_full_intrusion_chain(self, generated):
        events, log_type = auto_parse(generated)
        assert log_type == 'windows'
        types = {t['threat_type'] for t in run_all_rules(events, 'windows')}
        assert types >= {
            'Brute Force Attack',
            'Unexpected Privilege Assignment',
            'Off-Hours Account Creation',
            'Account Lockout',
        }

    def test_attributes_the_spray_to_the_attacker(self, generated):
        events, _ = auto_parse(generated)
        brute = [t for t in run_all_rules(events, 'windows')
                 if t['threat_type'] == 'Brute Force Attack']
        assert [t['ip'] for t in brute] == ['198.51.100.77']

    def test_leaves_ordinary_staff_logons_alone(self, generated):
        events, _ = auto_parse(generated)
        flagged = {t['ip'] for t in run_all_rules(events, 'windows')}
        assert not any(ip.startswith('10.0.5.') for ip in flagged)

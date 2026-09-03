"""ATT&CK mapping tests, including Sigma/Python consistency.

Two failure modes matter here. One is a detection shipping with no technique
at all. The other is quieter: the Sigma rules and the Python engine drifting
apart until they claim different techniques for the same behaviour.
"""

import glob
import os
import re

import pytest
import yaml

from analyzer.attack_mapping import ATTACK_TECHNIQUES, coverage, technique_for
from analyzer.rule_engine import run_all_rules

SIGMA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'rules', 'sigma'
)
SIGMA_FILES = sorted(glob.glob(os.path.join(SIGMA_DIR, '*.yml')))
TECHNIQUE_ID = re.compile(r'^T\d{4}(\.\d{3})?$')


def _load(path):
    with open(path, encoding='utf-8') as f:
        return yaml.safe_load(f)


class TestMappingTable:
    def test_every_technique_id_is_well_formed(self):
        for name, mapping in ATTACK_TECHNIQUES.items():
            if mapping['technique'] is not None:
                assert TECHNIQUE_ID.match(mapping['technique']), name

    def test_mapped_entries_carry_a_name_and_tactic(self):
        for name, mapping in ATTACK_TECHNIQUES.items():
            if mapping['technique']:
                assert mapping['technique_name'], name
                assert mapping['tactic'], name

    def test_partial_mappings_explain_themselves(self):
        """A 'partial' label with no reason is worse than no label."""
        for name, mapping in ATTACK_TECHNIQUES.items():
            if mapping['confidence'] == 'partial':
                assert mapping['note'].strip(), f'{name} is partial but has no note'

    def test_confidence_values_are_from_the_known_set(self):
        for name, mapping in ATTACK_TECHNIQUES.items():
            assert mapping['confidence'] in {'confirmed', 'partial', 'unmapped'}, name

    def test_unknown_threat_type_returns_unmapped_not_none(self):
        result = technique_for('Some Future Detection')
        assert result['technique'] is None
        assert result['confidence'] == 'unmapped'

    def test_coverage_excludes_unmapped_entries(self):
        assert all(row['technique'] for row in coverage())


class TestVerifiedCorrections:
    """
    These three were wrong in the first draft and were corrected against
    attack.mitre.org. Pinning them stops a plausible-looking revert.
    """

    def test_directory_traversal_is_not_file_discovery(self):
        """T1083 is host-local Discovery, not a remote web exploit attempt."""
        mapping = technique_for('Directory Traversal')
        assert mapping['technique'] == 'T1190'
        assert mapping['technique'] != 'T1083'

    def test_xss_is_not_the_javascript_execution_technique(self):
        """T1059.007 is Execution and never mentions XSS."""
        mapping = technique_for('XSS Attempt')
        assert mapping['technique'] == 'T1190'
        assert mapping['confidence'] == 'partial'

    def test_scanner_is_wordlist_not_vulnerability_scanning(self):
        """The rule counts 404 volume, which is enumeration."""
        mapping = technique_for('Path Scanner Detected')
        assert mapping['technique'] == 'T1595.003'

    def test_credential_stuffing_uses_the_parent_technique(self):
        """Auth logs cannot separate stuffing from spraying, so don't claim to."""
        mapping = technique_for('Credential Stuffing')
        assert mapping['technique'] == 'T1110'
        assert mapping['confidence'] == 'partial'


class TestThreatsCarryTechniques:
    def test_rule_threats_are_tagged(self, auth_events):
        threats = run_all_rules(auth_events(count=10), 'auth')
        assert threats
        for t in threats:
            assert t['technique'], t['threat_type']
            assert t['tactic']
            assert t['mapping_confidence'] in {'confirmed', 'partial'}

    def test_web_threats_are_tagged(self, web_events):
        threats = run_all_rules(web_events(paths=["/x?id=1' OR '1'='1"]), 'web')
        assert threats
        assert all(t['technique'] for t in threats)

    def test_ml_anomalies_are_explicitly_unmapped(self):
        """An outlier is a statistic, not an adversary behaviour. Say so."""
        mapping = technique_for('ML Anomaly Detected')
        assert mapping['technique'] is None
        assert mapping['confidence'] == 'unmapped'


class TestSigmaRules:
    def test_rules_exist(self):
        assert SIGMA_FILES, 'no Sigma rules found in rules/sigma/'

    @pytest.mark.parametrize('path', SIGMA_FILES, ids=lambda p: os.path.basename(p))
    def test_is_valid_yaml_with_required_keys(self, path):
        rule = _load(path)
        for key in ('title', 'id', 'description', 'logsource', 'detection',
                    'level', 'tags', 'falsepositives'):
            assert key in rule, f'{os.path.basename(path)} missing {key}'

    @pytest.mark.parametrize('path', SIGMA_FILES, ids=lambda p: os.path.basename(p))
    def test_detection_has_a_condition(self, path):
        assert 'condition' in _load(path)['detection']

    @pytest.mark.parametrize('path', SIGMA_FILES, ids=lambda p: os.path.basename(p))
    def test_declares_false_positives(self, path):
        """A rule with no stated false positives has not been thought through."""
        assert _load(path)['falsepositives']

    @pytest.mark.parametrize('path', SIGMA_FILES, ids=lambda p: os.path.basename(p))
    def test_attack_tag_matches_the_python_mapping(self, path):
        """The Sigma rules and the engine must not drift to different IDs."""
        rule = _load(path)
        technique_tags = [t for t in rule['tags'] if re.match(r'^attack\.t\d{4}', t)]
        assert len(technique_tags) == 1, f'{os.path.basename(path)}: expected one technique tag'

        tag_id = technique_tags[0].replace('attack.', '').upper()
        known = {m['technique'] for m in ATTACK_TECHNIQUES.values() if m['technique']}
        assert tag_id in known, (
            f'{os.path.basename(path)} claims {tag_id}, which no Python rule maps to'
        )

    def test_rule_ids_are_unique(self):
        ids = [_load(p)['id'] for p in SIGMA_FILES]
        assert len(ids) == len(set(ids))

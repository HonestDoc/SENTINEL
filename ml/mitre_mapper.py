# SENTINEL/ml/mitre_mapper.py
# Runs on: HOST Windows 11
# Downloads MITRE ATT&CK data and builds lookup tables

import json
import requests
import os

class MitreMapper:
    """
    Downloads MITRE ATT&CK STIX data and builds lookup structures.
    Used by: TTP predictor, chain reconstructor, coverage reporter.
    """

    STIX_URL = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    )

    TACTIC_ORDER = {
        'reconnaissance': 1,
        'resource-development': 2,
        'initial-access': 3,
        'execution': 4,
        'persistence': 5,
        'privilege-escalation': 6,
        'defense-evasion': 7,
        'credential-access': 8,
        'discovery': 9,
        'lateral-movement': 10,
        'collection': 11,
        'command-and-control': 12,
        'exfiltration': 13,
        'impact': 14
    }

    def __init__(self, cache_path='data/processed/attack_cache.json'):
        self.cache_path = cache_path
        self.techniques = {}
        self.groups = {}
        self._load_or_download()

    def _load_or_download(self):
        if os.path.exists(self.cache_path):
            print(f"Loading ATT&CK data from cache: {self.cache_path}")
            with open(self.cache_path, 'r') as f:
                cache = json.load(f)
                self.techniques = cache.get('techniques', {})
                self.groups = cache.get('groups', {})
            print(f"Loaded {len(self.techniques)} techniques, "
                  f"{len(self.groups)} groups")
        else:
            print("Downloading MITRE ATT&CK STIX data...")
            self._download_and_parse()

    def _download_and_parse(self):
        try:
            response = requests.get(self.STIX_URL, timeout=30)
            data = response.json()
        except Exception as e:
            print(f"Download failed: {e}")
            print("Using minimal built-in technique set instead")
            self._load_minimal()
            return

        for obj in data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                tech_id = ''
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        tech_id = ref.get('external_id', '')

                if not tech_id or tech_id.startswith('T') is False:
                    continue

                tactics = [
                    phase.get('phase_name', '')
                    for phase in obj.get('kill_chain_phases', [])
                    if phase.get('kill_chain_name') == 'mitre-attack'
                ]

                self.techniques[tech_id] = {
                    'id': tech_id,
                    'name': obj.get('name', ''),
                    'description': obj.get('description', '')[:200],
                    'tactics': tactics,
                    'primary_tactic': tactics[0] if tactics else '',
                    'tactic_order': min(
                        [self.TACTIC_ORDER.get(t, 99) for t in tactics],
                        default=99
                    ),
                    'is_subtechnique': '.' in tech_id,
                    'parent_technique': tech_id.split('.')[0] if '.' in tech_id else ''
                }

        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        with open(self.cache_path, 'w') as f:
            json.dump({
                'techniques': self.techniques,
                'groups': self.groups
            }, f, indent=2)

        print(f"Downloaded and cached {len(self.techniques)} techniques")

    def _load_minimal(self):
        """Minimal built-in set for offline use"""
        self.techniques = {
            'T1059.001': {'id': 'T1059.001', 'name': 'PowerShell',
                          'primary_tactic': 'execution', 'tactic_order': 4},
            'T1021.002': {'id': 'T1021.002', 'name': 'SMB/Windows Admin Shares',
                          'primary_tactic': 'lateral-movement', 'tactic_order': 10},
            'T1003.001': {'id': 'T1003.001', 'name': 'LSASS Memory',
                          'primary_tactic': 'credential-access', 'tactic_order': 8},
            'T1071.001': {'id': 'T1071.001', 'name': 'Web Protocols',
                          'primary_tactic': 'command-and-control', 'tactic_order': 12},
            'T1547.001': {'id': 'T1547.001', 'name': 'Registry Run Keys',
                          'primary_tactic': 'persistence', 'tactic_order': 5},
        }

    def get_technique(self, technique_id):
        return self.techniques.get(technique_id, {})

    def get_tactic_order(self, technique_id):
        tech = self.get_technique(technique_id)
        return tech.get('tactic_order', 99)

    def get_techniques_by_tactic(self, tactic):
        return {
            tid: tech for tid, tech in self.techniques.items()
            if tactic in tech.get('tactics', [])
        }

    def coverage_report(self, detected_techniques):
        """
        Given a set of detected technique IDs,
        report coverage per tactic.
        """
        report = {}
        for tactic in self.TACTIC_ORDER:
            all_in_tactic = self.get_techniques_by_tactic(tactic)
            detected_in_tactic = {
                t for t in detected_techniques
                if t in all_in_tactic
            }
            report[tactic] = {
                'total': len(all_in_tactic),
                'detected': len(detected_in_tactic),
                'coverage_pct': round(
                    len(detected_in_tactic) / max(len(all_in_tactic), 1) * 100, 1
                ),
                'gaps': list(set(all_in_tactic.keys()) - detected_in_tactic)
            }
        return report


if __name__ == '__main__':
    mapper = MitreMapper()

    print(f"\nTotal techniques loaded: {len(mapper.techniques)}")

    tech = mapper.get_technique('T1059.001')
    print(f"\nT1059.001 details:")
    print(f"  Name:    {tech.get('name')}")
    print(f"  Tactic:  {tech.get('primary_tactic')}")
    print(f"  Order:   {tech.get('tactic_order')}")

    detected = {'T1059.001', 'T1021.002', 'T1003.001'}
    report = mapper.coverage_report(detected)
    print(f"\nCoverage report (tactics with any coverage):")
    for tactic, data in report.items():
        if data['detected'] > 0:
            print(f"  {tactic}: {data['detected']}/{data['total']} "
                  f"({data['coverage_pct']}%)")
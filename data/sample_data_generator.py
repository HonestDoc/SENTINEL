# SENTINEL/data/sample_data_generator.py
# Runs on: HOST Windows 11
# Generates fake logs for testing ML models
# before real VM logs are flowing

import json
import random
import math
from datetime import datetime, timedelta

class SampleDataGenerator:
    """
    Generates realistic fake log events.
    Produces baseline (normal) and attack scenarios.
    Use for ML training before your VMs are generating logs.
    """

    NORMAL_PROCESSES = [
        'chrome.exe', 'outlook.exe', 'winword.exe', 'excel.exe',
        'teams.exe', 'explorer.exe', 'svchost.exe', 'lsass.exe',
        'csrss.exe', 'notepad.exe', 'mspaint.exe'
    ]

    SUSPICIOUS_PROCESSES = [
        'mimikatz.exe', 'psexec.exe', 'mshta.exe',
        'regsvr32.exe', 'certutil.exe', 'wmic.exe'
    ]

    INTERNAL_HOSTS = [
        'WIN-001', 'WIN-002', 'WIN-003', 'WIN-007', 'SRV-01', 'DC-01'
    ]
    INTERNAL_IPS = [
        '10.0.0.1', '10.0.0.2', '10.0.0.3',
        '10.0.0.7', '10.0.0.10', '10.0.0.20'
    ]

    def _random_internal_ip(self):
        return random.choice(self.INTERNAL_IPS)

    def _business_hour_timestamp(self, base_date):
        hour = random.randint(8, 18)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        return base_date.replace(hour=hour, minute=minute, second=second)

    def generate_baseline(self, host, days=30, events_per_day=200):
        """Generate normal baseline activity — training data for Isolation Forest"""
        events = []
        base = datetime.now() - timedelta(days=days)

        for day in range(days):
            current_day = base + timedelta(days=day)
            count = events_per_day // 4 if current_day.weekday() >= 5 \
                else events_per_day

            for _ in range(count):
                ts = self._business_hour_timestamp(current_day)
                process = random.choice(self.NORMAL_PROCESSES)
                events.append({
                    'timestamp': ts.isoformat(),
                    'host': host,
                    'event_type': 'process_create',
                    'process_name': process,
                    'cmdline': f'{process} --normal-arg',
                    'source_ip': self._random_internal_ip(),
                    'destination_ip': self._random_internal_ip(),
                    'label': 0  # benign
                })
        return events

    def generate_attack_scenario(self, host, attack_type='lateral_movement'):
        """Generate attack event sequence"""
        events = []
        base_time = datetime.now() - timedelta(hours=2)

        if attack_type == 'lateral_movement':
            sequence = [
                (0,  'net.exe',       'net view /domain',                        'T1018'),
                (2,  'powershell.exe','powershell -enc aGVsbG8=',               'T1059.001'),
                (5,  'mimikatz.exe',  'privilege::debug sekurlsa::logonpasswords','T1003.001'),
                (8,  'psexec.exe',    'psexec \\\\DC-01 cmd',                    'T1021.002'),
                (12, 'cmd.exe',       'whoami /all',                             'T1033'),
            ]
            for offset_min, process, cmdline, technique in sequence:
                ts = base_time + timedelta(minutes=offset_min)
                events.append({
                    'timestamp': ts.isoformat(),
                    'host': host,
                    'event_type': 'process_create',
                    'process_name': process,
                    'cmdline': cmdline,
                    'source_ip': self._random_internal_ip(),
                    'destination_ip': self._random_internal_ip(),
                    'mitre_technique': technique,
                    'label': 1
                })

        elif attack_type == 'c2_beaconing':
            for i in range(20):
                jitter = random.randint(-30, 30)
                offset_seconds = (i * 300) + jitter
                ts = base_time + timedelta(seconds=offset_seconds)
                events.append({
                    'timestamp': ts.isoformat(),
                    'host': host,
                    'event_type': 'network_connection',
                    'process_name': 'svchost.exe',
                    'cmdline': 'svchost.exe',
                    'destination_ip': '185.234.100.50',
                    'destination_port': 443,
                    'bytes_sent': random.randint(280, 340),
                    'mitre_technique': 'T1071.001',
                    'label': 1
                })

        return events

    def save(self, events, filepath):
        import os
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + '\n')
        print(f"Saved {len(events)} events to {filepath}")


if __name__ == '__main__':
    gen = SampleDataGenerator()

    print("Generating baseline data...")
    baseline = gen.generate_baseline('WIN-007', days=30, events_per_day=150)
    gen.save(baseline, 'data/raw/win007_baseline.jsonl')

    print("Generating lateral movement attack...")
    attack = gen.generate_attack_scenario('WIN-007', 'lateral_movement')
    gen.save(attack, 'data/raw/win007_lateral_movement.jsonl')

    print("Generating C2 beaconing...")
    c2 = gen.generate_attack_scenario('WIN-007', 'c2_beaconing')
    gen.save(c2, 'data/raw/win007_c2_beaconing.jsonl')

    print(f"\nGenerated:")
    print(f"  Baseline:  {len(baseline)} events")
    print(f"  Attack:    {len(attack)} events")
    print(f"  C2:        {len(c2)} events")
    print("\nRun log_parser.py on these files to verify normalization.")
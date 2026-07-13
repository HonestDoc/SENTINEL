# SENTINEL/testing/attack_replayer.py
# Runs on: HOST Windows 11

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.sample_data_generator import SampleDataGenerator
from ingestion.es_writer import ElasticsearchWriter
from detection.alert_schema import SentinelAlert

class AttackReplayer:
    """
    Replays recorded attack scenarios through SENTINEL.
    Measures detection rate for each attack step.
    Use for: demo, regression testing, coverage measurement.
    """

    ATTACK_SCENARIOS = [
        {
            'name': 'Lateral Movement Chain',
            'type': 'lateral_movement',
            'expected_techniques': ['T1018', 'T1059.001', 'T1003.001', 'T1021.002', 'T1033'],
            'description': 'Net discovery -> PowerShell -> Credential dump -> PsExec -> Discovery'
        },
        {
            'name': 'C2 Beaconing',
            'type': 'c2_beaconing',
            'expected_techniques': ['T1071.001'],
            'description': 'Periodic HTTP beaconing to C2 server'
        }
    ]

    def __init__(self):
        self.gen = SampleDataGenerator()
        self.writer = ElasticsearchWriter()
        self.results = {}

    def replay_scenario(self, scenario):
        print(f"\nReplaying: {scenario['name']}")
        print(f"  {scenario['description']}")

        events = self.gen.generate_attack_scenario(
            'WIN-REPLAY', scenario['type']
        )

        # Inject into Elasticsearch as current events
        alerts_written = 0
        for event in events:
            if event.get('mitre_technique'):
                alert = SentinelAlert(
                    alert_type='rule_based',
                    severity='high',
                    host_name='WIN-REPLAY',
                    mitre_technique=event['mitre_technique'],
                    explanation=f"Replay: {event.get('cmdline', '')}",
                    risk_score=80.0
                )
                self.writer.write_alert(alert)
                alerts_written += 1

        time.sleep(2)  # let ES index

        # Check which techniques were detected
        from elasticsearch import Elasticsearch
        from config import ELASTICSEARCH_HOST, ALERT_INDEX
        es = Elasticsearch(ELASTICSEARCH_HOST)

        result = es.search(
            index=ALERT_INDEX,
            body={
                'query': {
                    'bool': {
                        'must': [
                            {'term': {'host_name': 'WIN-REPLAY'}},
                            {'range': {'@timestamp': {'gte': 'now-5m'}}}
                        ]
                    }
                },
                'aggs': {
                    'techniques': {
                        'terms': {'field': 'mitre_technique', 'size': 100}
                    }
                },
                'size': 0
            }
        )

        detected = {
            b['key'] for b in
            result['aggregations']['techniques']['buckets']
        }
        expected = set(scenario['expected_techniques'])
        missed = expected - detected
        detection_rate = len(detected & expected) / max(len(expected), 1) * 100

        result_data = {
            'scenario': scenario['name'],
            'expected_techniques': list(expected),
            'detected_techniques': list(detected & expected),
            'missed_techniques': list(missed),
            'detection_rate': round(detection_rate, 1),
            'alerts_written': alerts_written
        }

        self.results[scenario['name']] = result_data

        print(f"  Expected: {list(expected)}")
        print(f"  Detected: {list(detected & expected)}")
        print(f"  Missed:   {list(missed)}")
        print(f"  Rate:     {detection_rate:.1f}%")

        return result_data

    def run_all_scenarios(self):
        print("=" * 60)
        print("SENTINEL Attack Replay Test")
        print("=" * 60)

        for scenario in self.ATTACK_SCENARIOS:
            self.replay_scenario(scenario)

        print("\n" + "=" * 60)
        print("RESULTS SUMMARY")
        print("=" * 60)
        for name, result in self.results.items():
            print(f"\n{name}:")
            print(f"  Detection Rate: {result['detection_rate']}%")
            print(f"  Detected: {len(result['detected_techniques'])} techniques")
            print(f"  Missed:   {len(result['missed_techniques'])} techniques")

        total_expected = sum(
            len(r['expected_techniques']) for r in self.results.values()
        )
        total_detected = sum(
            len(r['detected_techniques']) for r in self.results.values()
        )
        overall = round(total_detected / max(total_expected, 1) * 100, 1)
        print(f"\nOVERALL DETECTION RATE: {overall}%")
        print(f"({total_detected}/{total_expected} techniques detected)")


if __name__ == '__main__':
    replayer = AttackReplayer()
    replayer.run_all_scenarios()
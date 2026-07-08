# SENTINEL/detection/sigma_engine.py
# Runs on: HOST Windows 11
# Executes compiled Sigma rules against Elasticsearch

from elasticsearch import Elasticsearch
import json
import datetime
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ELASTICSEARCH_HOST, WINDOWS_LOG_INDEX, ALERT_INDEX
from detection.alert_schema import SentinelAlert
from ingestion.es_writer import ElasticsearchWriter

class SigmaEngine:
    """
    Runs compiled Sigma rules against Elasticsearch indices.
    Creates SentinelAlert for every rule match.
    Runs every 5 minutes (called by scheduler).
    """

    def __init__(self, rules_file='detection/compiled_rules.json'):
        self.es = Elasticsearch(ELASTICSEARCH_HOST)
        self.writer = ElasticsearchWriter()
        self.rules = self._load_rules(rules_file)
        print(f"Sigma Engine loaded {len(self.rules)} rules")

    def _load_rules(self, rules_file):
        try:
            with open(rules_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Rules file not found: {rules_file}")
            print("Run rule_compiler.py first")
            return {}

    def run_rule(self, rule_id, rule):
        """Execute one rule, return list of alerts"""
        alerts = []

        query = rule.get('query', {})
        if not query:
            return alerts

        # Add time window: only last 5 minutes
        if 'query' not in query:
            query = {'query': query}

        query.setdefault('query', {})
        original_query = query.get('query', {})

        time_bounded_query = {
            'query': {
                'bool': {
                    'must': [original_query],
                    'filter': [{
                        'range': {'@timestamp': {'gte': 'now-5m'}}
                    }]
                }
            },
            'size': 50
        }

        try:
            results = self.es.search(
                index=f"{WINDOWS_LOG_INDEX}-*",
                body=time_bounded_query
            )

            for hit in results.get('hits', {}).get('hits', []):
                alert = SentinelAlert.from_sigma_hit(rule, hit)
                alerts.append(alert)

        except Exception as e:
            print(f"Rule {rule_id} error: {e}")

        return alerts

    def run_all_rules(self):
        """Run all rules, write all alerts"""
        total_alerts = 0
        rules_fired = 0

        for rule_id, rule in self.rules.items():
            alerts = self.run_rule(rule_id, rule)
            if alerts:
                rules_fired += 1
                self.writer.write_alerts_bulk(alerts)
                total_alerts += len(alerts)
                print(f"Rule fired: {rule.get('title')} "
                      f"— {len(alerts)} alerts")

        print(f"\nSigma scan complete: "
              f"{rules_fired}/{len(self.rules)} rules fired, "
              f"{total_alerts} alerts created")
        return total_alerts


if __name__ == '__main__':
    engine = SigmaEngine()
    engine.run_all_rules()
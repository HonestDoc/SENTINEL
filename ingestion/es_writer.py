# SENTINEL/ingestion/es_writer.py
# Runs on: HOST Windows 11
# Connects to: Elasticsearch on HOST :9200

from elasticsearch import Elasticsearch, helpers
from datetime import datetime
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ELASTICSEARCH_HOST, ALERT_INDEX

class ElasticsearchWriter:
    """
    All Elasticsearch writes go through this class.
    Every other module imports this instead of
    talking to ES directly.
    """

    def __init__(self, host=ELASTICSEARCH_HOST):
        self.es = Elasticsearch(host)
        self._verify_connection()
        self._create_indices()

    def _verify_connection(self):
        if not self.es.ping():
            raise ConnectionError(
                f"Cannot connect to Elasticsearch at {ELASTICSEARCH_HOST}.\n"
                f"Make sure the service is running:\n"
                f"  elasticsearch-service.bat start"
            )
        info = self.es.info()
        print(f"Connected to Elasticsearch "
              f"v{info['version']['number']} at {ELASTICSEARCH_HOST}")

    def _create_indices(self):
        alert_mapping = {
            'mappings': {
                'properties': {
                    '@timestamp':      {'type': 'date'},
                    'risk_score':      {'type': 'float'},
                    'anomaly_score':   {'type': 'float'},
                    'confidence':      {'type': 'float'},
                    'host_name':       {'type': 'keyword'},
                    'user_name':       {'type': 'keyword'},
                    'source_ip':       {'type': 'ip'},
                    'destination_ip':  {'type': 'ip'},
                    'mitre_technique': {'type': 'keyword'},
                    'mitre_tactic':    {'type': 'keyword'},
                    'alert_type':      {'type': 'keyword'},
                    'severity':        {'type': 'keyword'},
                    'false_positive':  {'type': 'boolean'},
                    'acknowledged':    {'type': 'boolean'},
                    'explanation':     {'type': 'text'},
                }
            }
        }
        if not self.es.indices.exists(index=ALERT_INDEX):
            self.es.indices.create(index=ALERT_INDEX, body=alert_mapping)
            print(f"Created index: {ALERT_INDEX}")
        else:
            print(f"Index exists: {ALERT_INDEX}")

    def write_alert(self, alert):
        doc = alert.to_es_doc() if hasattr(alert, 'to_es_doc') else alert
        result = self.es.index(index=ALERT_INDEX, document=doc)
        return result['_id']

    def write_alerts_bulk(self, alerts):
        actions = [
            {
                '_index': ALERT_INDEX,
                '_source': (a.to_es_doc() if hasattr(a, 'to_es_doc') else a)
            }
            for a in alerts
        ]
        success, errors = helpers.bulk(self.es, actions)
        return success, errors

    def query_alerts(self, host_name=None, minutes_back=60,
                      alert_type=None):
        must_clauses = [
            {'range': {'@timestamp': {'gte': f'now-{minutes_back}m'}}}
        ]
        if host_name:
            must_clauses.append({'term': {'host_name': host_name}})
        if alert_type:
            must_clauses.append({'term': {'alert_type': alert_type}})

        result = self.es.search(
            index=ALERT_INDEX,
            body={
                'query': {'bool': {'must': must_clauses}},
                'sort': [{'@timestamp': {'order': 'desc'}}],
                'size': 500
            }
        )
        return [hit['_source'] for hit in result['hits']['hits']]

    def mark_false_positive(self, alert_id, analyst_notes=''):
        self.es.update(
            index=ALERT_INDEX,
            id=alert_id,
            body={
                'doc': {
                    'false_positive': True,
                    'analyst_notes': analyst_notes,
                    'reviewed_at': datetime.utcnow().isoformat()
                }
            }
        )

    def get_entity_risk_history(self, host_name, days=7):
        result = self.es.search(
            index=ALERT_INDEX,
            body={
                'query': {
                    'bool': {
                        'must': [
                            {'term': {'host_name': host_name}},
                            {'range': {'@timestamp': {'gte': f'now-{days}d'}}}
                        ]
                    }
                },
                'aggs': {
                    'risk_over_time': {
                        'date_histogram': {
                            'field': '@timestamp',
                            'fixed_interval': '1h'
                        },
                        'aggs': {
                            'max_risk': {'max': {'field': 'risk_score'}}
                        }
                    }
                },
                'size': 0
            }
        )
        buckets = result['aggregations']['risk_over_time']['buckets']
        return [
            {'time': b['key_as_string'],
             'risk_score': b['max_risk']['value'] or 0}
            for b in buckets
        ]


if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    from detection.alert_schema import SentinelAlert

    writer = ElasticsearchWriter()

    test_alert = SentinelAlert(
        alert_type='rule_based',
        severity='high',
        confidence=1.0,
        host_name='WIN-007',
        mitre_technique='T1059.001',
        mitre_tactic='Execution',
        explanation='Test alert — Elasticsearch writer working correctly',
        risk_score=75.0
    )

    alert_id = writer.write_alert(test_alert)
    print(f"Written alert ID: {alert_id}")

    alerts = writer.query_alerts(host_name='WIN-007', minutes_back=5)
    print(f"Found {len(alerts)} recent alerts for WIN-007")
    if alerts:
        print(f"First alert explanation: {alerts[0]['explanation']}")
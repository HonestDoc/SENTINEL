# SENTINEL/api/app.py
# Runs on: HOST Windows 11
# Serves data to dashboard and D3.js graph

from flask import Flask, jsonify, request
from flask_cors import CORS
from elasticsearch import Elasticsearch
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ELASTICSEARCH_HOST, ALERT_INDEX
from graph.communication_graph import HostCommunicationGraph
from ml.risk_scorer import RiskScorer
from ml.explainer import AlertExplainer
from ml.ttp_predictor import TTPPredictor

app = Flask(__name__)
CORS(app)

es = Elasticsearch(ELASTICSEARCH_HOST)
graph = HostCommunicationGraph()
risk_scorer = RiskScorer()
risk_scorer.train()
explainer = AlertExplainer(risk_scorer)
ttp_predictor = TTPPredictor()

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'elasticsearch': es.ping()})

@app.route('/api/graph')
def get_graph():
    """Return host communication graph for D3.js"""
    return jsonify(graph.to_d3_json())

@app.route('/api/alerts')
def get_alerts():
    """Return recent alerts"""
    minutes = int(request.args.get('minutes', 60))
    host = request.args.get('host', None)

    must_clauses = [
        {'range': {'@timestamp': {'gte': f'now-{minutes}m'}}}
    ]
    if host:
        must_clauses.append({'term': {'host_name': host}})

    result = es.search(
        index=ALERT_INDEX,
        body={
            'query': {'bool': {'must': must_clauses}},
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'size': 200
        }
    )
    alerts = [hit['_source'] for hit in result['hits']['hits']]
    return jsonify(alerts)

@app.route('/api/risk-scores')
def get_risk_scores():
    """Return risk scores for all entities"""
    result = es.search(
        index=ALERT_INDEX,
        body={
            'query': {'range': {'@timestamp': {'gte': 'now-24h'}}},
            'aggs': {
                'by_host': {
                    'terms': {'field': 'host_name', 'size': 100},
                    'aggs': {
                        'max_risk': {'max': {'field': 'risk_score'}},
                        'alert_count': {'value_count': {'field': 'alert_id'}}
                    }
                }
            },
            'size': 0
        }
    )

    scores = []
    for bucket in result['aggregations']['by_host']['buckets']:
        scores.append({
            'host': bucket['key'],
            'risk_score': bucket['max_risk']['value'] or 0,
            'alert_count': bucket['alert_count']['value']
        })

    return jsonify(sorted(scores, key=lambda x: -x['risk_score']))

@app.route('/api/attack-paths/<host_id>')
def get_attack_paths(host_id):
    paths = graph.find_attack_paths(host_id)
    return jsonify(paths)

@app.route('/api/predictions/<host_name>')
def get_predictions(host_name):
    """Return TTP predictions for a host based on recent alerts"""
    result = es.search(
        index=ALERT_INDEX,
        body={
            'query': {
                'bool': {
                    'must': [
                        {'term': {'host_name': host_name}},
                        {'range': {'@timestamp': {'gte': 'now-2h'}}},
                        {'exists': {'field': 'mitre_technique'}}
                    ]
                }
            },
            'sort': [{'@timestamp': {'order': 'asc'}}],
            'size': 20
        }
    )

    observed_ttps = [
        hit['_source']['mitre_technique']
        for hit in result['hits']['hits']
        if hit['_source'].get('mitre_technique')
    ]

    if not observed_ttps:
        return jsonify({'host': host_name, 'observed': [], 'predictions': []})

    try:
        predictions = ttp_predictor.predict(observed_ttps, top_k=3)
        return jsonify({
            'host': host_name,
            'observed': observed_ttps,
            'predictions': [
                {'technique': t, 'probability': round(p * 100, 1)}
                for t, p in predictions
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/explain/<host_name>')
def explain_entity(host_name):
    """Return SHAP explanation for an entity's risk score"""
    result = es.search(
        index=ALERT_INDEX,
        body={
            'query': {
                'bool': {
                    'must': [
                        {'term': {'host_name': host_name}},
                        {'range': {'@timestamp': {'gte': 'now-24h'}}}
                    ]
                }
            },
            'aggs': {
                'unique_ttps': {'cardinality': {'field': 'mitre_technique'}},
                'unique_tactics': {'cardinality': {'field': 'mitre_tactic'}},
                'max_anomaly': {'min': {'field': 'anomaly_score'}},
                'alert_count': {'value_count': {'field': 'alert_id'}}
            },
            'size': 0
        }
    )

    aggs = result['aggregations']
    entity_data = {
        'sigma_alerts': aggs['alert_count']['value'],
        'anomaly_score': aggs['max_anomaly']['value'] or 0,
        'unique_ttps': aggs['unique_ttps']['value'],
        'tactic_categories': aggs['unique_tactics']['value'],
        'ti_hit': False, 'after_hours': False,
        'new_destinations': 0, 'peer_deviation': 1.0,
        'chain_length': aggs['unique_ttps']['value'],
        'beaconing_confidence': 0.0,
        'dns_tunnel_score': 0.0, 'lateral_movement_score': 0.0,
        'hours_since_first_alert': 1
    }

    explanation = explainer.explain(entity_data)
    return jsonify(explanation)

@app.route('/api/alerts/<alert_id>/feedback', methods=['POST'])
def submit_feedback(alert_id):
    """Analyst false-positive feedback"""
    data = request.json
    is_fp = data.get('is_false_positive', False)
    notes = data.get('notes', '')

    es.update(
        index=ALERT_INDEX,
        id=alert_id,
        body={
            'doc': {
                'false_positive': is_fp,
                'analyst_notes': notes,
                'reviewed': True
            }
        }
    )
    return jsonify({'status': 'updated', 'alert_id': alert_id})

@app.route('/api/coverage')
def get_coverage():
    """ATT&CK detection coverage report"""
    from ml.mitre_mapper import MitreMapper
    mapper = MitreMapper()

    result = es.search(
        index=ALERT_INDEX,
        body={
            'aggs': {
                'techniques': {
                    'terms': {'field': 'mitre_technique', 'size': 500}
                }
            },
            'size': 0
        }
    )

    detected = {
        b['key']
        for b in result['aggregations']['techniques']['buckets']
        if b['key']
    }

    report = mapper.coverage_report(detected)
    return jsonify({
        'detected_techniques': list(detected),
        'coverage_by_tactic': report
    })


if __name__ == '__main__':
    print("Starting SENTINEL API on http://localhost:5000")
    print("Open dashboard/graph.html in browser")
    app.run(host='0.0.0.0', port=5000, debug=False)
# SENTINEL/detection/alert_schema.py
# Runs on: HOST Windows 11

import uuid
import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any

@dataclass
class SentinelAlert:
    """
    Single canonical alert structure for all of SENTINEL.
    Every detector produces this. Every consumer reads this.
    One schema = everything is compatible.
    """
    # Identity
    alert_id:             str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:            str = field(
        default_factory=lambda: datetime.datetime.utcnow().isoformat()
    )

    # Classification
    alert_type:           str = ''    # rule_based | behavioral | graph | ml
    severity:             str = ''    # low | medium | high | critical
    confidence:           float = 0.0

    # Entity
    host_name:            str = ''
    user_name:            str = ''
    source_ip:            str = ''
    destination_ip:       str = ''
    destination_port:     int = 0

    # MITRE ATT&CK
    mitre_tactic:         str = ''
    mitre_technique:      str = ''
    mitre_technique_name: str = ''
    kill_chain_phase:     str = ''

    # Detection detail
    detection_source:     str = ''
    explanation:          str = ''
    raw_event:            Dict[str, Any] = field(default_factory=dict)

    # ML outputs
    risk_score:           float = 0.0
    anomaly_score:        float = 0.0
    shap_contributions:   List[Dict] = field(default_factory=list)

    # Vulnerability context
    cve_context:          List[Dict] = field(default_factory=list)

    # Analyst workflow
    acknowledged:         bool = False
    false_positive:       bool = False
    analyst_notes:        str = ''

    def to_dict(self):
        return asdict(self)

    def to_es_doc(self):
        """Convert to Elasticsearch document"""
        doc = self.to_dict()
        doc['@timestamp'] = doc.pop('timestamp')
        return doc

    @classmethod
    def from_sigma_hit(cls, rule_meta, es_hit):
        source = es_hit.get('_source', {})
        mitre_technique = ''
        mitre_tactic = ''

        for tag in rule_meta.get('tags', []):
            if tag.startswith('attack.t') and '.' in tag:
                mitre_technique = tag.replace('attack.t', 'T').upper()
            elif tag.startswith('attack.') and not tag.startswith('attack.t'):
                mitre_tactic = (
                    tag.replace('attack.', '').replace('_', ' ').title()
                )

        return cls(
            alert_type='rule_based',
            severity=rule_meta.get('level', 'medium'),
            confidence=1.0,
            host_name=source.get('host', {}).get('name', ''),
            user_name=source.get('user', {}).get('name', ''),
            source_ip=source.get('source', {}).get('ip', ''),
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            detection_source=rule_meta.get('id', ''),
            explanation=f"Sigma rule matched: {rule_meta.get('title', '')}",
            raw_event=source
        )

    @classmethod
    def from_behavioral_anomaly(cls, entity_id, anomaly_score,
                                 shap_contributions, feature_values):
        severity = (
            'critical' if anomaly_score < -0.7 else
            'high'     if anomaly_score < -0.5 else
            'medium'   if anomaly_score < -0.3 else
            'low'
        )
        top = sorted(
            shap_contributions,
            key=lambda x: abs(x['contribution']),
            reverse=True
        )[:3]
        parts = [
            f"{c['feature']} ({'+' if c['contribution']>0 else ''}"
            f"{c['contribution']:.1f})"
            for c in top
        ]
        explanation = (
            f"Behavioral anomaly detected. "
            f"Top factors: {', '.join(parts)}."
        )
        return cls(
            alert_type='behavioral',
            severity=severity,
            confidence=min(1.0, abs(anomaly_score)),
            host_name=entity_id,
            anomaly_score=anomaly_score,
            shap_contributions=shap_contributions,
            explanation=explanation,
            detection_source='isolation_forest_v1'
        )


if __name__ == '__main__':
    # Test rule-based alert
    fake_rule = {
        'id': 'rule-001',
        'title': 'PowerShell Encoded Command',
        'level': 'high',
        'tags': ['attack.execution', 'attack.t1059.001']
    }
    fake_hit = {
        '_source': {
            'host': {'name': 'WIN-007'},
            'user': {'name': 'jsmith'},
            'process': {'command_line': 'powershell -enc aGVsbG8='}
        }
    }
    alert = SentinelAlert.from_sigma_hit(fake_rule, fake_hit)
    print(f"Rule alert — Host: {alert.host_name}, "
          f"Technique: {alert.mitre_technique}, "
          f"Severity: {alert.severity}")

    # Test behavioral alert
    beh = SentinelAlert.from_behavioral_anomaly(
        entity_id='WIN-003',
        anomaly_score=-0.65,
        shap_contributions=[
            {'feature': 'Unusual command line', 'contribution': 2.3},
            {'feature': 'After-hours activity', 'contribution': 1.1},
        ],
        feature_values={}
    )
    print(f"Behavioral alert — {beh.explanation}")
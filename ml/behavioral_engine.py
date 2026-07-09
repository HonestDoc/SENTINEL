# SENTINEL/ml/behavioral_engine.py
# Runs on: HOST Windows 11
# Orchestrates ALL behavioral detectors

from elasticsearch import Elasticsearch
import pandas as pd
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ELASTICSEARCH_HOST, ALERT_INDEX, ZEEK_LOG_INDEX
from ml.beaconing_detector import BeaconingDetector
from ml.dns_detector import DNSTunnelingDetector
from ml.lateral_movement_detector import LateralMovementDetector, ReconDetector
from ml.entity_profile_manager import EntityProfileManager
from ml.risk_scorer import RiskScorer
from ml.explainer import AlertExplainer
from detection.chain_reconstructor import AttackChainReconstructor
from detection.alert_schema import SentinelAlert
from ingestion.es_writer import ElasticsearchWriter

class BehavioralAnalyticsEngine:
    """
    Master orchestrator for all behavioral detection.
    Run every 5 minutes via scheduler.
    """

    def __init__(self):
        self.es = Elasticsearch(ELASTICSEARCH_HOST)
        self.writer = ElasticsearchWriter()

        self.beaconing_detector = BeaconingDetector()
        self.dns_detector = DNSTunnelingDetector()
        self.lateral_detector = LateralMovementDetector()
        self.recon_detector = ReconDetector()
        self.profile_manager = EntityProfileManager()

        self.risk_scorer = RiskScorer()
        self.risk_scorer.train()

        self.explainer = AlertExplainer(self.risk_scorer)
        self.chain_reconstructor = AttackChainReconstructor()

        print("Behavioral Analytics Engine initialized")

    def _load_zeek_connections(self, hours=1):
        try:
            result = self.es.search(
                index=f"{ZEEK_LOG_INDEX}-*",
                body={
                    'query': {'range': {'@timestamp': {'gte': f'now-{hours}h'}}},
                    'size': 5000
                }
            )
            records = [hit['_source'] for hit in result['hits']['hits']]
            return pd.DataFrame(records) if records else pd.DataFrame()
        except Exception as e:
            print(f"Could not load Zeek connections: {e}")
            return pd.DataFrame()

    def _load_zeek_dns(self, hours=1):
        try:
            result = self.es.search(
                index=f"{ZEEK_LOG_INDEX}-*",
                body={
                    'query': {
                        'bool': {
                            'must': [
                                {'range': {'@timestamp': {'gte': f'now-{hours}h'}}},
                                {'exists': {'field': 'query'}}
                            ]
                        }
                    },
                    'size': 5000
                }
            )
            records = [hit['_source'] for hit in result['hits']['hits']]
            return pd.DataFrame(records) if records else pd.DataFrame()
        except Exception as e:
            print(f"Could not load Zeek DNS: {e}")
            return pd.DataFrame()

    def _load_recent_alerts(self, minutes=60):
        alerts = self.writer.query_alerts(minutes_back=minutes)
        return pd.DataFrame(alerts) if alerts else pd.DataFrame()

    def run(self):
        """Run full behavioral analysis cycle"""
        print("\n" + "="*50)
        print(f"Behavioral Engine Cycle")
        print("="*50)

        all_alerts = []

        # 1. Beaconing detection
        print("\n[1] C2 Beaconing Detection...")
        zeek_conns = self._load_zeek_connections()
        if not zeek_conns.empty:
            beaconing_alerts = self.beaconing_detector.scan_zeek_connections(
                zeek_conns
            )
            all_alerts.extend(beaconing_alerts)
            print(f"    Found: {len(beaconing_alerts)} beaconing alerts")
        else:
            print("    No Zeek connection data available")

        # 2. DNS tunneling
        print("\n[2] DNS Tunneling Detection...")
        zeek_dns = self._load_zeek_dns()
        if not zeek_dns.empty:
            dns_alerts = self.dns_detector.detect_tunneling(zeek_dns)
            all_alerts.extend(dns_alerts)
            print(f"    Found: {len(dns_alerts)} DNS tunnel alerts")
        else:
            print("    No DNS data available")

        # 3. Lateral movement
        print("\n[3] Lateral Movement Detection...")
        if not zeek_conns.empty:
            lateral_alerts = self.lateral_detector.detect_peer_expansion(zeek_conns)
            recon_alerts = self.recon_detector.detect_port_scan(zeek_conns)
            all_alerts.extend(lateral_alerts)
            all_alerts.extend(recon_alerts)
            print(f"    Found: {len(lateral_alerts)} lateral, "
                  f"{len(recon_alerts)} recon alerts")

        # 4. Write behavioral alerts to Elasticsearch
        print(f"\n[4] Writing {len(all_alerts)} behavioral alerts...")
        for alert_data in all_alerts:
            alert = SentinelAlert(
                alert_type='behavioral',
                severity=self._score_to_severity(
                    alert_data.get('confidence', 0.5)
                ),
                confidence=float(alert_data.get('confidence', 0.5)),
                host_name=alert_data.get('source_ip', ''),
                source_ip=alert_data.get('source_ip', ''),
                destination_ip=alert_data.get('destination_ip', ''),
                mitre_technique=alert_data.get('mitre_technique', ''),
                detection_source=alert_data.get('alert_type', ''),
                explanation=alert_data.get('explanation', ''),
            )
            self.writer.write_alert(alert)

        # 5. Reconstruct attack chains
        print("\n[5] Reconstructing attack chains...")
        recent_alerts_df = self._load_recent_alerts()
        if not recent_alerts_df.empty:
            chains = self.chain_reconstructor.reconstruct_chains(recent_alerts_df)
            print(f"    Reconstructed: {len(chains)} chains")

            for chain in chains:
                if chain['chain_length'] >= 2:
                    entity_data = {
                        'sigma_alerts': len(chain['ttp_sequence']),
                        'anomaly_score': -0.5,
                        'unique_ttps': chain['chain_length'],
                        'tactic_categories': chain['tactic_breadth'],
                        'ti_hit': False,
                        'after_hours': False,
                        'new_destinations': 0,
                        'peer_deviation': 1.0,
                        'chain_length': chain['chain_length'],
                        'beaconing_confidence': 0.0,
                        'dns_tunnel_score': 0.0,
                        'lateral_movement_score': 0.3,
                        'hours_since_first_alert': 1
                    }
                    risk = self.risk_scorer.score(entity_data)
                    explanation = self.explainer.explain(entity_data)

                    print(f"    Chain on {chain['host']}: "
                          f"{chain['ttp_sequence']} "
                          f"| Risk: {risk} | {chain['chain_severity'].upper()}")

        print("\nBehavioral engine cycle complete")

    def _score_to_severity(self, confidence):
        if confidence >= 0.8: return 'critical'
        if confidence >= 0.6: return 'high'
        if confidence >= 0.4: return 'medium'
        return 'low'


if __name__ == '__main__':
    engine = BehavioralAnalyticsEngine()
    engine.run()
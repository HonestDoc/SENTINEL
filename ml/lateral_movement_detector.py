# SENTINEL/ml/lateral_movement_detector.py
# Runs on: HOST Windows 11

from elasticsearch import Elasticsearch
import pandas as pd
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ELASTICSEARCH_HOST, WINDOWS_LOG_INDEX

class LateralMovementDetector:
    def __init__(self):
        self.es = Elasticsearch(ELASTICSEARCH_HOST)

    def get_historical_peers(self, host_ip, days=30):
        try:
            result = self.es.search(
                index=f"{WINDOWS_LOG_INDEX}-*",
                body={
                    'query': {
                        'bool': {
                            'must': [
                                {'term': {'source.ip': host_ip}},
                                {'range': {'@timestamp': {'gte': f'now-{days}d'}}}
                            ]
                        }
                    },
                    'aggs': {
                        'dest_ips': {'terms': {'field': 'destination.ip', 'size': 1000}}
                    },
                    'size': 0
                }
            )
            return set(
                b['key'] for b in
                result['aggregations']['dest_ips']['buckets']
            )
        except Exception:
            return set()

    def detect_peer_expansion(self, current_connections_df):
        alerts = []

        if current_connections_df.empty:
            return alerts

        src_col = 'source.ip' if 'source.ip' in current_connections_df.columns else 'id.orig_h'
        dst_col = 'destination.ip' if 'destination.ip' in current_connections_df.columns else 'id.resp_h'

        for src_ip, group in current_connections_df.groupby(src_col):
            # Skip external IPs
            if not any(str(src_ip).startswith(prefix)
                       for prefix in ['10.', '192.168.', '172.']):
                continue

            current_peers = set(group[dst_col].unique())
            historical_peers = self.get_historical_peers(src_ip)

            new_peers = current_peers - historical_peers
            expansion_ratio = len(new_peers) / (len(historical_peers) + 1)

            if len(new_peers) >= 3 and expansion_ratio > 0.5:
                alerts.append({
                    'source_ip': src_ip,
                    'new_peer_count': len(new_peers),
                    'historical_peer_count': len(historical_peers),
                    'expansion_ratio': round(expansion_ratio, 3),
                    'new_peers': list(new_peers)[:10],
                    'alert_type': 'lateral_movement_peer_expansion',
                    'mitre_technique': 'T1021',
                    'confidence': min(1.0, expansion_ratio),
                    'explanation': (
                        f"{src_ip} contacted {len(new_peers)} new internal hosts "
                        f"(historical baseline: {len(historical_peers)} peers). "
                        f"Expansion ratio: {expansion_ratio:.1%}. "
                        f"New peers: {', '.join(list(new_peers)[:3])}..."
                    )
                })

        return alerts


class ReconDetector:
    """Detects network reconnaissance (port scanning, host discovery)"""

    def __init__(self, port_threshold=50, host_threshold=20):
        self.port_threshold = port_threshold
        self.host_threshold = host_threshold

    def detect_port_scan(self, conn_df, window_minutes=5):
        """Detect hosts scanning many ports on few targets"""
        alerts = []

        src_col = 'source.ip' if 'source.ip' in conn_df.columns else 'id.orig_h'
        dst_col = 'destination.ip' if 'destination.ip' in conn_df.columns else 'id.resp_h'
        port_col = ('destination.port' if 'destination.port' in conn_df.columns
                    else 'id.resp_p')

        for src_ip, group in conn_df.groupby(src_col):
            unique_ports = group[port_col].nunique()
            unique_hosts = group[dst_col].nunique()

            failed_ratio = 0.0
            if 'conn_state' in group.columns:
                failed = group['conn_state'].isin(['REJ', 'S0', 'RSTOS0']).sum()
                failed_ratio = failed / len(group)

            # Port scan: many ports, few hosts, high failure rate
            if (unique_ports > self.port_threshold and
                    failed_ratio > 0.5):
                alerts.append({
                    'source_ip': src_ip,
                    'unique_ports_scanned': int(unique_ports),
                    'unique_hosts': int(unique_hosts),
                    'failed_connection_ratio': round(failed_ratio, 3),
                    'alert_type': 'port_scan',
                    'mitre_technique': 'T1046',
                    'confidence': min(1.0, unique_ports / 200),
                    'explanation': (
                        f"{src_ip} scanned {unique_ports} unique ports "
                        f"across {unique_hosts} hosts. "
                        f"Failed connection ratio: {failed_ratio:.1%}"
                    )
                })

            # Host discovery: few ports, many hosts
            elif (unique_hosts > self.host_threshold and unique_ports <= 3):
                alerts.append({
                    'source_ip': src_ip,
                    'unique_hosts_discovered': int(unique_hosts),
                    'unique_ports': int(unique_ports),
                    'alert_type': 'host_discovery',
                    'mitre_technique': 'T1018',
                    'confidence': min(1.0, unique_hosts / 50),
                    'explanation': (
                        f"{src_ip} contacted {unique_hosts} unique hosts "
                        f"on only {unique_ports} ports — host discovery pattern."
                    )
                })

        return alerts


if __name__ == '__main__':
    # Test with synthetic data
    import pandas as pd
    import random

    print("Testing lateral movement detector...")
    lateral_detector = LateralMovementDetector()

    # Simulate current connections with many new peers
    conns = pd.DataFrame([
        {'source.ip': '10.0.0.7', 'destination.ip': f'10.0.0.{i}'}
        for i in range(2, 20)
    ])
    alerts = lateral_detector.detect_peer_expansion(conns)
    print(f"Lateral movement alerts: {len(alerts)}")
    if alerts:
        print(f"  {alerts[0]['explanation']}")

    print("\nTesting recon detector...")
    recon_detector = ReconDetector(port_threshold=10, host_threshold=5)

    # Simulate port scan
    scan_conns = pd.DataFrame([
        {
            'source.ip': '10.0.0.1',
            'destination.ip': '10.0.0.5',
            'destination.port': port,
            'conn_state': random.choice(['REJ', 'REJ', 'S0', 'SF'])
        }
        for port in range(1, 60)
    ])

    recon_alerts = recon_detector.detect_port_scan(scan_conns)
    print(f"Recon alerts: {len(recon_alerts)}")
    if recon_alerts:
        print(f"  {recon_alerts[0]['explanation']}")
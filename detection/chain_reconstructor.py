# SENTINEL/detection/chain_reconstructor.py
# Runs on: HOST Windows 11

import networkx as nx
import pandas as pd
from datetime import datetime, timedelta
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TACTIC_ORDER = {
    'initial-access': 1, 'execution': 2, 'persistence': 3,
    'privilege-escalation': 4, 'defense-evasion': 5,
    'credential-access': 6, 'discovery': 7, 'lateral-movement': 8,
    'collection': 9, 'command-and-control': 10,
    'exfiltration': 11, 'impact': 12
}

class AttackChainReconstructor:
    """
    Groups related alerts into attack chains.
    Builds a directed graph per host showing TTP progression.
    Scores chains by advancement and breadth.
    """

    def __init__(self, time_window_minutes=120):
        self.time_window = time_window_minutes

    def reconstruct_chains(self, alerts_df):
        """
        alerts_df: DataFrame of SentinelAlert records from Elasticsearch.
        Returns list of chain dicts with networkx graphs.
        """
        chains = []

        if alerts_df.empty:
            return chains

        cutoff = datetime.utcnow() - timedelta(minutes=self.time_window)
        ts = pd.to_datetime(
            alerts_df.get('@timestamp', alerts_df.get('timestamp', pd.Series())),
            errors='coerce', utc=True
        )
        recent = alerts_df[ts > pd.Timestamp(cutoff, tz='UTC')]

        if recent.empty:
            return chains

        for host, host_alerts in recent.groupby('host_name'):
            if len(host_alerts) < 2:
                continue

            sorted_alerts = host_alerts.sort_values(
                '@timestamp' if '@timestamp' in host_alerts.columns else 'timestamp'
            )

            G = nx.DiGraph()
            prev_ttp = None

            for _, alert in sorted_alerts.iterrows():
                ttp = alert.get('mitre_technique', '')
                if not ttp:
                    continue

                tactic = alert.get('mitre_tactic', '')
                tactic_key = tactic.lower().replace(' ', '-')

                G.add_node(ttp, **{
                    'tactic': tactic,
                    'tactic_order': TACTIC_ORDER.get(tactic_key, 99),
                    'severity': alert.get('severity', 'medium'),
                    'timestamp': str(alert.get('@timestamp',
                                               alert.get('timestamp', ''))),
                    'explanation': alert.get('explanation', ''),
                    'risk_score': float(alert.get('risk_score', 0))
                })

                if prev_ttp and prev_ttp != ttp:
                    if G.has_edge(prev_ttp, ttp):
                        G[prev_ttp][ttp]['weight'] += 1
                    else:
                        G.add_edge(prev_ttp, ttp, weight=1,
                                   time_delta='unknown')

                prev_ttp = ttp

            if len(G.nodes) < 2:
                continue

            # Order TTPs by tactic phase
            try:
                if nx.is_directed_acyclic_graph(G):
                    ttp_sequence = list(nx.topological_sort(G))
                else:
                    ttp_sequence = sorted(
                        G.nodes,
                        key=lambda n: G.nodes[n].get('tactic_order', 99)
                    )
            except Exception:
                ttp_sequence = list(G.nodes)

            unique_tactics = set(
                G.nodes[n].get('tactic', '') for n in G.nodes
                if G.nodes[n].get('tactic')
            )

            chain = {
                'host': host,
                'graph': G,
                'ttp_sequence': ttp_sequence,
                'chain_length': len(G.nodes),
                'unique_tactics': list(unique_tactics),
                'tactic_breadth': len(unique_tactics),
                'kill_chain_advancement': max(
                    (G.nodes[n].get('tactic_order', 0) for n in G.nodes),
                    default=0
                ),
                'max_risk_score': max(
                    (G.nodes[n].get('risk_score', 0) for n in G.nodes),
                    default=0
                ),
                'chain_severity': self._score_chain(G)
            }
            chains.append(chain)

        chains.sort(key=lambda c: c['kill_chain_advancement'], reverse=True)
        return chains

    def _score_chain(self, G):
        """Assign severity based on advancement and breadth"""
        advancement = max(
            (G.nodes[n].get('tactic_order', 0) for n in G.nodes), default=0
        )
        breadth = len(set(
            G.nodes[n].get('tactic', '') for n in G.nodes
        ))

        if advancement >= 10 or breadth >= 4:
            return 'critical'
        if advancement >= 7 or breadth >= 3:
            return 'high'
        if advancement >= 4 or breadth >= 2:
            return 'medium'
        return 'low'

    def chain_to_dict(self, chain):
        """Serialize chain to JSON-friendly dict"""
        return {
            'host': chain['host'],
            'ttp_sequence': chain['ttp_sequence'],
            'chain_length': chain['chain_length'],
            'unique_tactics': chain['unique_tactics'],
            'tactic_breadth': chain['tactic_breadth'],
            'kill_chain_advancement': chain['kill_chain_advancement'],
            'max_risk_score': chain['max_risk_score'],
            'chain_severity': chain['chain_severity'],
            'graph_nodes': [
                {
                    'id': n,
                    'tactic': chain['graph'].nodes[n].get('tactic', ''),
                    'severity': chain['graph'].nodes[n].get('severity', ''),
                    'timestamp': chain['graph'].nodes[n].get('timestamp', '')
                }
                for n in chain['graph'].nodes
            ],
            'graph_edges': [
                {'from': u, 'to': v, 'weight': chain['graph'][u][v]['weight']}
                for u, v in chain['graph'].edges
            ]
        }


if __name__ == '__main__':
    # Test with synthetic alert data
    from data.sample_data_generator import SampleDataGenerator
    from ingestion.log_parser import LogParser
    import pandas as pd

    gen = SampleDataGenerator()
    attack_events = gen.generate_attack_scenario('WIN-007', 'lateral_movement')

    # Simulate alerts from attack events
    alerts = []
    for event in attack_events:
        if event.get('mitre_technique'):
            alerts.append({
                '@timestamp': event['timestamp'],
                'host_name': event['host'],
                'mitre_technique': event['mitre_technique'],
                'mitre_tactic': 'Execution',
                'severity': 'high',
                'explanation': f"Attack: {event['cmdline']}",
                'risk_score': 80.0
            })

    alerts_df = pd.DataFrame(alerts)
    # Make timestamps current
    from datetime import datetime, timedelta
    now = datetime.utcnow()
    alerts_df['@timestamp'] = [
        (now - timedelta(minutes=10 - i)).isoformat() + 'Z'
        for i in range(len(alerts_df))
    ]

    reconstructor = AttackChainReconstructor(time_window_minutes=60)
    chains = reconstructor.reconstruct_chains(alerts_df)

    print(f"Chains reconstructed: {len(chains)}")
    for chain in chains:
        print(f"\n  Host: {chain['host']}")
        print(f"  TTP sequence: {chain['ttp_sequence']}")
        print(f"  Breadth: {chain['tactic_breadth']} tactics")
        print(f"  Advancement: {chain['kill_chain_advancement']}")
        print(f"  Severity: {chain['chain_severity']}")
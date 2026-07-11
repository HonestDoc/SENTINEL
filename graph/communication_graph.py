# SENTINEL/graph/communication_graph.py
# Runs on: HOST Windows 11

import networkx as nx
import pandas as pd
import numpy as np
from community import best_partition
import json
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CROWN_JEWEL_HOSTS

class HostCommunicationGraph:
    """
    Builds and analyzes host communication graph from network logs.
    Detects: new edges, degree anomalies, community violations, attack paths.
    """

    def __init__(self):
        self.G = nx.DiGraph()
        self.baseline_edges = set()
        self.crown_jewels = set(CROWN_JEWEL_HOSTS)
        self.communities = {}

    def build_from_connections(self, conn_df, baseline_conn_df=None):
        """Build graph from connection DataFrame"""
        if baseline_conn_df is not None and not baseline_conn_df.empty:
            src_col = ('source.ip' if 'source.ip' in baseline_conn_df.columns
                       else 'id.orig_h')
            dst_col = ('destination.ip' if 'destination.ip' in baseline_conn_df.columns
                       else 'id.resp_h')
            for _, row in baseline_conn_df.iterrows():
                self.baseline_edges.add((row[src_col], row[dst_col]))

        if conn_df.empty:
            return

        src_col = 'source.ip' if 'source.ip' in conn_df.columns else 'id.orig_h'
        dst_col = 'destination.ip' if 'destination.ip' in conn_df.columns else 'id.resp_h'
        port_col = ('destination.port' if 'destination.port' in conn_df.columns
                    else 'id.resp_p')
        bytes_col = 'orig_bytes' if 'orig_bytes' in conn_df.columns else None

        for _, row in conn_df.iterrows():
            src = str(row.get(src_col, ''))
            dst = str(row.get(dst_col, ''))
            port = str(row.get(port_col, ''))
            bytes_out = int(row.get(bytes_col, 0)) if bytes_col else 0

            if not src or not dst:
                continue

            # Add nodes
            for node in [src, dst]:
                if node not in self.G:
                    is_crown = any(cj.lower() in node.lower()
                                   for cj in self.crown_jewels)
                    self.G.add_node(node,
                        type='host',
                        risk_score=0.0,
                        is_crown_jewel=is_crown
                    )

            # Add/update edge
            is_new = (src, dst) not in self.baseline_edges
            if self.G.has_edge(src, dst):
                self.G[src][dst]['connection_count'] += 1
                self.G[src][dst]['bytes_transferred'] += bytes_out
            else:
                self.G.add_edge(src, dst,
                    connection_count=1,
                    bytes_transferred=bytes_out,
                    port=port,
                    is_new_edge=is_new
                )

    def update_risk_scores(self, risk_scores_dict):
        """Update node risk scores from ML risk scorer"""
        for node, score in risk_scores_dict.items():
            if node in self.G:
                self.G.nodes[node]['risk_score'] = score

    def detect_new_edges(self, min_risk_score=0):
        """Return new edges where source has elevated risk"""
        return [
            (u, v, self.G[u][v])
            for u, v in self.G.edges()
            if (self.G[u][v].get('is_new_edge', False) and
                self.G.nodes[u].get('risk_score', 0) >= min_risk_score)
        ]

    def detect_degree_anomalies(self, baseline_degrees=None):
        """Flag nodes with abnormally high out-degree"""
        anomalies = []
        for node in self.G.nodes():
            current_degree = self.G.out_degree(node)
            if baseline_degrees and node in baseline_degrees:
                mean = baseline_degrees[node]['mean']
                std = baseline_degrees[node]['std']
                z_score = (current_degree - mean) / (std + 1e-9)
                if z_score > 3.0:
                    anomalies.append({
                        'node': node,
                        'current_out_degree': current_degree,
                        'baseline_mean': mean,
                        'z_score': round(z_score, 2),
                        'anomaly_type': 'degree_anomaly'
                    })
            elif current_degree > 20:  # fallback threshold
                anomalies.append({
                    'node': node,
                    'current_out_degree': current_degree,
                    'anomaly_type': 'high_degree'
                })
        return anomalies

    def find_attack_paths(self, compromised_host):
        """Find shortest paths from compromised host to crown jewels"""
        paths = []
        if compromised_host not in self.G:
            return paths

        crown_nodes = [
            n for n in self.G.nodes()
            if self.G.nodes[n].get('is_crown_jewel', False)
        ]

        for target in crown_nodes:
            try:
                path = nx.shortest_path(self.G, compromised_host, target)
                risk = self.G.nodes[compromised_host].get('risk_score', 0)
                paths.append({
                    'source': compromised_host,
                    'target': target,
                    'path': path,
                    'length': len(path) - 1,
                    'path_risk_score': round(risk * (1 / max(len(path) - 1, 1)), 1)
                })
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        return sorted(paths, key=lambda p: p['path_risk_score'], reverse=True)

    def run_community_detection(self):
        """Detect communities and flag cross-community new edges"""
        undirected = self.G.to_undirected()
        if len(undirected.nodes) < 2:
            return [], {}

        try:
            self.communities = best_partition(undirected)
        except Exception as e:
            print(f"Community detection failed: {e}")
            return [], {}

        violations = []
        for u, v in self.G.edges():
            if (self.communities.get(u) != self.communities.get(v) and
                    self.G[u][v].get('is_new_edge', False)):
                violations.append({
                    'source': u, 'destination': v,
                    'source_community': self.communities.get(u),
                    'dest_community': self.communities.get(v),
                    'anomaly_type': 'cross_community_new_edge'
                })

        return violations, self.communities

    def to_d3_json(self):
        """Export graph for D3.js visualization"""
        nodes = []
        for node_id in self.G.nodes():
            node_data = self.G.nodes[node_id]
            risk = node_data.get('risk_score', 0)
            nodes.append({
                'id': node_id,
                'risk_score': risk,
                'is_crown_jewel': node_data.get('is_crown_jewel', False),
                'community': self.communities.get(node_id, 0),
                'out_degree': self.G.out_degree(node_id),
                'risk_tier': (
                    'critical' if risk >= 80 else
                    'high' if risk >= 60 else
                    'medium' if risk >= 40 else 'low'
                )
            })

        links = []
        for u, v in self.G.edges():
            edge = self.G[u][v]
            links.append({
                'source': u,
                'target': v,
                'connection_count': edge.get('connection_count', 1),
                'bytes_transferred': edge.get('bytes_transferred', 0),
                'is_new_edge': edge.get('is_new_edge', False),
                'port': edge.get('port', '')
            })

        return {'nodes': nodes, 'links': links}


if __name__ == '__main__':
    graph = HostCommunicationGraph()
    graph.crown_jewels = {'DC-01'}

    # Simulate connections
    conn_data = pd.DataFrame([
        {'source.ip': '10.0.0.1', 'destination.ip': '10.0.0.10',
         'destination.port': 445, 'orig_bytes': 1024},
        {'source.ip': '10.0.0.2', 'destination.ip': '10.0.0.10',
         'destination.port': 445, 'orig_bytes': 512},
        {'source.ip': '10.0.0.7', 'destination.ip': '10.0.0.10',
         'destination.port': 445, 'orig_bytes': 2048},
        {'source.ip': '10.0.0.7', 'destination.ip': 'DC-01',
         'destination.port': 389, 'orig_bytes': 4096},
    ])

    graph.build_from_connections(conn_data)
    graph.update_risk_scores({'10.0.0.7': 75.0})

    print(f"Graph: {len(graph.G.nodes)} nodes, {len(graph.G.edges)} edges")

    attack_paths = graph.find_attack_paths('10.0.0.7')
    print(f"\nAttack paths from 10.0.0.7:")
    for path in attack_paths:
        print(f"  {' -> '.join(path['path'])} "
              f"(length: {path['length']}, risk: {path['path_risk_score']})")

    d3_data = graph.to_d3_json()
    print(f"\nD3 export: {len(d3_data['nodes'])} nodes, "
          f"{len(d3_data['links'])} links")
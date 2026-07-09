# SENTINEL/ml/peer_grouping.py
# Runs on: HOST Windows 11

from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from elasticsearch import Elasticsearch
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ELASTICSEARCH_HOST

class PeerGroupAnalyzer:
    """
    Clusters entities into peer groups using K-Means.
    A deviation is more suspicious when the entity differs
    from its specific peer group, not just the whole population.
    """

    def __init__(self, n_clusters=5):
        self.n_clusters = n_clusters
        self.kmeans = KMeans(n_clusters=n_clusters,
                              random_state=42, n_init=10)
        self.scaler = StandardScaler()
        self.entity_groups = {}
        self.es = Elasticsearch(ELASTICSEARCH_HOST)

    def load_profiles_from_es(self):
        """Load all entity profiles from Elasticsearch"""
        try:
            result = self.es.search(
                index='sentinel-profiles',
                body={'query': {'match_all': {}}, 'size': 1000}
            )
            profiles = {}
            for hit in result['hits']['hits']:
                entity_id = hit['_source']['entity_id']
                profiles[entity_id] = hit['_source']
            return profiles
        except Exception as e:
            print(f"Could not load profiles from ES: {e}")
            return self._get_sample_profiles()

    def _get_sample_profiles(self):
        """Sample profiles for testing without real ES data"""
        return {
            'WIN-001': {'active_hours_mean': 9.5, 'active_hours_std': 2.1,
                        'unique_processes': 25, 'cmdline_entropy_mean': 2.1,
                        'unique_dest_ips': 8},
            'WIN-002': {'active_hours_mean': 10.2, 'active_hours_std': 1.8,
                        'unique_processes': 22, 'cmdline_entropy_mean': 2.3,
                        'unique_dest_ips': 6},
            'SRV-01':  {'active_hours_mean': 12.0, 'active_hours_std': 6.0,
                        'unique_processes': 45, 'cmdline_entropy_mean': 2.8,
                        'unique_dest_ips': 35},
            'DC-01':   {'active_hours_mean': 12.0, 'active_hours_std': 8.0,
                        'unique_processes': 60, 'cmdline_entropy_mean': 2.5,
                        'unique_dest_ips': 50},
        }

    def build_peer_groups(self, profiles=None):
        """Cluster entities into peer groups"""
        if profiles is None:
            profiles = self.load_profiles_from_es()

        if len(profiles) < self.n_clusters:
            self.n_clusters = max(2, len(profiles))
            self.kmeans = KMeans(n_clusters=self.n_clusters,
                                  random_state=42, n_init=10)

        feature_cols = ['active_hours_mean', 'active_hours_std',
                        'unique_processes', 'cmdline_entropy_mean',
                        'unique_dest_ips']

        entity_ids = list(profiles.keys())
        feature_matrix = []

        for entity_id in entity_ids:
            profile = profiles[entity_id]
            row = [profile.get(col, 0) for col in feature_cols]
            feature_matrix.append(row)

        X = np.array(feature_matrix)
        X_scaled = self.scaler.fit_transform(X)

        labels = self.kmeans.fit_predict(X_scaled)

        self.entity_groups = {
            entity_id: int(label)
            for entity_id, label in zip(entity_ids, labels)
        }

        print(f"Peer groups assigned:")
        for group_id in range(self.n_clusters):
            members = [e for e, g in self.entity_groups.items()
                      if g == group_id]
            print(f"  Group {group_id}: {members}")

        return self.entity_groups

    def get_peer_group(self, entity_id):
        return self.entity_groups.get(entity_id, -1)

    def get_group_members(self, group_id):
        return [e for e, g in self.entity_groups.items()
                if g == group_id]

    def compute_peer_deviation(self, entity_id, current_features,
                                 profiles=None):
        """
        Score how much an entity deviates from its peer group centroid.
        Returns z-score of deviation.
        """
        group_id = self.get_peer_group(entity_id)
        peers = self.get_group_members(group_id)
        peers = [p for p in peers if p != entity_id]

        if not peers or profiles is None:
            return 0.0

        peer_values = []
        feature_cols = ['active_hours_mean', 'active_hours_std',
                        'unique_processes', 'cmdline_entropy_mean',
                        'unique_dest_ips']

        for peer in peers:
            if peer in profiles:
                peer_values.append(
                    [profiles[peer].get(c, 0) for c in feature_cols]
                )

        if not peer_values:
            return 0.0

        peer_array = np.array(peer_values)
        peer_mean = peer_array.mean(axis=0)
        peer_std = peer_array.std(axis=0) + 1e-9

        entity_vec = np.array(
            [current_features.get(c, 0) for c in feature_cols]
        )
        z_scores = np.abs((entity_vec - peer_mean) / peer_std)
        return float(z_scores.mean())


if __name__ == '__main__':
    analyzer = PeerGroupAnalyzer(n_clusters=3)
    groups = analyzer.build_peer_groups()
    print(f"\nTotal entities grouped: {len(groups)}")
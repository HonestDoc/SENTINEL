# SENTINEL/ml/risk_scorer.py
# Runs on: HOST Windows 11

import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import pandas as pd
import numpy as np
import joblib
import os

class RiskScorer:
    """
    Combines all detection signals into one unified risk score per entity.
    XGBoost on tabular features from all detectors.
    Input: combined signal features from all detection engines.
    Output: risk score 0-100 + SHAP explanations.
    """

    def __init__(self):
        self.model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric='logloss',
            random_state=42,
            use_label_encoder=False
        )
        self.is_trained = False
        self.feature_names = [
            'sigma_alert_count',
            'behavioral_anomaly_score',
            'unique_ttp_count',
            'tactic_breadth',
            'threat_intel_hit',
            'after_hours_flag',
            'new_dest_count',
            'peer_group_deviation',
            'chain_length',
            'beaconing_score',
            'dns_tunnel_score',
            'lateral_movement_score',
            'time_decay_weight'
        ]

    def build_features(self, entity_data):
        """
        Build feature dict from entity data dict.
        entity_data: aggregated signals for one entity in one time window.
        """
        hours_since = entity_data.get('hours_since_first_alert', 0)
        time_decay = float(np.exp(-0.05 * hours_since))

        return {
            'sigma_alert_count':      entity_data.get('sigma_alerts', 0),
            'behavioral_anomaly_score': abs(entity_data.get('anomaly_score', 0)),
            'unique_ttp_count':        entity_data.get('unique_ttps', 0),
            'tactic_breadth':          entity_data.get('tactic_categories', 0),
            'threat_intel_hit':        int(entity_data.get('ti_hit', False)),
            'after_hours_flag':        int(entity_data.get('after_hours', False)),
            'new_dest_count':          entity_data.get('new_destinations', 0),
            'peer_group_deviation':    entity_data.get('peer_deviation', 0),
            'chain_length':            entity_data.get('chain_length', 0),
            'beaconing_score':         entity_data.get('beaconing_confidence', 0),
            'dns_tunnel_score':        entity_data.get('dns_tunnel_score', 0),
            'lateral_movement_score':  entity_data.get('lateral_movement_score', 0),
            'time_decay_weight':       time_decay
        }

    def generate_training_data(self, n_benign=500, n_malicious=200):
        """
        Generate synthetic training data for initial model.
        Replace with real CALDERA-labeled data when available.
        """
        import random

        records = []

        # Benign samples: low scores across all features
        for _ in range(n_benign):
            record = {
                'sigma_alerts':         random.randint(0, 2),
                'anomaly_score':        random.uniform(-0.2, 0.0),
                'unique_ttps':          random.randint(0, 1),
                'tactic_categories':    random.randint(0, 1),
                'ti_hit':               False,
                'after_hours':          random.random() < 0.1,
                'new_destinations':     random.randint(0, 3),
                'peer_deviation':       random.uniform(0, 0.5),
                'chain_length':         random.randint(0, 1),
                'beaconing_confidence': 0.0,
                'dns_tunnel_score':     random.uniform(0, 0.2),
                'lateral_movement_score': 0.0,
                'hours_since_first_alert': random.randint(0, 48),
                'label': 0
            }
            records.append(record)

        # Malicious samples: elevated scores
        for _ in range(n_malicious):
            record = {
                'sigma_alerts':         random.randint(3, 15),
                'anomaly_score':        random.uniform(-0.9, -0.5),
                'unique_ttps':          random.randint(2, 8),
                'tactic_categories':    random.randint(2, 5),
                'ti_hit':               random.random() < 0.4,
                'after_hours':          random.random() < 0.6,
                'new_destinations':     random.randint(5, 30),
                'peer_deviation':       random.uniform(1.5, 5.0),
                'chain_length':         random.randint(3, 10),
                'beaconing_confidence': random.uniform(0.5, 1.0),
                'dns_tunnel_score':     random.uniform(0.3, 1.0),
                'lateral_movement_score': random.uniform(0.5, 1.0),
                'hours_since_first_alert': random.randint(0, 12),
                'label': 1
            }
            records.append(record)

        df = pd.DataFrame(records)
        X = pd.DataFrame([self.build_features(r) for r in records])
        y = df['label']
        return X, y

    def train(self, X=None, y=None):
        """Train on provided data or generate synthetic data"""
        if X is None or y is None:
            print("No training data provided — using synthetic data")
            print("Replace with real CALDERA-labeled data for production")
            X, y = self.generate_training_data()

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        self.model.fit(
            X_train, y_train,
            eval_set=[(X_test, y_test)],
            verbose=False
        )

        preds = self.model.predict(X_test)
        proba = self.model.predict_proba(X_test)[:, 1]

        print("Risk Scorer Training Results:")
        print(classification_report(y_test, preds,
              target_names=['benign', 'malicious']))
        print(f"ROC-AUC: {roc_auc_score(y_test, proba):.3f}")

        self.is_trained = True
        return self

    def score(self, entity_data):
        """Score one entity. Returns 0-100."""
        if not self.is_trained:
            self.train()

        features = self.build_features(entity_data)
        X = pd.DataFrame([features])
        proba = self.model.predict_proba(X)[0, 1]
        return round(proba * 100, 1)

    def save(self, path='data/models/risk_scorer.pkl'):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({'model': self.model,
                     'is_trained': self.is_trained,
                     'feature_names': self.feature_names}, path)
        print(f"Risk scorer saved: {path}")

    def load(self, path='data/models/risk_scorer.pkl'):
        data = joblib.load(path)
        self.model = data['model']
        self.is_trained = data['is_trained']
        self.feature_names = data['feature_names']
        print(f"Risk scorer loaded: {path}")


if __name__ == '__main__':
    scorer = RiskScorer()
    scorer.train()
    scorer.save()

    benign_entity = {
        'sigma_alerts': 0, 'anomaly_score': -0.1,
        'unique_ttps': 0, 'tactic_categories': 0,
        'ti_hit': False, 'after_hours': False,
        'new_destinations': 1, 'peer_deviation': 0.2,
        'chain_length': 0, 'beaconing_confidence': 0.0,
        'dns_tunnel_score': 0.1, 'lateral_movement_score': 0.0,
        'hours_since_first_alert': 24
    }

    malicious_entity = {
        'sigma_alerts': 8, 'anomaly_score': -0.75,
        'unique_ttps': 5, 'tactic_categories': 4,
        'ti_hit': True, 'after_hours': True,
        'new_destinations': 18, 'peer_deviation': 3.5,
        'chain_length': 6, 'beaconing_confidence': 0.85,
        'dns_tunnel_score': 0.7, 'lateral_movement_score': 0.9,
        'hours_since_first_alert': 2
    }

    print(f"\nBenign entity risk score:    {scorer.score(benign_entity)}")
    print(f"Malicious entity risk score: {scorer.score(malicious_entity)}")
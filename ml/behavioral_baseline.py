# SENTINEL/ml/behavioral_baseline.py
# Runs on: HOST Windows 11

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
import numpy as np
import joblib
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.feature_engineering import extract_behavioral_features

class BehavioralBaselineModel:
    """
    Per-entity anomaly detection using Isolation Forest.
    Trained on 30 days of normal behavior.
    No labeled attack data required for training.
    """

    def __init__(self, entity_id, contamination=0.05):
        self.entity_id = entity_id
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            max_samples='auto',
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = []

    def train(self, events_df, all_events_df=None):
        """Train on normal behavior DataFrame"""
        if events_df.empty:
            print(f"No training data for {self.entity_id}")
            return False

        features = extract_behavioral_features(events_df, all_events_df)
        self.feature_names = features.columns.tolist()

        scaled = self.scaler.fit_transform(features)
        self.model.fit(scaled)
        self.is_trained = True

        print(f"Trained baseline for {self.entity_id} "
              f"on {len(events_df)} events, "
              f"{len(self.feature_names)} features")
        return True

    def score(self, events_df, all_events_df=None):
        """
        Score events against baseline.
        Returns array of scores: lower = more anomalous.
        Normal range: -0.1 to 0.0
        Anomalous: below -0.5
        """
        if not self.is_trained:
            raise RuntimeError(f"Model for {self.entity_id} not trained yet")

        features = extract_behavioral_features(events_df, all_events_df)
        # Use only features model was trained on
        for col in self.feature_names:
            if col not in features.columns:
                features[col] = 0
        features = features[self.feature_names]

        scaled = self.scaler.transform(features)
        return self.model.score_samples(scaled)

    def flag_anomalies(self, events_df, threshold=-0.5, all_events_df=None):
        """Return only anomalous events with their scores"""
        scores = self.score(events_df, all_events_df)
        events_df = events_df.copy()
        events_df['anomaly_score'] = scores
        events_df['is_anomaly'] = scores < threshold
        return events_df[events_df['is_anomaly']]

    def save(self, directory='data/models'):
        os.makedirs(directory, exist_ok=True)
        path = f"{directory}/baseline_{self.entity_id}.pkl"
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'entity_id': self.entity_id,
            'is_trained': self.is_trained
        }, path)
        print(f"Model saved: {path}")

    def load(self, directory='data/models'):
        path = f"{directory}/baseline_{self.entity_id}.pkl"
        data = joblib.load(path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.feature_names = data['feature_names']
        self.entity_id = data['entity_id']
        self.is_trained = data['is_trained']
        print(f"Model loaded: {path}")


if __name__ == '__main__':
    from data.sample_data_generator import SampleDataGenerator
    import pandas as pd

    gen = SampleDataGenerator()

    print("Generating training data (30 days normal)...")
    baseline_events = gen.generate_baseline('WIN-007', days=30, events_per_day=100)
    df_baseline = pd.DataFrame(baseline_events)

    print("Training Isolation Forest...")
    model = BehavioralBaselineModel('WIN-007')
    model.train(df_baseline)

    print("\nScoring normal events (should be near 0):")
    normal_sample = pd.DataFrame(
        gen.generate_baseline('WIN-007', days=1, events_per_day=10)
    )
    normal_scores = model.score(normal_sample)
    print(f"  Mean score: {normal_scores.mean():.3f}")
    print(f"  Min score:  {normal_scores.min():.3f}")

    print("\nScoring attack events (should be negative/low):")
    attack_events = gen.generate_attack_scenario('WIN-007', 'lateral_movement')
    df_attack = pd.DataFrame(attack_events)
    attack_scores = model.score(df_attack)
    print(f"  Mean score: {attack_scores.mean():.3f}")
    print(f"  Min score:  {attack_scores.min():.3f}")
    print(f"  Events flagged as anomalies: "
          f"{(attack_scores < -0.5).sum()}/{len(attack_scores)}")

    model.save()
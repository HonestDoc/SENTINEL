# SENTINEL/ml/explainer.py
# Runs on: HOST Windows 11

import shap
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class AlertExplainer:
    """
    Makes every ML-based alert explainable.
    Produces SHAP values and natural language explanations.
    Analyst trust depends on this component.
    """

    FEATURE_DESCRIPTIONS = {
        'sigma_alert_count':       'Number of rule-based detections triggered',
        'behavioral_anomaly_score':'Behavioral deviation from baseline',
        'unique_ttp_count':        'Distinct ATT&CK techniques observed',
        'tactic_breadth':          'Number of attack tactic categories active',
        'threat_intel_hit':        'Connection to known malicious infrastructure',
        'after_hours_flag':        'Activity outside normal business hours',
        'new_dest_count':          'Connections to never-seen-before destinations',
        'peer_group_deviation':    'Deviation from peer group behavioral norm',
        'chain_length':            'Length of reconstructed attack chain',
        'beaconing_score':         'C2 beaconing periodicity detected',
        'dns_tunnel_score':        'DNS tunneling indicators present',
        'lateral_movement_score':  'Lateral movement signals detected',
        'time_decay_weight':       'Recency of alert activity'
    }

    def __init__(self, risk_scorer):
        self.scorer = risk_scorer
        self.explainer = shap.TreeExplainer(risk_scorer.model)

    def explain(self, entity_data):
        """
        Generate full explanation for one entity's risk score.
        Returns structured dict with natural language contributions.
        """
        features = self.scorer.build_features(entity_data)
        X = pd.DataFrame([features])

        shap_values = self.explainer.shap_values(X)

        contributions = []
        for feat_name, shap_val in zip(X.columns, shap_values[0]):
            if abs(shap_val) > 0.001:
                contributions.append({
                    'feature_key': feat_name,
                    'feature_description': self.FEATURE_DESCRIPTIONS.get(
                        feat_name, feat_name
                    ),
                    'shap_value': round(float(shap_val), 4),
                    'contribution_pct': round(float(shap_val) * 100, 1),
                    'direction': 'increases risk' if shap_val > 0 else 'reduces risk',
                    'raw_value': round(float(features[feat_name]), 3)
                })

        contributions.sort(key=lambda x: abs(x['shap_value']), reverse=True)

        risk_score = self.scorer.score(entity_data)
        top_3 = contributions[:3]

        narrative = self._build_narrative(risk_score, top_3, entity_data)

        return {
            'risk_score': risk_score,
            'risk_tier': self._score_to_tier(risk_score),
            'contributions': contributions,
            'top_contributors': top_3,
            'narrative': narrative
        }

    def _build_narrative(self, risk_score, top_contributors, entity_data):
        """Build a natural language explanation"""
        tier = self._score_to_tier(risk_score)
        parts = []

        for contrib in top_contributors:
            if contrib['direction'] == 'increases risk':
                parts.append(contrib['feature_description'])

        if not parts:
            return f"Risk score {risk_score}: No significant risk factors identified."

        narrative = (
            f"Risk score {risk_score} ({tier}). "
            f"Primary risk factors: {'; '.join(parts)}. "
        )

        if entity_data.get('chain_length', 0) >= 3:
            narrative += (
                f"Attack chain of {entity_data['chain_length']} "
                f"techniques reconstructed. "
            )

        if entity_data.get('beaconing_confidence', 0) > 0.7:
            narrative += "C2 beaconing pattern detected with high confidence. "

        return narrative

    def _score_to_tier(self, score):
        if score >= 80: return 'CRITICAL'
        if score >= 60: return 'HIGH'
        if score >= 40: return 'MEDIUM'
        return 'LOW'

    def plot_waterfall(self, entity_data, entity_id='entity',
                        save_dir='data/explanations'):
        """Generate SHAP waterfall chart"""
        os.makedirs(save_dir, exist_ok=True)

        features = self.scorer.build_features(entity_data)
        X = pd.DataFrame([features])
        shap_values_obj = self.explainer(X)

        plt.figure(figsize=(10, 6))
        shap.plots.waterfall(shap_values_obj[0], show=False)
        plt.title(f'Risk Score Explanation — {entity_id}')
        plt.tight_layout()

        save_path = f"{save_dir}/shap_{entity_id}.png"
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"Saved SHAP chart: {save_path}")
        return save_path


if __name__ == '__main__':
    from ml.risk_scorer import RiskScorer

    scorer = RiskScorer()
    scorer.train()

    explainer = AlertExplainer(scorer)

    entity = {
        'sigma_alerts': 7, 'anomaly_score': -0.72,
        'unique_ttps': 4, 'tactic_categories': 3,
        'ti_hit': True, 'after_hours': True,
        'new_destinations': 12, 'peer_deviation': 2.8,
        'chain_length': 5, 'beaconing_confidence': 0.81,
        'dns_tunnel_score': 0.4, 'lateral_movement_score': 0.75,
        'hours_since_first_alert': 3
    }

    explanation = explainer.explain(entity)

    print(f"Risk Score: {explanation['risk_score']} ({explanation['risk_tier']})")
    print(f"\nNarrative: {explanation['narrative']}")
    print("\nTop Contributors:")
    for contrib in explanation['top_contributors']:
        arrow = '↑' if contrib['direction'] == 'increases risk' else '↓'
        print(f"  {arrow} {contrib['feature_description']}: "
              f"{contrib['contribution_pct']:+.1f}% "
              f"(value: {contrib['raw_value']})")

    explainer.plot_waterfall(entity, entity_id='WIN-007')
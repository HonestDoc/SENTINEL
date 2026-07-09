# SENTINEL/ml/feature_engineering.py
# Runs on: HOST Windows 11

import numpy as np
import pandas as pd
import math
import sys
import os
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def cyclic_encode(value, max_value):
    """
    Cyclically encode a periodic value.
    Use for: hour (max 24), day of week (max 7), month (max 12).
    """
    sin_val = np.sin(2 * np.pi * value / max_value)
    cos_val = np.cos(2 * np.pi * value / max_value)
    return sin_val, cos_val

def shannon_entropy(text):
    """High entropy = random/encoded. Used for cmdline + DNS."""
    if not text or len(text) == 0:
        return 0.0
    counts = Counter(str(text))
    length = len(str(text))
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

def compute_process_rarity(process_name, all_processes_series):
    """
    TF-IDF style rarity: rare processes are suspicious.
    Returns 0 (common) to 1 (never seen before).
    """
    total = len(all_processes_series)
    if total == 0:
        return 1.0
    count = (all_processes_series == process_name).sum()
    return 1.0 - (count / total)

def extract_behavioral_features(events_df, all_events_df=None):
    """
    Extract complete behavioral feature vector from events DataFrame.
    Returns feature DataFrame ready for ML models.
    """
    features = pd.DataFrame(index=events_df.index)

    # Temporal features (cyclic)
    if 'timestamp' in events_df.columns:
        ts = pd.to_datetime(events_df['timestamp'], errors='coerce')
        hours = ts.dt.hour.fillna(12)
        dow = ts.dt.dayofweek.fillna(0)

        features['hour_sin'] = hours.apply(lambda h: cyclic_encode(h, 24)[0])
        features['hour_cos'] = hours.apply(lambda h: cyclic_encode(h, 24)[1])
        features['dow_sin']  = dow.apply(lambda d: cyclic_encode(d, 7)[0])
        features['dow_cos']  = dow.apply(lambda d: cyclic_encode(d, 7)[1])
        features['is_after_hours'] = (~hours.between(8, 18)).astype(float)
        features['is_weekend']     = (dow >= 5).astype(float)

    # Process features
    if 'cmdline' in events_df.columns:
        cmdlines = events_df['cmdline'].fillna('')
        features['cmdline_length']  = cmdlines.str.len()
        features['cmdline_entropy'] = cmdlines.apply(shannon_entropy)
        features['cmdline_has_b64'] = cmdlines.str.contains(
            r'[A-Za-z0-9+/]{20,}={0,2}', regex=True, na=False
        ).astype(float)
        features['cmdline_has_enc'] = cmdlines.str.lower().str.contains(
            '-enc|-encodedcommand', regex=True, na=False
        ).astype(float)

    if 'process_name' in events_df.columns:
        if all_events_df is not None:
            all_procs = all_events_df.get('process_name', pd.Series())
            features['process_rarity'] = events_df['process_name'].apply(
                lambda p: compute_process_rarity(p, all_procs)
            )
        else:
            features['process_rarity'] = 0.5  # default if no baseline

    # Network features
    if 'destination_ip' in events_df.columns:
        features['is_external'] = (~events_df['destination_ip'].str.startswith(
            ('10.', '192.168.', '172.'), na=True
        )).astype(float)

    if 'destination_port' in events_df.columns:
        port = pd.to_numeric(events_df['destination_port'], errors='coerce').fillna(0)
        features['is_high_port'] = (port > 49151).astype(float)
        features['is_common_port'] = port.isin([80, 443, 22, 53, 445, 3389]).astype(float)

    return features.fillna(0)


if __name__ == '__main__':
    # Test with sample data
    from data.sample_data_generator import SampleDataGenerator
    gen = SampleDataGenerator()

    baseline = gen.generate_baseline('WIN-007', days=7, events_per_day=50)
    attack = gen.generate_attack_scenario('WIN-007', 'lateral_movement')
    all_events = baseline + attack

    import pandas as pd
    df_baseline = pd.DataFrame(baseline)
    df_attack = pd.DataFrame(attack)
    df_all = pd.DataFrame(all_events)

    feat_baseline = extract_behavioral_features(df_baseline, df_all)
    feat_attack = extract_behavioral_features(df_attack, df_all)

    print("Baseline feature sample:")
    print(feat_baseline[['hour_sin', 'cmdline_entropy',
                           'process_rarity']].describe())

    print("\nAttack feature sample:")
    print(feat_attack[['hour_sin', 'cmdline_entropy',
                         'process_rarity']].describe())

    print(f"\nMean cmdline entropy — Baseline: "
          f"{feat_baseline['cmdline_entropy'].mean():.3f}, "
          f"Attack: {feat_attack['cmdline_entropy'].mean():.3f}")
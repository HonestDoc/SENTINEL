# SENTINEL/ingestion/log_parser.py

import pandas as pd
import json
from datetime import datetime
from collections import Counter
import math
import numpy as np


def shannon_entropy(text):
    if not text:
        return 0.0
    counts = Counter(str(text))
    length = len(str(text))
    return -sum(
        (c / length) * math.log2(c / length)
        for c in counts.values()
    )


def cyclic_encode_hour(hour):
    sin_val = np.sin(2 * math.pi * hour / 24)
    cos_val = np.cos(2 * math.pi * hour / 24)
    return sin_val, cos_val


class LogParser:

    REQUIRED_FIELDS = ['timestamp', 'host', 'event_type']

    def load_from_file(self, filepath):
        records = []
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return pd.DataFrame(records)

    def normalize(self, df):
        if df.empty:
            return df

        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])

        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        df['is_after_hours'] = (~df['hour'].between(8, 18)).astype(int)

        df['hour_sin'] = df['hour'].apply(lambda h: cyclic_encode_hour(h)[0])
        df['hour_cos'] = df['hour'].apply(lambda h: cyclic_encode_hour(h)[1])

        if 'cmdline' in df.columns:
            df['cmdline_length'] = df['cmdline'].fillna('').str.len()
            df['cmdline_entropy'] = df['cmdline'].fillna('').apply(shannon_entropy)

        return df

    def summarize(self, df):
        print(f"Total events:  {len(df)}")
        print(f"Time range:    {df['timestamp'].min()} → {df['timestamp'].max()}")
        print(f"Unique hosts:  {df['host'].nunique()}")
        print(f"Event types:\n{df['event_type'].value_counts()}")
        if 'cmdline_entropy' in df.columns:
            print(f"\nTop 5 high-entropy command lines:")
            top = df.nlargest(5, 'cmdline_entropy')[['host', 'cmdline', 'cmdline_entropy']]
            print(top.to_string())
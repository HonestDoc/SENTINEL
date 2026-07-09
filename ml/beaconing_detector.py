# SENTINEL/ml/beaconing_detector.py
# Runs on: HOST Windows 11
# Input: Zeek conn.log data from Ubuntu VM

import numpy as np
import pandas as pd
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scipy import stats

class BeaconingDetector:
    """
    Detects C2 beaconing using autocorrelation and CoV analysis.
    Works even on jittered beacons (Cobalt Strike, Sliver).
    """

    def __init__(self, min_connections=10, cov_threshold=0.3,
                  acf_threshold=0.5):
        self.min_connections = min_connections
        self.cov_threshold = cov_threshold
        self.acf_threshold = acf_threshold

    def analyze_connection_tuple(self, timestamps):
        """
        Analyze a list of connection timestamps for beaconing.
        timestamps: list of Unix timestamps (floats)
        """
        if len(timestamps) < self.min_connections:
            return {'is_beaconing': False,
                    'reason': 'insufficient_connections'}

        ts_sorted = sorted(timestamps)
        iats = np.diff(ts_sorted)   # inter-arrival times

        if len(iats) < 5:
            return {'is_beaconing': False, 'reason': 'insufficient_iats'}

        mean_iat = float(np.mean(iats))
        std_iat = float(np.std(iats))
        cov = std_iat / mean_iat if mean_iat > 0 else float('inf')

        # ACF (handles jitter)
        normalized = (iats - mean_iat) / (std_iat + 1e-9)
        acf_values = []
        for lag in range(1, min(20, len(iats) // 2)):
            if lag < len(normalized):
                corr = np.corrcoef(
                    normalized[:-lag], normalized[lag:]
                )[0, 1]
                acf_values.append(corr if not np.isnan(corr) else 0)

        max_acf = max(acf_values) if acf_values else 0
        peak_lag_idx = np.argmax(acf_values) + 1 if acf_values else 0

        # Payload consistency
        regular_beaconing = cov < self.cov_threshold
        jittered_beaconing = (max_acf > self.acf_threshold
                               and cov >= self.cov_threshold)

        is_beaconing = regular_beaconing or jittered_beaconing
        confidence = 0.0
        if is_beaconing:
            if regular_beaconing:
                confidence = min(1.0, (1 - cov) * 1.5)
            else:
                confidence = min(1.0, max_acf)

        return {
            'is_beaconing': is_beaconing,
            'beacon_type': 'regular' if regular_beaconing else 'jittered',
            'mean_interval_seconds': round(mean_iat, 1),
            'coefficient_of_variation': round(cov, 3),
            'acf_peak_strength': round(float(max_acf), 3),
            'acf_peak_lag_seconds': round(
                peak_lag_idx * mean_iat, 1
            ) if is_beaconing else 0,
            'connection_count': len(timestamps),
            'confidence': round(confidence, 3)
        }

    def scan_zeek_connections(self, conn_df, lookback_hours=4):
        """
        Scan all connection tuples in a Zeek conn.log DataFrame.
        Groups by (src_ip, dst_ip, dst_port) and analyzes each.
        """
        alerts = []

        if conn_df.empty:
            return alerts

        ts_col = 'ts' if 'ts' in conn_df.columns else '@timestamp'
        src_col = 'source.ip' if 'source.ip' in conn_df.columns else 'id.orig_h'
        dst_col = 'destination.ip' if 'destination.ip' in conn_df.columns else 'id.resp_h'
        port_col = 'destination.port' if 'destination.port' in conn_df.columns else 'id.resp_p'

        cutoff = pd.Timestamp.now(tz='UTC') - pd.Timedelta(hours=lookback_hours)

        ts_series = pd.to_datetime(conn_df[ts_col], utc=True, errors='coerce')
        recent = conn_df[ts_series > cutoff].copy()

        if recent.empty:
            return alerts

        for (src, dst, port), group in recent.groupby([src_col, dst_col, port_col]):
            timestamps = pd.to_numeric(
                pd.to_datetime(group[ts_col], errors='coerce')
                  .astype(np.int64)
            ).dropna().tolist()
            timestamps = [t / 1e9 for t in timestamps]  # convert ns to seconds

            result = self.analyze_connection_tuple(timestamps)

            if result['is_beaconing']:
                result.update({
                    'source_ip': src,
                    'destination_ip': dst,
                    'destination_port': port,
                    'alert_type': 'c2_beaconing',
                    'mitre_technique': 'T1071.001',
                    'explanation': (
                        f"Process on {src} shows beaconing to {dst}:{port}. "
                        f"Mean interval: {result['mean_interval_seconds']}s, "
                        f"CoV: {result['coefficient_of_variation']}, "
                        f"ACF peak: {result['acf_peak_strength']}"
                    )
                })
                alerts.append(result)

        return alerts


if __name__ == '__main__':
    from data.sample_data_generator import SampleDataGenerator
    import pandas as pd

    gen = SampleDataGenerator()
    c2_events = gen.generate_attack_scenario('WIN-007', 'c2_beaconing')
    df = pd.DataFrame(c2_events)
    df['ts'] = pd.to_datetime(df['timestamp'])
    df['source.ip'] = '10.0.0.7'
    df['destination.ip'] = df['destination_ip']
    df['destination.port'] = df['destination_port']

    detector = BeaconingDetector(min_connections=5)
    alerts = detector.scan_zeek_connections(df, lookback_hours=24)

    print(f"Beaconing alerts found: {len(alerts)}")
    for alert in alerts:
        print(f"\n  Source: {alert['source_ip']} -> {alert['destination_ip']}")
        print(f"  Type: {alert['beacon_type']}")
        print(f"  Interval: {alert['mean_interval_seconds']}s")
        print(f"  Confidence: {alert['confidence']}")
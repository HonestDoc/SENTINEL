# SENTINEL/ingestion/zeek_parser.py
# Runs on: HOST Windows 11
# Reads Zeek logs shipped from Ubuntu VM

import pandas as pd
import json
from datetime import datetime

class ZeekParser:
    """
    Parses Zeek log files into normalized DataFrames.
    Zeek logs are TSV (tab-separated) with a header format.
    """

    def parse_conn_log(self, filepath):
        """
        Parse Zeek conn.log into DataFrame.
        conn.log contains one row per network connection.
        """
        records = []

        with open(filepath, 'r') as f:
            fields = []
            for line in f:
                line = line.strip()
                if line.startswith('#fields'):
                    fields = line.split('\t')[1:]
                elif line.startswith('#'):
                    continue
                elif fields:
                    values = line.split('\t')
                    if len(values) == len(fields):
                        record = dict(zip(fields, values))
                        records.append(record)

        df = pd.DataFrame(records)
        if df.empty:
            return df

        # Normalize to ECS-like schema
        df = df.rename(columns={
            'id.orig_h': 'source.ip',
            'id.orig_p': 'source.port',
            'id.resp_h': 'destination.ip',
            'id.resp_p': 'destination.port',
        })

        # Convert types
        df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
        df['@timestamp'] = pd.to_datetime(df['ts'], unit='s', utc=True)

        numeric_cols = ['orig_bytes', 'resp_bytes', 'duration']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

        # Add behavioral features
        df['hour'] = df['@timestamp'].dt.hour
        df['is_after_hours'] = (~df['hour'].between(8, 18)).astype(int)

        # Flag internal vs external
        df['is_external_dest'] = (~df['destination.ip'].str.startswith(
            ('10.', '192.168.', '172.')
        )).astype(int)

        return df

    def parse_dns_log(self, filepath):
        """
        Parse Zeek dns.log into DataFrame.
        Used by DNS tunneling and DGA detectors.
        """
        records = []

        with open(filepath, 'r') as f:
            fields = []
            for line in f:
                line = line.strip()
                if line.startswith('#fields'):
                    fields = line.split('\t')[1:]
                elif line.startswith('#'):
                    continue
                elif fields:
                    values = line.split('\t')
                    if len(values) == len(fields):
                        records.append(dict(zip(fields, values)))

        df = pd.DataFrame(records)
        if df.empty:
            return df

        df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
        df['@timestamp'] = pd.to_datetime(df['ts'], unit='s', utc=True)

        # Add tunnel detection features
        df['query_length'] = df.get('query', pd.Series()).str.len().fillna(0)
        df['subdomain_count'] = df.get('query', pd.Series()).str.count(
            '\.'
        ).fillna(0)

        return df

    def get_connection_summary(self, conn_df):
        """Quick stats for a connection DataFrame"""
        if conn_df.empty:
            return {}
        return {
            'total_connections': len(conn_df),
            'unique_sources': conn_df['source.ip'].nunique(),
            'unique_destinations': conn_df['destination.ip'].nunique(),
            'external_connections': conn_df['is_external_dest'].sum(),
            'time_range': f"{conn_df['@timestamp'].min()} → "
                         f"{conn_df['@timestamp'].max()}"
        }


if __name__ == '__main__':
    # Test with a sample Zeek conn.log format
    sample_conn = """#separator \\t
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\tconn_state
1710000000.0\tABC123\t10.0.0.1\t54321\t8.8.8.8\t53\tudp\t0.1\t50\t100\tSF
1710000060.0\tDEF456\t10.0.0.2\t54322\t185.234.100.50\t443\ttcp\t300.5\t1024\t512\tSF
1710000120.0\tGHI789\t10.0.0.1\t54323\t10.0.0.10\t445\ttcp\t1.2\t2048\t1024\tSF
"""
    with open('test_conn.log', 'w') as f:
        f.write(sample_conn)

    parser = ZeekParser()
    df = parser.parse_conn_log('test_conn.log')
    print("Parsed conn.log:")
    print(df[['source.ip', 'destination.ip', 'destination.port',
               'is_external_dest', 'is_after_hours']].to_string())
    print(f"\nSummary: {parser.get_connection_summary(df)}")
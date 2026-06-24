# SENTINEL/test_pipeline.py
# Runs on: HOST Windows 11
# Tests: sample data → parse → enrich → create alert → write to ES

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ingestion.log_parser import LogParser, shannon_entropy
from ingestion.event_enricher import EventEnricher
from ingestion.es_writer import ElasticsearchWriter
from detection.alert_schema import SentinelAlert
from data.sample_data_generator import SampleDataGenerator

def run_pipeline_test():
    print("=" * 60)
    print("SENTINEL Pipeline Integration Test")
    print("=" * 60)

    # Step 1: Generate sample data
    print("\n[1/5] Generating sample data...")
    gen = SampleDataGenerator()
    baseline = gen.generate_baseline('WIN-007', days=7, events_per_day=50)
    attack = gen.generate_attack_scenario('WIN-007', 'lateral_movement')
    gen.save(baseline, 'data/raw/test_baseline.jsonl')
    gen.save(attack, 'data/raw/test_attack.jsonl')
    print(f"     Generated {len(baseline)} baseline + {len(attack)} attack events")

    # Step 2: Parse and normalize
    print("\n[2/5] Parsing and normalizing logs...")
    parser = LogParser()
    df_baseline = parser.normalize(parser.load_from_file('data/raw/test_baseline.jsonl'))
    df_attack = parser.normalize(parser.load_from_file('data/raw/test_attack.jsonl'))
    print(f"     Baseline: {len(df_baseline)} events normalized")
    print(f"     Attack:   {len(df_attack)} events normalized")

    # Step 3: Enrich events
    print("\n[3/5] Enriching events...")
    enricher = EventEnricher()
    sample_event = df_attack.iloc[0].to_dict() if not df_attack.empty else {}
    if sample_event:
        enriched = enricher.enrich(sample_event)
        print(f"     Enriched fields: {list(enriched.keys())}")

    # Step 4: Create alerts for attack events
    print("\n[4/5] Creating alerts from attack events...")
    alerts = []
    for _, row in df_attack.iterrows():
        if row.get('mitre_technique'):
            alert = SentinelAlert(
                alert_type='rule_based',
                severity='high',
                confidence=0.9,
                host_name=row.get('host', 'UNKNOWN'),
                mitre_technique=row.get('mitre_technique', ''),
                explanation=f"Attack event: {row.get('cmdline', '')}",
                risk_score=80.0
            )
            alerts.append(alert)

    print(f"     Created {len(alerts)} alerts")

    # Step 5: Write to Elasticsearch
    print("\n[5/5] Writing alerts to Elasticsearch...")
    try:
        writer = ElasticsearchWriter()
        success, errors = writer.write_alerts_bulk(alerts)
        print(f"     Written: {success} alerts, Errors: {len(errors)}")

        # Verify by reading back
        import time
        time.sleep(2)  # wait for ES to index
        stored = writer.query_alerts(host_name='WIN-007', minutes_back=5)
        print(f"     Verified: {len(stored)} alerts readable from ES")

    except ConnectionError as e:
        print(f"     ES not available: {e}")
        print("     (This is OK — ES writes will work once service is running)")

    print("\n" + "=" * 60)
    print("Pipeline test complete")
    print("=" * 60)


if __name__ == '__main__':
    run_pipeline_test()
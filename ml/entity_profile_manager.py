# SENTINEL/ml/entity_profile_manager.py
# Runs on: HOST Windows 11

from elasticsearch import Elasticsearch
import pandas as pd
import numpy as np
from datetime import datetime
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ELASTICSEARCH_HOST, WINDOWS_LOG_INDEX
from ml.behavioral_baseline import BehavioralBaselineModel
from ml.feature_engineering import shannon_entropy

class EntityProfileManager:
    """
    Manages behavioral profiles for all entities (hosts + users).
    Builds and updates Isolation Forest models per entity.
    Runs nightly to refresh baselines.
    """

    def __init__(self):
        self.es = Elasticsearch(ELASTICSEARCH_HOST)
        self.models = {}

    def get_entity_events(self, entity_id, days=30, entity_type='host'):
        """Pull historical events for one entity from Elasticsearch"""
        field = 'host.name' if entity_type == 'host' else 'user.name'

        query = {
            'query': {
                'bool': {
                    'must': [
                        {'term': {field: entity_id}},
                        {'range': {'@timestamp': {'gte': f'now-{days}d'}}}
                    ]
                }
            },
            'size': 10000,
            '_source': ['@timestamp', 'process.name',
                       'process.command_line', 'source.ip',
                       'destination.ip', 'destination.port']
        }

        try:
            result = self.es.search(
                index=f"{WINDOWS_LOG_INDEX}-*",
                body=query
            )
            records = [hit['_source'] for hit in result['hits']['hits']]

            if not records:
                return pd.DataFrame()

            df = pd.DataFrame(records)
            df = df.rename(columns={
                '@timestamp': 'timestamp',
                'process.name': 'process_name',
                'process.command_line': 'cmdline',
                'destination.ip': 'destination_ip',
                'destination.port': 'destination_port'
            })
            return df

        except Exception as e:
            print(f"ES query error for {entity_id}: {e}")
            return pd.DataFrame()

    def build_statistical_profile(self, entity_id, events_df):
        """Build and store a statistical profile in Elasticsearch"""
        if events_df.empty:
            return None

        ts = pd.to_datetime(events_df.get('timestamp', pd.Series()), errors='coerce')
        hours = ts.dt.hour.dropna()

        profile = {
            'entity_id': entity_id,
            'last_updated': datetime.utcnow().isoformat(),
            'event_count': len(events_df),
            'active_hours_mean': float(hours.mean()) if len(hours) > 0 else 12.0,
            'active_hours_std': float(hours.std()) if len(hours) > 1 else 2.0,
            'unique_processes': int(
                events_df.get('process_name', pd.Series()).nunique()
            ),
            'cmdline_entropy_mean': float(
                events_df.get('cmdline', pd.Series(''))
                .fillna('').apply(shannon_entropy).mean()
            ),
            'unique_dest_ips': int(
                events_df.get('destination_ip', pd.Series()).nunique()
            ),
        }

        try:
            self.es.index(
                index='sentinel-profiles',
                id=entity_id,
                document=profile
            )
        except Exception as e:
            print(f"Profile save error: {e}")

        return profile

    def train_entity_model(self, entity_id, days=30):
        """Train or retrain Isolation Forest for one entity"""
        print(f"Training model for: {entity_id}")
        events = self.get_entity_events(entity_id, days=days)

        if events.empty:
            print(f"  No events found — using sample data for {entity_id}")
            from data.sample_data_generator import SampleDataGenerator
            gen = SampleDataGenerator()
            events = pd.DataFrame(
                gen.generate_baseline(entity_id, days=7, events_per_day=50)
            )

        model = BehavioralBaselineModel(entity_id)
        model.train(events)
        model.save()

        self.models[entity_id] = model
        self.build_statistical_profile(entity_id, events)

        return model

    def get_model(self, entity_id):
        if entity_id not in self.models:
            model = BehavioralBaselineModel(entity_id)
            try:
                model.load()
                self.models[entity_id] = model
            except Exception:
                self.train_entity_model(entity_id)
        return self.models.get(entity_id)

    def train_all_entities(self, entity_ids):
        """Train models for a list of entities"""
        for entity_id in entity_ids:
            self.train_entity_model(entity_id)
        print(f"\nTrained {len(entity_ids)} entity models")


if __name__ == '__main__':
    manager = EntityProfileManager()

    test_entities = ['WIN-007', 'WIN-003', 'SRV-01']
    for entity in test_entities:
        model = manager.train_entity_model(entity)
        print(f"Model ready for {entity}: {model.is_trained}")
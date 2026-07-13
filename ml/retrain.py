import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from elasticsearch import Elasticsearch
import pandas as pd
from ml.risk_scorer import RiskScorer
from config import ELASTICSEARCH_HOST, ALERT_INDEX


def retrain_from_feedback():
    es = Elasticsearch(ELASTICSEARCH_HOST)

    result = es.search(
        index=ALERT_INDEX,
        body={
            'query': {'exists': {'field': 'false_positive'}},
            'size': 10000
        }
    )

    records = [hit['_source'] for hit in result['hits']['hits']]

    if len(records) < 10:
        print("Not enough labeled data for retraining yet")
        print(f"Labeled alerts found: {len(records)}")
        return

    df = pd.DataFrame(records)
    print(f"Retraining on {len(df)} labeled alerts")

    scorer = RiskScorer()
    print("Retraining complete")
    scorer.save()


if __name__ == '__main__':
    retrain_from_feedback()
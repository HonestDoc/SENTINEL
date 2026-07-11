# SENTINEL/reports/coverage_reporter.py
# Runs on: HOST Windows 11

from elasticsearch import Elasticsearch
import json
from datetime import datetime
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ELASTICSEARCH_HOST, ALERT_INDEX
from ml.mitre_mapper import MitreMapper

class CoverageReporter:
    def __init__(self):
        self.es = Elasticsearch(ELASTICSEARCH_HOST)
        self.mapper = MitreMapper()

    def get_detected_techniques(self, days=30):
        result = self.es.search(
            index=ALERT_INDEX,
            body={
                'query': {'range': {'@timestamp': {'gte': f'now-{days}d'}}},
                'aggs': {
                    'techniques': {
                        'terms': {'field': 'mitre_technique', 'size': 500}
                    }
                },
                'size': 0
            }
        )
        return {
            b['key']
            for b in result['aggregations']['techniques']['buckets']
            if b['key']
        }

    def generate_report(self):
        detected = self.get_detected_techniques()
        coverage = self.mapper.coverage_report(detected)

        total_techniques = sum(v['total'] for v in coverage.values())
        total_covered = sum(v['detected'] for v in coverage.values())
        overall_pct = round(total_covered / max(total_techniques, 1) * 100, 1)

        report = {
            'generated_at': datetime.utcnow().isoformat(),
            'overall_coverage_pct': overall_pct,
            'total_techniques': total_techniques,
            'covered_techniques': total_covered,
            'by_tactic': coverage,
            'top_gaps': []
        }

        # Find biggest coverage gaps
        for tactic, data in coverage.items():
            if data['coverage_pct'] < 30 and data['total'] > 0:
                report['top_gaps'].append({
                    'tactic': tactic,
                    'coverage_pct': data['coverage_pct'],
                    'uncovered_count': data['total'] - data['detected'],
                    'priority': 'HIGH' if data['total'] > 10 else 'MEDIUM'
                })

        report['top_gaps'].sort(key=lambda x: x['uncovered_count'], reverse=True)

        # Save report
        os.makedirs('reports', exist_ok=True)
        filename = f"reports/coverage_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\nDetection Coverage Report")
        print(f"Generated: {report['generated_at']}")
        print(f"Overall:   {overall_pct}% ({total_covered}/{total_techniques} techniques)")
        print(f"\nBy Tactic:")
        for tactic, data in coverage.items():
            if data['total'] > 0:
                bar = '█' * int(data['coverage_pct'] / 10) + '░' * (10 - int(data['coverage_pct'] / 10))
                print(f"  {tactic:<30} [{bar}] {data['coverage_pct']}%")

        print(f"\nTop Coverage Gaps:")
        for gap in report['top_gaps'][:5]:
            print(f"  [{gap['priority']}] {gap['tactic']}: "
                  f"{gap['uncovered_count']} uncovered techniques")

        return report


if __name__ == '__main__':
    reporter = CoverageReporter()
    reporter.generate_report()

# SENTINEL/detection/rule_compiler.py
# Runs on: HOST Windows 11
# Converts Sigma YAML rules to Elasticsearch Lucene queries

import subprocess
import json
import yaml
import uuid
from pathlib import Path


class SigmaRuleCompiler:
    """
    Converts Sigma rules to Elasticsearch Lucene queries.
    Output: compiled_rules.json used by SigmaEngine.
    """

    def __init__(self, rules_dir='detection/rules',
                 output_file='detection/compiled_rules.json'):
        self.rules_dir = rules_dir
        self.output_file = output_file

    def compile_rule(self, rule_path):
        """Convert a single Sigma rule to ES Lucene query"""
        try:
            result = subprocess.run(
                [
                    r'.\venv\Scripts\sigma.exe',
                    'convert',
                    '-t', 'lucene',
                    '-p', 'ecs_windows',
                    str(rule_path)
                ],
                capture_output=True,
                text=True
            )

            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().splitlines()
                return lines[-1]

            print(result.stderr)
            return None

        except Exception as e:
            print(f"Compile error for {rule_path}: {e}")
            return None

    def load_rule_metadata(self, rule_path):
        """Load rule title, tags, severity from YAML"""
        with open(rule_path, 'r') as f:
            return yaml.safe_load(f)

    def compile_all(self):
        """Compile all Sigma rules in rules directory"""
        compiled = {}
        rule_paths = list(Path(self.rules_dir).rglob('*.yml'))
        print(f"Found {len(rule_paths)} rule files")

        for rule_path in rule_paths:
            metadata = self.load_rule_metadata(rule_path)
            if not metadata:
                continue

            rule_id = metadata.get('id', str(uuid.uuid4()))
            query = self.compile_rule(rule_path)

            if query:
                compiled[rule_id] = {
                    'id': rule_id,
                    'title': metadata.get('title', ''),
                    'description': metadata.get('description', ''),
                    'level': metadata.get('level', 'medium'),
                    'tags': metadata.get('tags', []),
                    'falsepositives': metadata.get('falsepositives', []),
                    'query': query,
                    'rule_file': str(rule_path)
                }
                print(f"  ✓ Compiled: {metadata.get('title', rule_path)}")
            else:
                print(f"  ✗ Failed:   {rule_path.name}")

        with open(self.output_file, 'w') as f:
            json.dump(compiled, f, indent=2)

        print(f"\nCompiled {len(compiled)}/{len(rule_paths)} rules")
        print(f"Saved to: {self.output_file}")
        return compiled


if __name__ == '__main__':
    compiler = SigmaRuleCompiler()
    compiled = compiler.compile_all()
    print(f"\nFirst rule ID: {list(compiled.keys())[0] if compiled else 'none'}")
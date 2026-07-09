# SENTINEL/ml/ttp_data_builder.py
# Runs on: HOST Windows 11

import json
import numpy as np
import os

class TTPSequenceDataBuilder:
    """
    Builds training data for TTP sequence prediction model.
    Uses MITRE ATT&CK group-to-technique data.
    """

    # Known APT technique chains (manually curated from ATT&CK)
    APT_CHAINS = {
        'APT29': [
            'T1566', 'T1059.001', 'T1547.001', 'T1078', 'T1021.002',
            'T1003.001', 'T1018', 'T1083', 'T1071.001', 'T1041'
        ],
        'APT28': [
            'T1566', 'T1059', 'T1053', 'T1078', 'T1021',
            'T1003', 'T1016', 'T1071', 'T1048'
        ],
        'Lazarus': [
            'T1566', 'T1059.003', 'T1036', 'T1547', 'T1021.001',
            'T1003', 'T1082', 'T1071.001', 'T1041', 'T1486'
        ],
        'FIN7': [
            'T1566', 'T1059.001', 'T1059.003', 'T1053.005',
            'T1078', 'T1021.002', 'T1074', 'T1041'
        ],
        'Ransomware': [
            'T1566', 'T1059', 'T1547', 'T1078', 'T1021',
            'T1003', 'T1490', 'T1486'
        ]
    }

    def __init__(self, vocab_path='data/processed/ttp_vocab.json'):
        self.vocab_path = vocab_path
        self.vocab = {}
        self.reverse_vocab = {}

    def build_vocab(self, all_chains):
        """Build TTP ID → integer mapping"""
        all_ttps = set()
        for chain in all_chains:
            all_ttps.update(chain)

        # Reserve 0 for padding
        self.vocab = {'<PAD>': 0}
        for i, ttp in enumerate(sorted(all_ttps), start=1):
            self.vocab[ttp] = i

        self.reverse_vocab = {v: k for k, v in self.vocab.items()}

        os.makedirs(os.path.dirname(self.vocab_path), exist_ok=True)
        with open(self.vocab_path, 'w') as f:
            json.dump(self.vocab, f, indent=2)

        print(f"Vocabulary: {len(self.vocab)} TTP tokens")
        return self.vocab

    def load_vocab(self):
        if os.path.exists(self.vocab_path):
            with open(self.vocab_path, 'r') as f:
                self.vocab = json.load(f)
            self.reverse_vocab = {v: k for k, v in self.vocab.items()}
            return self.vocab
        return None

    def get_base_chains(self):
        """Get all APT chains as training sequences"""
        chains = list(self.APT_CHAINS.values())

        # Also try to load from MITRE STIX if available
        stix_path = 'data/raw/enterprise-attack.json'
        if os.path.exists(stix_path):
            try:
                chains.extend(self._extract_from_stix(stix_path))
                print(f"Loaded additional chains from STIX")
            except Exception as e:
                print(f"Could not load STIX: {e}")

        return chains

    def _extract_from_stix(self, stix_path):
        """Extract technique chains from MITRE STIX data"""
        tactic_order = [
            'reconnaissance', 'resource-development', 'initial-access',
            'execution', 'persistence', 'privilege-escalation',
            'defense-evasion', 'credential-access', 'discovery',
            'lateral-movement', 'collection', 'command-and-control',
            'exfiltration', 'impact'
        ]

        with open(stix_path, 'r') as f:
            data = json.load(f)

        tech_tactics = {}
        for obj in data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                tech_id = ''
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        tech_id = ref.get('external_id', '')
                if not tech_id:
                    continue
                tactics = [
                    p.get('phase_name', '')
                    for p in obj.get('kill_chain_phases', [])
                    if p.get('kill_chain_name') == 'mitre-attack'
                ]
                if tactics:
                    tech_tactics[tech_id] = min(
                        [tactic_order.index(t) for t in tactics
                         if t in tactic_order],
                        default=99
                    )

        chains = []
        for obj in data.get('objects', []):
            if obj.get('type') == 'intrusion-set':
                techniques = []
                for rel in data.get('objects', []):
                    if (rel.get('type') == 'relationship'
                            and rel.get('relationship_type') == 'uses'
                            and rel.get('source_ref') == obj.get('id')):
                        target = rel.get('target_ref', '')
                        for t_obj in data.get('objects', []):
                            if (t_obj.get('id') == target
                                    and t_obj.get('type') == 'attack-pattern'):
                                for ref in t_obj.get('external_references', []):
                                    if ref.get('source_name') == 'mitre-attack':
                                        techniques.append(
                                            ref.get('external_id', '')
                                        )

                if len(techniques) >= 3:
                    sorted_techs = sorted(
                        techniques,
                        key=lambda t: tech_tactics.get(t, 99)
                    )
                    chains.append(sorted_techs)

        return chains

    def augment_sequences(self, base_chains, factor=10):
        """Augment training data via random subsequence sampling"""
        augmented = []
        for chain in base_chains:
            augmented.append(chain)  # original
            for _ in range(factor):
                if len(chain) < 3:
                    continue
                start = np.random.randint(0, len(chain) - 2)
                end = np.random.randint(start + 2, len(chain) + 1)
                augmented.append(chain[start:end])
        return augmented

    def build_training_pairs(self, sequences, window=5):
        """
        Build (input_sequence, target) pairs for training.
        Input: last `window` TTPs
        Target: next TTP
        """
        pairs = []
        for seq in sequences:
            for i in range(1, len(seq)):
                input_seq = seq[max(0, i - window):i]
                target = seq[i]
                if target in self.vocab and all(
                    t in self.vocab for t in input_seq
                ):
                    input_ids = [self.vocab[t] for t in input_seq]
                    target_id = self.vocab[target]
                    pairs.append((input_ids, target_id))
        return pairs


if __name__ == '__main__':
    builder = TTPSequenceDataBuilder()
    chains = builder.get_base_chains()
    print(f"Base chains: {len(chains)}")

    vocab = builder.build_vocab(chains)
    print(f"Vocab size: {len(vocab)}")

    augmented = builder.augment_sequences(chains, factor=10)
    print(f"Augmented sequences: {len(augmented)}")

    pairs = builder.build_training_pairs(augmented)
    print(f"Training pairs: {len(pairs)}")

    # Show example
    example_input, example_target = pairs[0]
    print(f"\nExample:")
    print(f"  Input TTPs: {[builder.reverse_vocab[i] for i in example_input]}")
    print(f"  Target TTP: {builder.reverse_vocab[example_target]}")
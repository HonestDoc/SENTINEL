# SENTINEL/ml/ttp_predictor.py
# Runs on: HOST Windows 11

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import numpy as np
import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.ttp_data_builder import TTPSequenceDataBuilder

class TTPDataset(Dataset):
    def __init__(self, pairs, max_seq_len=5):
        self.pairs = pairs
        self.max_seq_len = max_seq_len

    def __len__(self):
        return len(self.pairs)

    def __getitem__(self, idx):
        input_ids, target_id = self.pairs[idx]
        # Pad to max_seq_len
        padded = [0] * (self.max_seq_len - len(input_ids)) + input_ids
        padded = padded[-self.max_seq_len:]
        return (
            torch.tensor(padded, dtype=torch.long),
            torch.tensor(target_id, dtype=torch.long)
        )

class TTPSequenceModel(nn.Module):
    """
    LSTM-based next-TTP predictor.
    Given last N TTPs, predicts most likely next technique.
    Architecture chosen because attacks are temporal sequences
    with long-range dependencies.
    """

    def __init__(self, vocab_size, embed_dim=64,
                  hidden_dim=128, n_layers=2, dropout=0.3):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, n_layers,
                            batch_first=True, dropout=dropout)
        self.dropout = nn.Dropout(dropout)
        self.output_layer = nn.Linear(hidden_dim, vocab_size)

    def forward(self, x):
        embedded = self.dropout(self.embedding(x))
        lstm_out, _ = self.lstm(embedded)
        last_hidden = lstm_out[:, -1, :]
        logits = self.output_layer(self.dropout(last_hidden))
        return logits

class TTPPredictor:
    def __init__(self, vocab_path='data/processed/ttp_vocab.json',
                  model_path='data/models/ttp_predictor.pt'):
        self.vocab_path = vocab_path
        self.model_path = model_path
        self.vocab = {}
        self.reverse_vocab = {}
        self.model = None
        self.device = torch.device(
            'cuda' if torch.cuda.is_available() else 'cpu'
        )

    def train(self, epochs=50, batch_size=32):
        """Build data and train LSTM model"""
        builder = TTPSequenceDataBuilder(self.vocab_path)
        chains = builder.get_base_chains()

        if not builder.load_vocab():
            builder.build_vocab(chains)

        self.vocab = builder.vocab
        self.reverse_vocab = builder.reverse_vocab

        augmented = builder.augment_sequences(chains, factor=15)
        pairs = builder.build_training_pairs(augmented)

        if not pairs:
            print("No training pairs — check data")
            return

        print(f"Training on {len(pairs)} pairs, "
              f"vocab size: {len(self.vocab)}")

        dataset = TTPDataset(pairs)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        self.model = TTPSequenceModel(
            vocab_size=len(self.vocab),
            embed_dim=64,
            hidden_dim=128,
            n_layers=2
        ).to(self.device)

        optimizer = optim.Adam(self.model.parameters(), lr=0.001)
        criterion = nn.CrossEntropyLoss(ignore_index=0)
        scheduler = optim.lr_scheduler.StepLR(
            optimizer, step_size=20, gamma=0.5
        )

        self.model.train()
        for epoch in range(epochs):
            total_loss = 0
            correct = 0
            total = 0

            for inputs, targets in loader:
                inputs, targets = inputs.to(self.device), targets.to(self.device)
                optimizer.zero_grad()
                outputs = self.model(inputs)
                loss = criterion(outputs, targets)
                loss.backward()
                nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()

                total_loss += loss.item()
                preds = outputs.argmax(dim=1)
                correct += (preds == targets).sum().item()
                total += len(targets)

            scheduler.step()

            if (epoch + 1) % 10 == 0:
                acc = correct / total * 100
                print(f"Epoch {epoch+1}/{epochs}: "
                      f"Loss={total_loss/len(loader):.4f}, "
                      f"Acc={acc:.1f}%")

        self.save()
        print(f"TTP predictor trained and saved")

    def predict(self, observed_ttps, top_k=3):
        """
        Given observed TTP sequence, predict most likely next TTPs.
        Returns list of (ttp_id, probability) tuples.
        """
        if self.model is None:
            self.load()

        if not observed_ttps:
            return []

        # Encode input
        input_ids = [
            self.vocab.get(t, 0) for t in observed_ttps[-5:]
        ]

        # Pad to length 5
        padded = [0] * (5 - len(input_ids)) + input_ids
        input_tensor = torch.tensor(
            [padded], dtype=torch.long
        ).to(self.device)

        self.model.eval()
        with torch.no_grad():
            logits = self.model(input_tensor)
            probs = torch.softmax(logits, dim=-1)[0]

        # Get top-k predictions (exclude PAD token)
        top_probs, top_indices = torch.topk(probs, top_k + 5)

        results = []
        for prob, idx in zip(top_probs.tolist(), top_indices.tolist()):
            ttp_id = self.reverse_vocab.get(idx, '')
            if ttp_id and ttp_id != '<PAD>':
                results.append((ttp_id, round(prob, 4)))
            if len(results) >= top_k:
                break

        return results

    def save(self):
        os.makedirs('data/models', exist_ok=True)
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'vocab': self.vocab,
            'reverse_vocab': self.reverse_vocab
        }, self.model_path)

    def load(self):
        if not os.path.exists(self.model_path):
            print("No saved model — training now")
            self.train()
            return

        checkpoint = torch.load(self.model_path,
                                  map_location=self.device)
        self.vocab = checkpoint['vocab']
        self.reverse_vocab = checkpoint['reverse_vocab']

        self.model = TTPSequenceModel(
            vocab_size=len(self.vocab)
        ).to(self.device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.eval()
        print(f"TTP predictor loaded from {self.model_path}")


if __name__ == '__main__':
    predictor = TTPPredictor()
    predictor.train(epochs=50)

    test_sequence = ['T1566', 'T1059.001', 'T1547.001']
    predictions = predictor.predict(test_sequence, top_k=3)

    print(f"\nGiven: {test_sequence}")
    print("Predicted next TTPs:")
    for ttp_id, prob in predictions:
        print(f"  {ttp_id}: {prob:.2%}")
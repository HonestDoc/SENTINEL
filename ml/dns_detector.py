# SENTINEL/ml/dns_detector.py
# Runs on: HOST Windows 11
# Input: Zeek dns.log from Ubuntu VM

import pandas as pd
import numpy as np
from collections import Counter
import math
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

def shannon_entropy(text):
    if not text or len(text) == 0:
        return 0.0
    counts = Counter(str(text))
    length = len(str(text))
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

class DNSTunnelingDetector:
    """
    Detects DNS tunneling via statistical analysis of query patterns.
    Also includes a DGA (Domain Generation Algorithm) classifier.
    """

    def __init__(self):
        self.dga_model = None
        self.dga_model_path = 'data/models/dga_classifier.pkl'

    def extract_domain_features(self, domain):
        """Extract features from a single domain name"""
        if not domain:
            return {}

        labels = str(domain).split('.')
        subdomain = '.'.join(labels[:-2]) if len(labels) > 2 else ''
        apex = '.'.join(labels[-2:]) if len(labels) >= 2 else domain

        return {
            'total_length': len(domain),
            'subdomain_length': len(subdomain),
            'label_count': len(labels),
            'max_label_length': max(len(l) for l in labels) if labels else 0,
            'subdomain_entropy': shannon_entropy(subdomain),
            'full_entropy': shannon_entropy(domain.replace('.', '')),
            'digit_ratio': sum(c.isdigit() for c in subdomain) / (len(subdomain) + 1),
            'vowel_ratio': sum(c in 'aeiou' for c in subdomain.lower()) / (len(subdomain) + 1),
            'unique_char_ratio': len(set(subdomain)) / (len(subdomain) + 1),
        }

    def detect_tunneling(self, dns_df, window_minutes=60):
        """Analyze DNS log for tunneling patterns"""
        alerts = []

        if dns_df.empty:
            return alerts

        query_col = 'query' if 'query' in dns_df.columns else 'dns.question.name'
        src_col = 'source.ip' if 'source.ip' in dns_df.columns else 'id.orig_h'
        type_col = 'qtype_name' if 'qtype_name' in dns_df.columns else 'dns.question.type'
        rcode_col = 'rcode_name' if 'rcode_name' in dns_df.columns else 'dns.response_code'

        dns_df = dns_df.copy()
        dns_df['apex_domain'] = dns_df[query_col].apply(
            lambda q: '.'.join(str(q).split('.')[-2:]) if q and '.' in str(q) else str(q)
        )

        for (src, apex), group in dns_df.groupby([src_col, 'apex_domain']):
            query_count = len(group)
            if query_count < 5:
                continue

            txt_ratio = 0.0
            if type_col in group.columns:
                txt_ratio = (group[type_col] == 'TXT').mean()

            nxdomain_ratio = 0.0
            if rcode_col in group.columns:
                nxdomain_ratio = (group[rcode_col] == 'NXDOMAIN').mean()

            mean_length = group[query_col].str.len().mean()
            mean_entropy = group[query_col].apply(
                lambda q: shannon_entropy(str(q))
            ).mean()

            tunnel_score = float(
                (mean_length > 50) * 0.30 +
                (mean_entropy > 3.5) * 0.30 +
                (txt_ratio > 0.2) * 0.20 +
                (query_count > 100) * 0.10 +
                (nxdomain_ratio > 0.3) * 0.10
            )

            if tunnel_score >= 0.5:
                alerts.append({
                    'source_ip': src,
                    'suspect_domain': apex,
                    'tunnel_score': round(tunnel_score, 3),
                    'query_count': query_count,
                    'mean_query_length': round(mean_length, 1),
                    'mean_entropy': round(mean_entropy, 3),
                    'txt_query_ratio': round(txt_ratio, 3),
                    'nxdomain_ratio': round(nxdomain_ratio, 3),
                    'alert_type': 'dns_tunneling',
                    'mitre_technique': 'T1071.004',
                    'explanation': (
                        f"DNS tunneling indicators from {src} to {apex}. "
                        f"Query count: {query_count}, "
                        f"Mean entropy: {mean_entropy:.2f}, "
                        f"Mean length: {mean_length:.0f} chars, "
                        f"TXT ratio: {txt_ratio:.1%}"
                    )
                })

        return alerts

    def train_dga_classifier(self):
        """
        Train Random Forest DGA classifier.
        Requires: Bambenek DGA list + Alexa top 1M domains.
        Uses synthetic data if real datasets unavailable.
        """
        print("Training DGA classifier...")

        # Synthetic training data (replace with real datasets)
        legitimate = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'youtube.com', 'twitter.com',
            'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com',
            'wikipedia.org', 'cloudflare.com', 'fastly.com', 'akamai.com'
        ]

        dga_samples = [
            'xkq7mzpldf.com', 'aabbccdd1122.net', 'zxyw9876qpoi.org',
            'mnbvcxzlkjh.com', 'qwertyu12345.net', 'aaaabbbb1234.com',
            'kdjfhskdjfh.org', 'xncmvbxcvb12.net', 'pqowieur1234.com',
            'zxcvbnmasdf.org', 'lkjhgfdsapo.net', 'mnbvcxzqwert.com'
        ]

        all_domains = legitimate + dga_samples
        labels = [0] * len(legitimate) + [1] * len(dga_samples)

        features = [self.extract_domain_features(d) for d in all_domains]
        X = pd.DataFrame(features).fillna(0)
        y = labels

        self.dga_model = RandomForestClassifier(
            n_estimators=100, random_state=42
        )
        self.dga_model.fit(X, y)

        os.makedirs('data/models', exist_ok=True)
        joblib.dump(self.dga_model, self.dga_model_path)
        print(f"DGA classifier trained and saved")

    def score_domain_dga(self, domain):
        """Return DGA probability for a domain (0=legitimate, 1=DGA)"""
        if self.dga_model is None:
            if os.path.exists(self.dga_model_path):
                self.dga_model = joblib.load(self.dga_model_path)
            else:
                self.train_dga_classifier()

        features = self.extract_domain_features(domain)
        X = pd.DataFrame([features]).fillna(0)
        proba = self.dga_model.predict_proba(X)[0, 1]
        return round(float(proba), 3)


if __name__ == '__main__':
    detector = DNSTunnelingDetector()

    # Test DGA classifier
    detector.train_dga_classifier()
    test_domains = [
        'google.com',
        'microsoft.com',
        'xkq7mzpldf.com',
        'aabbccdd1122.net',
        'github.com'
    ]

    print("\nDGA Scores:")
    for domain in test_domains:
        score = detector.score_domain_dga(domain)
        label = 'DGA' if score > 0.5 else 'Legit'
        print(f"  {domain:<30} {score:.3f}  {label}")

    # Test tunnel detection with synthetic data
    sample_dns = pd.DataFrame([
        {'source.ip': '10.0.0.1', 'query': f'aGVsbG8gd29ybGQ{i}AAAAAA.evil.com',
         'qtype_name': 'TXT', 'rcode_name': 'NOERROR'}
        for i in range(20)
    ] + [
        {'source.ip': '10.0.0.1', 'query': 'google.com',
         'qtype_name': 'A', 'rcode_name': 'NOERROR'}
        for _ in range(5)
    ])

    alerts = detector.detect_tunneling(sample_dns)
    print(f"\nDNS tunneling alerts: {len(alerts)}")
    for alert in alerts:
        print(f"  {alert['source_ip']} -> {alert['suspect_domain']}: "
              f"score={alert['tunnel_score']}")
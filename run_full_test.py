# SENTINEL/run_full_test.py
# Runs on: HOST Windows 11

import time
import subprocess
import sys

print("SENTINEL Full Integration Test")
print("=" * 60)

print("\n[1] Starting Flask API...")
# Start in background: python api/app.py

print("\n[2] Starting behavioral engine...")
from ml.behavioral_engine import BehavioralAnalyticsEngine
engine = BehavioralAnalyticsEngine()

print("\n[3] Running Sigma engine...")
from detection.sigma_engine import SigmaEngine
sigma = SigmaEngine()
sigma.run_all_rules()

print("\n[4] Running behavioral analysis...")
engine.run()

print("\n[5] Testing LLM integration...")
from api.ai_engine import AIAnalysisEngine
ai = AIAnalysisEngine()
test_chain = {
    'host': 'WIN-007',
    'ttp_sequence': ['T1059.001', 'T1021.002'],
    'chain_severity': 'high',
    'timestamps': ['14:22:11', '14:28:45']
}
narrative = ai.generate_incident_narrative(test_chain)
print(f"LLM narrative generated: {len(narrative)} chars")

print("\n[6] Testing TTP predictor...")
from ml.ttp_predictor import TTPPredictor
predictor = TTPPredictor()
predictions = predictor.predict(['T1059.001', 'T1021.002'], top_k=3)
print(f"Predictions: {predictions}")

print("\n" + "=" * 60)
print("Integration test complete")
print("Open http://localhost:5000/api/health to verify API")
print("Open dashboard/graph.html in browser to see graph")
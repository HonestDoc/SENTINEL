import os
from dotenv import load_dotenv

load_dotenv()

ELASTICSEARCH_HOST = os.getenv('ELASTICSEARCH_HOST', 'http://localhost:9200')
ANTHROPIC_API_KEY  = os.getenv('ANTHROPIC_API_KEY', '')
ALERT_INDEX        = os.getenv('ALERT_INDEX', 'sentinel-alerts')
WINDOWS_LOG_INDEX  = os.getenv('WINDOWS_LOG_INDEX', 'sentinel-windows')
ZEEK_LOG_INDEX     = os.getenv('ZEEK_LOG_INDEX', 'sentinel-zeek')

CROWN_JEWEL_HOSTS      = ['DC-01', 'DB-SERVER', 'FILE-SERVER']
ANOMALY_CONTAMINATION  = 0.05
BEACONING_COV_THRESHOLD = 0.3
MIN_BEACON_CONNECTIONS  = 10
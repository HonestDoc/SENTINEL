\# SENTINEL Detection Engine



\## Overview



The SENTINEL detection engine is responsible for running detection logic against normalized security logs stored in Elasticsearch and creating alerts in the `sentinel-alerts` index.



The current detection system supports Sigma-based detections. Sigma rules are written in YAML, compiled into Elasticsearch-compatible queries, and executed by the Sigma engine.



\---



\## Detection Architecture



The detection pipeline follows this flow:



```text

Windows VM / Ubuntu VM

&#x20;       ↓

Winlogbeat / Filebeat

&#x20;       ↓

Elasticsearch

&#x20;       ↓

Logstash normalization

&#x20;       ↓

sentinel-normalized-\* / sentinel-windows-\* / filebeat-\*

&#x20;       ↓

Sigma rule compiler

&#x20;       ↓

compiled\_rules.json

&#x20;       ↓

Sigma engine

&#x20;       ↓

sentinel-alerts

&#x20;       ↓

Kibana Alert Center

# SENTINEL Detection Engine

## ATT&CK Technique Coverage

Current implemented ATT&CK techniques covered: **1**

| Technique | Name | Status |
|---|---|---|
| T1059.001 | PowerShell | Implemented |

## Day 26 Detection Coverage Table

| Technique | Test Name | Detected | Notes |
|---|---|---|---|
| T1059.001 | PowerShell execution | NO | Atomic ran, but Sigma rule did not fire |
| T1053.005 | Scheduled task creation | NO | Missing rule |
| T1136.001 | Local account creation | NO | Missing rule |
| T1003.001 | LSASS credential dump attempt | NO | Missing rule |
| T1018 | Network discovery | NO | Missing rule |

## Detection Engine Architecture

SENTINEL collects Windows, Ubuntu auditd, and Zeek logs using Winlogbeat and Filebeat.

Logs are stored in Elasticsearch. Logstash normalizes logs into `sentinel-normalized-*`.

Sigma rules are stored in `detection/rules/custom/`.

`detection/rule_compiler.py` converts Sigma YAML rules into Elasticsearch queries and saves them in `detection/compiled_rules.json`.

`detection/sigma_engine.py` loads compiled rules, runs them against Elasticsearch, creates SentinelAlert objects, and writes alerts to `sentinel-alerts`.

Alerts are visualized in Kibana using the `SENTINEL Alert Center` dashboard.

## Main Detection Files

| File | Purpose |
|---|---|
| detection/rules/custom/proc_creation_powershell_encoded.yml | Custom Sigma rule |
| detection/rule_compiler.py | Converts Sigma rules |
| detection/compiled_rules.json | Stores compiled rules |
| detection/sigma_engine.py | Runs rules against Elasticsearch |
| detection/alert_schema.py | Defines alert format |
| ingestion/es_writer.py | Writes alerts to Elasticsearch |

## 5-Minute Explanation

SENTINEL collects endpoint and network logs from lab machines and sends them to Elasticsearch.

Winlogbeat collects Windows logs. Filebeat collects Ubuntu auditd and Zeek logs. Logstash normalizes important fields.

Sigma rules are compiled into Elasticsearch queries. The Sigma engine runs those compiled rules against Elasticsearch. If a rule matches, it creates a SentinelAlert and writes it to `sentinel-alerts`.

Kibana has two dashboards: `SENTINEL Overview` for log flow and `SENTINEL Alert Center` for alert investigation.

Current coverage is limited to one implemented ATT&CK technique: T1059.001. More rules are needed for better detection coverage.


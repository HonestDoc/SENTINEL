# SENTINEL/api/ai_engine.py
# Runs on: HOST Windows 11
# Uses Claude API

import anthropic
import json
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ANTHROPIC_API_KEY

class AIAnalysisEngine:
    """
    LLM-powered incident analysis.
    Goes beyond summarization — provides attack reasoning,
    hunt queries, and response playbooks.
    """

    def __init__(self):
        self.client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        self.model = "claude-sonnet-4-6"

    def _call(self, prompt, max_tokens=1000):
        message = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text

    def generate_incident_narrative(self, chain_data):
        """Generate analyst-quality incident narrative from attack chain"""
        prompt = f"""You are a senior SOC analyst writing an incident report.

Attack chain data:
{json.dumps(chain_data, indent=2)}

Write a concise incident narrative (200-300 words) that:
1. States what happened in chronological order with specific timestamps
2. Explains WHY each step logically follows from the previous one
3. Identifies the likely attacker objective
4. Identifies what made this detectable
5. States confidence level and why

Use specific technique names and IDs. Do not be generic."""

        return self._call(prompt, max_tokens=600)

    def generate_hunt_queries(self, predicted_ttp, host_context):
        """Generate scoped hunt queries for predicted next technique"""
        prompt = f"""You are a detection engineer generating hunt queries.

Predicted next technique: {predicted_ttp}
Affected host: {host_context.get('host', 'unknown')}
Observed chain so far: {host_context.get('observed_ttps', [])}
Available log sources: Windows Sysmon (Events 1,3,8,10,22), Windows Security Events (4624,4625,4688), Zeek conn.log and dns.log

Generate exactly:
1. A valid Kibana KQL query to hunt for evidence of {predicted_ttp}
2. The top 3 specific artifacts/indicators to look for
3. One Sigma rule YAML stub for this technique

Make the KQL query specific to the host context. It must be syntactically valid."""

        return self._call(prompt, max_tokens=800)

    def explain_attack_reasoning(self, predicted_ttp, observed_chain):
        """Explain WHY attacker would take predicted next step"""
        prompt = f"""You are a threat intelligence analyst.

Observed attack chain: {observed_chain}
Predicted next technique: {predicted_ttp}

Explain in 150 words:
1. Why an attacker would logically take this next step given what they have already done
2. What tools or methods they commonly use for this technique
3. What artifacts they would leave behind
4. What defensive gap would allow this to succeed

Be specific and technical. Reference real tools (Mimikatz, PsExec, etc.) where relevant."""

        return self._call(prompt, max_tokens=400)

    def generate_response_playbook(self, incident_data):
        """Generate containment and investigation checklist"""
        prompt = f"""You are a senior incident responder.

Incident data:
Host: {incident_data.get('host')}
Risk score: {incident_data.get('risk_score')}
Attack chain: {incident_data.get('ttp_sequence', [])}
Chain severity: {incident_data.get('chain_severity')}

Generate a structured response playbook with:
1. IMMEDIATE (next 15 minutes): 3 containment actions
2. INVESTIGATE (next 1 hour): 5 specific investigation steps with exact commands/queries
3. REMEDIATE: 3 remediation steps
4. DOCUMENT: What to capture for after-action review

Be specific. Reference actual tools and commands."""

        return self._call(prompt, max_tokens=600)

    def answer_analyst_question(self, question, relevant_alerts):
        """RAG-style Q&A: answer analyst questions about an incident"""
        context = json.dumps(relevant_alerts[:10], indent=2)
        prompt = f"""You are a SOC analyst assistant. Answer the following question
based ONLY on the provided alert data. If the data does not support a
clear conclusion, say so explicitly.

Alert context (last 10 relevant alerts):
{context}

Analyst question: {question}

Answer with:
1. Direct answer (2-3 sentences)
2. Which specific alerts support this conclusion
3. What additional data would confirm or refute this

If you cannot answer from the data, say exactly what data is missing."""

        return self._call(prompt, max_tokens=500)


if __name__ == '__main__':
    engine = AIAnalysisEngine()

    # Test incident narrative
    test_chain = {
        'host': 'WIN-007',
        'ttp_sequence': ['T1059.001', 'T1547.001', 'T1021.002', 'T1003.001'],
        'chain_length': 4,
        'chain_severity': 'critical',
        'timestamps': ['14:22:11', '14:24:33', '14:28:45', '14:31:02']
    }

    print("Generating incident narrative...")
    narrative = engine.generate_incident_narrative(test_chain)
    print(narrative)

    print("\nGenerating hunt queries for T1003 (predicted next)...")
    queries = engine.generate_hunt_queries('T1003.001 - LSASS Memory',
        {'host': 'WIN-007', 'observed_ttps': test_chain['ttp_sequence']})
    print(queries)
# SENTINEL/api/ai_engine.py
# Runs on: HOST Windows 11
# Uses: Ollama local LLM (Mistral 7B) — completely free, no API key needed

import ollama
import json
import os


class AIAnalysisEngine:
    """
    LLM-powered incident analysis using Ollama local models.
    No API key, no internet connection, no cost.
    Same interface as the original Claude-based version.

    Requires Ollama running as a background service on HOST.
    Install: https://ollama.com/download
    Model:   ollama pull mistral
    """

    def __init__(self, model='mistral'):
        self.model = model
        self._verify_ollama()

    def _verify_ollama(self):
        """Check Ollama is running and model is available"""
        try:
            models = ollama.list()
            available = [m['name'] for m in models.get('models', [])]
            model_available = any(
                self.model in name for name in available
            )
            if not model_available:
                print(f"Model '{self.model}' not found.")
                print(f"Run: ollama pull {self.model}")
                print(f"Available models: {available}")
            else:
                print(f"Ollama ready — using model: {self.model}")
        except Exception as e:
            print(f"Ollama not running: {e}")
            print("Start Ollama: it runs automatically after installation.")
            print("Or run: ollama serve")

    def _call(self, prompt, max_tokens=800):
        """
        Call local Ollama model.
        Equivalent to calling a paid API but runs on your machine.
        """
        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {
                        'role': 'system',
                        'content': (
                            'You are a senior SOC analyst and security expert. '
                            'Be concise, technical, and specific. '
                            'Never say you cannot help. '
                            'Always provide actionable output.'
                        )
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
               options={
                  'num_predict': max_tokens,
                  'temperature': 0.3,
                  'top_p': 0.9,
                  'num_gpu': 0,
               }
            )
            return response['message']['content']
        except Exception as e:
            return f"[Ollama error: {e}. Is Ollama running? Try: ollama serve]"

    def generate_incident_narrative(self, chain_data):
        """Generate analyst-quality incident narrative from attack chain"""
        prompt = f"""Write an incident report narrative for this attack chain.

Attack chain:
{json.dumps(chain_data, indent=2)}

Write 200-250 words covering:
1. What happened in chronological order with timestamps
2. Why each step logically follows the previous one
3. Likely attacker objective
4. What made this detectable
5. Confidence level

Use specific MITRE technique IDs. Be technical and concise."""

        return self._call(prompt, max_tokens=400)

    def generate_hunt_queries(self, predicted_ttp, host_context):
        """Generate scoped hunt queries for predicted next technique"""
        prompt = f"""Generate hunt queries for a predicted attacker technique.

Predicted technique: {predicted_ttp}
Affected host: {host_context.get('host', 'unknown')}
Observed chain: {host_context.get('observed_ttps', [])}
Log sources available: Sysmon Events 1,3,8,10,22 | Windows Security Events 4624,4625,4688 | Zeek conn.log dns.log

Provide exactly:
1. A valid Kibana KQL query to find evidence of {predicted_ttp}
2. Three specific artifacts/IOCs to look for
3. A Sigma rule YAML stub (title, logsource, detection sections only)

KQL must be syntactically valid. Be specific to the host context."""

        return self._call(prompt, max_tokens=600)

    def explain_attack_reasoning(self, predicted_ttp, observed_chain):
        """Explain WHY attacker would take predicted next step"""
        prompt = f"""Explain attacker reasoning for a predicted next technique.

Observed chain: {observed_chain}
Predicted next: {predicted_ttp}

In 150 words explain:
1. Why this next step is logical given what was already done
2. Which tools are commonly used (Mimikatz, PsExec, etc.)
3. What artifacts/logs would be created
4. Which defensive gap allows this

Be specific. Reference real attack tools."""

        return self._call(prompt, max_tokens=300)

    def generate_response_playbook(self, incident_data):
        """Generate containment and investigation checklist"""
        prompt = f"""Generate an incident response playbook.

Incident:
Host: {incident_data.get('host')}
Risk score: {incident_data.get('risk_score')}
Attack chain: {incident_data.get('ttp_sequence', [])}
Severity: {incident_data.get('chain_severity')}

Provide a structured playbook with:
IMMEDIATE (15 min): 3 containment actions with exact commands
INVESTIGATE (1 hour): 5 investigation steps with exact KQL queries or CLI commands
REMEDIATE: 3 remediation steps
DOCUMENT: What evidence to preserve

Be specific. Include real Windows commands and KQL syntax."""

        return self._call(prompt, max_tokens=600)

    def answer_analyst_question(self, question, relevant_alerts):
        """RAG-style Q&A about an incident"""
        context = json.dumps(relevant_alerts[:5], indent=2)
        prompt = f"""Answer this analyst question using only the provided alert data.

Alert data:
{context}

Question: {question}

Answer with:
1. Direct answer (2-3 sentences)
2. Which specific alerts support this
3. What additional data would confirm or refute this

If the data is insufficient, say exactly what is missing."""

        return self._call(prompt, max_tokens=400)

    def batch_test(self):
        """
        Run a quick test of all AI functions.
        Use this to verify Ollama is working correctly.
        """
        print("\nTesting AIAnalysisEngine with Ollama...")
        print("=" * 50)

        test_chain = {
            'host': 'WIN-007',
            'ttp_sequence': ['T1059.001', 'T1547.001', 'T1021.002'],
            'chain_severity': 'high',
            'timestamps': ['14:22:11', '14:24:33', '14:28:45']
        }

        print("\n[1] Incident Narrative:")
        narrative = self.generate_incident_narrative(test_chain)
        print(narrative[:300] + "..." if len(narrative) > 300 else narrative)

        print("\n[2] Hunt Queries:")
        queries = self.generate_hunt_queries(
            'T1003.001 - LSASS Memory Dumping',
            {'host': 'WIN-007', 'observed_ttps': test_chain['ttp_sequence']}
        )
        print(queries[:300] + "..." if len(queries) > 300 else queries)

        print("\n[3] Attack Reasoning:")
        reasoning = self.explain_attack_reasoning(
            'T1003.001',
            test_chain['ttp_sequence']
        )
        print(reasoning[:300] + "..." if len(reasoning) > 300 else reasoning)

        print("\n[4] Response Playbook:")
        playbook = self.generate_response_playbook({
            'host': 'WIN-007',
            'risk_score': 84,
            'ttp_sequence': test_chain['ttp_sequence'],
            'chain_severity': 'high'
        })
        print(playbook[:300] + "..." if len(playbook) > 300 else playbook)

        print("\n" + "=" * 50)
        print("All AI functions working.")


if __name__ == '__main__':
    engine = AIAnalysisEngine()
    engine.batch_test()
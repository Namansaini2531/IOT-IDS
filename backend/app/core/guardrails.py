import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class GuardrailResult:
    is_allowed: bool
    category: Optional[str] = None
    reason: Optional[str] = None
    refusal_message: Optional[str] = None


# =====================================================================
# Guardrail Patterns
# =====================================================================

# 1. Prompt Injection & Jailbreak Heuristics
PROMPT_INJECTION_PATTERNS = [
    r"(?i)\bignore\s+(all\s+|your\s+)?(previous|prior|above|system)\s+(instructions?|directives?|rules?|prompts?)\b",
    r"(?i)\bdisregard\s+(all\s+)?(previous|prior|system)\s+(instructions?|prompts?|rules?)\b",
    r"(?i)\b(reveal|display|output|show|print|leak|repeat)\s+(the\s+)?(system\s+prompt|initial\s+prompt|secret\s+key|api\s*key|internal\s+instructions?)\b",
    r"(?i)\bwhat\s+(is|are)\s+your\s+(initial\s+prompt|system\s+prompt|hidden\s+instructions?|api\s*key|groq\s*key)\b",
    r"(?i)\b(dan\s+mode|jailbreak|unrestricted\s+mode|do\s+anything\s+now|developer\s+mode\s+enabled)\b",
    r"(?i)\b(you\s+are\s+now\s+(an?\s+)?unfiltered|pretend\s+you\s+have\s+no\s+(rules|ethics|guardrails))\b",
    r"(?i)\b(bypass\s+(safety|content\s+filter|guardrails?|restrictions?))\b"
]

# 2. Malicious Weaponization & Cyber Harms (Offensive Exploitation)
WEAPONIZATION_PATTERNS = [
    # Authoring malware, ransomware, botnets, keyloggers
    r"(?i)\b(write|create|code|generate|build|make)\s+(an?\s+)?(executable\s+)?(ransomware|keylogger|worm|trojan|rootkit|spyware|wiper|c2\s+server|botnet(\s+malware)?)\b",
    r"(?i)\b(write|create|code|generate)\s+a\s+(ddos|dos|packet\s+flooder)\s+(script|tool|program|bot)\b",
    r"(?i)\b(write|generate|craft)\s+(an?\s+)?(exploit\s+payload|reverse\s+shell\s+payload|zero-?day\s+exploit|buffer\s+overflow\s+exploit)\b",
    r"(?i)\b(how\s+to\s+infiltrate|how\s+to\s+hack\s+into|hack\s+someone(\'s)?|breach\s+without\s+permission)\b",
    r"(?i)\b(phishing\s+template|credential\s+stealer|harvest\s+passwords\s+from)\b",
    r"(?i)\b(exploit\s+code\s+targeting|attack\s+victim\s+at)\b"
]

# 3. Off-Topic Domain Whitelist / Relevance Keywords
CYBER_SECURITY_KEYWORDS = [
    "iot", "ids", "ips", "network", "firewall", "iptables", "ufw", "cisco", "acl",
    "threat", "attack", "anomaly", "malware", "botnet", "mirai", "ddos", "dos",
    "reconnaissance", "spoofing", "bruteforce", "port", "packet", "pcap", "flow",
    "telemetry", "traffic", "autoencoder", "classifier", "machine learning", "ml",
    "ip", "mac", "dns", "arp", "tcp", "udp", "http", "mqtt", "coap", "telnet",
    "ssh", "quarantine", "containment", "mitigation", "cve", "vulnerability",
    "incident", "soc", "forensic", "security", "defense", "payload", "triage",
    "pipeline", "reconstruction", "detector", "device", "endpoint", "zero trust"
]

OFF_TOPIC_EXCLUSION_PATTERNS = [
    r"(?i)\b(write\s+(a\s+)?(poem|song|story|essay\s+about|romance|screenplay))\b",
    r"(?i)\b(recipe\s+for|cook(ing)?\s+directions?|baking\s+cake)\b",
    r"(?i)\b(dating\s+advice|horoscope|astrology\s+reading)\b",
    r"(?i)\b(who\s+won\s+the\s+(super\s*bowl|world\s*cup|oscar|grammy|presidential\s+election))\b"
]

# Output Secret Redaction Pattern
SECRET_REDACTION_PATTERNS = [
    (re.compile(r"gsk_[a-zA-Z0-9]{20,}", re.IGNORECASE), "[REDACTED_API_KEY]"),
    (re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]"), "api_key=[REDACTED]")
]


# =====================================================================
# Guardrail Validation Engine
# =====================================================================

def validate_user_input(prompt: str) -> GuardrailResult:
    """
    Evaluates input prompt through multi-stage security guardrails:
    1. Prompt Injection / Jailbreak Filter
    2. Weaponization & Malware Generation Filter
    3. Off-Topic Domain Guardrail
    """
    cleaned = prompt.strip()
    if not cleaned:
        return GuardrailResult(
            is_allowed=False,
            category="EMPTY_INPUT",
            reason="Empty prompt received",
            refusal_message="Please enter a valid cybersecurity or IoT incident query."
        )

    # 1. Prompt Injection Check
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, cleaned):
            return GuardrailResult(
                is_allowed=False,
                category="PROMPT_INJECTION",
                reason="Adversarial prompt injection or system override detected",
                refusal_message=(
                    "🛡️ **CortexIO Guardrail Alert [Policy Violation - Injection Defense]:**\n\n"
                    "Your request was flagged for attempting to modify, bypass, or reveal system guardrails. "
                    "The AI Cyber Advisor operates exclusively under strict defensive SOC operational protocols."
                )
            )

    # 2. Weaponization / Cyber Harms Check
    for pattern in WEAPONIZATION_PATTERNS:
        if re.search(pattern, cleaned):
            # Check if this is an explicit defensive containment question
            if any(term in cleaned.lower() for term in ["block", "prevent", "mitigate", "detect", "remediate", "stop", "contain", "defend"]):
                continue  # Allow defensive inquiry
            return GuardrailResult(
                is_allowed=False,
                category="MALICIOUS_WEAPONIZATION",
                reason="Request asks for offensive exploit, attack script, or malware creation",
                refusal_message=(
                    "🛡️ **CortexIO Guardrail Alert [Policy Violation - Offensive Code Restriction]:**\n\n"
                    "Generating offensive exploit tools, ransomware, weaponized attack payloads, or malware scripts "
                    "is strictly prohibited under CortexIO Defense Safety Guidelines.\n\n"
                    "**Permitted Assistance:**\n"
                    "- Generating firewall blocking rules (e.g. `iptables`, `ufw`)\n"
                    "- IoT endpoint isolation and quarantine playbooks\n"
                    "- Root-cause forensic analysis of network anomalies\n"
                    "- Threat signature identification and remediation guidance"
                )
            )

    # 3. Off-Topic Guardrail Check
    for pattern in OFF_TOPIC_EXCLUSION_PATTERNS:
        if re.search(pattern, cleaned):
            return GuardrailResult(
                is_allowed=False,
                category="OFF_TOPIC",
                reason="Out of domain query detected",
                refusal_message=(
                    "🛡️ **CortexIO Guardrail [Out of Scope]:**\n\n"
                    "CortexIO AI Advisor is a specialized IoT Incident Response & Network Defense system. "
                    "I am focused solely on IoT security, anomaly telemetry, firewall containment, and threat triage. "
                    "Please ask a question related to IoT network security or your scanned traffic."
                )
            )

    return GuardrailResult(is_allowed=True)


def sanitize_ai_output(content: str) -> str:
    """
    Scans the LLM output for sensitive secret leaks or accidental credential exposure.
    """
    sanitized = content
    for pattern, replacement in SECRET_REDACTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized

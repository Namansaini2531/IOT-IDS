import os
import json
import httpx
from typing import Dict, Any, List, Optional

SYSTEM_PROMPT = """You are CortexIO AI Cyber Defense Advisor, a Tier-3 IoT Incident Response & SOC Security Specialist.
You have direct real-time access to telemetry and alerts from an AI-based Network Intrusion and Anomaly Detection System (IoT-IDS).

The system uses a 2-Stage Machine Learning Pipeline:
1. Stage 1: Benign-Trained Unsupervised Autoencoder calibrated to flag flows exceeding the 98th percentile reconstruction error threshold.
2. Stage 2: Supervised Multi-Class Classifier (Random Forest / XGBoost) trained to attribute attack families:
   - Benign (Normal IoT Telemetry)
   - DDoS (Distributed Denial of Service flood)
   - DoS (Denial of Service)
   - Mirai-Botnet (IoT C2, scanner, Telnet/SSH brute force)
   - Reconnaissance (Port scan, OS fingerprinting, vulnerability probing)
   - BruteForce-Web (Credential stuffing on HTTP/HTTPS management portals)
   - Spoofing (ARP/DNS/IP spoofing, cache poisoning)
   - Suspected Novel Anomaly (Autoencoder flagged anomaly, but doesn't match known signatures)

When answering:
- Provide specific, actionable, production-grade cybersecurity best practices.
- Give ready-to-execute firewall rules (iptables, UFW, or Cisco ACL) when relevant to drop rogue traffic.
- Give IoT-specific device containment steps (VLAN segregation, credential rotation, disabling Telnet/UPnP).
- Be concise, clear, and structured with markdown headers, bold highlights, and code blocks.
"""

def generate_local_rule_based_advice(context: Dict[str, Any], user_query: str) -> str:
    """
    Intelligent local fallback generator when Groq API key is not configured or offline.
    Generates tailored, high-grade incident response playbooks directly from anomaly telemetry.
    """
    total_records = context.get("total_records", 0)
    anomalies = context.get("anomalies_detected", 0)
    anomaly_rate = context.get("anomaly_rate", "0%")
    attack_families = context.get("attack_families", {})
    high_risk_devices = context.get("high_risk_devices", [])
    top_signals = context.get("top_signals", [])
    selected_flow = context.get("selected_flow")

    # Determine primary threat
    primary_attack = "General Threat"
    if attack_families:
        non_benign = {k: v for k, v in attack_families.items() if k != "Benign"}
        if non_benign:
            primary_attack = max(non_benign.items(), key=lambda x: x[1])[0]

    affected_dev_str = ", ".join(high_risk_devices[:3]) if high_risk_devices else "Identified IoT Endpoints"
    
    # Specific mitigations by attack family
    firewall_rules = []
    playbook_steps = []
    
    if "Mirai" in primary_attack:
        playbook_steps = [
            "**Immediate Quarantine:** Disconnect suspected IoT devices from the primary LAN and place into an isolated quarantine VLAN (e.g., VLAN 99).",
            "**Credential Remediation:** Immediately terminate active Telnet (port 23/2323) and SSH (port 22) sessions. Rotate factory default credentials (`admin/admin`, `root/xc3511`).",
            "**Firmware & Reboot:** Reboot devices from a secure read-only image or reflash firmware, as Mirai resides in volatile memory (`/tmp`, `/var/run`).",
            "**Inbound/Outbound Port Filtering:** Block outbound scanning on ports 23, 2323, 5555, and block known Mirai C2 IPs."
        ]
        firewall_rules = [
            "# 1. Block outbound Telnet & known Mirai scanner ports from quarantined IoT subnet",
            "iptables -A FORWARD -s 192.168.1.0/24 -p tcp -m multiport --dports 23,2323,5555 -j DROP",
            "# 2. Isolate compromised IoT endpoint from internal network",
            f"iptables -I FORWARD -s 192.168.1.101 -j DROP",
            "# 3. Log and drop unauthorized outbound DNS requests",
            "iptables -A FORWARD -s 192.168.1.0/24 -p udp --dport 53 ! -d 192.168.1.1 -j REJECT"
        ]
    elif "DDoS" in primary_attack or "DoS" in primary_attack:
        playbook_steps = [
            "**Activate SYN Flood Protection:** Enable kernel-level TCP SYN cookies and reduce SYN-ACK retransmission attempts.",
            "**Rate-Limiting Ingress:** Enforce packet rate-limiting at the gateway switch or reverse proxy.",
            "**Upstream BGP Blackholing:** If traffic saturates your pipe, contact ISP or CDN upstream provider for BGP flowspec or Anycast scrubbing.",
            "**Inspect Amplification Ports:** Ensure NTP (123), DNS (53), and SNMP (161) services are not acting as open reflective amplifiers."
        ]
        firewall_rules = [
            "# 1. Enable TCP SYN Cookies against SYN Flood exhaustion",
            "sysctl -w net.ipv4.tcp_syncookies=1",
            "sysctl -w net.ipv4.tcp_max_syn_backlog=4096",
            "# 2. Rate limit new incoming connections per second",
            "iptables -A INPUT -p tcp --syn -m limit --limit 20/s --limit-burst 50 -j ACCEPT",
            "iptables -A INPUT -p tcp --syn -j DROP",
            "# 3. Drop malformed or invalid packets immediately",
            "iptables -A INPUT -m conntrack --ctstate INVALID -j DROP"
        ]
    elif "Reconnaissance" in primary_attack:
        playbook_steps = [
            "**Nullify Scanners:** Deploy tarpits or dynamic IP blacklisting for hosts triggering rapid multi-port connection attempts.",
            "**Disable Unneeded Daemon Ports:** Close unnecessary diagnostic ports on IoT hardware (e.g., UPnP, SSDP, Telnet, HTTP debug endpoints).",
            "**Enable Stealth Dropping:** Drop rather than reject probe packets (RST/ICMP unreachable) to delay and hinder adversary scanning tools like Nmap."
        ]
        firewall_rules = [
            "# 1. Block aggressive port scanning using recent tracking module",
            "iptables -N PORT_SCAN_DETECT",
            "iptables -A INPUT -p tcp -m state --state NEW -m recent --set --name SCANNER",
            "iptables -A INPUT -p tcp -m state --state NEW -m recent --update --seconds 60 --hitcount 20 --name SCANNER -j DROP",
            "# 2. Silently drop ICMP ping sweeps",
            "iptables -A INPUT -p icmp --icmp-type echo-request -j DROP"
        ]
    elif "BruteForce" in primary_attack:
        playbook_steps = [
            "**Enforce Fail2Ban / Account Lockout:** Temporarily lock accounts or IP addresses after 5 consecutive failed authentication attempts.",
            "**Mandate Multi-Factor Authentication (MFA):** Enforce token or cert-based auth for IoT gateway admin consoles.",
            "**Restrict Admin Access Subnet:** Limit management interface access to an internal bastion IP or VPN only."
        ]
        firewall_rules = [
            "# 1. Rate-limit HTTP management login attempts",
            "iptables -I INPUT -p tcp --dport 80 -m state --state NEW -m recent --set",
            "iptables -I INPUT -p tcp --dport 80 -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP",
            "# 2. Restrict administration to internal management subnet only",
            "iptables -A INPUT -p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 443 -j DROP"
        ]
    else:
        playbook_steps = [
            "**Deep Packet Inspection (DPI):** Capture full payload PCAPs of the flagged flow for protocol-level forensic carving.",
            "**Baseline Validation:** Compare observed deviations against known baseline device firmware specifications.",
            "**Microsegmentation:** Enforce Zero Trust microsegmentation rules restricting IoT endpoints strictly to required cloud telemetry endpoints."
        ]
        firewall_rules = [
            "# 1. Isolate anomalous IoT endpoint pending forensic verification",
            "iptables -I FORWARD -s 192.168.1.100/28 -d 192.168.1.0/24 -j DROP",
            "# 2. Log anomalous traffic for Wireshark analysis",
            "iptables -A FORWARD -m limit --limit 5/m -j LOG --log-prefix '[IOT-IDS-ANOMALY]: '"
        ]

    top_signal_text = ""
    if top_signals:
        signals_formatted = ", ".join([f"`{s.get('feature')}` ({s.get('anomalous_occurrences')} hits)" for s in top_signals[:3]])
        top_signal_text = f"\n- **Key Deviating Telemetry Signals:** {signals_formatted}"

    response = f"""### 🛡️ CortexIO Incident Response Playbook: **{primary_attack}**

> **AI SOC Advisory Context:** Analyzed **{total_records:,} flows** — detected **{anomalies:,} anomalies ({anomaly_rate})** across IoT fleet. Impacted endpoints: `{affected_dev_str}`.{top_signal_text}

---

#### 🚨 1. Immediate Incident Containment
{chr(10).join(f"- {step}" for step in playbook_steps)}

---

#### 💻 2. Gateway / Linux Firewall Mitigation Rules
Execute these rules on the IoT perimeter gateway or Linux firewall:

```bash
{chr(10).join(firewall_rules)}
```

---

#### 🔍 3. Forensic & Root Cause Checklist
- [ ] **Volatile Memory Dump:** Collect process list (`ps aux`, `netstat -tlpn`) before rebooting hardware.
- [ ] **Audit Open Ports:** Verify no unintended services are listening on public interfaces (`nmap -sS -p- <device-ip>`).
- [ ] **Firmware Verification:** Validate cryptographic SHA-256 hash against vendor official release.
- [ ] **Zero Trust Network Policy:** Restrict endpoint egress strictly to required MQTT/HTTPS endpoints.

*(Note: Operating in Local AI Rule-Engine Mode. Add a `GROQ_API_KEY` to `.env` or in UI settings to enable interactive live Llama-3.3-70B reasoning.)*
"""
    return response

async def query_groq_advisor(
    messages: List[Dict[str, str]],
    context: Dict[str, Any],
    api_key: Optional[str] = None,
    model: str = "llama-3.3-70b-versatile"
) -> Dict[str, Any]:
    """
    Queries Groq's high-speed inference API with full anomaly context.
    Falls back gracefully to the local expert heuristic playbook if no key or on error.
    """
    effective_key = (api_key or os.getenv("GROQ_API_KEY") or "").strip()

    # Context enrichment for system prompt
    context_summary = f"""
CURRENT INCIDENT CONTEXT:
- Dataset / Capture: {context.get('filename', 'Live Telemetry')}
- Total Records Scanned: {context.get('total_records', 0)}
- Anomalies Detected: {context.get('anomalies_detected', 0)} ({context.get('anomaly_rate', '0%')})
- Attack Distribution: {json.dumps(context.get('attack_families', {}))}
- Severity Counts: {json.dumps(context.get('severity_breakdown', {}))}
- Affected High-Risk Devices: {', '.join(context.get('high_risk_devices', [])) or 'None'}
- Top Deviating Features: {json.dumps(context.get('top_signals', []))}
"""
    if context.get("selected_flow"):
        context_summary += f"\n- Selected Specific Flow: {json.dumps(context.get('selected_flow'))}"

    # If no Groq API Key available, return smart local playbook
    if not effective_key:
        last_user_query = messages[-1]["content"] if messages else "Generate incident remediation plan"
        advice = generate_local_rule_based_advice(context, last_user_query)
        return {
            "reply": advice,
            "model": "local-rule-engine (Set Groq Key for Llama-3.3-70B)",
            "status": "SUCCESS_LOCAL"
        }

    # Call Groq API via high-speed async HTTP
    groq_url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {effective_key}",
        "Content-Type": "application/json"
    }

    full_system_prompt = f"{SYSTEM_PROMPT}\n{context_summary}"
    groq_messages = [{"role": "system", "content": full_system_prompt}]
    
    # Add recent message history (up to last 6 messages)
    for m in messages[-6:]:
        groq_messages.append({"role": m.get("role", "user"), "content": m.get("content", "")})

    payload = {
        "model": model or "llama-3.3-70b-versatile",
        "messages": groq_messages,
        "temperature": 0.25,
        "max_tokens": 1400
    }

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.post(groq_url, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                return {
                    "reply": content,
                    "model": data.get("model", model),
                    "status": "SUCCESS_GROQ"
                }
            else:
                err_text = resp.text
                print(f"[Warning] Groq API returned status {resp.status_code}: {err_text}")
                # Fallback to local advice with notice
                last_user_query = messages[-1]["content"] if messages else "Remediation"
                advice = generate_local_rule_based_advice(context, last_user_query)
                advice = f"> ⚠️ *Groq API Notice ({resp.status_code}): Using Local Incident Knowledge Engine.* \n\n" + advice
                return {
                    "reply": advice,
                    "model": "local-rule-engine-fallback",
                    "status": "FALLBACK"
                }
    except Exception as e:
        print(f"[Warning] Groq API call failed: {e}")
        last_user_query = messages[-1]["content"] if messages else "Remediation"
        advice = generate_local_rule_based_advice(context, last_user_query)
        advice = f"> ⚠️ *Network unreachable for Groq: Using Local Incident Knowledge Engine.* \n\n" + advice
        return {
            "reply": advice,
            "model": "local-rule-engine-fallback",
            "status": "FALLBACK"
        }

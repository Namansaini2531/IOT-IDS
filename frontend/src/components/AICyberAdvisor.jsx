import React, { useState, useEffect, useRef } from 'react';
import {
  Bot,
  Sparkles,
  Send,
  X,
  Copy,
  Check,
  Key,
  ShieldAlert,
  Terminal,
  Cpu,
  RefreshCw,
  AlertTriangle,
  ChevronDown,
  Layers,
  FileText,
  Lock,
  ExternalLink
} from 'lucide-react';

const QUICK_ACTIONS = [
  {
    icon: ShieldAlert,
    label: "Incident Playbook",
    prompt: "Analyze the current anomaly telemetry and generate a step-by-step Incident Response Playbook for our IoT fleet, including immediate containment and mitigation."
  },
  {
    icon: Terminal,
    label: "Firewall Rules",
    prompt: "Generate production-ready Linux iptables and UFW firewall rules to block and mitigate the attack traffic detected in this scan."
  },
  {
    icon: Cpu,
    label: "Explain Feature Deviations",
    prompt: "Explain why the Stage 1 Autoencoder flagged this anomaly. What do the top deviating telemetry features reveal about adversary behavior?"
  },
  {
    icon: Lock,
    label: "Quarantine IoT Devices",
    prompt: "Provide step-by-step instructions to isolate and quarantine the flagged IoT endpoints safely without taking down other operational equipment."
  },
  {
    icon: FileText,
    label: "Draft SOC Report",
    prompt: "Draft an executive SOC Incident Report in Markdown summarizing this attack, fleet risk score, impacted devices, and remedial action items."
  }
];

export default function AICyberAdvisor({
  apiBase,
  fileAnalysisResult,
  selectedTarget = null, // e.g. specific device or flow
  isOpen,
  onClose
}) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [groqKey, setGroqKey] = useState(() => localStorage.getItem('cortexio_groq_key') || '');
  const [tempKey, setTempKey] = useState(groqKey);
  const [showConfig, setShowConfig] = useState(false);
  const [selectedModel, setSelectedModel] = useState('llama-3.3-70b-versatile');
  const [copiedIndex, setCopiedIndex] = useState(null);

  const messagesEndRef = useRef(null);
  const textareaRef = useRef(null);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  // Initial greeting when opening
  useEffect(() => {
    if (isOpen && messages.length === 0) {
      const summaryDevice = selectedTarget?.device_id || (fileAnalysisResult?.high_risk_devices_affected?.[0] ?? 'IoT fleet');
      const attackName = selectedTarget?.classification || 
        (fileAnalysisResult?.attack_family_breakdown ? 
          Object.keys(fileAnalysisResult.attack_family_breakdown).find(k => k !== 'Benign') || 'Benign' 
          : 'telemetry');

      setMessages([
        {
          id: 'welcome',
          role: 'assistant',
          model: groqKey ? 'Groq LPU (Llama-3.3-70B)' : 'Local Cyber Expert Engine',
          content: `👋 **Welcome to CortexIO AI Cyber Defense Advisor.**

I am your real-time Tier-3 Incident Response Specialist. I have full visibility into your **2-Stage ML Pipeline** (Unsupervised Autoencoder + Attack Classifier).

${fileAnalysisResult ? `📊 **Active Anomaly Telemetry Detected:**
- **Capture File:** \`${fileAnalysisResult.filename || 'telemetry'}\`
- **Scanned Flows:** **${fileAnalysisResult.total_records_analyzed?.toLocaleString() || 0}** (Anomalies: **${fileAnalysisResult.anomalies_detected || 0}**, Rate: **${fileAnalysisResult.anomaly_rate_percentage || 0}%**)
- **Dominant Threat:** \`${attackName}\`
- **High-Risk Targets:** \`${fileAnalysisResult.high_risk_devices_affected?.join(', ') || 'None'}\`
` : `*No capture file uploaded yet. You can still ask general questions about IoT defense, Mirai containment, DDoS mitigation, or paste flow telemetry!*`}

Select a 1-click incident action below or ask me any question to begin containment!`
        }
      ]);
    }
  }, [isOpen, fileAnalysisResult, selectedTarget]);

  const handleSaveKey = (e) => {
    e?.preventDefault();
    const clean = tempKey.trim();
    setGroqKey(clean);
    localStorage.setItem('cortexio_groq_key', clean);
    setShowConfig(false);
  };

  const handleClearChat = () => {
    setMessages([]);
  };

  const handleSendMessage = async (textToSend) => {
    const query = (textToSend || input).trim();
    if (!query || isLoading) return;

    setInput('');

    const userMsg = {
      id: Date.now().toString(),
      role: 'user',
      content: query
    };

    const newHistory = [...messages, userMsg];
    setMessages(newHistory);
    setIsLoading(true);

    // Build context payload from active scan
    const contextPayload = {
      filename: fileAnalysisResult?.filename || 'Live Capture',
      total_records: fileAnalysisResult?.total_records_analyzed || 0,
      anomalies_detected: fileAnalysisResult?.anomalies_detected || 0,
      anomaly_rate: `${fileAnalysisResult?.anomaly_rate_percentage || 0}%`,
      attack_families: fileAnalysisResult?.attack_family_breakdown || {},
      severity_breakdown: fileAnalysisResult?.severity_breakdown || {},
      high_risk_devices: fileAnalysisResult?.high_risk_devices_affected || [],
      top_signals: fileAnalysisResult?.top_fleet_signals || [],
      selected_flow: selectedTarget || null
    };

    try {
      const res = await fetch(`${apiBase}/chat/remediate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: newHistory.map(m => ({ role: m.role, content: m.content })),
          context: contextPayload,
          groq_api_key: groqKey || undefined,
          model: selectedModel
        })
      });

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }

      const data = await res.json();
      setMessages(prev => [
        ...prev,
        {
          id: (Date.now() + 1).toString(),
          role: 'assistant',
          content: data.reply,
          model: data.model || (groqKey ? 'Groq LPU' : 'Local AI Engine')
        }
      ]);
    } catch (err) {
      console.error("Chat error:", err);
      setMessages(prev => [
        ...prev,
        {
          id: (Date.now() + 1).toString(),
          role: 'assistant',
          content: `⚠️ **Advisory Connection Error:** Could not reach the backend endpoint at \`${apiBase}/chat/remediate\`.\n\n*Error details:* ${err.message}`,
          model: 'System Error'
        }
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  // Minimal Markdown renderer with code block copy support
  const renderFormattedContent = (content, msgIdx) => {
    const lines = content.split('\n');
    const elements = [];
    let inCodeBlock = false;
    let codeBlockLang = '';
    let codeBlockContent = [];

    lines.forEach((line, i) => {
      if (line.startsWith('```')) {
        if (!inCodeBlock) {
          inCodeBlock = true;
          codeBlockLang = line.replace('```', '').trim() || 'bash';
          codeBlockContent = [];
        } else {
          // Finish code block
          inCodeBlock = false;
          const fullCode = codeBlockContent.join('\n');
          const codeId = `${msgIdx}-code-${i}`;
          elements.push(
            <div key={codeId} className="ai-codeblock-wrapper">
              <div className="ai-codeblock-header">
                <span className="ai-codeblock-lang">{codeBlockLang}</span>
                <button
                  type="button"
                  onClick={() => copyToClipboard(fullCode, codeId)}
                  className="ai-copy-btn"
                  title="Copy Code"
                >
                  {copiedIndex === codeId ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                  <span>{copiedIndex === codeId ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
              <pre className="ai-codeblock-body">
                <code>{fullCode}</code>
              </pre>
            </div>
          );
        }
        return;
      }

      if (inCodeBlock) {
        codeBlockContent.push(line);
        return;
      }

      // Headers
      if (line.startsWith('### ')) {
        elements.push(<h3 key={i} className="ai-md-h3">{line.replace('### ', '')}</h3>);
      } else if (line.startsWith('#### ')) {
        elements.push(<h4 key={i} className="ai-md-h4">{line.replace('#### ', '')}</h4>);
      } else if (line.startsWith('> ')) {
        elements.push(<blockquote key={i} className="ai-md-quote">{line.replace('> ', '')}</blockquote>);
      } else if (line.startsWith('- [ ] ') || line.startsWith('- [x] ')) {
        const checked = line.startsWith('- [x] ');
        elements.push(
          <div key={i} className="ai-md-checklist-item">
            <input type="checkbox" readOnly checked={checked} />
            <span>{line.replace(/- \[[ x]\] /, '')}</span>
          </div>
        );
      } else if (line.startsWith('- ') || line.startsWith('* ')) {
        // Parse bold and inline code in list item
        const text = line.substring(2);
        elements.push(
          <li key={i} className="ai-md-li">
            {formatInlineText(text)}
          </li>
        );
      } else if (line.trim() === '---') {
        elements.push(<hr key={i} className="ai-md-hr" />);
      } else if (line.trim().length > 0) {
        elements.push(
          <p key={i} className="ai-md-p">
            {formatInlineText(line)}
          </p>
        );
      }
    });

    return elements;
  };

  const formatInlineText = (text) => {
    // Regex for bold (**text**), inline code (`code`), and italics (*text*)
    const parts = text.split(/(\*\*.*?\*\*|`.*?`|\*.*?\*)/g);
    return parts.map((part, idx) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={idx}>{part.slice(2, -2)}</strong>;
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code key={idx} className="ai-inline-code">{part.slice(1, -1)}</code>;
      }
      if (part.startsWith('*') && part.endsWith('*')) {
        return <em key={idx}>{part.slice(1, -1)}</em>;
      }
      return part;
    });
  };

  if (!isOpen) return null;

  return (
    <div className="ai-advisor-overlay" onClick={onClose}>
      <div className="ai-advisor-drawer" onClick={(e) => e.stopPropagation()}>
        
        {/* Drawer Header */}
        <div className="ai-advisor-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <div className="ai-advisor-avatar-glow">
              <Bot size={20} color="#38bdf8" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ fontSize: '1.05rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                  CortexIO AI Advisor
                </span>
                <span className={`ai-model-tag ${groqKey ? 'groq-active' : 'local-active'}`}>
                  {groqKey ? '⚡ Groq LPU' : '🛡️ Local AI Engine'}
                </span>
              </div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                {groqKey ? `Powered by ${selectedModel} (Sub-second SOC triage)` : 'Heuristic Incident Playbook Mode'}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              type="button"
              onClick={() => setShowConfig(!showConfig)}
              className="ai-header-btn"
              title="Groq API Key Settings"
            >
              <Key size={14} color={groqKey ? '#38bdf8' : '#f59e0b'} />
              <span>{groqKey ? 'Key Active' : 'Set Key'}</span>
            </button>

            <button
              type="button"
              onClick={handleClearChat}
              className="ai-header-btn"
              title="Clear Chat History"
            >
              <RefreshCw size={13} />
            </button>

            <button
              type="button"
              onClick={onClose}
              className="ai-close-btn"
              title="Close Advisor"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Optional Groq API Key Configuration Dropdown */}
        {showConfig && (
          <div className="ai-config-panel">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                🔑 Groq LPU API Configuration
              </span>
              <a
                href="https://console.groq.com/keys"
                target="_blank"
                rel="noreferrer"
                style={{ fontSize: '0.72rem', color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '0.25rem', textDecoration: 'none' }}
              >
                Get Free Groq Key <ExternalLink size={10} />
              </a>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.65rem', lineHeight: 1.4 }}>
              Enter your Groq API key to unlock lightning-fast token generation with <strong>Llama-3.3-70B</strong>. Saved securely in your browser's local storage.
            </p>
            <form onSubmit={handleSaveKey} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <input
                type="password"
                placeholder="gsk_..."
                value={tempKey}
                onChange={(e) => setTempKey(e.target.value)}
                className="ai-config-input"
              />
              <button type="submit" className="ai-config-save-btn">
                Save Key
              </button>
            </form>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Model:</span>
              <select
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
                className="ai-config-select"
              >
                <option value="llama-3.3-70b-versatile">llama-3.3-70b-versatile (Recommended)</option>
                <option value="llama-3.1-8b-instant">llama-3.1-8b-instant (Fastest)</option>
                <option value="mixtral-8x7b-32768">mixtral-8x7b-32768</option>
              </select>
            </div>
          </div>
        )}

        {/* Telemetry Snapshot Banner */}
        {fileAnalysisResult && (
          <div className="ai-context-banner">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              <span className="ai-context-pill">
                📁 <strong>{fileAnalysisResult.filename || 'File'}</strong>
              </span>
              <span className="ai-context-pill alert">
                ⚠️ <strong>{fileAnalysisResult.anomalies_detected} Anomalies</strong> ({fileAnalysisResult.anomaly_rate_percentage}%)
              </span>
              {fileAnalysisResult.high_risk_devices_affected?.length > 0 && (
                <span className="ai-context-pill warning">
                  🚨 <strong>{fileAnalysisResult.high_risk_devices_affected.length} Compromised Devices</strong>
                </span>
              )}
            </div>
          </div>
        )}

        {/* Chat Messages Stream */}
        <div className="ai-messages-container">
          {messages.map((msg, idx) => (
            <div key={msg.id || idx} className={`ai-message-row ${msg.role}`}>
              {msg.role === 'assistant' && (
                <div className="ai-avatar-msg">
                  <Bot size={15} color="#38bdf8" />
                </div>
              )}
              <div className={`ai-message-bubble ${msg.role}`}>
                {msg.role === 'assistant' && msg.model && (
                  <div className="ai-bubble-badge">
                    <Sparkles size={11} color="#38bdf8" />
                    <span>{msg.model}</span>
                  </div>
                )}
                <div className="ai-markdown-body">
                  {renderFormattedContent(msg.content, idx)}
                </div>
              </div>
            </div>
          ))}

          {isLoading && (
            <div className="ai-message-row assistant">
              <div className="ai-avatar-msg">
                <Bot size={15} color="#38bdf8" />
              </div>
              <div className="ai-message-bubble assistant loading">
                <RefreshCw size={14} className="pulse-active" color="#38bdf8" />
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  Analyzing telemetry & formulating cyber remediation playbook...
                </span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* 1-Click Quick Action Prompt Chips */}
        <div className="ai-quick-actions-bar">
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '0.35rem', fontWeight: 600 }}>
            ⚡ 1-Click Incident Playbooks:
          </div>
          <div className="ai-chips-scroll">
            {QUICK_ACTIONS.map((action, i) => {
              const IconComp = action.icon;
              return (
                <button
                  key={i}
                  type="button"
                  disabled={isLoading}
                  onClick={() => handleSendMessage(action.prompt)}
                  className="ai-chip-btn"
                >
                  <IconComp size={12} color="#38bdf8" />
                  <span>{action.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Chat Input Bar */}
        <div className="ai-input-container">
          <textarea
            ref={textareaRef}
            rows={1}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleSendMessage();
              }
            }}
            placeholder="Ask about this attack, containment steps, iptables rules, or IoT device forensics..."
            className="ai-chat-input"
          />
          <button
            type="button"
            disabled={!input.trim() || isLoading}
            onClick={() => handleSendMessage()}
            className="ai-send-btn"
            title="Send Message"
          >
            {isLoading ? <RefreshCw size={15} className="pulse-active" /> : <Send size={15} />}
          </button>
        </div>

      </div>
    </div>
  );
}

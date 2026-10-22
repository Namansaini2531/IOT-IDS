import React, { useState, useEffect, useRef } from 'react';
import {
  Bot,
  Send,
  X,
  Copy,
  Check,
  RefreshCw
} from 'lucide-react';

export default function AICyberAdvisor({
  apiBase,
  fileAnalysisResult,
  selectedTarget = null,
  isOpen,
  onClose
}) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
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

      setMessages([
        {
          id: 'welcome',
          role: 'assistant',
          content: fileAnalysisResult
            ? `👋 **${fileAnalysisResult.anomalies_detected || 0} anomalies detected** in \`${fileAnalysisResult.filename || 'telemetry'}\`. Ask me for step-by-step device isolation, firewall rules, or password remediation steps!`
            : `👋 Hi! I am your field technical assistant. Ask me for step-by-step instructions to isolate compromised devices, apply firewall rules, or troubleshoot IoT network anomalies.`
        }
      ]);
    }
  }, [isOpen, fileAnalysisResult, selectedTarget]);

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
          context: contextPayload
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
          isBlocked: data.is_blocked || data.status === 'BLOCKED_BY_GUARDRAIL'
        }
      ]);
    } catch (err) {
      console.error("Chat error:", err);
      setMessages(prev => [
        ...prev,
        {
          id: (Date.now() + 1).toString(),
          role: 'assistant',
          content: `⚠️ **Advisory Connection Error:** Could not reach the backend endpoint at \`${apiBase}/chat/remediate\`.\n\n*Error details:* ${err.message}`
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

  // Lightweight Markdown renderer with code block copy support
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
                  <span>{copiedIndex === codeId ? 'Copied' : 'Copy'}</span>
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
        
        {/* Minimal Drawer Header */}
        <div className="ai-advisor-header">
          <div className="ai-header-left">
            <div className="ai-advisor-avatar-glow">
              <Bot size={18} color="#38bdf8" />
            </div>
            <div>
              <div className="ai-header-title-row">
                <span className="ai-header-title">AI Cyber Advisor</span>
                <span className="ai-status-pill">
                  <span className="ai-status-dot"></span>
                  Active
                </span>
              </div>
              <div className="ai-header-subtitle">
                Autonomous IoT Incident Mitigation & Triage
              </div>
            </div>
          </div>

          <div className="ai-header-actions">
            <button
              type="button"
              onClick={handleClearChat}
              className="ai-icon-btn"
              title="Reset Chat"
            >
              <RefreshCw size={14} />
            </button>

            <button
              type="button"
              onClick={onClose}
              className="ai-icon-btn close-btn"
              title="Close Advisor"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Minimal Context Banner */}
        {fileAnalysisResult && (
          <div className="ai-context-banner">
            <span className="ai-context-pill">
              📁 {fileAnalysisResult.filename || 'Telemetry'}
            </span>
            <span className="ai-context-pill alert">
              ⚠️ {fileAnalysisResult.anomalies_detected} Anomalies ({fileAnalysisResult.anomaly_rate_percentage}%)
            </span>
            {fileAnalysisResult.high_risk_devices_affected?.length > 0 && (
              <span className="ai-context-pill warning">
                🚨 {fileAnalysisResult.high_risk_devices_affected.length} Flagged
              </span>
            )}
          </div>
        )}

        {/* Chat Messages Stream */}
        <div className="ai-messages-container">
          {messages.map((msg, idx) => (
            <div key={msg.id || idx} className={`ai-message-row ${msg.role}`}>
              {msg.role === 'assistant' && (
                <div className="ai-avatar-msg">
                  <Bot size={14} color="#38bdf8" />
                </div>
              )}
              <div className={`ai-message-bubble ${msg.role} ${msg.isBlocked ? 'guardrail-blocked' : ''}`}>
                <div className="ai-markdown-body">
                  {renderFormattedContent(msg.content, idx)}
                </div>
              </div>
            </div>
          ))}

          {isLoading && (
            <div className="ai-message-row assistant">
              <div className="ai-avatar-msg">
                <Bot size={14} color="#38bdf8" />
              </div>
              <div className="ai-message-bubble assistant loading">
                <RefreshCw size={13} className="pulse-active" color="#38bdf8" />
                <span>Formulating incident remediation playbook...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
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
            placeholder="Ask about threats, iptables containment, forensic checklist..."
            className="ai-chat-input"
          />
          <button
            type="button"
            disabled={!input.trim() || isLoading}
            onClick={() => handleSendMessage()}
            className="ai-send-btn"
            title="Send Message"
          >
            {isLoading ? <RefreshCw size={14} className="pulse-active" /> : <Send size={14} />}
          </button>
        </div>

      </div>
    </div>
  );
}

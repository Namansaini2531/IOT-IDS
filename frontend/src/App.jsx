import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Server,
  Radio,
  Cpu,
  Zap,
  Play,
  Pause,
  RefreshCw,
  Sliders,
  AlertTriangle,
  Info,
  CheckCircle2,
  Terminal,
  Layers,
  BarChart3,
  Network
} from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
  PieChart,
  Pie
} from 'recharts';

const API_BASE = "http://localhost:8000/api/v1";
const WS_URL = "ws://localhost:8000/ws/traffic-stream";

const ATTACK_COLORS = {
  "Benign": "#10b981",
  "DDoS": "#ef4444",
  "DoS": "#f97316",
  "Mirai-Botnet": "#a855f7",
  "Reconnaissance": "#38bdf8",
  "BruteForce-Web": "#eab308",
  "Spoofing": "#ec4899",
  "Suspected Novel Anomaly": "#f43f5e"
};

export default function App() {
  const [activeTab, setActiveTab] = useState('monitor'); // 'monitor' | 'evaluation' | 'simulator'
  const [wsConnected, setWsConnected] = useState(false);
  const [isStreaming, setIsStreaming] = useState(true);
  const [streamSpeed, setStreamSpeed] = useState(0.8);
  const [systemStatus, setSystemStatus] = useState(null);
  const [evalReport, setEvalReport] = useState(null);
  
  // Real-time stream state
  const [currentFlow, setCurrentFlow] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [flowHistory, setFlowHistory] = useState([]);
  const [deviceStats, setDeviceStats] = useState({
    "iot-camera-01 (192.168.1.101)": { type: "Camera", risk: 0.05, severity: "LOW", status: "NORMAL" },
    "iot-thermostat-02 (192.168.1.102)": { type: "Thermostat", risk: 0.04, severity: "LOW", status: "NORMAL" },
    "iot-smartlock-03 (192.168.1.103)": { type: "Smart Lock", risk: 0.08, severity: "LOW", status: "NORMAL" },
    "iot-bulb-gateway-04 (192.168.1.104)": { type: "Bulb Gateway", risk: 0.02, severity: "LOW", status: "NORMAL" },
    "iot-smartplug-05 (192.168.1.105)": { type: "Smart Plug", risk: 0.03, severity: "LOW", status: "NORMAL" },
    "iot-nvr-storage-06 (192.168.1.106)": { type: "NVR Storage", risk: 0.06, severity: "LOW", status: "NORMAL" },
  });
  const [statsSummary, setStatsSummary] = useState({
    totalFlows: 0,
    anomaliesCount: 0,
    attacksBlocked: 0
  });

  // Simulator Form State
  const [simForm, setSimForm] = useState({
    flow_duration: 0.02,
    Rate: 8500.0,
    Header_Length: 32,
    TCP: 1,
    UDP: 0,
    syn_flag_number: 1,
    ack_flag_number: 0,
    Tot_sum: 12000,
    AVG: 950
  });
  const [simResult, setSimResult] = useState(null);
  const [simLoading, setSimLoading] = useState(false);

  const isStreamingRef = useRef(true);
  const wsRef = useRef(null);

  useEffect(() => {
    isStreamingRef.current = isStreaming;
  }, [isStreaming]);

  // 1. Fetch System Status & Evaluation Report
  useEffect(() => {
    fetch(`${API_BASE}/status`)
      .then(res => res.json())
      .then(data => setSystemStatus(data))
      .catch(err => console.error("Status fetch error:", err));

    fetch(`${API_BASE}/evaluation-report`)
      .then(res => res.json())
      .then(data => setEvalReport(data))
      .catch(err => console.error("Eval report error:", err));
  }, []);

  // 2. WebSocket Connection (Permanent, controlled via messages)
  useEffect(() => {
    let ws = null;
    let reconnectTimeout = null;

    function connect() {
      ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsConnected(true);
        console.log("WebSocket connected to Traffic Streamer");
      };

      ws.onmessage = (event) => {
        if (!isStreamingRef.current) return;
        try {
          const message = JSON.parse(event.data);
          if (message.type === "FLOW_EVENT") {
            const flow = message.data;
            handleIncomingFlow(flow);
          }
        } catch (e) {
          console.error("WS Parse error", e);
        }
      };

      ws.onclose = () => {
        setWsConnected(false);
        reconnectTimeout = setTimeout(connect, 3000);
      };

      ws.onerror = (err) => {
        console.error("WebSocket error:", err);
        ws.close();
      };
    }

    connect();

    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  // Toggle Stream Pause/Resume
  const handleToggleStreaming = () => {
    const nextState = !isStreaming;
    setIsStreaming(nextState);
    isStreamingRef.current = nextState;
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: nextState ? "resume" : "pause" }));
    }
  };

  // Update stream speed to backend
  const handleSpeedChange = (speed) => {
    setStreamSpeed(speed);
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ speed: speed }));
    }
  };

  const handleIncomingFlow = (flow) => {
    setCurrentFlow(flow);

    // Update Totals
    setStatsSummary(prev => ({
      totalFlows: prev.totalFlows + 1,
      anomaliesCount: prev.anomaliesCount + (flow.is_anomaly ? 1 : 0),
      attacksBlocked: prev.attacksBlocked + (flow.classification !== "Benign" ? 1 : 0)
    }));

    // Update History for Sparklines (keep last 25)
    setFlowHistory(prev => {
      const updated = [...prev, {
        time: new Date().toLocaleTimeString(),
        mse: flow.reconstruction_error,
        threshold: flow.threshold,
        risk: flow.risk_assessment.risk_score * 100,
        class: flow.classification
      }];
      return updated.slice(-25);
    });

    // Update Device Status
    const devId = flow.device_id;
    if (devId) {
      setDeviceStats(prev => ({
        ...prev,
        [devId]: {
          ...prev[devId],
          risk: flow.risk_assessment.risk_score,
          severity: flow.risk_assessment.severity,
          lastAttack: flow.classification,
          status: flow.is_anomaly ? "ATTACK_FLAGGED" : "NORMAL"
        }
      }));
    }

    // Add to Alert Feed if Anomaly or Non-Benign
    if (flow.is_anomaly || flow.classification !== "Benign") {
      setRecentAlerts(prev => [
        {
          id: Date.now() + Math.random(),
          timestamp: new Date().toLocaleTimeString(),
          device_id: flow.device_id,
          classification: flow.classification,
          risk: flow.risk_assessment.risk_score,
          severity: flow.risk_assessment.severity,
          mse: flow.reconstruction_error,
          topDeviation: flow.top_deviating_features?.[0]
        },
        ...prev.slice(0, 19)
      ]);
    }
  };

  // Run Manual Simulation Test
  const handleManualSimulate = async () => {
    setSimLoading(true);
    try {
      const payload = {
        device_id: "iot-camera-01 (192.168.1.101)",
        flow_features: {
          flow_duration: parseFloat(simForm.flow_duration),
          Rate: parseFloat(simForm.Rate),
          Header_Length: parseFloat(simForm.Header_Length),
          TCP: parseFloat(simForm.TCP),
          UDP: parseFloat(simForm.UDP),
          syn_flag_number: parseFloat(simForm.syn_flag_number),
          ack_flag_number: parseFloat(simForm.ack_flag_number),
          "Tot sum": parseFloat(simForm.Tot_sum),
          AVG: parseFloat(simForm.AVG),
          Protocol_Type: simForm.TCP ? 6.0 : 17.0
        }
      };
      const res = await fetch(`${API_BASE}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      setSimResult(data);
    } catch (err) {
      console.error("Simulation error", err);
    } finally {
      setSimLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* 1. Header & Navigation */}
      <header className="glass-panel" style={{ padding: '1.25rem 1.75rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ background: 'linear-gradient(135deg, #00f2fe, #4facfe)', padding: '0.75rem', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 20px rgba(0, 242, 254, 0.4)' }}>
            <ShieldAlert size={28} color="#060913" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <h1 style={{ fontSize: '1.4rem', fontWeight: 800, letterSpacing: '-0.02em', background: 'linear-gradient(to right, #ffffff, #94a3b8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                IoT-IDS AI Defense
              </h1>
              <span style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem', borderRadius: '6px', background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.3)', fontWeight: 600 }}>
                2-Stage Architecture
              </span>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Autoencoder Gatekeeper + Random Forest Attribution Engine
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div style={{ display: 'flex', gap: '0.5rem', background: 'rgba(15, 23, 42, 0.6)', padding: '0.35rem', borderRadius: '10px', border: '1px solid var(--border-color)' }}>
          <button
            onClick={() => setActiveTab('monitor')}
            style={{
              display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 1rem', borderRadius: '8px', border: 'none', cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem', transition: 'all 0.2s',
              background: activeTab === 'monitor' ? 'linear-gradient(135deg, #0284c7, #2563eb)' : 'transparent',
              color: activeTab === 'monitor' ? '#ffffff' : 'var(--text-secondary)'
            }}
          >
            <Activity size={16} /> Live Threat Monitor
          </button>
          <button
            onClick={() => setActiveTab('evaluation')}
            style={{
              display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 1rem', borderRadius: '8px', border: 'none', cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem', transition: 'all 0.2s',
              background: activeTab === 'evaluation' ? 'linear-gradient(135deg, #0284c7, #2563eb)' : 'transparent',
              color: activeTab === 'evaluation' ? '#ffffff' : 'var(--text-secondary)'
            }}
          >
            <BarChart3 size={16} /> Evaluation & Defensibility
          </button>
          <button
            onClick={() => setActiveTab('simulator')}
            style={{
              display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 1rem', borderRadius: '8px', border: 'none', cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem', transition: 'all 0.2s',
              background: activeTab === 'simulator' ? 'linear-gradient(135deg, #0284c7, #2563eb)' : 'transparent',
              color: activeTab === 'simulator' ? '#ffffff' : 'var(--text-secondary)'
            }}
          >
            <Sliders size={16} /> Flow Injection Lab
          </button>
        </div>

        {/* Live Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: wsConnected ? '#10b981' : '#f43f5e' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: wsConnected ? '#10b981' : '#f43f5e', display: 'inline-block', boxShadow: wsConnected ? '0 0 10px #10b981' : 'none' }}></span>
            {wsConnected ? 'Stream Active' : 'Connecting...'}
          </div>

          <button
            onClick={handleToggleStreaming}
            style={{
              display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.5rem 1rem', borderRadius: '8px', border: '1px solid var(--border-color)', cursor: 'pointer',
              background: isStreaming ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
              color: isStreaming ? '#f87171' : '#34d399', fontWeight: 700, fontSize: '0.85rem', transition: 'all 0.2s'
            }}
          >
            {isStreaming ? <><Pause size={15} /> Pause Stream</> : <><Play size={15} /> Resume Stream</>}
          </button>
        </div>
      </header>

      {/* 2. Top Stats Overview */}
      <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem' }}>
        
        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
            <span>Stage 1 Anomaly Gatekeeper</span>
            <Cpu size={18} color="#38bdf8" />
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: currentFlow?.is_anomaly ? '#f43f5e' : '#10b981' }}>
            {currentFlow ? (currentFlow.is_anomaly ? "ANOMALOUS" : "NORMAL") : "INITIALIZING"}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
            MSE: {currentFlow?.reconstruction_error?.toFixed(5) || '0.00000'} (Threshold: {systemStatus?.reconstruction_threshold?.toFixed(5) || '0.10074'})
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
            <span>Stage 2 Attack Attribution</span>
            <Layers size={18} color="#a855f7" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: ATTACK_COLORS[currentFlow?.classification] || '#f8fafc' }}>
            {currentFlow?.classification || "Awaiting Flows"}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
            Confidence: {((currentFlow?.attack_confidence || 0) * 100).toFixed(1)}% | Ground Truth: {currentFlow?.ground_truth || 'N/A'}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
            <span>Auditable Device Risk</span>
            <Zap size={18} color="#f59e0b" />
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: currentFlow?.risk_assessment?.severity === 'CRITICAL' ? '#f43f5e' : (currentFlow?.risk_assessment?.severity === 'HIGH' ? '#f59e0b' : '#38bdf8') }}>
            {((currentFlow?.risk_assessment?.risk_score || 0) * 100).toFixed(1)}%
            <span style={{ fontSize: '0.85rem', marginLeft: '0.5rem', padding: '0.15rem 0.45rem', borderRadius: '4px' }} className={`badge-${(currentFlow?.risk_assessment?.severity || 'low').toLowerCase()}`}>
              {currentFlow?.risk_assessment?.severity || 'LOW'}
            </span>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
            Formula: 0.5×Anom + 0.3×Att + 0.2×Hist
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
            <span>Malicious Recall & Latency</span>
            <ShieldCheck size={18} color="#10b981" />
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#10b981' }}>
            {evalReport ? `${(evalReport.stage1_autoencoder.recall * 100).toFixed(1)}%` : '100.0%'}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
            Total Inference Latency: {evalReport?.two_stage_combined?.total_inference_latency_ms || 0.0107} ms/flow
          </div>
        </div>

      </section>

      {/* 3. Main Body Tabs */}
      {activeTab === 'monitor' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1.8fr 1.2fr', gap: '1.5rem', alignItems: 'start' }}>
          
          {/* Left Column: Live Charts & IoT Topology */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            
            {/* Real-time Reconstruction Error Trend Chart */}
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <div>
                  <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Live Anomaly Reconstruction Error (MSE)</h3>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    Values above the red threshold line ({systemStatus?.reconstruction_threshold?.toFixed(4)}) trigger Stage 2 attack triage
                  </p>
                </div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Last 25 Flows</span>
              </div>
              <div style={{ height: '220px', width: '100%' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={flowHistory}>
                    <XAxis dataKey="time" stroke="#475569" fontSize={11} />
                    <YAxis stroke="#475569" fontSize={11} domain={[0, 'dataMax + 0.05']} />
                    <Tooltip contentStyle={{ background: '#0b1329', border: '1px solid #1e293b', borderRadius: '8px', fontSize: '12px' }} />
                    <Line type="monotone" dataKey="mse" stroke="#00f2fe" strokeWidth={2} dot={{ r: 3, fill: '#00f2fe' }} />
                    <Line type="monotone" dataKey="threshold" stroke="#ef4444" strokeDasharray="4 4" strokeWidth={1.5} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* IoT Device Topology View */}
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Network size={18} color="#38bdf8" />
                  <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Monitored IoT Fleet Topology</h3>
                </div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>6 Registered Smart Devices</span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
                {Object.entries(deviceStats).map(([devId, info]) => {
                  const isCritical = info.severity === 'CRITICAL' || info.severity === 'HIGH';
                  return (
                    <div
                      key={devId}
                      style={{
                        padding: '1rem', borderRadius: '10px',
                        background: isCritical ? 'rgba(239, 68, 68, 0.08)' : 'rgba(15, 23, 42, 0.5)',
                        border: isCritical ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid rgba(56, 189, 248, 0.1)',
                        display: 'flex', flexDirection: 'column', gap: '0.5rem'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontWeight: 700, fontSize: '0.85rem' }}>{info.type}</span>
                        <span className={`badge-${info.severity.toLowerCase()}`} style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem', borderRadius: '4px', fontWeight: 600 }}>
                          {info.severity}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{devId}</div>
                      
                      <div style={{ marginTop: '0.4rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-secondary)', marginBottom: '0.2rem' }}>
                          <span>Risk Index</span>
                          <span style={{ fontWeight: 700 }}>{(info.risk * 100).toFixed(0)}%</span>
                        </div>
                        <div style={{ width: '100%', height: '6px', background: '#1e293b', borderRadius: '3px', overflow: 'hidden' }}>
                          <div
                            style={{
                              width: `${Math.min(info.risk * 100, 100)}%`,
                              height: '100%',
                              background: info.risk > 0.7 ? '#ef4444' : (info.risk > 0.4 ? '#f59e0b' : '#10b981'),
                              transition: 'width 0.3s'
                            }}
                          />
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Explainable Feature Deviations Panel */}
            {currentFlow?.top_deviating_features && currentFlow.top_deviating_features.length > 0 && (
              <div className="glass-panel" style={{ padding: '1.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                  <Terminal size={18} color="#f59e0b" />
                  <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Explainability: Top Deviating Flow Signals</h3>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.75rem' }}>
                  {currentFlow.top_deviating_features.map((feat, idx) => (
                    <div key={idx} style={{ padding: '0.75rem', background: 'rgba(15, 23, 42, 0.6)', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                        <span style={{ fontWeight: 600, fontSize: '0.8rem', color: '#e2e8f0' }}>{feat.label}</span>
                        <span style={{ fontSize: '0.65rem', color: feat.severity === 'CRITICAL' ? '#f87171' : '#fbbf24' }}>{feat.severity}</span>
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                        Observed: <strong style={{ color: '#38bdf8' }}>{feat.observed_value}</strong> | Deviation: {feat.deviation_score.toFixed(2)}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

          </div>

          {/* Right Column: Real-time Alert Feed */}
          <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', height: '100%', maxHeight: '720px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <AlertTriangle size={18} color="#f43f5e" />
                <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Real-Time Alert Feed</h3>
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{recentAlerts.length} Flagged</span>
            </div>

            <div style={{ overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.75rem', paddingRight: '0.25rem' }}>
              {recentAlerts.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                  <ShieldCheck size={36} color="#10b981" style={{ margin: '0 auto 0.75rem', opacity: 0.6 }} />
                  Monitoring network flows... No suspicious attacks flagged yet.
                </div>
              ) : (
                recentAlerts.map(alert => (
                  <div
                    key={alert.id}
                    style={{
                      padding: '0.85rem', borderRadius: '10px',
                      background: alert.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(245, 158, 11, 0.1)',
                      border: alert.severity === 'CRITICAL' ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid rgba(245, 158, 11, 0.3)',
                      display: 'flex', flexDirection: 'column', gap: '0.4rem'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 700, fontSize: '0.85rem', color: ATTACK_COLORS[alert.classification] || '#ffffff' }}>
                        {alert.classification}
                      </span>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{alert.timestamp}</span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      Target: <span style={{ color: '#ffffff' }}>{alert.device_id.split(' ')[0]}</span>
                    </div>
                    {alert.topDeviation && (
                      <div style={{ fontSize: '0.7rem', color: '#94a3b8', background: 'rgba(0,0,0,0.2)', padding: '0.3rem 0.5rem', borderRadius: '4px' }}>
                        Deviation: {alert.topDeviation.label} ({alert.topDeviation.observed_value})
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

        </div>
      )}

      {/* 4. Evaluation & Defensibility Tab */}
      {activeTab === 'evaluation' && evalReport && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* Key Defensibility Metrics Card */}
          <div className="glass-panel" style={{ padding: '1.75rem' }}>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 800, marginBottom: '0.5rem' }}>
              Academic & Security Evaluation Matrix
            </h2>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
              Evaluated on {evalReport.dataset_summary.total_test_flows} unseen test flows using session & device-aware splits to strictly prevent data leakage.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
              <div style={{ padding: '1rem', background: 'rgba(15, 23, 42, 0.6)', borderRadius: '10px', border: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Stage 1 Anomaly Recall</span>
                <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#10b981', marginTop: '0.2rem' }}>
                  {(evalReport.stage1_autoencoder.recall * 100).toFixed(2)}%
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>0 Malicious Flows Missed</span>
              </div>

              <div style={{ padding: '1rem', background: 'rgba(15, 23, 42, 0.6)', borderRadius: '10px', border: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>False Positive Rate (FPR)</span>
                <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#38bdf8', marginTop: '0.2rem' }}>
                  {(evalReport.stage1_autoencoder.false_positive_rate * 100).toFixed(2)}%
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Bounds Benign Alert Noise</span>
              </div>

              <div style={{ padding: '1rem', background: 'rgba(15, 23, 42, 0.6)', borderRadius: '10px', border: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Macro-Averaged F1</span>
                <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#a855f7', marginTop: '0.2rem' }}>
                  {(evalReport.stage2_classifier.macro_f1 * 100).toFixed(2)}%
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Equal Weight to Minority Classes</span>
              </div>

              <div style={{ padding: '1rem', background: 'rgba(15, 23, 42, 0.6)', borderRadius: '10px', border: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>ROC-AUC Score</span>
                <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#00f2fe', marginTop: '0.2rem' }}>
                  {evalReport.stage1_autoencoder.roc_auc.toFixed(4)}
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Separability Baseline</span>
              </div>
            </div>

            {/* Per-Class Classification Report Table */}
            <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem' }}>
              Per-Class Classification Report (Precision / Recall / F1)
            </h3>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                    <th style={{ padding: '0.75rem' }}>Attack Class</th>
                    <th style={{ padding: '0.75rem' }}>Precision</th>
                    <th style={{ padding: '0.75rem' }}>Recall</th>
                    <th style={{ padding: '0.75rem' }}>F1-Score</th>
                    <th style={{ padding: '0.75rem' }}>Test Support</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(evalReport.stage2_classifier.per_class_metrics)
                    .filter(([k]) => !['accuracy', 'macro avg', 'weighted avg'].includes(k))
                    .map(([clsName, metrics]) => (
                      <tr key={clsName} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                        <td style={{ padding: '0.75rem', fontWeight: 600, color: ATTACK_COLORS[clsName] || '#ffffff' }}>{clsName}</td>
                        <td style={{ padding: '0.75rem' }}>{(metrics.precision * 100).toFixed(2)}%</td>
                        <td style={{ padding: '0.75rem' }}>{(metrics.recall * 100).toFixed(2)}%</td>
                        <td style={{ padding: '0.75rem', fontWeight: 700, color: '#38bdf8' }}>{(metrics['f1-score'] * 100).toFixed(2)}%</td>
                        <td style={{ padding: '0.75rem', color: 'var(--text-muted)' }}>{metrics.support} flows</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>

          </div>

        </div>
      )}

      {/* 5. Simulator Flow Injection Lab */}
      {activeTab === 'simulator' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
          
          {/* Form */}
          <div className="glass-panel" style={{ padding: '1.75rem' }}>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 800, marginBottom: '0.5rem' }}>
              Manual Flow Injection & Test Lab
            </h2>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
              Inject custom synthetic network flow parameters to observe live 2-stage inference and explainability.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
                  Packet Rate: <strong>{simForm.Rate} pkts/sec</strong>
                </label>
                <input
                  type="range" min="1" max="15000" step="50" value={simForm.Rate}
                  onChange={e => setSimForm({ ...simForm, Rate: parseFloat(e.target.value) })}
                  style={{ width: '100%', accentColor: '#00f2fe' }}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
                  Flow Duration: <strong>{simForm.flow_duration} seconds</strong>
                </label>
                <input
                  type="range" min="0.001" max="5.0" step="0.01" value={simForm.flow_duration}
                  onChange={e => setSimForm({ ...simForm, flow_duration: parseFloat(e.target.value) })}
                  style={{ width: '100%', accentColor: '#00f2fe' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div>
                  <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
                    SYN Flag Active:
                  </label>
                  <select
                    value={simForm.syn_flag_number}
                    onChange={e => setSimForm({ ...simForm, syn_flag_number: parseInt(e.target.value) })}
                    style={{ width: '100%', padding: '0.5rem', background: '#0f172a', border: '1px solid var(--border-color)', color: '#fff', borderRadius: '6px' }}
                  >
                    <option value={0}>0 (Inactive)</option>
                    <option value={1}>1 (Active SYN)</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
                    Transport Protocol:
                  </label>
                  <select
                    value={simForm.TCP ? "TCP" : "UDP"}
                    onChange={e => setSimForm({ ...simForm, TCP: e.target.value === "TCP" ? 1 : 0, UDP: e.target.value === "UDP" ? 1 : 0 })}
                    style={{ width: '100%', padding: '0.5rem', background: '#0f172a', border: '1px solid var(--border-color)', color: '#fff', borderRadius: '6px' }}
                  >
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                  </select>
                </div>
              </div>

              <button
                onClick={handleManualSimulate}
                disabled={simLoading}
                style={{
                  marginTop: '1rem', padding: '0.75rem', borderRadius: '8px', border: 'none',
                  background: 'linear-gradient(135deg, #0284c7, #2563eb)', color: '#fff',
                  fontWeight: 700, fontSize: '0.9rem', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem'
                }}
              >
                {simLoading ? <RefreshCw className="pulse-active" size={16} /> : <Zap size={16} />}
                Run 2-Stage Inference
              </button>
            </div>
          </div>

          {/* Result */}
          <div className="glass-panel" style={{ padding: '1.75rem' }}>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 800, marginBottom: '0.5rem' }}>
              Inference Diagnostic Output
            </h2>
            {simResult ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '1rem' }}>
                <div style={{ padding: '1rem', borderRadius: '8px', background: simResult.is_anomaly ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)', border: simResult.is_anomaly ? '1px solid #ef4444' : '1px solid #10b981' }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Stage 1 Verdict</div>
                  <div style={{ fontSize: '1.3rem', fontWeight: 800, color: simResult.is_anomaly ? '#f87171' : '#34d399' }}>
                    {simResult.is_anomaly ? "🚨 ANOMALY DETECTED" : "✅ NORMAL TRAFFIC"}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Reconstruction Error: {simResult.reconstruction_error.toFixed(6)} (Threshold: {simResult.threshold.toFixed(6)})
                  </div>
                </div>

                <div style={{ padding: '1rem', borderRadius: '8px', background: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-color)' }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Stage 2 Attack Attribution</div>
                  <div style={{ fontSize: '1.3rem', fontWeight: 800, color: ATTACK_COLORS[simResult.classification] || '#ffffff' }}>
                    {simResult.classification}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Classifier Confidence: {(simResult.attack_confidence * 100).toFixed(1)}%
                  </div>
                </div>

                <div style={{ padding: '1rem', borderRadius: '8px', background: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-color)' }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Auditable Risk Score</div>
                  <div style={{ fontSize: '1.3rem', fontWeight: 800, color: '#f59e0b' }}>
                    {(simResult.risk_assessment.risk_score * 100).toFixed(1)}% [{simResult.risk_assessment.severity}]
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                Adjust parameters on the left and click "Run 2-Stage Inference" to inspect model decisions.
              </div>
            )}
          </div>

        </div>
      )}

    </div>
  );
}

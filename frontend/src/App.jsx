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
  Network,
  UploadCloud,
  FileSpreadsheet,
  Search,
  FileText,
  CheckCircle,
  ArrowRight,
  Download,
  Flame,
  Filter,
  ExternalLink,
  PlusCircle
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

const API_BASE = import.meta.env.VITE_API_BASE || (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' ? "http://localhost:8000/api/v1" : "/api/v1");

const ATTACK_COLORS = {
  "Benign": "#10b981",
  "DDoS": "#f43f5e",
  "DoS": "#f97316",
  "Mirai-Botnet": "#a855f7",
  "Reconnaissance": "#38bdf8",
  "BruteForce-Web": "#eab308",
  "Spoofing": "#ec4899",
  "Suspected Novel Anomaly": "#fb7185"
};

export default function App() {
  const [activeTab, setActiveTab] = useState('analyzer'); // 'analyzer' | 'simulator' | 'architecture'
  const [systemStatus, setSystemStatus] = useState(null);
  const [evalReport, setEvalReport] = useState(null);

  // File Upload & Dataset Analyzer State
  const [selectedFile, setSelectedFile] = useState(null);
  const [maxAnalyzeRows, setMaxAnalyzeRows] = useState(500);
  const [isAnalyzingFile, setIsAnalyzingFile] = useState(false);
  const [fileAnalysisResult, setFileAnalysisResult] = useState(null);
  const [analysisFilter, setAnalysisFilter] = useState('ALL'); // 'ALL' | 'ANOMALY_ONLY' | 'CRITICAL'
  const [analysisSearch, setAnalysisSearch] = useState('');
  const [uploadToast, setUploadToast] = useState('');
  const [selectedDeviceFilter, setSelectedDeviceFilter] = useState('ALL');

  // Simulator Form State (Lab Tab)
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

  const fileInputRef = useRef(null);

  // Fetch System Status & Model Report
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

  // Upload File & Analyze with 2-Stage AI Model
  const handleUploadAndAnalyze = async () => {
    if (!selectedFile) return;
    setIsAnalyzingFile(true);
    setUploadToast('');
    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      formData.append("max_rows", maxAnalyzeRows);

      const res = await fetch(`${API_BASE}/upload-and-analyze`, {
        method: "POST",
        body: formData
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to analyze file");
      }

      const data = await res.json();
      setFileAnalysisResult(data);
      setSelectedDeviceFilter('ALL');
      setUploadToast(`Analysis Complete: Scanned ${data.total_records_analyzed} flows across ${data.total_devices_scanned || 0} IoT devices. Detected ${data.anomalies_detected} anomalies.`);
    } catch (err) {
      console.error(err);
      setUploadToast(`Error: ${err.message}`);
    } finally {
      setIsAnalyzingFile(false);
    }
  };

  // Run Manual Flow Simulation
  const handleRunSimulation = async (e) => {
    e.preventDefault();
    setSimLoading(true);
    try {
      const res = await fetch(`${API_BASE}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          device_id: "test-iot-node",
          flow_features: simForm
        })
      });
      const data = await res.json();
      setSimResult(data);
    } catch (err) {
      console.error("Simulation error:", err);
    } finally {
      setSimLoading(false);
    }
  };

  // Download Anomaly JSON Report
  const handleDownloadReport = () => {
    if (!fileAnalysisResult) return;
    const blob = new Blob([JSON.stringify(fileAnalysisResult, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `iot_anomaly_audit_${fileAnalysisResult.filename || 'report'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      
      {/* 1. Proper Shadow Black Navigation Bar */}
      <nav className="shadow-navbar">
        {/* Left: Brand Identity */}
        <div className="nav-brand-container">
          <div className="nav-brand-icon">
            <ShieldAlert size={24} color="#38bdf8" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontSize: '1.25rem', fontWeight: 800, letterSpacing: '-0.02em', color: '#ffffff' }}>
                IoT Sentinel
              </span>
              <span style={{ fontSize: '0.68rem', padding: '0.15rem 0.45rem', borderRadius: '4px', background: 'rgba(255, 255, 255, 0.07)', color: '#94a3b8', border: '1px solid rgba(255, 255, 255, 0.1)', fontWeight: 700, letterSpacing: '0.04em' }}>
                v2.4
              </span>
            </div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', fontWeight: 500 }}>
              AI Anomaly Gatekeeper & Attack Triage Engine
            </div>
          </div>
        </div>

        {/* Center: Navigation Links */}
        <div className="nav-tabs-wrapper">
          <button
            onClick={() => setActiveTab('analyzer')}
            className={`nav-tab-btn ${activeTab === 'analyzer' ? 'active' : ''}`}
          >
            <UploadCloud size={15} color={activeTab === 'analyzer' ? '#38bdf8' : 'currentColor'} />
            <span>Log & PCAP Analyzer</span>
          </button>
          
          <button
            onClick={() => setActiveTab('simulator')}
            className={`nav-tab-btn ${activeTab === 'simulator' ? 'active' : ''}`}
          >
            <Sliders size={15} color={activeTab === 'simulator' ? '#38bdf8' : 'currentColor'} />
            <span>Flow Injection Lab</span>
          </button>
        </div>

        {/* Right: Quick Action */}
        <div className="nav-actions-group">
          {fileAnalysisResult ? (
            <button
              onClick={handleDownloadReport}
              style={{
                display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.45rem 0.85rem', borderRadius: '7px', border: '1px solid rgba(255, 255, 255, 0.12)',
                background: '#14141a', color: '#f4f4f6', fontWeight: 600, fontSize: '0.78rem', cursor: 'pointer', boxShadow: '0 4px 12px rgba(0, 0, 0, 0.6)'
              }}
            >
              <Download size={13} color="#38bdf8" /> Export JSON
            </button>
          ) : (
            <button
              onClick={() => {
                setActiveTab('analyzer');
                fileInputRef.current?.click();
              }}
              style={{
                display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.45rem 0.85rem', borderRadius: '7px', border: '1px solid rgba(56, 189, 248, 0.3)',
                background: 'linear-gradient(135deg, #191b24, #0e0f14)', color: '#38bdf8', fontWeight: 600, fontSize: '0.78rem', cursor: 'pointer', boxShadow: '0 4px 12px rgba(0, 0, 0, 0.7)'
              }}
            >
              <PlusCircle size={13} /> Select File
            </button>
          )}
        </div>
      </nav>

      {/* Main App Content Area */}
      <main style={{ padding: '1.5rem 2rem', display: 'flex', flexDirection: 'column', gap: '1.5rem', flexGrow: 1 }}>
        
        {/* Tab 1: Log & PCAP Analyzer */}
        {activeTab === 'analyzer' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            
            {/* File Ingestion & Configuration Hero */}
            <div className="glass-panel" style={{ padding: '1.75rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
                <div>
                  <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <FileSpreadsheet size={19} color="#38bdf8" />
                    IoT File Ingestion & Device Anomaly Engine
                  </h2>
                  <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                    Upload raw Wireshark captures (<strong>.pcap</strong>, <strong>.pcapng</strong>, <strong>.cap</strong>) or IoT device log datasets (<strong>.csv</strong>, <strong>.json</strong>).
                  </p>
                </div>

                {fileAnalysisResult && (
                  <button
                    onClick={handleDownloadReport}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.45rem 0.9rem', borderRadius: '7px', border: '1px solid rgba(255, 255, 255, 0.12)',
                      background: '#14141a', color: '#f4f4f6', fontWeight: 600, fontSize: '0.8rem', cursor: 'pointer', boxShadow: '0 4px 12px rgba(0, 0, 0, 0.6)'
                    }}
                  >
                    <Download size={14} color="#38bdf8" /> Export Audit JSON
                  </button>
                )}
              </div>

              {/* Dropzone Area */}
              <div
                onClick={() => fileInputRef.current?.click()}
                style={{
                  border: '1.5px dashed rgba(255, 255, 255, 0.14)',
                  borderRadius: '12px',
                  padding: '2.25rem 1.5rem',
                  textAlign: 'center',
                  background: 'rgba(8, 8, 12, 0.75)',
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: '0.75rem',
                  boxShadow: 'inset 0 2px 12px rgba(0, 0, 0, 0.8)'
                }}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                    setSelectedFile(e.dataTransfer.files[0]);
                  }
                }}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".pcap,.pcapng,.cap,.csv,.json,.log"
                  style={{ display: 'none' }}
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      setSelectedFile(e.target.files[0]);
                    }
                  }}
                />
                <div style={{ background: 'rgba(255, 255, 255, 0.05)', padding: '0.85rem', borderRadius: '50%', color: '#38bdf8', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                  <UploadCloud size={28} />
                </div>
                <div>
                  <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc' }}>
                    {selectedFile ? `Selected: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)` : "Select or drag & drop Wireshark / IoT Log file"}
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                    Accepts <strong>.pcap</strong>, <strong>.pcapng</strong>, <strong>.cap</strong>, <strong>Zeek logs</strong>, and <strong>CSV/JSON datasets</strong>
                  </div>
                </div>
              </div>

              {/* Ingestion Controls */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>Analyze Max Rows:</span>
                  <select
                    value={maxAnalyzeRows}
                    onChange={(e) => setMaxAnalyzeRows(Number(e.target.value))}
                    style={{ padding: '0.45rem 0.75rem', background: '#07070a', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#fff', borderRadius: '6px', fontSize: '0.82rem' }}
                  >
                    <option value={100}>100 Flows</option>
                    <option value={500}>500 Flows</option>
                    <option value={1000}>1,000 Flows</option>
                    <option value={5000}>5,000 Flows</option>
                    <option value={20000}>All Flows (Up to 20k)</option>
                  </select>
                </div>

                <button
                  onClick={handleUploadAndAnalyze}
                  disabled={!selectedFile || isAnalyzingFile}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.65rem 1.4rem', borderRadius: '8px', border: selectedFile ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid rgba(255, 255, 255, 0.08)',
                    background: selectedFile ? 'linear-gradient(135deg, #1c1e28, #101117)' : 'rgba(255, 255, 255, 0.04)',
                    color: selectedFile ? '#ffffff' : 'var(--text-muted)',
                    fontWeight: 700, fontSize: '0.88rem', cursor: selectedFile ? 'pointer' : 'not-allowed',
                    boxShadow: selectedFile ? '0 8px 20px rgba(0, 0, 0, 0.9), 0 0 12px rgba(56, 189, 248, 0.15)' : 'none'
                  }}
                >
                  {isAnalyzingFile ? <RefreshCw className="pulse-active" size={15} /> : <Search size={15} color="#38bdf8" />}
                  {isAnalyzingFile ? "Analyzing Traffic with AI..." : "Run IoT Anomaly Audit"}
                </button>
              </div>

              {uploadToast && (
                <div style={{ padding: '0.65rem 0.9rem', borderRadius: '7px', background: uploadToast.startsWith('Error') ? 'rgba(244, 63, 94, 0.1)' : 'rgba(16, 185, 129, 0.1)', border: `1px solid ${uploadToast.startsWith('Error') ? 'rgba(244, 63, 94, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`, color: uploadToast.startsWith('Error') ? '#fb7185' : '#34d399', fontSize: '0.82rem', fontWeight: 600 }}>
                  {uploadToast}
                </div>
              )}
            </div>

            {/* Audit Results Section */}
            {fileAnalysisResult ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                
                {/* 1. Fleet Executive Overview KPIs */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem' }}>
                  <div className="glass-panel" style={{ padding: '1.25rem' }}>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>Total Flow Records Scanned</div>
                    <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#f8fafc' }}>
                      {fileAnalysisResult.total_records_analyzed.toLocaleString()}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                      File contains {fileAnalysisResult.total_file_records.toLocaleString()} total rows
                    </div>
                  </div>

                  <div className="glass-panel" style={{ padding: '1.25rem' }}>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>IoT Devices / Endpoints Found</div>
                    <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#38bdf8' }}>
                      {fileAnalysisResult.total_devices_scanned || (fileAnalysisResult.device_summaries ? fileAnalysisResult.device_summaries.length : 1)} Nodes
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                      Distinct IPs / device fingerprints
                    </div>
                  </div>

                  <div className="glass-panel" style={{ padding: '1.25rem' }}>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>Anomalous Flows Flagged</div>
                    <div style={{ fontSize: '1.6rem', fontWeight: 800, color: fileAnalysisResult.anomalies_detected > 0 ? '#f43f5e' : '#10b981' }}>
                      {fileAnalysisResult.anomalies_detected.toLocaleString()}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                      Fleet Anomaly Rate: <strong>{fileAnalysisResult.anomaly_rate_percentage}%</strong>
                    </div>
                  </div>

                  <div className="glass-panel" style={{ padding: '1.25rem' }}>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>High-Risk Compromised Devices</div>
                    <div style={{ fontSize: '1.6rem', fontWeight: 800, color: fileAnalysisResult.high_risk_devices_affected.length > 0 ? '#f59e0b' : '#10b981' }}>
                      {fileAnalysisResult.high_risk_devices_affected.length} Devices
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                      Exhibiting severe attack patterns
                    </div>
                  </div>
                </div>

                {/* 2. Discovered IoT Devices & Health Status Rollup */}
                {fileAnalysisResult.device_summaries && fileAnalysisResult.device_summaries.length > 0 && (
                  <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                      <div>
                        <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <Radio size={17} color="#38bdf8" />
                          Discovered IoT Devices — Anomaly & Risk Breakdown
                        </h3>
                        <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                          Per-endpoint risk assessment based on Autoencoder reconstruction deviations & attack classifications.
                        </p>
                      </div>

                      {selectedDeviceFilter !== 'ALL' && (
                        <button
                          onClick={() => setSelectedDeviceFilter('ALL')}
                          style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem', background: '#181820', border: '1px solid rgba(255, 255, 255, 0.12)', color: '#fff', borderRadius: '4px', cursor: 'pointer' }}
                        >
                          Clear Filter (Showing {selectedDeviceFilter})
                        </button>
                      )}
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(290px, 1fr))', gap: '1rem' }}>
                      {fileAnalysisResult.device_summaries.map((dev) => (
                        <div
                          key={dev.device_id}
                          onClick={() => setSelectedDeviceFilter(selectedDeviceFilter === dev.device_id ? 'ALL' : dev.device_id)}
                          style={{
                            padding: '1.1rem',
                            borderRadius: '10px',
                            background: selectedDeviceFilter === dev.device_id ? 'rgba(25, 28, 38, 0.95)' : 'rgba(10, 10, 14, 0.85)',
                            border: selectedDeviceFilter === dev.device_id ? '1.5px solid #38bdf8' : `1px solid ${dev.overall_health === 'CRITICAL' ? 'rgba(244, 63, 94, 0.3)' : dev.overall_health === 'HIGH_RISK' ? 'rgba(245, 158, 11, 0.3)' : 'rgba(255, 255, 255, 0.07)'}`,
                            cursor: 'pointer',
                            transition: 'all 0.2s',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '0.6rem',
                            boxShadow: '0 8px 24px rgba(0, 0, 0, 0.75)'
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontWeight: 700, fontSize: '0.88rem', color: '#f8fafc' }}>
                              {dev.device_id}
                            </span>
                            <span
                              style={{
                                padding: '0.15rem 0.45rem',
                                borderRadius: '4px',
                                fontSize: '0.68rem',
                                fontWeight: 700,
                                background: dev.overall_health === 'CRITICAL' ? 'rgba(244, 63, 94, 0.15)' : dev.overall_health === 'HIGH_RISK' ? 'rgba(245, 158, 11, 0.15)' : dev.overall_health === 'SUSPICIOUS' ? 'rgba(56, 189, 248, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                                color: dev.overall_health === 'CRITICAL' ? '#fb7185' : dev.overall_health === 'HIGH_RISK' ? '#fbbf24' : dev.overall_health === 'SUSPICIOUS' ? '#38bdf8' : '#34d399',
                                border: `1px solid ${dev.overall_health === 'CRITICAL' ? 'rgba(244, 63, 94, 0.3)' : dev.overall_health === 'HIGH_RISK' ? 'rgba(245, 158, 11, 0.3)' : 'rgba(255, 255, 255, 0.1)'}`
                              }}
                            >
                              {dev.overall_health.replace('_', ' ')}
                            </span>
                          </div>

                          {/* Risk Bar */}
                          <div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.74rem', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>
                              <span>Max Risk Score</span>
                              <strong style={{ color: dev.max_risk_score >= 70 ? '#fb7185' : dev.max_risk_score >= 40 ? '#fbbf24' : '#34d399' }}>
                                {dev.max_risk_score}%
                              </strong>
                            </div>
                            <div style={{ height: '5px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '3px', overflow: 'hidden' }}>
                              <div style={{ width: `${Math.min(100, dev.max_risk_score)}%`, height: '100%', background: dev.max_risk_score >= 70 ? '#f43f5e' : dev.max_risk_score >= 40 ? '#f59e0b' : '#10b981' }}></div>
                            </div>
                          </div>

                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
                            <span>Anomalies: <strong>{dev.anomaly_flows}/{dev.total_flows} ({dev.anomaly_rate}%)</strong></span>
                            <span>Attribution: <strong style={{ color: ATTACK_COLORS[dev.primary_attack] || '#fff' }}>{dev.primary_attack}</strong></span>
                          </div>

                          {dev.top_signals && dev.top_signals.length > 0 && (
                            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', background: '#07070a', padding: '0.3rem 0.45rem', borderRadius: '4px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                              Trigger: {dev.top_signals.join(", ")}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 3. Visualizations */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '1.5rem' }}>
                  
                  {/* Autoencoder Reconstruction Chart */}
                  <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <h4 style={{ fontSize: '0.88rem', fontWeight: 700, color: '#f8fafc' }}>
                        Autoencoder Reconstruction MSE (vs 98th Percentile Baseline)
                      </h4>
                      <span style={{ fontSize: '0.72rem', color: '#38bdf8' }}>
                        Threshold: {fileAnalysisResult.reconstruction_threshold_used.toFixed(4)}
                      </span>
                    </div>
                    <div style={{ height: '220px', width: '100%' }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={fileAnalysisResult.rows.slice(0, 50)}>
                          <XAxis dataKey="row_index" stroke="rgba(255,255,255,0.2)" fontSize={11} tickLine={false} />
                          <YAxis stroke="rgba(255,255,255,0.2)" fontSize={11} tickLine={false} />
                          <Tooltip
                            contentStyle={{ background: '#09090c', borderColor: '#22222a', borderRadius: '8px', fontSize: '0.75rem', boxShadow: '0 8px 24px rgba(0,0,0,0.9)' }}
                            formatter={(value, name) => [value, name === 'reconstruction_error' ? 'Recon MSE' : name]}
                          />
                          <Line type="monotone" dataKey="reconstruction_error" stroke="#38bdf8" strokeWidth={2} dot={{ r: 2 }} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Attack Breakdown Distribution */}
                  <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    <h4 style={{ fontSize: '0.88rem', fontWeight: 700, color: '#f8fafc' }}>
                      Detected Attack Family Classifications
                    </h4>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.6rem' }}>
                      {Object.entries(fileAnalysisResult.attack_family_breakdown).map(([atkName, count]) => (
                        <div
                          key={atkName}
                          style={{
                            padding: '0.45rem 0.8rem',
                            borderRadius: '8px',
                            background: 'rgba(10, 10, 14, 0.9)',
                            border: `1px solid ${ATTACK_COLORS[atkName] || '#38bdf8'}35`,
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.5rem',
                            fontSize: '0.78rem',
                            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.6)'
                          }}
                        >
                          <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: ATTACK_COLORS[atkName] || '#fff' }}></span>
                          <span style={{ fontWeight: 600, color: ATTACK_COLORS[atkName] || '#fff' }}>{atkName}:</span>
                          <strong style={{ color: '#fff' }}>{count} flows</strong>
                        </div>
                      ))}
                    </div>
                  </div>

                </div>

                {/* 4. Filterable Diagnostic Flow Log Table */}
                <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                    <div>
                      <h3 style={{ fontSize: '0.98rem', fontWeight: 700, color: '#f8fafc' }}>
                        Diagnostic Flow Records & Feature Deviations
                      </h3>
                      <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                        Inspection of each bidirectional packet flow with root-cause feature attribution.
                      </p>
                    </div>

                    <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
                      <input
                        type="text"
                        placeholder="Search IP, device, attack..."
                        value={analysisSearch}
                        onChange={(e) => setAnalysisSearch(e.target.value)}
                        style={{ padding: '0.4rem 0.75rem', background: '#07070a', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#fff', borderRadius: '6px', fontSize: '0.8rem', minWidth: '180px' }}
                      />

                      <select
                        value={analysisFilter}
                        onChange={(e) => setAnalysisFilter(e.target.value)}
                        style={{ padding: '0.4rem 0.75rem', background: '#07070a', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#fff', borderRadius: '6px', fontSize: '0.8rem' }}
                      >
                        <option value="ALL">All Flows</option>
                        <option value="ANOMALY_ONLY">Anomalies Only</option>
                        <option value="CRITICAL">Critical / High Severity</option>
                      </select>
                    </div>
                  </div>

                  <div style={{ overflowX: 'auto', maxHeight: '520px' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                          <th style={{ padding: '0.65rem' }}>#</th>
                          <th style={{ padding: '0.65rem' }}>IoT Endpoint / IP</th>
                          <th style={{ padding: '0.65rem' }}>Stage 1 Verdict</th>
                          <th style={{ padding: '0.65rem' }}>Stage 2 Attack Attribution</th>
                          <th style={{ padding: '0.65rem' }}>Recon MSE</th>
                          <th style={{ padding: '0.65rem' }}>Risk Score</th>
                          <th style={{ padding: '0.65rem' }}>Root Cause Signal Deviation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {fileAnalysisResult.rows
                          .filter(r => {
                            if (selectedDeviceFilter !== 'ALL' && r.device_id !== selectedDeviceFilter) return false;
                            if (analysisFilter === 'ANOMALY_ONLY' && !r.is_anomaly) return false;
                            if (analysisFilter === 'CRITICAL' && !['CRITICAL', 'HIGH'].includes(r.severity)) return false;
                            if (analysisSearch) {
                              const query = analysisSearch.toLowerCase();
                              return r.device_id.toLowerCase().includes(query) || r.classification.toLowerCase().includes(query);
                            }
                            return true;
                          })
                          .map((row) => (
                            <tr key={row.row_index} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)', background: row.is_anomaly ? 'rgba(244, 63, 94, 0.03)' : 'transparent' }}>
                              <td style={{ padding: '0.65rem', color: 'var(--text-muted)' }}>{row.row_index}</td>
                              <td style={{ padding: '0.65rem', fontWeight: 600, color: '#f8fafc' }}>{row.device_id}</td>
                              <td style={{ padding: '0.65rem' }}>
                                <span style={{ padding: '0.15rem 0.45rem', borderRadius: '4px', fontSize: '0.68rem', fontWeight: 700, background: row.is_anomaly ? 'rgba(244, 63, 94, 0.15)' : 'rgba(16, 185, 129, 0.15)', color: row.is_anomaly ? '#fb7185' : '#34d399', border: `1px solid ${row.is_anomaly ? 'rgba(244, 63, 94, 0.3)' : 'rgba(16, 185, 129, 0.3)'}` }}>
                                  {row.is_anomaly ? "ANOMALY" : "NORMAL"}
                                </span>
                              </td>
                              <td style={{ padding: '0.65rem', fontWeight: 700, color: ATTACK_COLORS[row.classification] || '#fff' }}>
                                {row.classification}
                              </td>
                              <td style={{ padding: '0.65rem', fontFamily: 'var(--font-mono)' }}>
                                {row.reconstruction_error.toFixed(4)}
                              </td>
                              <td style={{ padding: '0.65rem' }}>
                                <span style={{ padding: '0.15rem 0.45rem', borderRadius: '4px', fontSize: '0.68rem', fontWeight: 600, background: row.severity === 'CRITICAL' ? 'rgba(244, 63, 94, 0.15)' : row.severity === 'HIGH' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(16, 185, 129, 0.12)', color: row.severity === 'CRITICAL' ? '#fb7185' : row.severity === 'HIGH' ? '#fbbf24' : '#34d399', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                                  {(row.risk_score * 100).toFixed(0)}% [{row.severity}]
                                </span>
                              </td>
                              <td style={{ padding: '0.65rem', color: 'var(--text-secondary)' }}>
                                {row.top_deviation ? `${row.top_deviation.label} (${row.top_deviation.observed_value})` : 'Normal Baseline'}
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                </div>

              </div>
            ) : (
              /* Empty State */
              <div className="glass-panel" style={{ padding: '3.5rem 2rem', textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem' }}>
                <div style={{ background: 'rgba(255, 255, 255, 0.05)', padding: '1.25rem', borderRadius: '50%', color: '#38bdf8', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                  <Shield size={40} />
                </div>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#f8fafc' }}>
                  Ready to Ingest IoT Device Logs & Captures
                </h3>
                <p style={{ maxWidth: '520px', fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  Upload any Wireshark packet capture (<strong>.pcap</strong> / <strong>.pcapng</strong>) or device log export (<strong>.csv</strong> / <strong>.json</strong>) in the dropzone above to run 2-Stage AI Anomaly Detection, calculate risk scores, and isolate compromised IoT endpoints.
                </p>
              </div>
            )}

          </div>
        )}

        {/* Tab 2: Flow Injection Lab */}
        {activeTab === 'simulator' && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.5rem' }}>
            
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.4rem', color: '#f8fafc' }}>
                Manual IoT Flow Parameter Tester
              </h3>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                Simulate edge packet telemetry to evaluate how the Autoencoder reconstruction gatekeeper and classifier triage attacks.
              </p>

              <form onSubmit={handleRunSimulation} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div>
                    <label style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>Flow Duration (s)</label>
                    <input
                      type="number" step="0.001"
                      value={simForm.flow_duration}
                      onChange={(e) => setSimForm({ ...simForm, flow_duration: parseFloat(e.target.value) || 0 })}
                      style={{ width: '100%', padding: '0.5rem', background: '#07070a', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#fff', borderRadius: '6px' }}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>Packet Rate (pkts/sec)</label>
                    <input
                      type="number" step="1"
                      value={simForm.Rate}
                      onChange={(e) => setSimForm({ ...simForm, Rate: parseFloat(e.target.value) || 0 })}
                      style={{ width: '100%', padding: '0.5rem', background: '#07070a', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#fff', borderRadius: '6px' }}
                    />
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div>
                    <label style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>TCP Protocol (1 or 0)</label>
                    <input
                      type="number" min="0" max="1"
                      value={simForm.TCP}
                      onChange={(e) => setSimForm({ ...simForm, TCP: parseInt(e.target.value) || 0 })}
                      style={{ width: '100%', padding: '0.5rem', background: '#07070a', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#fff', borderRadius: '6px' }}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>SYN Flags Count</label>
                    <input
                      type="number"
                      value={simForm.syn_flag_number}
                      onChange={(e) => setSimForm({ ...simForm, syn_flag_number: parseInt(e.target.value) || 0 })}
                      style={{ width: '100%', padding: '0.5rem', background: '#07070a', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#fff', borderRadius: '6px' }}
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={simLoading}
                  style={{
                    marginTop: '0.5rem', padding: '0.7rem', borderRadius: '8px', border: '1px solid rgba(56, 189, 248, 0.4)',
                    background: 'linear-gradient(135deg, #1c1e28, #101117)', color: '#fff', fontWeight: 700, cursor: 'pointer',
                    boxShadow: '0 8px 20px rgba(0,0,0,0.8)'
                  }}
                >
                  {simLoading ? "Evaluating Flow..." : "Evaluate Simulated Flow"}
                </button>
              </form>
            </div>

            {/* Result Card */}
            <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc' }}>
                Live Triage Diagnostics
              </h3>
              {simResult ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.75rem', background: simResult.is_anomaly ? 'rgba(244, 63, 94, 0.12)' : 'rgba(16, 185, 129, 0.12)', borderRadius: '8px', border: `1px solid ${simResult.is_anomaly ? 'rgba(244, 63, 94, 0.3)' : 'rgba(16, 185, 129, 0.3)'}` }}>
                    <span style={{ fontWeight: 700, color: simResult.is_anomaly ? '#fb7185' : '#34d399' }}>
                      {simResult.is_anomaly ? "ANOMALOUS FLOW" : "BENIGN FLOW"}
                    </span>
                    <span style={{ fontWeight: 700, color: ATTACK_COLORS[simResult.classification] || '#fff' }}>
                      {simResult.classification} ({((simResult.attack_confidence || 0) * 100).toFixed(1)}%)
                    </span>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div style={{ background: '#09090d', padding: '0.75rem', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                      <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>Reconstruction MSE</div>
                      <div style={{ fontSize: '1.2rem', fontWeight: 700, color: '#38bdf8' }}>{simResult.reconstruction_error.toFixed(4)}</div>
                    </div>
                    <div style={{ background: '#09090d', padding: '0.75rem', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                      <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>Assessed Risk Score</div>
                      <div style={{ fontSize: '1.2rem', fontWeight: 700, color: '#fbbf24' }}>{(simResult.risk_assessment.risk_score * 100).toFixed(1)}%</div>
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', textAlign: 'center', margin: 'auto' }}>
                  Submit parameters on the left to evaluate risk.
                </div>
              )}
            </div>

          </div>
        )}

      </main>

    </div>
  );
}

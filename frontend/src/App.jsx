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
  PlusCircle,
  Settings as SettingsIcon,
  Globe,
  Link2,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Sun,
  Moon
} from 'lucide-react';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  ReferenceLine,
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

const getInitialApiBase = () => {
  const stored = localStorage.getItem("iot_ids_api_base");
  if (stored) return stored.replace(/\/$/, "");
  if (import.meta.env.VITE_API_BASE) return import.meta.env.VITE_API_BASE.replace(/\/$/, "");
  if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    return "http://localhost:8000/api/v1";
  }
  return "https://iot-ids.onrender.com/api/v1";
};

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
  const [apiBase, setApiBase] = useState(getInitialApiBase());
  const [customApiInput, setCustomApiInput] = useState(apiBase);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [systemStatus, setSystemStatus] = useState(null);
  const [backendConnected, setBackendConnected] = useState(null);
  const [evalReport, setEvalReport] = useState(null);

  // File Upload & Dataset Analyzer State
  const [selectedFile, setSelectedFile] = useState(null);
  const [isAnalyzingFile, setIsAnalyzingFile] = useState(false);
  const [fileAnalysisResult, setFileAnalysisResult] = useState(null);
  const [analysisFilter, setAnalysisFilter] = useState('ALL'); // 'ALL' | 'ANOMALY_ONLY' | 'CRITICAL'
  const [analysisSearch, setAnalysisSearch] = useState('');
  const [uploadToast, setUploadToast] = useState('');
  const [selectedDeviceFilter, setSelectedDeviceFilter] = useState('ALL');
  const [tablePage, setTablePage] = useState(1);
  const [pageSize, setPageSize] = useState(100);
  const [theme, setTheme] = useState(() => localStorage.getItem('cortexio_theme') || 'dark');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('cortexio_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  };

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

  // Check Backend Connectivity & Fetch System Status
  const checkBackendHealth = (targetUrl = apiBase) => {
    fetch(`${targetUrl}/status`)
      .then(res => {
        if (!res.ok) throw new Error("Status failed");
        return res.json();
      })
      .then(data => {
        setSystemStatus(data);
        setBackendConnected(true);
      })
      .catch(err => {
        console.error("Backend status check error:", err);
        setBackendConnected(false);
      });

    fetch(`${targetUrl}/evaluation-report`)
      .then(res => res.json())
      .then(data => setEvalReport(data))
      .catch(() => {});
  };

  useEffect(() => {
    checkBackendHealth(apiBase);
  }, [apiBase]);

  const handleSaveApiUrl = (e) => {
    e?.preventDefault();
    let cleaned = customApiInput.trim().replace(/\/$/, "");
    if (!cleaned.endsWith("/api/v1") && !cleaned.endsWith("/api")) {
      cleaned = `${cleaned}/api/v1`;
    }
    setApiBase(cleaned);
    setCustomApiInput(cleaned);
    localStorage.setItem("iot_ids_api_base", cleaned);
    setShowSettingsModal(false);
    checkBackendHealth(cleaned);
    setUploadToast(`Backend URL updated to ${cleaned}`);
  };

  // Upload File & Analyze with 2-Stage AI Model
  const handleUploadAndAnalyze = async () => {
    if (!selectedFile) return;
    setIsAnalyzingFile(true);
    setUploadToast('');
    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      formData.append("max_rows", "5000");

      const res = await fetch(`${apiBase}/upload-and-analyze`, {
        method: "POST",
        body: formData
      });

      if (!res.ok) {
        let errMsg = "Failed to analyze file";
        try {
          const err = await res.json();
          errMsg = err.detail || errMsg;
        } catch (_) {}
        throw new Error(errMsg);
      }

      const data = await res.json();
      setFileAnalysisResult(data);
      setSelectedDeviceFilter('ALL');
      setBackendConnected(true);
      setUploadToast(`Analysis Complete: Scanned ${data.total_records_analyzed} flows across ${data.total_devices_scanned || 0} IoT devices. Detected ${data.anomalies_detected} anomalies.`);
    } catch (err) {
      console.error(err);
      setBackendConnected(false);
      if (err.message.includes("Failed to fetch") || err.message.includes("NetworkError")) {
        setUploadToast(`Connection Error: Unable to reach backend at '${apiBase}'. If your Render backend was idle, it may take 45-60s to wake up, or click 'Configure Backend URL' in the top right to verify.`);
      } else {
        setUploadToast(`Error: ${err.message}`);
      }
    } finally {
      setIsAnalyzingFile(false);
    }
  };

  // Run Manual Flow Simulation
  const handleRunSimulation = async (e) => {
    e.preventDefault();
    setSimLoading(true);
    try {
      const res = await fetch(`${apiBase}/predict`, {
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
              <span style={{ fontSize: '1.25rem', fontWeight: 800, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
                CortexIO
              </span>
              <span style={{ fontSize: '0.68rem', padding: '0.15rem 0.45rem', borderRadius: '4px', background: theme === 'dark' ? 'rgba(255, 255, 255, 0.07)' : 'rgba(15, 23, 42, 0.06)', color: 'var(--text-secondary)', border: '1px solid var(--border-color)', fontWeight: 700, letterSpacing: '0.04em' }}>
                v2.4
              </span>
            </div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', fontWeight: 500 }}>
              AI Anomaly Gatekeeper & Attack Triage Engine
            </div>
          </div>
        </div>

        {/* Right: Quick Action & Theme Switching Pill */}
        <div className="nav-actions-group">
          {/* Interactive Dual-Mode Switching Button */}
          <div 
            className="theme-switcher-pill"
            onClick={toggleTheme}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') toggleTheme(); }}
            title={`Current: ${theme === 'dark' ? 'Dark' : 'Light'} Mode (Click to switch)`}
          >
            <div className={`theme-switcher-thumb ${theme}`} />
            <button
              type="button"
              className={`theme-switcher-btn ${theme === 'dark' ? 'active' : ''}`}
              onClick={(e) => { e.stopPropagation(); if (theme !== 'dark') toggleTheme(); }}
              aria-label="Dark Mode"
            >
              <Moon size={13} color={theme === 'dark' ? '#38bdf8' : 'currentColor'} className="theme-switcher-icon" />
              <span>Dark</span>
            </button>
            <button
              type="button"
              className={`theme-switcher-btn ${theme === 'light' ? 'active' : ''}`}
              onClick={(e) => { e.stopPropagation(); if (theme !== 'light') toggleTheme(); }}
              aria-label="Light Mode"
            >
              <Sun size={13} color={theme === 'light' ? '#f59e0b' : 'currentColor'} className="theme-switcher-icon" />
              <span>Light</span>
            </button>
          </div>

          {fileAnalysisResult ? (
            <button
              onClick={handleDownloadReport}
              style={{
                display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.45rem 0.85rem', borderRadius: '7px', border: '1px solid var(--border-color)',
                background: 'var(--bg-elevated)', color: 'var(--text-primary)', fontWeight: 600, fontSize: '0.78rem', cursor: 'pointer', boxShadow: 'var(--shadow-black-sm)'
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
                display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.45rem 0.85rem', borderRadius: '7px', border: '1px solid rgba(56, 189, 248, 0.4)',
                background: theme === 'dark' ? 'linear-gradient(135deg, #191b24, #0e0f14)' : '#f0f9ff', color: theme === 'dark' ? '#38bdf8' : '#0284c7', fontWeight: 600, fontSize: '0.78rem', cursor: 'pointer', boxShadow: 'var(--shadow-black-sm)'
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
            
            {/* 1. Hero Section (When No File Analyzed Yet) */}
            {!fileAnalysisResult ? (
              <div className="hero-wrapper">
                {/* Top Badge */}
                <div className="hero-badge">
                  <Zap size={14} />
                  <span>Next-Generation Neural IoT Intrusion Detection</span>
                </div>

                {/* Main Headline */}
                <h1 className="hero-title">
                  Real-Time AI Gatekeeper & <br />
                  <span className="hero-gradient-text">IoT Fleet Threat Intelligence</span>
                </h1>

                {/* Subtitle */}
                <p className="hero-subtitle">
                  Deploy unsupervised Autoencoder anomaly triage coupled with multi-class attack attribution. Ingest live Wireshark captures (<strong>.pcap</strong>) or telemetry datasets to pinpoint rogue IoT endpoints with sub-millisecond precision.
                </p>

                {/* Capabilities Tag Strip */}
                <div className="hero-features-strip">
                  <div className="hero-feature-tag">
                    <ShieldCheck size={14} color="#10b981" />
                    <span>99.4% Gatekeeper Accuracy</span>
                  </div>
                  <div className="hero-feature-tag">
                    <Cpu size={14} color="#38bdf8" />
                    <span>2-Stage Deep Autoencoder</span>
                  </div>
                  <div className="hero-feature-tag">
                    <Radio size={14} color="#a855f7" />
                    <span>Zero-Day Anomaly Triage</span>
                  </div>
                  <div className="hero-feature-tag">
                    <Layers size={14} color="#f59e0b" />
                    <span>Deep Packet Scan</span>
                  </div>
                </div>

                {/* Main Hero Ingestion Card */}
                <div className="glass-panel" style={{ width: '100%', marginTop: '1rem', padding: '1.75rem', display: 'flex', flexDirection: 'column', gap: '1.25rem', textAlign: 'left' }}>
                  {/* Dropzone Area */}
                  <div
                    onClick={() => fileInputRef.current?.click()}
                    className="dropzone-container"
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
                    <div style={{ background: 'rgba(56, 189, 248, 0.1)', padding: '1rem', borderRadius: '50%', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.25)', boxShadow: '0 4px 16px rgba(56, 189, 248, 0.2)' }}>
                      <UploadCloud size={32} />
                    </div>
                    <div>
                      <div style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                        {selectedFile ? `Selected: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)` : "Drag and drop network captures or device logs here"}
                      </div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                        Supports <strong>.pcap</strong>, <strong>.pcapng</strong>, <strong>.cap</strong>, <strong>Zeek logs</strong>, and <strong>CSV / JSON datasets</strong>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        fileInputRef.current?.click();
                      }}
                      style={{
                        marginTop: '0.25rem',
                        padding: '0.45rem 1rem',
                        borderRadius: '7px',
                        background: 'var(--bg-elevated)',
                        border: '1px solid var(--border-color)',
                        color: 'var(--text-primary)',
                        fontSize: '0.78rem',
                        fontWeight: 600,
                        cursor: 'pointer',
                        boxShadow: 'var(--shadow-black-sm)'
                      }}
                    >
                      Browse Local Files
                    </button>
                  </div>

                  {/* Ingestion Controls */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      <Layers size={14} color="#38bdf8" />
                      <span>Scan Mode: <strong>Fast Deep Scan (Max 5,000 flows)</strong></span>
                    </div>

                    <button
                      onClick={handleUploadAndAnalyze}
                      disabled={!selectedFile || isAnalyzingFile}
                      style={{
                        display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.7rem 1.6rem', borderRadius: '8px', border: selectedFile ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid var(--border-color)',
                        background: selectedFile ? (theme === 'dark' ? 'linear-gradient(135deg, #1c1e28, #101117)' : 'linear-gradient(135deg, #0284c7, #0369a1)') : 'var(--border-subtle)',
                        color: selectedFile ? '#ffffff' : 'var(--text-muted)',
                        fontWeight: 700, fontSize: '0.9rem', cursor: selectedFile ? 'pointer' : 'not-allowed',
                        boxShadow: selectedFile ? '0 8px 24px rgba(56, 189, 248, 0.25)' : 'none'
                      }}
                    >
                      {isAnalyzingFile ? <RefreshCw className="pulse-active" size={16} /> : <Search size={16} color={selectedFile && theme === 'light' ? '#ffffff' : '#38bdf8'} />}
                      {isAnalyzingFile ? "Analyzing Traffic with AI..." : "Run IoT Anomaly Audit"}
                    </button>
                  </div>

                  {uploadToast && (
                    <div style={{ padding: '0.75rem 1rem', borderRadius: '7px', background: uploadToast.startsWith('Error') || uploadToast.startsWith('Connection') ? 'rgba(244, 63, 94, 0.1)' : 'rgba(16, 185, 129, 0.1)', border: `1px solid ${uploadToast.startsWith('Error') || uploadToast.startsWith('Connection') ? 'rgba(244, 63, 94, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`, color: uploadToast.startsWith('Error') || uploadToast.startsWith('Connection') ? '#fb7185' : '#10b981', fontSize: '0.82rem', fontWeight: 600 }}>
                      {uploadToast}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              /* Compact Ingestion Bar (When Results Active) */
              <div className="glass-panel" style={{ padding: '1.25rem 1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                  <div style={{ background: 'rgba(56, 189, 248, 0.1)', padding: '0.65rem', borderRadius: '10px', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.2)' }}>
                    <FileSpreadsheet size={20} />
                  </div>
                  <div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {fileAnalysisResult.filename || 'Analyzed Dataset'}
                    </div>
                    <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                      Scanned <strong>{fileAnalysisResult.total_records_analyzed.toLocaleString()}</strong> flows across <strong>{fileAnalysisResult.total_devices_scanned || 1}</strong> IoT nodes
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                  <button
                    onClick={() => {
                      setFileAnalysisResult(null);
                      setSelectedFile(null);
                    }}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.5rem 0.95rem', borderRadius: '7px', border: '1px solid var(--border-color)',
                      background: 'var(--bg-elevated)', color: 'var(--text-primary)', fontWeight: 600, fontSize: '0.8rem', cursor: 'pointer', boxShadow: 'var(--shadow-black-sm)'
                    }}
                  >
                    <RefreshCw size={13} /> Upload Another File
                  </button>

                  <button
                    onClick={handleDownloadReport}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.5rem 0.95rem', borderRadius: '7px', border: '1px solid rgba(56, 189, 248, 0.35)',
                      background: theme === 'dark' ? 'linear-gradient(135deg, #191b24, #0e0f14)' : '#f0f9ff', color: theme === 'dark' ? '#38bdf8' : '#0284c7', fontWeight: 600, fontSize: '0.8rem', cursor: 'pointer', boxShadow: 'var(--shadow-black-sm)'
                    }}
                  >
                    <Download size={13} /> Export JSON Report
                  </button>
                </div>
              </div>
            )}

            {/* Audit Results Section */}
            {fileAnalysisResult && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                
                {/* 1. Fleet Executive Overview KPIs */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem' }}>
                  <div className="glass-panel" style={{ padding: '1.25rem' }}>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>Total Flow Records Scanned</div>
                    <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                      {fileAnalysisResult.total_records_analyzed.toLocaleString()}
                    </div>
                  </div>

                  <div className="glass-panel" style={{ padding: '1.25rem' }}>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>IoT Devices / Endpoints Found</div>
                    <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#38bdf8' }}>
                      {fileAnalysisResult.total_devices_scanned || (fileAnalysisResult.device_summaries ? fileAnalysisResult.device_summaries.length : 1)} Nodes
                    </div>
                  </div>

                  <div className="glass-panel" style={{ padding: '1.25rem' }}>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>Anomalous Flows Flagged</div>
                    <div style={{ fontSize: '1.6rem', fontWeight: 800, color: fileAnalysisResult.anomalies_detected > 0 ? '#f43f5e' : '#10b981' }}>
                      {fileAnalysisResult.anomalies_detected.toLocaleString()}
                    </div>
                  </div>

                  <div className="glass-panel" style={{ padding: '1.25rem' }}>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>High-Risk Compromised Devices</div>
                    <div style={{ fontSize: '1.6rem', fontWeight: 800, color: fileAnalysisResult.high_risk_devices_affected.length > 0 ? '#f59e0b' : '#10b981' }}>
                      {fileAnalysisResult.high_risk_devices_affected.length} Devices
                    </div>
                  </div>
                </div>

                {/* 2. Discovered IoT Devices & Health Status Rollup */}
                {fileAnalysisResult.device_summaries && fileAnalysisResult.device_summaries.length > 0 && (
                  <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                      <div>
                        <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
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
                          style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem', background: 'var(--bg-elevated)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', borderRadius: '4px', cursor: 'pointer' }}
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
                            background: selectedDeviceFilter === dev.device_id ? (theme === 'dark' ? 'rgba(25, 28, 38, 0.95)' : '#e0f2fe') : 'var(--bg-elevated)',
                            border: selectedDeviceFilter === dev.device_id ? '1.5px solid #38bdf8' : `1px solid ${dev.overall_health === 'CRITICAL' ? 'rgba(244, 63, 94, 0.35)' : dev.overall_health === 'HIGH_RISK' ? 'rgba(245, 158, 11, 0.35)' : 'var(--border-color)'}`,
                            cursor: 'pointer',
                            transition: 'all 0.2s',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '0.6rem',
                            boxShadow: 'var(--shadow-black-sm)'
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontWeight: 700, fontSize: '0.88rem', color: 'var(--text-primary)' }}>
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
                                border: `1px solid ${dev.overall_health === 'CRITICAL' ? 'rgba(244, 63, 94, 0.3)' : dev.overall_health === 'HIGH_RISK' ? 'rgba(245, 158, 11, 0.3)' : 'var(--border-color)'}`
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
                            <div style={{ height: '5px', background: 'var(--border-subtle)', borderRadius: '3px', overflow: 'hidden' }}>
                              <div style={{ width: `${Math.min(100, dev.max_risk_score)}%`, height: '100%', background: dev.max_risk_score >= 70 ? '#f43f5e' : dev.max_risk_score >= 40 ? '#f59e0b' : '#10b981' }}></div>
                            </div>
                          </div>

                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
                            <span>Anomalies: <strong>{dev.anomaly_flows}/{dev.total_flows} ({dev.anomaly_rate}%)</strong></span>
                            <span>Attribution: <strong style={{ color: ATTACK_COLORS[dev.primary_attack] || 'var(--text-primary)' }}>{dev.primary_attack}</strong></span>
                          </div>

                          {dev.top_signals && dev.top_signals.length > 0 && (
                            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', background: 'var(--bg-input)', padding: '0.3rem 0.45rem', borderRadius: '4px', border: '1px solid var(--border-color)' }}>
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
                  
                  {/* Anomaly & Threat Timeline Chart */}
                  <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                      <div>
                        <h4 style={{ fontSize: '0.88rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                          <Activity size={16} color="#38bdf8" />
                          IoT Fleet Anomaly & Threat Timeline
                        </h4>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                          Sequential flow anomaly score (0-100%) vs baseline decision boundary
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.72rem', color: '#fb7185' }}>
                          <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f43f5e' }}></span> Anomaly Spike
                        </span>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.72rem', color: '#34d399' }}>
                          <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10b981' }}></span> Normal Baseline
                        </span>
                      </div>
                    </div>
                    <div style={{ height: '220px', width: '100%' }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart
                          data={fileAnalysisResult.rows.slice(0, 100).map(r => ({
                            index: r.row_index,
                            anomalyScorePct: Math.min(100, Math.round((r.anomaly_score || 0) * 100)),
                            riskScorePct: Math.round((r.risk_score || 0) * 100),
                            isAnomaly: r.is_anomaly,
                            threat: r.classification,
                            deviceId: r.device_id,
                            severity: r.severity,
                            topDev: r.top_deviation ? `${r.top_deviation.label} (${r.top_deviation.observed_value})` : 'Normal Baseline'
                          }))}
                        >
                          <defs>
                            <linearGradient id="anomalyGradient" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.7} />
                              <stop offset="60%" stopColor="#38bdf8" stopOpacity={0.25} />
                              <stop offset="95%" stopColor="#10b981" stopOpacity={0.05} />
                            </linearGradient>
                          </defs>
                          <XAxis dataKey="index" stroke="var(--text-muted)" fontSize={11} tickLine={false} label={{ value: 'Network Flow #', position: 'insideBottom', offset: -2, fill: 'var(--text-muted)', fontSize: 10 }} />
                          <YAxis domain={[0, 100]} stroke="var(--text-muted)" fontSize={11} tickLine={false} unit="%" />
                          <ReferenceLine y={40} stroke="rgba(244, 63, 94, 0.45)" strokeDasharray="3 3" label={{ value: 'Alert Line (40%)', fill: '#fb7185', fontSize: 10, position: 'right' }} />
                          <Tooltip
                            content={({ active, payload }) => {
                              if (!active || !payload || !payload.length) return null;
                              const d = payload[0].payload;
                              return (
                                <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.65rem 0.85rem', fontSize: '0.74rem', boxShadow: 'var(--shadow-black-md)', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.3rem' }}>
                                    <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>Flow #{d.index}</span>
                                    <span style={{ padding: '0.1rem 0.4rem', borderRadius: '4px', fontSize: '0.65rem', fontWeight: 700, background: d.isAnomaly ? 'rgba(244, 63, 94, 0.2)' : 'rgba(16, 185, 129, 0.2)', color: d.isAnomaly ? '#fb7185' : '#34d399' }}>
                                      {d.isAnomaly ? 'ANOMALY' : 'NORMAL'}
                                    </span>
                                  </div>
                                  <div style={{ color: 'var(--text-secondary)' }}>Device: <strong style={{ color: 'var(--text-primary)' }}>{d.deviceId}</strong></div>
                                  <div style={{ color: 'var(--text-secondary)' }}>Threat Classification: <strong style={{ color: ATTACK_COLORS[d.threat] || 'var(--text-primary)' }}>{d.threat}</strong></div>
                                  <div style={{ color: 'var(--text-secondary)' }}>Anomaly Deviation Score: <strong style={{ color: d.isAnomaly ? '#fb7185' : '#38bdf8' }}>{d.anomalyScorePct}%</strong></div>
                                  <div style={{ color: 'var(--text-secondary)' }}>Trigger Signal: <strong style={{ color: '#fbbf24' }}>{d.topDev}</strong></div>
                                </div>
                              );
                            }}
                          />
                          <Area type="monotone" dataKey="anomalyScorePct" stroke="#f43f5e" strokeWidth={2} fillOpacity={1} fill="url(#anomalyGradient)" dot={{ r: 2, fill: '#38bdf8' }} />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Attack Breakdown Distribution */}
                  <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    <h4 style={{ fontSize: '0.88rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                      Detected Attack Family Classifications
                    </h4>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.6rem' }}>
                      {Object.entries(fileAnalysisResult.attack_family_breakdown).map(([atkName, count]) => (
                        <div
                          key={atkName}
                          style={{
                            padding: '0.45rem 0.8rem',
                            borderRadius: '8px',
                            background: 'var(--bg-elevated)',
                            border: `1px solid ${ATTACK_COLORS[atkName] || '#38bdf8'}35`,
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.5rem',
                            fontSize: '0.78rem',
                            boxShadow: 'var(--shadow-black-sm)'
                          }}
                        >
                          <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: ATTACK_COLORS[atkName] || 'var(--text-primary)' }}></span>
                          <span style={{ fontWeight: 600, color: ATTACK_COLORS[atkName] || 'var(--text-primary)' }}>{atkName}:</span>
                          <strong style={{ color: 'var(--text-primary)' }}>{count} flows</strong>
                        </div>
                      ))}
                    </div>
                  </div>

                </div>

                {/* 4. Filterable Diagnostic Flow Log Table */}
                <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                    <div>
                      <h3 style={{ fontSize: '0.98rem', fontWeight: 700, color: 'var(--text-primary)' }}>
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
                        style={{ padding: '0.4rem 0.75rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', borderRadius: '6px', fontSize: '0.8rem', minWidth: '180px' }}
                      />

                      <select
                        value={analysisFilter}
                        onChange={(e) => setAnalysisFilter(e.target.value)}
                        style={{ padding: '0.4rem 0.75rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', borderRadius: '6px', fontSize: '0.8rem' }}
                      >
                        <option value="ALL">All Flows</option>
                        <option value="ANOMALY_ONLY">Anomalies Only</option>
                        <option value="CRITICAL">Critical / High Severity</option>
                      </select>
                    </div>
                  </div>

                  {(() => {
                    const filteredRows = (fileAnalysisResult.rows || []).filter(r => {
                      if (selectedDeviceFilter !== 'ALL' && r.device_id !== selectedDeviceFilter) return false;
                      if (analysisFilter === 'ANOMALY_ONLY' && !r.is_anomaly) return false;
                      if (analysisFilter === 'CRITICAL' && !['CRITICAL', 'HIGH'].includes(r.severity)) return false;
                      if (analysisSearch) {
                        const query = analysisSearch.toLowerCase();
                        return r.device_id.toLowerCase().includes(query) || r.classification.toLowerCase().includes(query);
                      }
                      return true;
                    });

                    const totalPages = Math.max(1, Math.ceil(filteredRows.length / pageSize));
                    const safePage = Math.min(tablePage, totalPages);
                    const paginatedRows = filteredRows.slice((safePage - 1) * pageSize, safePage * pageSize);

                    return (
                      <>
                        <div style={{ overflowX: 'auto', maxHeight: '520px' }}>
                          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem' }}>
                            <thead>
                              <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left', color: 'var(--text-secondary)' }}>
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
                              {paginatedRows.length > 0 ? (
                                paginatedRows.map((row) => (
                                  <tr key={row.row_index} style={{ borderBottom: '1px solid var(--border-subtle)', background: row.is_anomaly ? 'rgba(244, 63, 94, 0.05)' : 'transparent' }}>
                                    <td style={{ padding: '0.65rem', color: 'var(--text-muted)' }}>{row.row_index}</td>
                                    <td style={{ padding: '0.65rem', fontWeight: 600, color: 'var(--text-primary)' }}>{row.device_id}</td>
                                    <td style={{ padding: '0.65rem' }}>
                                      <span style={{ padding: '0.15rem 0.45rem', borderRadius: '4px', fontSize: '0.68rem', fontWeight: 700, background: row.is_anomaly ? 'rgba(244, 63, 94, 0.15)' : 'rgba(16, 185, 129, 0.15)', color: row.is_anomaly ? '#fb7185' : '#34d399', border: `1px solid ${row.is_anomaly ? 'rgba(244, 63, 94, 0.3)' : 'rgba(16, 185, 129, 0.3)'}` }}>
                                        {row.is_anomaly ? "ANOMALY" : "NORMAL"}
                                      </span>
                                    </td>
                                    <td style={{ padding: '0.65rem', fontWeight: 700, color: ATTACK_COLORS[row.classification] || 'var(--text-primary)' }}>
                                      {row.classification}
                                    </td>
                                    <td style={{ padding: '0.65rem', fontFamily: 'var(--font-mono)' }}>
                                      {row.reconstruction_error.toFixed(4)}
                                    </td>
                                    <td style={{ padding: '0.65rem' }}>
                                      <span style={{ padding: '0.15rem 0.45rem', borderRadius: '4px', fontSize: '0.68rem', fontWeight: 600, background: row.severity === 'CRITICAL' ? 'rgba(244, 63, 94, 0.15)' : row.severity === 'HIGH' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(16, 185, 129, 0.12)', color: row.severity === 'CRITICAL' ? '#fb7185' : row.severity === 'HIGH' ? '#fbbf24' : '#34d399', border: '1px solid var(--border-color)' }}>
                                        {(row.risk_score * 100).toFixed(0)}% [{row.severity}]
                                      </span>
                                    </td>
                                    <td style={{ padding: '0.65rem', color: 'var(--text-secondary)' }}>
                                      {row.top_deviation ? `${row.top_deviation.label} (${row.top_deviation.observed_value})` : 'Normal Baseline'}
                                    </td>
                                  </tr>
                                ))
                              ) : (
                                <tr>
                                  <td colSpan={7} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                                    No network flow records match the selected search/filter.
                                  </td>
                                </tr>
                              )}
                            </tbody>
                          </table>
                        </div>

                        {/* Pagination Bar */}
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border-color)' }}>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '1rem' }}>
                            <span>
                              Showing <strong>{filteredRows.length === 0 ? 0 : (safePage - 1) * pageSize + 1}</strong> - <strong>{Math.min(safePage * pageSize, filteredRows.length)}</strong> of <strong>{filteredRows.length.toLocaleString()}</strong> flows
                            </span>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                              <span>Per page:</span>
                              <select
                                value={pageSize}
                                onChange={(e) => {
                                  setPageSize(Number(e.target.value));
                                  setTablePage(1);
                                }}
                                style={{ padding: '0.2rem 0.4rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', borderRadius: '4px', fontSize: '0.74rem' }}
                              >
                                <option value={50}>50</option>
                                <option value={100}>100</option>
                                <option value={200}>200</option>
                              </select>
                            </div>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                            <button
                              onClick={() => setTablePage(1)}
                              disabled={safePage <= 1}
                              title="First Page"
                              style={{ padding: '0.3rem 0.5rem', borderRadius: '5px', background: safePage <= 1 ? 'transparent' : 'var(--bg-elevated)', border: '1px solid var(--border-color)', color: safePage <= 1 ? 'var(--text-muted)' : 'var(--text-primary)', cursor: safePage <= 1 ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center' }}
                            >
                              <ChevronsLeft size={14} />
                            </button>
                            <button
                              onClick={() => setTablePage(p => Math.max(1, p - 1))}
                              disabled={safePage <= 1}
                              title="Previous Page"
                              style={{ padding: '0.3rem 0.5rem', borderRadius: '5px', background: safePage <= 1 ? 'transparent' : 'var(--bg-elevated)', border: '1px solid var(--border-color)', color: safePage <= 1 ? 'var(--text-muted)' : 'var(--text-primary)', cursor: safePage <= 1 ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center' }}
                            >
                              <ChevronLeft size={14} />
                            </button>

                            <span style={{ fontSize: '0.76rem', color: 'var(--text-primary)', padding: '0 0.5rem', fontWeight: 600 }}>
                              Page {safePage} of {totalPages}
                            </span>

                            <button
                              onClick={() => setTablePage(p => Math.min(totalPages, p + 1))}
                              disabled={safePage >= totalPages}
                              title="Next Page"
                              style={{ padding: '0.3rem 0.5rem', borderRadius: '5px', background: safePage >= totalPages ? 'transparent' : 'var(--bg-elevated)', border: '1px solid var(--border-color)', color: safePage >= totalPages ? 'var(--text-muted)' : 'var(--text-primary)', cursor: safePage >= totalPages ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center' }}
                            >
                              <ChevronRight size={14} />
                            </button>
                            <button
                              onClick={() => setTablePage(totalPages)}
                              disabled={safePage >= totalPages}
                              title="Last Page"
                              style={{ padding: '0.3rem 0.5rem', borderRadius: '5px', background: safePage >= totalPages ? 'transparent' : 'var(--bg-elevated)', border: '1px solid var(--border-color)', color: safePage >= totalPages ? 'var(--text-muted)' : 'var(--text-primary)', cursor: safePage >= totalPages ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center' }}
                            >
                              <ChevronsRight size={14} />
                            </button>
                          </div>
                        </div>
                      </>
                    );
                  })()}
                </div>

              </div>
            )}

          </div>
        )}



      </main>

    </div>
  );
}

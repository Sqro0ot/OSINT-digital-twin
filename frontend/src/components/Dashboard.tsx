import React, { useEffect, useState, useCallback } from 'react';
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts';

const API_BASE = 'http://localhost:8000';

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
  UNKNOWN:  '#94a3b8',
};

const ALERT_TYPE_LABEL: Record<string, string> = {
  NEW_VULNERABILITIES:   '🆕 New CVE',
  RISK_ELEVATED:         '📈 Risk Up',
  HIGH_EPSS_SCORE:       '☣️ High EPSS',
  EXPOSED_CRITICAL_PORT: '🔓 Open Port',
  ZERO_DAY_DETECTED:     '💀 Zero-Day',
};

const ALERT_TYPE_COLOR: Record<string, string> = {
  NEW_VULNERABILITIES:   '#f97316',
  RISK_ELEVATED:         '#ef4444',
  HIGH_EPSS_SCORE:       '#a855f7',
  EXPOSED_CRITICAL_PORT: '#06b6d4',
  ZERO_DAY_DETECTED:     '#ef4444',
};

interface RiskEntry   { name: string; value: number; }
interface CveEntry    { cve_id: string; count: number; }
interface EpssEntry   { cve_id: string; epss_score: number; }
interface AlertEntry  { id: number; alert_type: string; severity: string; message: string; created_at: string; asset_id: number; }
interface DashboardProps { onSimulationComplete: () => void; }

export default function Dashboard({ onSimulationComplete }: DashboardProps) {
  const [riskData,      setRiskData]      = useState<RiskEntry[]>([]);
  const [cveData,       setCveData]       = useState<CveEntry[]>([]);
  const [epssData,      setEpssData]      = useState<EpssEntry[]>([]);
  const [recentAlerts,  setRecentAlerts]  = useState<AlertEntry[]>([]);
  const [totalCameras,  setTotalCameras]  = useState(0);
  const [criticalCount, setCriticalCount] = useState(0);
  const [epssMax,       setEpssMax]       = useState<number | null>(null);
  const [lastSync,      setLastSync]      = useState<string | null>(null);

  const [simLoading,        setSimLoading]        = useState(false);
  const [resetLoading,      setResetLoading]       = useState(false);
  const [clearAssetsLoading,setClearAssetsLoading] = useState(false);
  const [rebuildLoading,    setRebuildLoading]     = useState(false);
  const [lastSimTime,       setLastSimTime]        = useState<string | null>(null);

  // --- Add device by IP ---
  const [ipInput,     setIpInput]     = useState('');
  const [ipLoading,   setIpLoading]   = useState(false);
  const [ipResult,    setIpResult]    = useState<{ ok: boolean; message: string } | null>(null);

  const fetchAnalytics = useCallback(async () => {
    try {
      const [riskRes, cveRes, epssRes, alertRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/analytics/risk-distribution`),
        fetch(`${API_BASE}/analytics/top-cves?limit=5`),
        fetch(`${API_BASE}/analytics/epss-top?limit=5`).catch(() => null),
        fetch(`${API_BASE}/alerts/recent?limit=8`).catch(() => null),
        fetch(`${API_BASE}/stats/summary`).catch(() => null),
      ]);

      const risk: RiskEntry[] = await riskRes.json();
      const cves: CveEntry[]  = await cveRes.json();
      setRiskData(risk);
      setCveData(cves);

      const total = risk.reduce((s, r) => s + r.value, 0);
      setTotalCameras(total);
      setCriticalCount(risk.find(r => r.name === 'CRITICAL')?.value ?? 0);

      if (epssRes && epssRes.ok) {
        const epss: EpssEntry[] = await epssRes.json();
        setEpssData(epss);
        setEpssMax(epss.length > 0 ? epss[0].epss_score : null);
      }

      if (alertRes && alertRes.ok) {
        const alerts: AlertEntry[] = await alertRes.json();
        setRecentAlerts(alerts.map(a => ({ ...a, alert_type: a.alert_type || (a as any).type || 'UNKNOWN' })));
      }

      if (statsRes && statsRes.ok) {
        const stats = await statsRes.json();
        if (stats.last_sync) setLastSync(stats.last_sync);
      }
    } catch (e) {
      console.error('Failed to fetch analytics:', e);
    }
  }, []);

  useEffect(() => {
    fetchAnalytics();
    const interval = setInterval(fetchAnalytics, 15000);
    return () => clearInterval(interval);
  }, [fetchAnalytics]);

  const handleSimulate = async () => {
    setSimLoading(true);
    try {
      const res  = await fetch(`${API_BASE}/simulate/zero-day`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'success') {
        setLastSimTime(new Date().toLocaleTimeString());
        await fetchAnalytics();
        onSimulationComplete();
      } else alert(data.message || 'Simulation failed');
    } catch (e) { console.error(e); }
    setSimLoading(false);
  };

  const handleReset = async () => {
    setResetLoading(true);
    try {
      await fetch(`${API_BASE}/simulate/reset`, { method: 'POST' });
      setLastSimTime(null);
      await fetchAnalytics();
      onSimulationComplete();
    } catch (e) { console.error(e); }
    setResetLoading(false);
  };

  const handleClearAssets = async () => {
    if (!window.confirm('Удалить все камеры и алерты?')) return;
    setClearAssetsLoading(true);
    try {
      const res  = await fetch(`${API_BASE}/admin/assets/clear?confirm=DELETE&asset_type=camera`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'success') { setLastSimTime(null); await fetchAnalytics(); onSimulationComplete(); }
    } catch (e) { console.error(e); }
    setClearAssetsLoading(false);
  };

  const handleRebuild = async () => {
    if (!window.confirm('Пересоздать все активы из БД?')) return;
    setRebuildLoading(true);
    try {
      const res  = await fetch(`${API_BASE}/admin/assets/rebuild`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'success') { setLastSimTime(null); await fetchAnalytics(); onSimulationComplete(); }
    } catch (e) { console.error(e); }
    setRebuildLoading(false);
  };

  const handleAddIp = async () => {
    const ip = ipInput.trim();
    if (!ip) return;
    setIpLoading(true);
    setIpResult(null);
    try {
      const res = await fetch(`${API_BASE}/devices/add?ip=${encodeURIComponent(ip)}`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        setIpResult({ ok: true, message: `✅ Добавлено: ${data.ip} — ${data.risk_level}` });
        setIpInput('');
        await fetchAnalytics();
        onSimulationComplete();
      } else {
        setIpResult({ ok: false, message: `❌ ${data.detail || 'Ошибка'}` });
      }
    } catch (e) {
      setIpResult({ ok: false, message: '❌ Нет связи с сервером' });
    }
    setIpLoading(false);
  };

  const criticalPercent = totalCameras > 0 ? Math.round((criticalCount / totalCameras) * 100) : 0;

  const epssColor = epssMax === null ? '#94a3b8'
    : epssMax >= 0.7 ? '#ef4444'
    : epssMax >= 0.4 ? '#f97316'
    : '#22c55e';

  const btnBase: React.CSSProperties = {
    width: '100%', borderRadius: '6px', padding: '8px',
    fontWeight: 600, fontSize: '11px', transition: 'background 0.2s',
    marginBottom: '8px', cursor: 'pointer',
  };

  const sectionLabel: React.CSSProperties = {
    color: '#94a3b8', fontSize: '11px', marginBottom: '6px',
    textTransform: 'uppercase', letterSpacing: '0.05em',
  };

  return (
    <div style={{ background: '#0f172a', color: '#e2e8f0', height: '100%', overflowY: 'auto',
      display: 'flex', flexDirection: 'column', fontFamily: 'system-ui, sans-serif', fontSize: '13px' }}>

      {/* Header */}
      <div style={{ padding: '16px 16px 10px', borderBottom: '1px solid #1e293b',
        background: '#0f172a', position: 'sticky', top: 0, zIndex: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
          <span style={{ fontSize: '18px' }}>🛰️</span>
          <span style={{ fontWeight: 700, fontSize: '15px', color: '#f1f5f9' }}>OSINT Digital Twin</span>
        </div>
        <div style={{ color: '#64748b', fontSize: '11px' }}>Алматы • Мониторинг в реальном времени</div>
        {lastSync && (
          <div style={{ color: '#475569', fontSize: '10px', marginTop: '3px' }}>
            🕐 Синхронизировано: {new Date(lastSync).toLocaleString('ru-RU')}
          </div>
        )}
      </div>

      {/* KPI Cards */}
      <div style={{ padding: '12px 16px 8px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
        <div style={{ background: '#1e293b', borderRadius: '8px', padding: '10px', textAlign: 'center' }}>
          <div style={{ fontSize: '22px', fontWeight: 700, color: '#60a5fa' }}>{totalCameras}</div>
          <div style={{ fontSize: '10px', color: '#94a3b8', marginTop: '2px' }}>Камер</div>
        </div>
        <div style={{ background: '#1e293b', borderRadius: '8px', padding: '10px', textAlign: 'center' }}>
          <div style={{ fontSize: '22px', fontWeight: 700, color: '#ef4444' }}>{criticalCount}</div>
          <div style={{ fontSize: '10px', color: '#94a3b8', marginTop: '2px' }}>Критичных</div>
        </div>
        <div style={{ background: '#1e293b', borderRadius: '8px', padding: '10px', textAlign: 'center' }}>
          <div style={{ fontSize: '22px', fontWeight: 700, color: criticalPercent > 30 ? '#ef4444' : '#22c55e' }}>
            {criticalPercent}%
          </div>
          <div style={{ fontSize: '10px', color: '#94a3b8', marginTop: '2px' }}>% Критичных</div>
        </div>
        <div style={{ background: '#1e293b', borderRadius: '8px', padding: '10px', textAlign: 'center',
          border: epssMax !== null && epssMax >= 0.7 ? '1px solid #7c3aed' : '1px solid transparent' }}>
          <div style={{ fontSize: '22px', fontWeight: 700, color: epssColor }}>
            {epssMax !== null ? (epssMax * 100).toFixed(0) + '%' : '—'}
          </div>
          <div style={{ fontSize: '10px', color: '#94a3b8', marginTop: '2px' }}>EPSS max</div>
        </div>
      </div>

      {/* Add IP */}
      <div style={{ margin: '0 16px 8px', background: '#1e293b', borderRadius: '10px',
        padding: '14px', border: '1px solid #334155' }}>
        <div style={{ fontWeight: 600, fontSize: '12px', color: '#f1f5f9', marginBottom: '8px' }}>➕ Добавить устройство по IP</div>
        <div style={{ display: 'flex', gap: '6px' }}>
          <input
            type="text"
            value={ipInput}
            onChange={e => { setIpInput(e.target.value); setIpResult(null); }}
            onKeyDown={e => e.key === 'Enter' && !ipLoading && handleAddIp()}
            placeholder="Например: 77.91.68.35"
            disabled={ipLoading}
            style={{
              flex: 1, background: '#0f172a', border: '1px solid #334155',
              borderRadius: '6px', padding: '7px 10px', color: '#e2e8f0',
              fontSize: '12px', outline: 'none',
              opacity: ipLoading ? 0.5 : 1,
            }}
          />
          <button
            onClick={handleAddIp}
            disabled={ipLoading || !ipInput.trim()}
            style={{
              background: ipLoading || !ipInput.trim() ? '#1e3a5f' : '#2563eb',
              color: 'white', border: 'none', borderRadius: '6px',
              padding: '7px 14px', fontWeight: 600, fontSize: '12px',
              cursor: ipLoading || !ipInput.trim() ? 'not-allowed' : 'pointer',
              whiteSpace: 'nowrap',
            }}
          >
            {ipLoading ? '⏳' : '▶ Добавить'}
          </button>
        </div>
        {ipResult && (
          <div style={{
            marginTop: '8px', fontSize: '11px', lineHeight: '1.4',
            color: ipResult.ok ? '#86efac' : '#fca5a5',
            background: ipResult.ok ? '#052e16' : '#450a0a',
            border: `1px solid ${ipResult.ok ? '#166534' : '#7f1d1d'}`,
            borderRadius: '6px', padding: '7px 10px',
          }}>
            {ipResult.message}
          </div>
        )}
        <div style={{ color: '#475569', fontSize: '10px', marginTop: '6px' }}>
          Прогоняет IP через InternetDB → нормализацию → синхронизацию с картой
        </div>
      </div>

      {/* Pie Chart */}
      <div style={{ padding: '0 16px 8px' }}>
        <div style={sectionLabel}>Распределение рисков</div>
        <div style={{ height: '190px' }}>
          {riskData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={riskData} cx="50%" cy="50%" innerRadius={50} outerRadius={70}
                  paddingAngle={3} dataKey="value">
                  {riskData.map((entry, i) => (
                    <Cell key={i} fill={RISK_COLORS[entry.name] || RISK_COLORS.UNKNOWN} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#1e293b', border: 'none', borderRadius: '6px', color: '#e2e8f0' }} />
                <Legend iconSize={8} wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#475569' }}>Нет данных</div>
          )}
        </div>
      </div>

      {/* Top CVE by count */}
      {cveData.length > 0 && (
        <div style={{ padding: '0 16px 8px' }}>
          <div style={sectionLabel}>Топ CVE (частота)</div>
          <div style={{ height: '150px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={cveData} layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" tick={{ fontSize: 10, fill: '#64748b' }} />
                <YAxis dataKey="cve_id" type="category" width={105} tick={{ fontSize: 9, fill: '#94a3b8' }} />
                <Tooltip contentStyle={{ background: '#1e293b', border: 'none', borderRadius: '6px', color: '#e2e8f0', fontSize: '11px' }} />
                <Bar dataKey="count" fill="#f97316" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Top CVE by EPSS */}
      {epssData.length > 0 && (
        <div style={{ padding: '0 16px 8px' }}>
          <div style={{ ...sectionLabel, color: '#a78bfa' }}>☣️ Топ CVE по EPSS (вероятность эксплуатации)</div>
          <div style={{ height: '150px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={epssData} layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" domain={[0, 1]} tickFormatter={v => `${(v * 100).toFixed(0)}%`}
                  tick={{ fontSize: 10, fill: '#64748b' }} />
                <YAxis dataKey="cve_id" type="category" width={105} tick={{ fontSize: 9, fill: '#a78bfa' }} />
                <Tooltip
                  formatter={(value: number) => [`${(value * 100).toFixed(1)}%`, 'EPSS']}
                  contentStyle={{ background: '#1e293b', border: 'none', borderRadius: '6px', color: '#e2e8f0', fontSize: '11px' }} />
                <Bar dataKey="epss_score" fill="#a855f7" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Recent Alerts */}
      {recentAlerts.length > 0 && (
        <div style={{ padding: '0 16px 8px' }}>
          <div style={sectionLabel}>Последние алерты</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {recentAlerts.map(a => {
              const color = ALERT_TYPE_COLOR[a.alert_type] || '#94a3b8';
              const label = ALERT_TYPE_LABEL[a.alert_type] || a.alert_type;
              return (
                <div key={a.id} style={{
                  background: '#1e293b', borderRadius: '6px', padding: '7px 10px',
                  borderLeft: `3px solid ${color}`, fontSize: '11px',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                    <span style={{ color, fontWeight: 600 }}>{label}</span>
                    <span style={{ color: '#475569', fontSize: '10px' }}>
                      {new Date(a.created_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                  <div style={{ color: '#94a3b8', lineHeight: '1.4' }}>{a.message}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Simulation */}
      <div style={{ margin: '8px 16px 8px', background: '#1e293b', borderRadius: '10px',
        padding: '14px', border: '1px solid #334155' }}>
        <div style={{ fontWeight: 600, fontSize: '12px', color: '#f1f5f9', marginBottom: '4px' }}>🎯 Симуляция атаки</div>
        <div style={{ color: '#64748b', fontSize: '11px', marginBottom: '12px', lineHeight: '1.5' }}>
          Запустить симуляцию нулевого дня — сгенерирует алерты и изменит статус камер.
        </div>
        {lastSimTime && (
          <div style={{ background: '#450a0a', border: '1px solid #7f1d1d', borderRadius: '6px',
            padding: '8px', marginBottom: '10px', fontSize: '11px', color: '#fca5a5' }}>
            ⚠️ Симуляция активна с {lastSimTime}
          </div>
        )}
        <button onClick={handleSimulate} disabled={simLoading}
          style={{ ...btnBase, background: simLoading ? '#374151' : '#dc2626', color: 'white',
            border: 'none', padding: '10px', fontWeight: 700, fontSize: '12px',
            cursor: simLoading ? 'not-allowed' : 'pointer' }}>
          {simLoading ? '⏳ Выполняется...' : '🔴 SIMULATE ZERO-DAY ATTACK'}
        </button>
        <button onClick={handleReset} disabled={resetLoading}
          style={{ ...btnBase, background: 'transparent', color: '#93c5fd',
            border: '1px solid #2563eb', cursor: resetLoading ? 'not-allowed' : 'pointer', marginBottom: 0 }}>
          {resetLoading ? '⏳ Сброс...' : '🔄 Сбросить симуляцию'}
        </button>
      </div>

      {/* Admin */}
      <div style={{ margin: '0 16px 16px', background: '#1e293b', borderRadius: '10px',
        padding: '14px', border: '1px solid #334155' }}>
        <div style={{ fontWeight: 600, fontSize: '12px', color: '#94a3b8', marginBottom: '10px' }}>⚙️ Управление БД</div>
        <button onClick={handleRebuild} disabled={rebuildLoading}
          style={{ ...btnBase, background: 'transparent', color: '#86efac',
            border: '1px solid #16a34a', cursor: rebuildLoading ? 'not-allowed' : 'pointer' }}>
          {rebuildLoading ? '⏳ Перестройка...' : '🔄 Перестроить (clear + sync)'}
        </button>
        <button onClick={handleClearAssets} disabled={clearAssetsLoading}
          style={{ ...btnBase, background: 'transparent', color: '#fca5a5',
            border: '1px solid #ef4444', cursor: clearAssetsLoading ? 'not-allowed' : 'pointer', marginBottom: 0 }}>
          {clearAssetsLoading ? '⏳ Очистка...' : '🗑️ Очистить ассеты (DB)'}
        </button>
      </div>
    </div>
  );
}

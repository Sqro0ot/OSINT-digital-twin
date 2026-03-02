import React, { useEffect, useState, useCallback } from 'react';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';

const API_BASE = 'http://localhost:8000';

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  UNKNOWN: '#94a3b8',
};

interface RiskEntry {
  name: string;
  value: number;
}

interface CveEntry {
  cve_id: string;
  count: number;
}

interface DashboardProps {
  onSimulationComplete: () => void;
}

export default function Dashboard({ onSimulationComplete }: DashboardProps) {
  const [riskData, setRiskData] = useState<RiskEntry[]>([]);
  const [cveData, setCveData] = useState<CveEntry[]>([]);
  const [totalCameras, setTotalCameras] = useState<number>(0);
  const [criticalCount, setCriticalCount] = useState<number>(0);
  const [simLoading, setSimLoading] = useState(false);
  const [resetLoading, setResetLoading] = useState(false);
  const [clearLoading, setClearLoading] = useState(false);
  const [rebuildLoading, setRebuildLoading] = useState(false);
  const [lastSimTime, setLastSimTime] = useState<string | null>(null);

  const fetchAnalytics = useCallback(async () => {
    try {
      const [riskRes, cveRes] = await Promise.all([
        fetch(`${API_BASE}/analytics/risk-distribution`),
        fetch(`${API_BASE}/analytics/top-cves?limit=5`),
      ]);
      const risk: RiskEntry[] = await riskRes.json();
      const cves: CveEntry[] = await cveRes.json();

      setRiskData(risk);
      setCveData(cves);

      const total = risk.reduce((sum, r) => sum + r.value, 0);
      setTotalCameras(total);
      const crit = risk.find((r) => r.name === 'CRITICAL');
      setCriticalCount(crit ? crit.value : 0);
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
      const res = await fetch(`${API_BASE}/simulate/zero-day`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'success') {
        setLastSimTime(new Date().toLocaleTimeString());
        await fetchAnalytics();
        onSimulationComplete();
      } else {
        alert(data.message || 'Simulation failed');
      }
    } catch (e) {
      console.error('Simulation error:', e);
    }
    setSimLoading(false);
  };

  const handleReset = async () => {
    setResetLoading(true);
    try {
      await fetch(`${API_BASE}/simulate/reset`, { method: 'POST' });
      setLastSimTime(null);
      await fetchAnalytics();
      onSimulationComplete();
    } catch (e) {
      console.error('Reset error:', e);
    }
    setResetLoading(false);
  };

  const handleClearAssets = async () => {
    const ok = window.confirm(
      'Удалить все активы (камеры) и алерты из БД? Это действие нельзя отменить.'
    );
    if (!ok) return;
    setClearLoading(true);
    try {
      const res = await fetch(
        `${API_BASE}/admin/assets/clear?confirm=DELETE&asset_type=camera`,
        { method: 'POST' }
      );
      const data = await res.json();
      if (data.status !== 'success') {
        alert(data.detail || 'Не удалось очистить ассеты');
        return;
      }
      setLastSimTime(null);
      await fetchAnalytics();
      onSimulationComplete();
    } catch (e) {
      console.error('Clear assets error:', e);
    }
    setClearLoading(false);
  };

  const handleRebuild = async () => {
    const ok = window.confirm(
      'Пересоздать все активы из БД? (очистка + синхронизация)'
    );
    if (!ok) return;
    setRebuildLoading(true);
    try {
      const res = await fetch(`${API_BASE}/admin/assets/rebuild`, { method: 'POST' });
      const data = await res.json();
      if (data.status !== 'success') {
        alert(data.detail || 'Не удалось перестроить');
        return;
      }
      setLastSimTime(null);
      await fetchAnalytics();
      onSimulationComplete();
    } catch (e) {
      console.error('Rebuild error:', e);
    }
    setRebuildLoading(false);
  };

  const criticalPercent =
    totalCameras > 0 ? Math.round((criticalCount / totalCameras) * 100) : 0;

  return (
    <div
      style={{
        background: '#0f172a',
        color: '#e2e8f0',
        height: '100%',
        overflowY: 'auto',
        display: 'flex',
        flexDirection: 'column',
        fontFamily: 'system-ui, sans-serif',
        fontSize: '13px',
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '16px 16px 10px',
          borderBottom: '1px solid #1e293b',
          background: '#0f172a',
          position: 'sticky',
          top: 0,
          zIndex: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
          <span style={{ fontSize: '18px' }}>🛰️</span>
          <span style={{ fontWeight: 700, fontSize: '15px', color: '#f1f5f9' }}>
            OSINT Digital Twin
          </span>
        </div>
        <div style={{ color: '#64748b', fontSize: '11px' }}>Алматы • Мониторинг в реальном времени</div>
      </div>

      {/* KPI Cards */}
      <div style={{ padding: '12px 16px 8px', display: 'flex', gap: '8px' }}>
        <div style={{ flex: 1, background: '#1e293b', borderRadius: '8px', padding: '10px', textAlign: 'center' }}>
          <div style={{ fontSize: '22px', fontWeight: 700, color: '#60a5fa' }}>{totalCameras}</div>
          <div style={{ fontSize: '10px', color: '#94a3b8', marginTop: '2px' }}>Камер</div>
        </div>
        <div style={{ flex: 1, background: '#1e293b', borderRadius: '8px', padding: '10px', textAlign: 'center' }}>
          <div style={{ fontSize: '22px', fontWeight: 700, color: '#ef4444' }}>{criticalCount}</div>
          <div style={{ fontSize: '10px', color: '#94a3b8', marginTop: '2px' }}>Критичных</div>
        </div>
        <div style={{ flex: 1, background: '#1e293b', borderRadius: '8px', padding: '10px', textAlign: 'center' }}>
          <div style={{ fontSize: '22px', fontWeight: 700, color: criticalPercent > 30 ? '#ef4444' : '#22c55e' }}>
            {criticalPercent}%
          </div>
          <div style={{ fontSize: '10px', color: '#94a3b8', marginTop: '2px' }}>Риск</div>
        </div>
      </div>

      {/* Pie Chart - Risk Distribution */}
      <div style={{ padding: '0 16px 8px' }}>
        <div style={{ color: '#94a3b8', fontSize: '11px', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Распределение рисков
        </div>
        <div style={{ height: '200px' }}>
          {riskData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={75}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {riskData.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={RISK_COLORS[entry.name] || RISK_COLORS.UNKNOWN}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: '#1e293b',
                    border: 'none',
                    borderRadius: '6px',
                    color: '#e2e8f0',
                  }}
                />
                <Legend iconSize={8} wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#475569' }}>
              Нет данных
            </div>
          )}
        </div>
      </div>

      {/* Bar Chart - Top CVEs */}
      {cveData.length > 0 && (
        <div style={{ padding: '0 16px 8px' }}>
          <div style={{ color: '#94a3b8', fontSize: '11px', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Топ CVE
          </div>
          <div style={{ height: '160px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={cveData}
                layout="vertical"
                margin={{ left: 0, right: 16, top: 0, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" tick={{ fontSize: 10, fill: '#64748b' }} />
                <YAxis
                  dataKey="cve_id"
                  type="category"
                  width={100}
                  tick={{ fontSize: 9, fill: '#94a3b8' }}
                />
                <Tooltip
                  contentStyle={{
                    background: '#1e293b',
                    border: 'none',
                    borderRadius: '6px',
                    color: '#e2e8f0',
                    fontSize: '11px',
                  }}
                />
                <Bar dataKey="count" fill="#f97316" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Simulation Section */}
      <div
        style={{
          margin: '8px 16px 8px',
          background: '#1e293b',
          borderRadius: '10px',
          padding: '14px',
          border: '1px solid #334155',
        }}
      >
        <div style={{ fontWeight: 600, fontSize: '12px', color: '#f1f5f9', marginBottom: '4px' }}>
          🎯 Симуляция атаки
        </div>
        <div style={{ color: '#64748b', fontSize: '11px', marginBottom: '12px', lineHeight: '1.5' }}>
          Моделирует сценарий Zero-Day атаки на 5 случайных камер.
          Инъекцирует CVE-2026-9999 (CVSS 10.0) и генерирует CRITICAL-алерты.
        </div>

        {lastSimTime && (
          <div
            style={{
              background: '#450a0a',
              border: '1px solid #7f1d1d',
              borderRadius: '6px',
              padding: '8px',
              marginBottom: '10px',
              fontSize: '11px',
              color: '#fca5a5',
            }}
          >
            ⚠️ Симуляция активна с {lastSimTime}
          </div>
        )}

        <button
          onClick={handleSimulate}
          disabled={simLoading}
          style={{
            width: '100%',
            background: simLoading ? '#374151' : '#dc2626',
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            padding: '10px',
            fontWeight: 700,
            fontSize: '12px',
            cursor: simLoading ? 'not-allowed' : 'pointer',
            marginBottom: '8px',
            transition: 'background 0.2s',
          }}
        >
          {simLoading ? '⏳ Выполняется...' : '🔴 SIMULATE ZERO-DAY ATTACK'}
        </button>

        <button
          onClick={handleReset}
          disabled={resetLoading}
          style={{
            width: '100%',
            background: resetLoading ? '#374151' : 'transparent',
            color: '#93c5fd',
            border: '1px solid #2563eb',
            borderRadius: '6px',
            padding: '8px',
            fontWeight: 600,
            fontSize: '11px',
            cursor: resetLoading ? 'not-allowed' : 'pointer',
            transition: 'background 0.2s',
          }}
        >
          {resetLoading ? '⏳ Сброс...' : '🔄 Сбросить симуляцию'}
        </button>
      </div>

      {/* Admin Section */}
      <div
        style={{
          margin: '0 16px 16px',
          background: '#1e293b',
          borderRadius: '10px',
          padding: '14px',
          border: '1px solid #334155',
        }}
      >
        <div style={{ fontWeight: 600, fontSize: '12px', color: '#94a3b8', marginBottom: '10px' }}>
          ⚙️ Управление БД
        </div>

        <button
          onClick={handleRebuild}
          disabled={rebuildLoading}
          style={{
            width: '100%',
            background: rebuildLoading ? '#374151' : 'transparent',
            color: '#86efac',
            border: '1px solid #16a34a',
            borderRadius: '6px',
            padding: '8px',
            fontWeight: 600,
            fontSize: '11px',
            cursor: rebuildLoading ? 'not-allowed' : 'pointer',
            marginBottom: '8px',
            transition: 'background 0.2s',
          }}
        >
          {rebuildLoading ? '⏳ Перестройка...' : '🔄 Перестроить (clear + sync)'}
        </button>

        <button
          onClick={handleClearAssets}
          disabled={clearLoading}
          style={{
            width: '100%',
            background: clearLoading ? '#374151' : 'transparent',
            color: '#fca5a5',
            border: '1px solid #ef4444',
            borderRadius: '6px',
            padding: '8px',
            fontWeight: 600,
            fontSize: '11px',
            cursor: clearLoading ? 'not-allowed' : 'pointer',
            transition: 'background 0.2s',
          }}
        >
          {clearLoading ? '⏳ Очистка...' : '🗑️ Очистить ассеты (DB)'}
        </button>
      </div>
    </div>
  );
}

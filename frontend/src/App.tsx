// App.tsx
import React, { useEffect, useState, useCallback } from 'react';
import MapView from './components/MapView';
import Dashboard from './components/Dashboard';
import { fetchDevices } from './api';

export interface Device {
  id: number;
  lat: number;
  lon: number;
  risk_level?: string | null;
  name?: string | null;
  vulnerabilities?: {
    cve_id?: string | null;
    cvss_score?: number | null;
    epss_score?: number | null;
    description?: string | null;
  }[];
  cvss_max?: number | null;
  confidence?: number | null;
  last_seen?: string | null;
  // EPSS and geo fields may come nested in props or at top level
  props?: {
    epss_max?: number | null;
    geo_source?: string | null;
    [key: string]: unknown;
  };
  geo_source?: string | null;
}

export interface AlertItem {
  id: number;
  asset_id: number;
  severity: string;
  // Backend sends alert_type; legacy field was "type" — support both
  alert_type: string;
  type?: string;
  message: string;
  details: {
    ip?: string;
    new_cves?: string[];
    epss_score?: number | null;
    port?: number | null;
    [key: string]: unknown;
  };
  created_at: string;
}

function App() {
  const [devices, setDevices]               = useState<Device[]>([]);
  const [alerts, setAlerts]                 = useState<AlertItem[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<number | null>(null);
  const [loading, setLoading]               = useState<boolean>(true);
  const [error, setError]                   = useState<string | null>(null);

  const loadDevices = useCallback(async () => {
    try {
      const data = await fetchDevices();
      setDevices(data || []);
    } catch (e: any) {
      console.error(e);
      setError('Не удалось загрузить данные устройств');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAlerts = useCallback(async () => {
    try {
      const res  = await fetch('http://localhost:8000/alerts/recent');
      const data: AlertItem[] = await res.json();
      // Normalise: if backend returns "type" instead of "alert_type", map it
      const normalised = data.map(a => ({
        ...a,
        alert_type: a.alert_type || (a as any).type || 'UNKNOWN',
        details: a.details || {},
      }));
      setAlerts(normalised || []);
    } catch (e) {
      console.error('Не удалось загрузить алерты', e);
    }
  }, []);

  useEffect(() => { loadDevices(); }, [loadDevices]);

  useEffect(() => {
    loadAlerts();
    const id = setInterval(loadAlerts, 30000);
    return () => clearInterval(id);
  }, [loadAlerts]);

  const handleSimulationComplete = useCallback(async () => {
    await Promise.all([loadDevices(), loadAlerts()]);
  }, [loadDevices, loadAlerts]);

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: '100vh', background: '#0f172a', color: '#94a3b8',
        fontFamily: 'system-ui, sans-serif', fontSize: '16px', gap: '10px' }}>
        <span style={{ fontSize: '24px' }}>🛰️</span>
        Загрузка данных цифрового двойника…
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: '100vh', background: '#0f172a', color: '#ef4444',
        fontFamily: 'system-ui, sans-serif', fontSize: '14px' }}>
        ⚠️ {error}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', height: '100vh', width: '100vw', overflow: 'hidden', background: '#0f172a' }}>
      {/* Левая панель */}
      <div style={{ width: '340px', flexShrink: 0, borderRight: '1px solid #1e293b', overflowY: 'auto' }}>
        <Dashboard onSimulationComplete={handleSimulationComplete} />
      </div>

      {/* Карта + правая панель алертов */}
      <div style={{ flexGrow: 1, position: 'relative' }}>
        <MapView
          devices={devices}
          alerts={alerts}
          selectedAssetId={selectedAssetId}
          onSelectAsset={setSelectedAssetId}
          onAlertsCleared={loadAlerts}
        />
      </div>
    </div>
  );
}

export default App;

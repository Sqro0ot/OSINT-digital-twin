// App.tsx
import React, { useEffect, useState } from 'react';
import MapView from './components/MapView';
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
    description?: string | null;
  }[];
  cvss_max?: number | null;
  confidence?: number | null;
  last_seen?: string | null;
}

export interface AlertItem {
  id: number;
  asset_id: number;
  severity: string;
  type: string;
  message: string;
  details: {
    ip: string;
    new_cves: string[];
  };
  created_at: string;
}

function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<number | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadDevices = async () => {
      try {
        const data = await fetchDevices();
        setDevices(data || []);
      } catch (e: any) {
        console.error(e);
        setError('Не удалось загрузить данные устройств');
      } finally {
        setLoading(false);
      }
    };

    loadDevices();
  }, []);

  useEffect(() => {
    const loadAlerts = async () => {
      try {
        const res = await fetch('http://localhost:8000/alerts/recent');
        const data = await res.json();
        setAlerts(data || []);
      } catch (e) {
        console.error('Не удалось загрузить алерты', e);
      }
    };

    loadAlerts();
    const id = setInterval(loadAlerts, 30000);
    return () => clearInterval(id);
  }, []);

  if (loading) {
    return <div>Загрузка карты…</div>;
  }

  if (error) {
    return <div>{error}</div>;
  }

  return (
    <MapView
      devices={devices}
      alerts={alerts}
      selectedAssetId={selectedAssetId}
      onSelectAsset={setSelectedAssetId}
    />
  );
}

export default App;

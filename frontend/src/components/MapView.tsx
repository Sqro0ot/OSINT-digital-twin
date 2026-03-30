import React, { useEffect, useState, useCallback } from 'react';
import {
  MapContainer,
  TileLayer,
  Marker,
  Popup,
  useMap,
} from 'react-leaflet';
import L, { DivIcon } from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Device, AlertItem } from '../App';

const API_BASE = 'http://localhost:8000';

interface MapViewProps {
  devices: Device[];
  alerts: AlertItem[];
  selectedAssetId: number | null;
  onSelectAsset: (id: number) => void;
  onAlertsCleared?: () => void;
}

const isValidCoord = (x: unknown): x is number =>
  typeof x === 'number' && Number.isFinite(x);

const getMarkerIcon = (
  risk?: string | null,
  highlighted: boolean = false,
): DivIcon => {
  const r = risk?.toLowerCase();
  const borderColor =
    r === 'critical' || r === 'high'
      ? '#ff4d4f'
      : r === 'medium'
      ? '#faad14'
      : r === 'low'
      ? '#52c41a'
      : '#0050b3';
  const bg = highlighted ? '#ffd666' : '#91d5ff';
  const boxShadow = highlighted
    ? '0 0 10px rgba(250,173,20,0.9)'
    : '0 0 6px rgba(0,0,0,0.5)';
  const html = `
    <div style="width:26px;height:26px;border-radius:50%;border:3px solid ${borderColor};background-color:${bg};box-shadow:${boxShadow};display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:bold;color:#000;">C</div>
  `;
  return L.divIcon({ className: '', html, iconSize: [30, 30], iconAnchor: [15, 15], popupAnchor: [0, -18] });
};

const FocusOnSelected: React.FC<{ devices: Device[]; selectedAssetId: number | null }> = ({ devices, selectedAssetId }) => {
  const map = useMap();
  useEffect(() => {
    if (!selectedAssetId) return;
    const dev = devices.find((d) => d.id === selectedAssetId);
    if (!dev || !isValidCoord(dev.lat) || !isValidCoord(dev.lon)) return;
    map.setView([dev.lat, dev.lon], 15, { animate: true });
  }, [selectedAssetId, devices, map]);
  return null;
};

const MapView: React.FC<MapViewProps> = ({ devices, alerts, selectedAssetId, onSelectAsset, onAlertsCleared }) => {
  const [clearLoading, setClearLoading] = useState(false);

  const handleClearAlerts = useCallback(async () => {
    if (!window.confirm('Очистить все алерты? Камеры останутся нетронутыми.')) return;
    setClearLoading(true);
    try {
      const res = await fetch(`${API_BASE}/admin/alerts/clear`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'success' && onAlertsCleared) {
        onAlertsCleared();
      }
    } catch (e) {
      console.error('Clear alerts error:', e);
    }
    setClearLoading(false);
  }, [onAlertsCleared]);

  const center: [number, number] = [43.2389, 76.8897];
  const visibleDevices = devices.filter((d) => isValidCoord(d.lat) && isValidCoord(d.lon));

  return (
    <div style={{ display: 'flex', height: '100vh' }}>
      {/* Карта */}
      <div style={{ flex: 1, position: 'relative' }}>
        <MapContainer center={center} zoom={12} style={{ height: '100%', width: '100%' }}>
          <TileLayer attribution="&copy; OpenStreetMap contributors" url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
          <FocusOnSelected devices={visibleDevices} selectedAssetId={selectedAssetId} />
          {visibleDevices.map((device) => (
            <Marker
              key={device.id}
              position={[device.lat, device.lon]}
              icon={getMarkerIcon(device.risk_level, device.id === selectedAssetId)}
            >
              <Popup>
                <div style={{ maxWidth: 260 }}>
                  <div><b>{device.name || `Camera ${device.id}`}</b></div>
                  {device.cvss_max != null && <div>CVSS max: {device.cvss_max.toFixed(1)}</div>}
                  {device.confidence != null && <div>Confidence: {(device.confidence * 100).toFixed(0)}%</div>}
                  {device.last_seen && <div>Last seen: {device.last_seen}</div>}
                  {device.vulnerabilities && device.vulnerabilities.length > 0 ? (
                    <div style={{ marginTop: 4, maxHeight: 150, overflowY: 'auto' }}>
                      Vulns:
                      <ul style={{ paddingLeft: 18, margin: 0 }}>
                        {device.vulnerabilities.map((v, idx) => (
                          <li key={idx}>{v.cve_id || 'CVE unknown'}{v.cvss_score != null && ` (CVSS: ${v.cvss_score})`}</li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <div style={{ marginTop: 4 }}>Vulns: none</div>
                  )}
                </div>
              </Popup>
            </Marker>
          ))}
        </MapContainer>
      </div>

      {/* Правая панель — алерты */}
      <div
        style={{
          width: 360,
          borderLeft: '1px solid #ddd',
          background: '#fafafa',
          display: 'flex',
          flexDirection: 'column',
          height: '100vh',
        }}
      >
        {/* Заголовок */}
        <div style={{ padding: '12px 12px 4px', flexShrink: 0 }}>
          <h3 style={{ marginTop: 0, marginBottom: 0 }}>Alerts</h3>
        </div>

        {/* Список алертов — прокручивается */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '8px 12px' }}>
          {alerts.length === 0 && <div style={{ color: '#8c8c8c', fontSize: 13 }}>No alerts</div>}
          {alerts.map((a) => {
            const newCves = a.details?.new_cves || [];
            return (
              <div
                key={a.id}
                onClick={() => onSelectAsset(a.asset_id)}
                style={{
                  marginBottom: 8,
                  padding: 8,
                  borderRadius: 4,
                  border: a.asset_id === selectedAssetId ? '2px solid #fa8c16' : '1px solid #d9d9d9',
                  background: a.severity === 'CRITICAL' || a.severity === 'HIGH' ? '#fff1f0' : '#fffbe6',
                  fontSize: 12,
                  cursor: 'pointer',
                }}
              >
                <div style={{ fontWeight: 600 }}>[{a.severity}] Asset #{a.asset_id}</div>
                <div style={{ marginTop: 4 }}>{a.message}</div>
                <div style={{ marginTop: 4, color: '#595959' }}>IP: {a.details?.ip ?? '—'}</div>
                {newCves.length > 0 && (
                  <div style={{ marginTop: 4, color: '#8c8c8c' }}>
                    New CVEs: {newCves.slice(0, 3).join(', ')}{newCves.length > 3 && ' ...'}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Кнопка очистки — всегда внизу */}
        <div
          style={{
            flexShrink: 0,
            padding: '10px 12px',
            borderTop: '1px solid #e2e8f0',
            background: '#fafafa',
          }}
        >
          <button
            onClick={handleClearAlerts}
            disabled={clearLoading || alerts.length === 0}
            style={{
              width: '100%',
              padding: '8px 0',
              borderRadius: 6,
              border: '1px solid #d97706',
              background: 'transparent',
              color: clearLoading || alerts.length === 0 ? '#a8a29e' : '#b45309',
              fontWeight: 600,
              fontSize: 12,
              cursor: clearLoading || alerts.length === 0 ? 'not-allowed' : 'pointer',
              transition: 'background 0.2s',
            }}
          >
            {clearLoading ? '⏳ Очистка...' : '🗑️ Очистить алерты'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default MapView;

import React, { useEffect, useState, useCallback } from 'react';
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet';
import L, { DivIcon } from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Device, AlertItem } from '../App';

const API_BASE = 'http://localhost:8000';

const SEVERITY_BORDER: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
};
const SEVERITY_BG: Record<string, string> = {
  CRITICAL: '#fff1f0',
  HIGH:     '#fff7ed',
  MEDIUM:   '#fffbe6',
  LOW:      '#f0fdf4',
};
const SEVERITY_TEXT: Record<string, string> = {
  CRITICAL: '#b91c1c',
  HIGH:     '#c2410c',
  MEDIUM:   '#a16207',
  LOW:      '#15803d',
};

const ALERT_TYPE_LABEL: Record<string, string> = {
  NEW_VULNERABILITIES:   '🆕 New CVE',
  RISK_ELEVATED:         '📈 Risk Up',
  HIGH_EPSS_SCORE:       '☣️ High EPSS',
  EXPOSED_CRITICAL_PORT: '🔓 Open Port',
};

const isValidCoord = (x: unknown): x is number =>
  typeof x === 'number' && Number.isFinite(x);

const getMarkerIcon = (risk?: string | null, highlighted = false): DivIcon => {
  const r = (risk || '').toUpperCase();
  const borderColor = SEVERITY_BORDER[r] || '#0050b3';
  const bg = highlighted ? '#ffd666' : '#91d5ff';
  const boxShadow = highlighted
    ? '0 0 10px rgba(250,173,20,0.9)'
    : '0 0 6px rgba(0,0,0,0.5)';
  const html = `<div style="width:26px;height:26px;border-radius:50%;border:3px solid ${borderColor};background-color:${bg};box-shadow:${boxShadow};display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:bold;color:#000;">C</div>`;
  return L.divIcon({ className: '', html, iconSize: [30, 30], iconAnchor: [15, 15], popupAnchor: [0, -18] });
};

const FocusOnSelected: React.FC<{ devices: Device[]; selectedAssetId: number | null }> = ({ devices, selectedAssetId }) => {
  const map = useMap();
  useEffect(() => {
    if (!selectedAssetId) return;
    const dev = devices.find(d => d.id === selectedAssetId);
    if (!dev || !isValidCoord(dev.lat) || !isValidCoord(dev.lon)) return;
    map.setView([dev.lat, dev.lon], 15, { animate: true });
  }, [selectedAssetId, devices, map]);
  return null;
};

const epssColor = (score?: number | null) =>
  score == null ? '#94a3b8'
  : score >= 0.7 ? '#ef4444'
  : score >= 0.4 ? '#f97316'
  : '#22c55e';

interface MapViewProps {
  devices: Device[];
  alerts: AlertItem[];
  selectedAssetId: number | null;
  onSelectAsset: (id: number) => void;
  onAlertsCleared?: () => void;
}

const MapView: React.FC<MapViewProps> = ({ devices, alerts, selectedAssetId, onSelectAsset, onAlertsCleared }) => {
  const [clearLoading, setClearLoading] = useState(false);
  const [filter, setFilter]             = useState<string>('ALL');

  const handleClearAlerts = useCallback(async () => {
    if (!window.confirm('Очистить все алерты?')) return;
    setClearLoading(true);
    try {
      const res = await fetch(`${API_BASE}/admin/alerts/clear`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'success' && onAlertsCleared) onAlertsCleared();
    } catch (e) { console.error(e); }
    setClearLoading(false);
  }, [onAlertsCleared]);

  const center: [number, number] = [43.2389, 76.8897];
  const visibleDevices = devices.filter(d => isValidCoord(d.lat) && isValidCoord(d.lon));

  const alertTypes = Array.from(new Set(alerts.map(a => a.alert_type)));
  const filteredAlerts = filter === 'ALL' ? alerts : alerts.filter(a => a.alert_type === filter);

  return (
    <div style={{ display: 'flex', height: '100vh' }}>

      {/* Map */}
      <div style={{ flex: 1, position: 'relative' }}>
        <MapContainer center={center} zoom={12} style={{ height: '100%', width: '100%' }}>
          <TileLayer
            attribution="&copy; OpenStreetMap contributors"
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />
          <FocusOnSelected devices={visibleDevices} selectedAssetId={selectedAssetId} />
          {visibleDevices.map(device => {
            const props = (device as any).props || {};
            const epssMax: number | null = props.epss_max ?? null;
            const geoSource: string     = props.geo_source ?? (device as any).geo_source ?? '—';
            return (
              <Marker
                key={device.id}
                position={[device.lat, device.lon]}
                icon={getMarkerIcon(device.risk_level, device.id === selectedAssetId)}
              >
                <Popup>
                  <div style={{ maxWidth: 270, fontSize: 12 }}>
                    <div style={{ fontWeight: 700, marginBottom: 4 }}>
                      {device.name || `Camera ${device.id}`}
                    </div>

                    {/* Risk & CVSS */}
                    <div style={{ display: 'flex', gap: 6, marginBottom: 4, flexWrap: 'wrap' }}>
                      {device.risk_level && (
                        <span style={{
                          background: SEVERITY_BG[device.risk_level] || '#f5f5f5',
                          color: SEVERITY_TEXT[device.risk_level] || '#595959',
                          border: `1px solid ${SEVERITY_BORDER[device.risk_level] || '#d9d9d9'}`,
                          borderRadius: 4, padding: '1px 6px', fontSize: 11, fontWeight: 600,
                        }}>{device.risk_level}</span>
                      )}
                      {device.cvss_max != null && (
                        <span style={{ background: '#fff7ed', color: '#c2410c',
                          border: '1px solid #fed7aa', borderRadius: 4, padding: '1px 6px', fontSize: 11 }}>
                          CVSS {device.cvss_max.toFixed(1)}
                        </span>
                      )}
                      {epssMax !== null && (
                        <span style={{ background: '#faf5ff', color: epssColor(epssMax),
                          border: `1px solid ${epssColor(epssMax)}55`,
                          borderRadius: 4, padding: '1px 6px', fontSize: 11, fontWeight: 600 }}>
                          EPSS {(epssMax * 100).toFixed(1)}%
                        </span>
                      )}
                    </div>

                    {/* Geo source */}
                    <div style={{ color: '#6b7280', fontSize: 11, marginBottom: 4 }}>
                      📍 Источник гео: <span style={{ color: '#374151', fontWeight: 500 }}>{geoSource}</span>
                    </div>

                    {device.last_seen && (
                      <div style={{ color: '#9ca3af', fontSize: 11, marginBottom: 4 }}>
                        🕐 {device.last_seen}
                      </div>
                    )}

                    {/* Vulns */}
                    {device.vulnerabilities && device.vulnerabilities.length > 0 ? (
                      <div style={{ marginTop: 4, maxHeight: 130, overflowY: 'auto' }}>
                        <div style={{ color: '#6b7280', marginBottom: 2 }}>Уязвимости:</div>
                        <ul style={{ paddingLeft: 16, margin: 0 }}>
                          {device.vulnerabilities.map((v, idx) => (
                            <li key={idx} style={{ marginBottom: 2 }}>
                              <span style={{ fontWeight: 600 }}>{v.cve_id || 'CVE?'}</span>
                              {v.cvss_score != null && (
                                <span style={{ color: '#9ca3af' }}> CVSS {v.cvss_score}</span>
                              )}
                              {(v as any).epss_score != null && (
                                <span style={{ color: epssColor((v as any).epss_score) }}>
                                  {' '}EPSS {((v as any).epss_score * 100).toFixed(1)}%
                                </span>
                              )}
                            </li>
                          ))}
                        </ul>
                      </div>
                    ) : (
                      <div style={{ color: '#9ca3af', fontSize: 11 }}>Уязвимостей нет</div>
                    )}
                  </div>
                </Popup>
              </Marker>
            );
          })}
        </MapContainer>
      </div>

      {/* Right panel — alerts */}
      <div style={{ width: 360, borderLeft: '1px solid #ddd', background: '#fafafa',
        display: 'flex', flexDirection: 'column', height: '100vh' }}>

        {/* Panel header */}
        <div style={{ padding: '12px 12px 8px', flexShrink: 0, borderBottom: '1px solid #e5e7eb' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0, fontSize: 14 }}>Алерты</h3>
            <span style={{ fontSize: 11, color: '#9ca3af' }}>{filteredAlerts.length}</span>
          </div>
          {/* Type filter */}
          {alertTypes.length > 0 && (
            <div style={{ display: 'flex', gap: 4, marginTop: 8, flexWrap: 'wrap' }}>
              {['ALL', ...alertTypes].map(t => (
                <button key={t}
                  onClick={() => setFilter(t)}
                  style={{
                    fontSize: 10, padding: '2px 7px', borderRadius: 12,
                    border: filter === t ? '1px solid #2563eb' : '1px solid #d1d5db',
                    background: filter === t ? '#dbeafe' : 'white',
                    color: filter === t ? '#1d4ed8' : '#6b7280',
                    cursor: 'pointer', fontWeight: filter === t ? 600 : 400,
                  }}>
                  {t === 'ALL' ? 'Все' : (ALERT_TYPE_LABEL[t] || t)}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Alerts list */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '8px 12px' }}>
          {filteredAlerts.length === 0 && (
            <div style={{ color: '#9ca3af', fontSize: 13, textAlign: 'center', marginTop: 24 }}>Нет алертов</div>
          )}
          {filteredAlerts.map(a => {
            const sev         = a.severity as string;
            const newCves     = a.details?.new_cves || [];
            const epssScore   = a.details?.epss_score ?? null;
            const port        = a.details?.port ?? null;
            const bg          = SEVERITY_BG[sev]     || '#fffbe6';
            const borderColor = SEVERITY_BORDER[sev] || '#d9d9d9';
            const textColor   = SEVERITY_TEXT[sev]   || '#595959';
            const typeLabel   = ALERT_TYPE_LABEL[a.alert_type] || a.alert_type;
            return (
              <div
                key={a.id}
                onClick={() => onSelectAsset(a.asset_id)}
                style={{
                  marginBottom: 8, padding: 8, borderRadius: 4, cursor: 'pointer',
                  border: a.asset_id === selectedAssetId
                    ? `2px solid ${borderColor}` : `1px solid ${borderColor}`,
                  background: bg, fontSize: 12,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div style={{ fontWeight: 600, color: textColor }}>[{a.severity}] {typeLabel}</div>
                  <div style={{ fontSize: 10, color: '#9ca3af', marginLeft: 4, flexShrink: 0 }}>#{a.asset_id}</div>
                </div>
                <div style={{ marginTop: 4, color: '#374151' }}>{a.message}</div>
                <div style={{ marginTop: 4, color: '#6b7280' }}>IP: {a.details?.ip ?? '—'}</div>
                {epssScore !== null && (
                  <div style={{ marginTop: 3, color: epssColor(epssScore), fontWeight: 600, fontSize: 11 }}>
                    ☣️ EPSS: {(epssScore * 100).toFixed(1)}%
                  </div>
                )}
                {port !== null && (
                  <div style={{ marginTop: 3, color: '#0891b2', fontSize: 11 }}>
                    🔓 Порт: {port}
                  </div>
                )}
                {newCves.length > 0 && (
                  <div style={{ marginTop: 3, color: '#9ca3af', fontSize: 11 }}>
                    CVEs: {newCves.slice(0, 3).join(', ')}{newCves.length > 3 && ' ...'}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Clear button */}
        <div style={{ flexShrink: 0, padding: '10px 12px', borderTop: '1px solid #e2e8f0', background: '#fafafa' }}>
          <button
            onClick={handleClearAlerts}
            disabled={clearLoading || alerts.length === 0}
            style={{
              width: '100%', padding: '8px 0', borderRadius: 6,
              border: '1px solid #d97706',
              background: 'transparent',
              color: clearLoading || alerts.length === 0 ? '#a8a29e' : '#b45309',
              fontWeight: 600, fontSize: 12,
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
